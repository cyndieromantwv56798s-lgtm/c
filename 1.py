#!/usr/bin/env python3
"""
check_dnss_udp_stream.py
- Input: 1234567.txt (IP:PORT per line)
- Output: results.txt (CSV-like)
- Only UDP (no TCP)
- Streaming write: as soon as bytes_udp > 1000, append a line
- Query: ANY cloudflare.com
- Timeout: 1.5s
- Concurrency: 200
Requires: dnspython (pip install dnspython)
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.message
import dns.query
import dns.rdatatype
import dns.exception
import socket
import sys
import time
import random
import string
import threading
import os

INPUT_FILE = "1234567.txt"
OUTPUT_FILE = "results.txt"
TESTNAME = "cloudflare.com"
QUERY = "ANY"
REQ_EST_SIZE = 70
BUF_SIZE = 4096
TIMEOUT = 1.5
CONCURRENCY = 45
WRITE_THRESHOLD = 1000  # bytes threshold to save the host

write_lock = threading.Lock()

def parse_line(line):
    line = line.split("#", 1)[0].strip()
    if not line or ":" not in line:
        return None
    ip, port_s = line.split(":", 1)
    ip = ip.strip()
    try:
        port = int(port_s.strip())
        return ip, port
    except:
        return None

def build_query(qname=TESTNAME, qtype=dns.rdatatype.ANY, rd=True, bufsize=BUF_SIZE):
    q = dns.message.make_query(qname, qtype, use_edns=0, payload=bufsize)
    if rd:
        q.flags |= dns.flags.RD
    else:
        q.flags &= ~dns.flags.RD
    return q

def send_udp(ip, port, q):
    try:
        resp = dns.query.udp(q, ip, port=port, timeout=TIMEOUT)
        wire = resp.to_wire()
        wire_len = len(wire)
        tc = bool(resp.flags & dns.flags.TC)
        edns_size = getattr(resp, "edns", None)
        has_rrsig = False
        try:
            for rr in (resp.answer + resp.additional + resp.authority):
                for r in rr:
                    if r.rdtype == dns.rdatatype.RRSIG:
                        has_rrsig = True
                        break
                if has_rrsig:
                    break
        except Exception:
            pass
        return {"resp": resp, "wire_len": wire_len, "tc": tc, "edns_size": edns_size, "has_rrsig": has_rrsig, "err": None}
    except dns.exception.Timeout:
        return {"resp": None, "wire_len": 0, "tc": False, "edns_size": None, "has_rrsig": False, "err": "timeout"}
    except (OSError, socket.error) as e:
        return {"resp": None, "wire_len": 0, "tc": False, "edns_size": None, "has_rrsig": False, "err": f"socket_error:{e}"}
    except Exception as e:
        return {"resp": None, "wire_len": 0, "tc": False, "edns_size": None, "has_rrsig": False, "err": f"error:{type(e).__name__}:{e}"}

def is_recursive_response(resp):
    try:
        if not resp:
            return False
        if len(resp.answer) > 0 and not bool(resp.flags & dns.flags.AA):
            return True
    except Exception:
        pass
    return False

def write_result_line(r):
    # thread-safe append to OUTPUT_FILE
    line = ",".join([
        str(r.get("ip","")),
        str(r.get("port","")),
        str(r.get("query","")),
        str(r.get("bytes_udp","")),
        str(r.get("truncated_udp","")),
        str(r.get("edns_size","")),
        str(r.get("is_recursive","")),
        str(r.get("dnssec","")),
        (r.get("notes","") or "").replace("\n"," ").replace("\r"," ")
    ]) + "\n"
    with write_lock:
        with open(OUTPUT_FILE, "a", encoding="utf-8", newline="\n") as f:
            f.write(line)

def worker(ip, port):
    start = time.time()
    notes = []

    # 1) UDP ANY with EDNS
    q_udp = build_query(TESTNAME, dns.rdatatype.ANY, rd=True, bufsize=BUF_SIZE)
    r = send_udp(ip, port, q_udp)
    bytes_udp = r["wire_len"]
    truncated_udp = int(bool(r["tc"]))
    edns_size = r["edns_size"] if r["edns_size"] is not None else ""
    dnssec = int(bool(r["has_rrsig"]))
    if r["err"]:
        notes.append(r["err"])

    # 2) Heuristic recursion probe (random subdomain via UDP)
    randname = "probe-" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8)) + ".com"
    q_rand = build_query(randname, dns.rdatatype.A, rd=True, bufsize=512)
    rr = send_udp(ip, port, q_rand)
    is_recursive = False
    if rr["err"] is None and rr["wire_len"] > 0 and rr["resp"]:
        if is_recursive_response(rr["resp"]):
            is_recursive = True
            notes.append("recursive_resolver")
    elif rr["err"]:
        notes.append("randprobe:" + rr["err"])

    if bytes_udp and bytes_udp > WRITE_THRESHOLD:
        notes.append("possible_amplifier")

    dur = time.time() - start
    if bytes_udp:
        print(f"[OK] {ip}:{port} udp={bytes_udp} truncated={truncated_udp} t={dur:.2f}s", file=sys.stderr)
    else:
        print(f"[ERR] {ip}:{port} no response ({';'.join(notes)}) t={dur:.2f}s", file=sys.stderr)

    rec = {
        "ip": ip,
        "port": port,
        "query": QUERY,
        "bytes_udp": bytes_udp,
        "truncated_udp": truncated_udp,
        "edns_size": edns_size,
        "is_recursive": int(bool(is_recursive)),
        "dnssec": dnssec,
        "notes": ";".join(notes)
    }

    # streaming write: append immediately if threshold met
    if bytes_udp and bytes_udp > WRITE_THRESHOLD:
        write_result_line(rec)

    return rec

def main():
    # prepare output file: write header (overwrite if exists)
    header = ",".join([
        "ip","port","query","bytes_udp","truncated_udp",
        "edns_size","is_recursive","dnssec","notes"
    ]) + "\n"
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8", newline="\n") as f:
            f.write(header)
    except Exception as e:
        print(f"[ERR] Cannot create {OUTPUT_FILE}: {e}", file=sys.stderr)
        return

    try:
        lines = open(INPUT_FILE, "r", encoding="utf-8").read().splitlines()
    except Exception as e:
        print(f"[ERR] Cannot open {INPUT_FILE}: {e}", file=sys.stderr)
        return

    tasks = []
    for line in lines:
        parsed = parse_line(line)
        if parsed:
            tasks.append(parsed)

    if not tasks:
        print("[ERR] No valid IP:PORT found.", file=sys.stderr)
        return

    print(f"=== DNS UDP-only Amplification Stream Writer ===", file=sys.stderr)
    print(f"Targets: {len(tasks)}, concurrency={CONCURRENCY}, timeout={TIMEOUT}s, write_threshold={WRITE_THRESHOLD} bytes", file=sys.stderr)

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        future_to_target = {ex.submit(worker, ip, port): (ip, port) for ip, port in tasks}
        for fut in as_completed(future_to_target):
            try:
                _ = fut.result()
            except Exception as e:
                t = future_to_target.get(fut)
                print(f"[ERR] Worker failed for {t}: {e}", file=sys.stderr)

    print(f"\n✅ Done. Matching hosts were appended to {OUTPUT_FILE}", file=sys.stderr)

if __name__ == "__main__":
    main()
