#!/usr/bin/env bash
# check_dnss_ubuntu_debug.sh

set -euo pipefail

INPUT="${1:-$HOME/1234567.txt}"     
OUT="${OUT:-$(pwd)/results.csv}"    
TESTNAME="${TESTNAME:-cloudflare.com}" 
QUERY="${QUERY:-ANY}"
REQ_EST_SIZE=${REQ_EST_SIZE:-70}   

echo "=== DNS Amplification Checker (Debug Mode) ==="
echo "Input file : $INPUT"
echo "Output file: $OUT"
echo "Test query : $QUERY $TESTNAME"
echo "---------------------------------------------"

if ! command -v dig >/dev/null 2>&1; then
  echo "[ERR] dig not found. Cài đặt bằng: sudo apt install dnsutils"
  exit 1
fi

USE_TCPDUMP=0
if command -v tcpdump >/dev/null 2>&1; then
  if [ "$(id -u)" -eq 0 ]; then
    USE_TCPDUMP=1
  else
    echo "[WARN] tcpdump có sẵn nhưng bạn không chạy sudo -> sẽ bỏ qua capture."
  fi
fi

echo "ip,port,query,bytes_stdout,captured_packet_len,approx_amp_factor,notes" > "$OUT"

LINE_NUM=0
TOTAL_LINES=$(grep -c . "$INPUT" || echo 0)

while IFS= read -r line || [ -n "$line" ]; do
  LINE_NUM=$((LINE_NUM + 1))
  line="${line%%#*}"                   
  line="${line//[[:space:]]/}"         
  [ -z "$line" ] && continue

  ip="${line%%:*}"
  port="${line##*:}"
  if [[ -z "$ip" || -z "$port" || "$ip" == "$port" ]]; then
    echo "[WARN] ($LINE_NUM/$TOTAL_LINES) Dòng lỗi cú pháp: $line"
    continue
  fi

  echo -e "\n[INFO] ($LINE_NUM/$TOTAL_LINES) Kiểm tra $ip:$port ..."

  bytes_stdout=0
  pktlen=""
  notes=""


  echo "[DBG] Gửi dig @$ip -p $port $TESTNAME $QUERY ..."
  if dig_out=$(timeout 6 dig @"$ip" -p "$port" "$TESTNAME" $QUERY +dnssec +bufsize=4096 +noall +answer +additional +stats 2>/dev/null); then
    bytes_stdout=$(printf "%s" "$dig_out" | wc -c)
    echo "[OK] Nhận được phản hồi dài $bytes_stdout bytes"
  else
    echo "[ERR] Timeout hoặc không phản hồi từ $ip:$port"
    notes="${notes}dig_timeout_or_error;"
  fi

  if [ "$USE_TCPDUMP" -eq 1 ]; then
    TMPPCAP="/tmp/dns_cap_${ip//./_}_$$.pcap"
    echo "[DBG] Bắt gói phản hồi từ $ip (timeout 5s)..."
    timeout 6 tcpdump -n -i any "udp and src host $ip and src port $port and dst port 53" -c 1 -w "$TMPPCAP" 2>/dev/null || true
    if [ -f "$TMPPCAP" ]; then
      first_line=$(tcpdump -nn -q -r "$TMPPCAP" 2>/dev/null | head -n1 || true)
      if [[ "$first_line" =~ length[[:space:]]([0-9]+) ]]; then
        pktlen="${BASH_REMATCH[1]}"
        echo "[OK] Gói trả về có length $pktlen bytes"
      fi
      rm -f "$TMPPCAP"
    else
      echo "[DBG] Không bắt được gói phản hồi từ $ip"
    fi
  fi

  amp=""
  if [[ -n "$pktlen" && "$pktlen" -gt 0 ]]; then
    amp=$(awk -v p="$pktlen" -v r="$REQ_EST_SIZE" 'BEGIN{printf "%.1f", (p/r)}')
  else
    if [ "$bytes_stdout" -gt 0 ]; then
      amp=$(awk -v p="$bytes_stdout" -v r="$REQ_EST_SIZE" 'BEGIN{printf "%.1f", (p/r)}')
    fi
  fi

  if [[ -n "$amp" ]]; then
    echo "[DBG] Ước lượng hệ số khuếch đại: $amp x"
  fi

  if [[ -n "$amp" && $(echo "$amp >= 10" | bc -l) -eq 1 ]]; then
    notes="${notes}possible_amplifier;"
    echo "[WARN] Có thể bị lợi dụng amplification! (factor=$amp)"
  fi

  echo "${ip},${port},${QUERY},${bytes_stdout},${pktlen:-},${amp:-},${notes}" >> "$OUT"

  sleep 0.2
done < "$INPUT"

echo -e "\n✅ Hoàn tất! Kết quả được lưu tại: $OUT"
echo "Bạn có thể mở file này bằng Excel hoặc VSCode."
