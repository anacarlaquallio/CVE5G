#!/usr/bin/env bash
# =============================================================================
# 02_generate_traffic_v2.sh
# CVE5G Dataset v2.0
#
# Usage:
#   SCENARIO=1 ./scripts/02_generate_traffic_v2.sh
#   SCENARIO=2 ./scripts/02_generate_traffic_v2.sh
#   SCENARIO=3 ./scripts/02_generate_traffic_v2.sh
#
# =============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# ==========================================================================
# SETUP
# ==========================================================================
SCENARIO="${SCENARIO:-2}"
RESULTS_DIR="${ROOT_DIR}/results/scenario_${SCENARIO}"

PCAP_BRIDGE="$RESULTS_DIR/cve5g_s${SCENARIO}_bridge.pcap"   
PCAP_N2="$RESULTS_DIR/cve5g_s${SCENARIO}_n2.pcap"           
PCAP_FILTERED="$RESULTS_DIR/cve5g_s${SCENARIO}_filtered.pcap"
PCAP_RFSIM="$RESULTS_DIR/cve5g_s${SCENARIO}_rfsim.pcap"    
LABELS_TIME_CSV="$RESULTS_DIR/cve5g_s${SCENARIO}_labels_time.csv"   
LABELS_FLOW_CSV="$RESULTS_DIR/cve5g_s${SCENARIO}_labels_flow.csv"   
CAPTURE_STATS="$RESULTS_DIR/cve5g_s${SCENARIO}_capture_stats.txt"   
TCPDUMP_BRIDGE_PID="$RESULTS_DIR/tcpdump_bridge.pid"
TCPDUMP_RFSIM_PID="$RESULTS_DIR/tcpdump_rfsim.pid"
TCPDUMP_BRIDGE_LOG="/tmp/tcpdump_bridge_s${SCENARIO}.log"
TCPDUMP_RFSIM_LOG="/tmp/tcpdump_rfsim_s${SCENARIO}.log"
AMF_LOG="$RESULTS_DIR/amf_crash_s${SCENARIO}.log"

AMF_IP="192.168.70.132"
KALI_IP="192.168.70.140"
UPF_IP="192.168.70.134"  
GNB_IP="192.168.70.160"
UE_BIND_IP="${UE_BIND_IP:-}"
AMF_SBI_PORT=80
AMF_NGAP_PORT=38412
SUDO_PASSWORD="${SUDO_PASSWORD:-}"
TOTAL_DURATION=300
BRIDGE_IFACE="${BRIDGE_IFACE:-oaiworkshop}"

FILTERED_PROTOS="http2 or ngap or pfcp or gtp"

TRAFFIC_GEN="oai-traffic-sidecar"
SIDECAR_IMAGE="${SIDECAR_IMAGE:-cve5g-traffic-sidecar:ready}"
UE_REG_TIMEOUT="${UE_REG_TIMEOUT:-90}"   
CVE_METHOD="${CVE_METHOD:-python}"
EXPLOIT_SRC="scripts/exploits/cve_65805_exploit.py"

T0_EPOCH=$(date +%s.%N)
T0=${T0_EPOCH%.*}
mkdir -p "$RESULTS_DIR"

# ==========================================================================
# HELPERS
# ==========================================================================
sudo_run() {
  if [[ -n "$SUDO_PASSWORD" ]]; then
    printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' "$@"
  else
    sudo "$@"
  fi
}

container_running() {
  [[ "$(docker inspect -f '{{.State.Status}}' "$1" 2>/dev/null)" == "running" ]]
}

elapsed() { echo $(( $(date +%s) - T0 )); }
log()     { echo "[$(elapsed)s] $*"; }

now_epoch() { date +%s.%6N; }
rel_s()     { awk -v e="$1" -v t0="$T0_EPOCH" 'BEGIN { printf "%.3f", e - t0 }'; }
add_s()     { awk -v e="$1" -v d="$2" 'BEGIN { printf "%.6f", e + d }'; }

label_time() {
  local name="$1" src="$2" dst="$3" e_start="$4" e_end="$5"
  echo "$name,$src,$dst,$(rel_s "$e_start"),$(rel_s "$e_end"),$e_start,$e_end" >> "$LABELS_TIME_CSV"
}

label_flow() {
  local name="$1" proto="$2" src_ip="$3" src_port="$4" dst_ip="$5" dst_port="$6"
  echo "$name,$proto,$src_ip,$src_port,$dst_ip,$dst_port" >> "$LABELS_FLOW_CSV"
}

detect_ue_ip() {
  local ip
  ip=$(docker exec oai-nr-ue1 bash -c \
    "ip -4 addr show oaitun_ue1 2>/dev/null | grep -oP '(?<=inet )[\d.]+'") || true
  if [[ -z "$ip" ]]; then
    ip=$(docker exec oai-nr-ue1 bash -c \
      "ip -4 addr show | grep -v '127\.' | grep -v '192\.168\.' | \
       grep -oP '(?<=inet )[\d.]+' | head -1") || true
  fi
  echo "$ip"
}

start_sidecar() {
  docker rm -f "$TRAFFIC_GEN" >/dev/null 2>&1 || true
  docker run -d --name "$TRAFFIC_GEN" --network container:oai-nr-ue1 \
    --cap-add NET_ADMIN "$SIDECAR_IMAGE" tail -f /dev/null >/dev/null
}

wait_ue_ip() {
  local max="$1" waited=0 ip=""
  while [[ $waited -lt $max ]]; do
    ip=$(docker exec oai-nr-ue1 bash -c \
      "ip -4 addr show oaitun_ue1 2>/dev/null | grep -oP '(?<=inet )[\d.]+'" 2>/dev/null) || true
    if [[ -n "$ip" ]]; then echo "$ip"; return 0; fi
    sleep 1; waited=$(( waited + 1 ))
  done
  return 1
}

tshark_ok() {
  local rc="$1" errlog="$2"
  [[ "$rc" -eq 0 ]] && return 0
  [[ "$rc" -eq 2 ]] && grep -q "cut short in the middle of a packet" "$errlog" 2>/dev/null && return 0
  return 1
}

amf_alive() {
  container_running oai-amf && docker exec oai-amf bash -c "kill -0 1 2>/dev/null" 2>/dev/null
}

capture_amf_crash_log() {
  echo "[$(elapsed)s] Capturing AMF logs (crash evidence)..."
  docker logs oai-amf --tail 50 > "$AMF_LOG" 2>&1 || true
}

wait_ready() {
  local container="$1" sentinel="$2" label_="$3" max_wait="${4:-180}"
  echo "Waiting for $label_ to become ready..."
  local waited=0
  while ! docker exec "$container" test -f "$sentinel" 2>/dev/null; do
    if [[ $waited -ge $max_wait ]]; then
      echo "[error] $label_ did not become ready after ${max_wait}s."; exit 1
    fi
    sleep 5; waited=$(( waited + 5 ))
    echo "  ... waiting for $label_ ($waited/${max_wait}s)"
  done
  echo "$label_ ready."
}

safe_sleep_until() {
  local target="$1"
  local now; now=$(elapsed)
  local remaining=$(( target - now ))
  if [[ $remaining -gt 0 ]]; then sleep "$remaining"; fi
}

trigger_ue_reregistration() {
  log "Triggering UE re-registration (docker restart oai-nr-ue1)..."
  local TS; TS=$(now_epoch)

  docker restart -t 5 oai-nr-ue1 >/dev/null

  local ip
  if ! ip=$(wait_ue_ip "$UE_REG_TIMEOUT"); then
    log "[error] UE sem IP no oaitun_ue1 ${UE_REG_TIMEOUT}s após o restart."
    log "        Veja: docker logs oai-nr-ue1 --tail 50 ; docker logs oai-amf --tail 50"
    exit 1
  fi
  sleep 3   
  local TE; TE=$(now_epoch)
  UE_BIND_IP="$ip"
  log "UE registered again at t=$(rel_s "$TE")s (IP ${UE_BIND_IP})"

  start_sidecar
  log "Sidecar recreated in the new UE network namespace."

  label_time "benign_ngap_registration" "$GNB_IP" "$AMF_IP" "$TS" "$TE"

  label_flow "benign_ngap_registration" "132" "$GNB_IP" "any" "$AMF_IP" "38412"
}

# ==========================================================================
# BENIGN TRAFFIC
# ==========================================================================
start_benign_traffic() {
  local ue_ip="$1"
  local duration="$2"

  log "Configuring routes for the 5G tunnel..."
  docker exec "$TRAFFIC_GEN" bash -c "
    echo 'nameserver 8.8.8.8' > /etc/resolv.conf
    ip rule add from ${ue_ip} table 100 2>/dev/null || true
    ip route add default dev oaitun_ue1 table 100 2>/dev/null || true
  " || true

  log "Starting Ubuntu ISO downloads..."
  docker exec -d "$TRAFFIC_GEN" bash -c "
    END=\$(( \$(date +%s) + ${duration} ))
    while [[ \$(date +%s) -lt \$END ]]; do
      wget -q -O /dev/null --bind-address=${ue_ip} --limit-rate=20m --timeout=30 \
        https://releases.ubuntu.com/22.04/ubuntu-22.04.5-desktop-amd64.iso 2>/dev/null || true
      sleep 3
    done
  "

  log "Starting YouTube streaming via yt-dlp..."
  docker exec -d "$TRAFFIC_GEN" bash -c "
    END=\$(( \$(date +%s) + ${duration} ))
    while [[ \$(date +%s) -lt \$END ]]; do
      yt-dlp --source-address ${ue_ip} --format 'bestaudio[ext=m4a]' \
        --output '/tmp/yt_%(id)s.%(ext)s' --no-playlist --quiet \
        'https://www.youtube.com/live/Nv4DRqrSilM?si=O4LOhJhXLcI532n7' 2>/dev/null || true
      rm -f /tmp/yt_*.m4a 2>/dev/null || true
      sleep 5
    done
  "
}

# ==========================================================================
# ATTACKS
# ==========================================================================

run_portscan() {
  local until_s="$1"
  log "Attack 1: Port Scan (slow, multi-port) → $AMF_IP"
  local TS; TS=$(now_epoch)

  docker exec oai-attacker bash -c "
    nmap -sS -T1 --scan-delay 500ms \
      -p 22,80,443,8080,8443,38412,2152,8805,9090,3000,1000-1100 \
      $AMF_IP >/tmp/nmap_result.txt 2>&1 &
    NMAP_PID=\$!
    END=\$(( \$(date +%s) + $(( until_s - $(elapsed) )) ))
    while kill -0 \$NMAP_PID 2>/dev/null && [[ \$(date +%s) -lt \$END ]]; do sleep 1; done
    kill \$NMAP_PID 2>/dev/null || true
  " &
  local OUTER_PID=$!
  while kill -0 $OUTER_PID 2>/dev/null && [[ $(elapsed) -lt $until_s ]]; do sleep 1; done
  kill $OUTER_PID 2>/dev/null || true

  local TE; TE=$(now_epoch)
  label_time "attack_portscan" "$KALI_IP" "$AMF_IP" "$TS" "$TE"
  # Flow-level: TCP SYN para cada porta — registra o range genérico
  label_flow "attack_portscan" "6" "$KALI_IP" "any" "$AMF_IP" "any"
}

# ── SYN flood ────────────────────────────────────────────────
run_syn_flood() {
  local duration_s="$1"
  log "Attack: SYN Flood → $AMF_IP (${duration_s}s)"
  local TS; TS=$(now_epoch)
  docker exec oai-attacker timeout "$duration_s" \
    hping3 -S --flood -p "$AMF_SBI_PORT" "$AMF_IP" >/dev/null 2>&1 || true
  local TE; TE=$(now_epoch)
  label_time "attack_syn_flood" "$KALI_IP" "$AMF_IP" "$TS" "$TE"
  label_flow "attack_syn_flood" "6" "$KALI_IP" "any" "$AMF_IP" "$AMF_SBI_PORT"
}

# ── UDP flood ────────────────────────────────────────────────
run_udp_flood() {
  local duration_s="$1"
  log "Attack: UDP Flood → $AMF_IP (${duration_s}s)"
  local TS; TS=$(now_epoch)
  docker exec oai-attacker timeout "$duration_s" \
    hping3 --udp --flood -p "$AMF_SBI_PORT" "$AMF_IP" >/dev/null 2>&1 || true
  local TE; TE=$(now_epoch)
  label_time "attack_udp_flood" "$KALI_IP" "$AMF_IP" "$TS" "$TE"
  label_flow "attack_udp_flood" "17" "$KALI_IP" "any" "$AMF_IP" "$AMF_SBI_PORT"
}

# ── ICMP flood ────────────────────────────────────────
run_icmp_flood() {
  local duration_s="$1"
  log "Attack: ICMP Flood → $AMF_IP (${duration_s}s)"
  local TS; TS=$(now_epoch)
  docker exec oai-attacker timeout "$duration_s" \
    hping3 -1 --flood "$AMF_IP" >/dev/null 2>&1 || true
  local TE; TE=$(now_epoch)
  label_time "attack_icmp_flood" "$KALI_IP" "$AMF_IP" "$TS" "$TE"
  label_flow "attack_icmp_flood" "1" "$KALI_IP" "any" "$AMF_IP" "any"
}

# ── Background flood  ───────────────────
run_syn_flood_background() {
  local duration_s="$1"
  log "Attack: SYN Flood (background) → $AMF_IP (${duration_s}s)"
  local TS; TS=$(now_epoch)
  docker exec -d oai-attacker timeout "$duration_s" \
    hping3 -S --flood -p "$AMF_SBI_PORT" "$AMF_IP" >/dev/null 2>&1 || true
  label_time "attack_syn_flood" "$KALI_IP" "$AMF_IP" "$TS" "$(add_s "$TS" "$duration_s")"
  label_flow  "attack_syn_flood" "6" "$KALI_IP" "any" "$AMF_IP" "$AMF_SBI_PORT"
}

run_udp_flood_background() {
  local duration_s="$1"
  log "Attack: UDP Flood (background) → $AMF_IP (${duration_s}s)"
  local TS; TS=$(now_epoch)
  docker exec -d oai-attacker timeout "$duration_s" \
    hping3 --udp --flood -p "$AMF_SBI_PORT" "$AMF_IP" >/dev/null 2>&1 || true
  label_time "attack_udp_flood" "$KALI_IP" "$AMF_IP" "$TS" "$(add_s "$TS" "$duration_s")"
  label_flow  "attack_udp_flood" "17" "$KALI_IP" "any" "$AMF_IP" "$AMF_SBI_PORT"
}

# ── CVE-2025-65805 ────────────────────────────────────────────────────────
run_cve() {
  log "CVE Attack: CVE-2025-65805 → $AMF_IP"
  docker logs oai-amf --tail 100 > "${AMF_LOG}.before" 2>&1 || true
  local TS; TS=$(now_epoch)

  if [[ "$CVE_METHOD" == "python" ]]; then
    docker exec oai-attacker python3 /tmp/cve_65805_exploit.py \
      --target "$AMF_IP" --port "$AMF_NGAP_PORT" --imsi-len 1500 \
      >/dev/null 2>&1 || true
  fi

  local TE; TE=$(now_epoch)
  label_time "attack_cve_65805" "$KALI_IP" "$AMF_IP" "$TS" "$TE"
  # CVE usa SCTP (proto=132) para porta NGAP 38412
  label_flow "attack_cve_65805" "132" "$KALI_IP" "any" "$AMF_IP" "$AMF_NGAP_PORT"

  sleep 3
  if ! amf_alive; then
    log "*** AMF CRASHED ***"; capture_amf_crash_log
    label_time "benign_interrupted_by_cve" "$AMF_IP" "$UE_BIND_IP" "$TE" "$TE"
  fi
}

# ==========================================================================
# N2 PCAP
# ==========================================================================
derive_n2_from_bridge() {
  log "Deriving N2 PCAP from bridge capture..."
  tcpdump -r "$PCAP_BRIDGE" -w "$PCAP_N2" 'sctp or (tcp port 38412)' 2>/dev/null || \
    log "[aviso] Falha ao derivar N2 PCAP da bridge"
}

# ==========================================================================
# FILTERED PCAP
# ==========================================================================
generate_filtered() {
  log "Generating filtered PCAP (5G protocols only, two-pass)..."
  local errlog="/tmp/tshark_filtered_s${SCENARIO}.log" rc=0
  tshark -r "$PCAP_BRIDGE" -2 -Y "$FILTERED_PROTOS" -F pcap -w "$PCAP_FILTERED" 2>"$errlog" || rc=$?
  if ! tshark_ok "$rc" "$errlog"; then
    log "[aviso] tshark -2 falhou (status $rc, ver $errlog); usando filtro por endereço"
    rc=0
    tshark -r "$PCAP_BRIDGE" \
      -Y "$FILTERED_PROTOS or (ip.addr==$UPF_IP and ip.addr==$GNB_IP)" \
      -F pcap -w "$PCAP_FILTERED" 2>"$errlog" || rc=$?
    tshark_ok "$rc" "$errlog" || log "[erro] Falha ao gerar o filtered PCAP (status $rc, ver $errlog)"
  fi
}

# ==========================================================================
# POST-CAPTURE VERIFICATION
# ==========================================================================
verify_outputs() {
  echo ""
  echo "--- [verificação] drops do kernel (devem ser 0):"
  grep -H -E "dropped by (kernel|interface)" "$TCPDUMP_BRIDGE_LOG" "$TCPDUMP_RFSIM_LOG" 2>/dev/null \
    || echo "    (estatísticas do tcpdump não encontradas)"

  echo "--- [verificação] mensagens NGAP no N2 PCAP:"
  local ngap=0 ngap_all=0
  if [[ -s "$PCAP_N2" ]]; then
    ngap_all=$(tshark -r "$PCAP_N2" -Y ngap 2>/dev/null | wc -l) || ngap_all=0
    ngap=$(tshark -r "$PCAP_N2" -Y "ngap and ip.addr==$GNB_IP" 2>/dev/null | wc -l) || ngap=0
  fi
  echo "    $ngap frames NGAP gNB<->AMF (total NGAP: $ngap_all; o exploit do CVE responde pelo resto)"
  if grep -q '^benign_ngap_registration,' "$LABELS_TIME_CSV" && [[ "$ngap" -eq 0 ]]; then
    echo "    [aviso] Nenhuma mensagem NGAP de registro capturada: a re-registração do UE"
    echo "            não aconteceu. O rótulo benign_ngap_registration ficará vazio."
  fi

  echo "--- [verificação] fragmentos IP no filtered (cabeças e caudas devem aparecer):"
  local row heads tails
  row=$(tshark -r "$PCAP_FILTERED" -q -z "io,stat,0,ip.flags.mf#1==1,ip.frag_offset#1>0" \
        2>/dev/null | grep '<>' | head -1) || row=""
  heads=$(awk -F'|' '{ gsub(/ /, "", $3); print $3 }' <<<"$row")
  tails=$(awk -F'|' '{ gsub(/ /, "", $5); print $5 }' <<<"$row")
  echo "    cabeças (MF=1): ${heads:-?}   caudas (offset>0): ${tails:-?}"
  if [[ "${heads:-0}" == "0" && "${tails:-0}" != "0" ]]; then
    echo "    [aviso] Só há caudas de fragmentos: o filtered perdeu o payload de downlink."
  fi
}

# ==========================================================================
# CLEANUP
# ==========================================================================
cleanup() {
  echo "[cleanup] Stopping all capture processes..."

  # Para ambos os tcpdump (bridge + rfsim) no host
  sudo_run pkill -15 -f "tcpdump -i ${BRIDGE_IFACE}" 2>/dev/null || true
  sleep 2

  rm -f "$TCPDUMP_BRIDGE_PID" "$TCPDUMP_RFSIM_PID" 2>/dev/null || true

  docker rm -f "$TRAFFIC_GEN" >/dev/null 2>&1 || true

  docker exec oai-attacker pkill hping3 >/dev/null 2>&1 || true
  docker exec oai-attacker pkill nmap   >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM QUIT HUP

# ==========================================================================
# PRE-CHECKS
# ==========================================================================
echo "=== CVE5G v2.3 — Pre-checks for Scenario ${SCENARIO} ==="

for c in oai-upf oai-nr-ue1 oai-attacker oai-amf oai-gnb; do
  if ! container_running "$c"; then echo "[error] Container $c is not active."; exit 1; fi
done

docker exec oai-upf iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
docker exec oai-upf iptables -t nat -A POSTROUTING -s 12.1.1.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true

echo "Starting Sidecar container attached to the UE1 network..."
# [v2.3] Reaproveita a imagem pronta; na 1ª execução instala e faz docker commit
if docker image inspect "$SIDECAR_IMAGE" >/dev/null 2>&1; then
  start_sidecar
else
  docker rm -f "$TRAFFIC_GEN" >/dev/null 2>&1 || true
  docker run -d --name "$TRAFFIC_GEN" --network container:oai-nr-ue1 \
    --cap-add NET_ADMIN kalilinux/kali-rolling tail -f /dev/null >/dev/null 2>&1

  echo "Installing traffic dependencies in the Sidecar (may take ~60s)..."
  docker exec "$TRAFFIC_GEN" bash -c "
    apt-get update -qq &&
    apt-get install -y -qq procps wget curl python3 python3-pip iptables iproute2 dnsutils &&
    pip3 install yt-dlp --break-system-packages --quiet &&
    touch /tmp/traffic_ready
  "
  echo "Saving sidecar image $SIDECAR_IMAGE (reused by the next runs)..."
  docker commit "$TRAFFIC_GEN" "$SIDECAR_IMAGE" >/dev/null
fi

wait_ready "oai-attacker" "/tmp/ready"         "Kali Linux" 180
wait_ready "$TRAFFIC_GEN" "/tmp/traffic_ready" "Sidecar"    180

if [[ "$CVE_METHOD" == "python" ]]; then
  if [[ ! -f "$EXPLOIT_SRC" ]]; then echo "[error] Exploit $EXPLOIT_SRC not found!"; exit 1; fi
  docker cp "$EXPLOIT_SRC" oai-attacker:/tmp/cve_65805_exploit.py
fi

if [[ -z "$UE_BIND_IP" ]]; then
  echo "Detecting UE IP..."
  UE_BIND_IP=$(detect_ue_ip)
  if [[ -z "$UE_BIND_IP" ]]; then echo "[error] UE IP not detected."; exit 1; fi
  echo "Detected IP: $UE_BIND_IP"
fi

# ==========================================================================
# BEGIN
# ==========================================================================
echo ""
echo "=== CVE5G v2.3 — Scenario ${SCENARIO} (${TOTAL_DURATION}s) ==="

echo "label,src_ip,dst_ip,t_start,t_end,t_start_epoch,t_end_epoch" > "$LABELS_TIME_CSV"
echo "label,proto,src_ip,src_port,dst_ip,dst_port"                 > "$LABELS_FLOW_CSV"

# ── Inicia capturas ANTES de redefinir T0 ─────────────────────────────────
# BPF 'not tcp port 4043' exclui o RF simulator em kernel, evitando que o
# volume de IQ samples (~330 MB/s) estoure o buffer e cause perda de pacotes.
# N2 PCAP será derivado da bridge após o fim da captura (derive_n2_from_bridge).
echo "Starting bridge capture (data plane) on $BRIDGE_IFACE..."
sudo_run tcpdump -i "$BRIDGE_IFACE" -w "$PCAP_BRIDGE" -B 524288 'not tcp port 4043' \
  >"$TCPDUMP_BRIDGE_LOG" 2>&1 &
echo $! > "$TCPDUMP_BRIDGE_PID"

echo "Starting RF simulator capture (TCP 4043) on $BRIDGE_IFACE..."
sudo_run tcpdump -i "$BRIDGE_IFACE" -w "$PCAP_RFSIM" -B 524288 'tcp port 4043' \
  >"$TCPDUMP_RFSIM_LOG" 2>&1 &
echo $! > "$TCPDUMP_RFSIM_PID"

sleep 1

T0_EPOCH=$(date +%s.%N)
T0=${T0_EPOCH%.*}

log "Baseline phase (0s→30s): idle network."
sleep 30

trigger_ue_reregistration

log "UE IP after re-registration: $UE_BIND_IP"

TS_BENIGN=$(now_epoch)
BENIGN_DUR=$(( TOTAL_DURATION - $(elapsed) ))
log "Starting realistic benign traffic..."
start_benign_traffic "$UE_BIND_IP" "$BENIGN_DUR"

label_flow "benign_iso_tcp"     "6" "$UE_BIND_IP" "any" "releases.ubuntu.com" "443"
label_flow "benign_ytdlp_https" "6" "$UE_BIND_IP" "any" "youtube.com"         "443"

# ==========================================================================
# SCENARIOS
# ==========================================================================
if [[ "$SCENARIO" == "1" ]]; then
  log "Scenario 1: benign traffic only (+ control-plane registration)."

elif [[ "$SCENARIO" == "2" ]]; then
  log "Scenario 2: sequential attacks."
  # ── Port scan lento (t=60..85s, 25s) — gera ≥20 flows TCP SYN ──────────
  safe_sleep_until 60; run_portscan 85

  # ── SYN flood (t=100..130s, 30s) ─────────────────────────────────────────
  safe_sleep_until 100; run_syn_flood 30

  # ── UDP flood (t=145..175s, 30s) ─────────────────────────────────────────
  safe_sleep_until 145; run_udp_flood 30

  # ── ICMP flood (t=190..220s, 30s) ─────────────────────────────────────────
  safe_sleep_until 190; run_icmp_flood 30

  # ── CVE-2025-65805 (t=240s) ──────────────────────────────────────────────
  safe_sleep_until 240; [[ "$CVE_METHOD" != "none" ]] && run_cve

elif [[ "$SCENARIO" == "3" ]]; then
  log "Scenario 3: overlapping attacks."
  safe_sleep_until 60; run_portscan 80

  safe_sleep_until 90;  run_syn_flood_background 30
  safe_sleep_until 110; run_udp_flood_background 30
  safe_sleep_until 130; run_icmp_flood 30

  safe_sleep_until 210; [[ "$CVE_METHOD" != "none" ]] && run_cve
fi

REMAINING=$(( TOTAL_DURATION - $(elapsed) ))
if [[ "$REMAINING" -gt 0 ]]; then
  log "Waiting ${REMAINING}s to complete the experiment duration."
  sleep "$REMAINING"
fi

TE_BENIGN=$(now_epoch)
label_time "benign_iso_tcp"     "$UE_BIND_IP" "releases.ubuntu.com" "$TS_BENIGN" "$TE_BENIGN"
label_time "benign_ytdlp_https" "$UE_BIND_IP" "youtube.com"         "$TS_BENIGN" "$TE_BENIGN"

log "Stopping packet capture..."
cleanup
trap - EXIT

sudo_run chown "$USER":"$(id -gn)" "$PCAP_BRIDGE" 2>/dev/null || true
sudo_run chown "$USER":"$(id -gn)" "$PCAP_RFSIM"  2>/dev/null || true

{
  echo "# tcpdump capture statistics — scenario ${SCENARIO}"
  echo "## bridge (not tcp port 4043)"; cat "$TCPDUMP_BRIDGE_LOG" 2>/dev/null || echo "(log not found)"
  echo "## rfsim (tcp port 4043)";      cat "$TCPDUMP_RFSIM_LOG"  2>/dev/null || echo "(log not found)"
} > "$CAPTURE_STATS"

derive_n2_from_bridge

generate_filtered

echo ""
echo "=== Completed — Scenario ${SCENARIO} ==="
echo "--- Outputs:"
echo "    Bridge PCAP   : $PCAP_BRIDGE  ($(du -h "$PCAP_BRIDGE" 2>/dev/null | cut -f1))"
echo "    N2 PCAP       : $PCAP_N2  ($(du -h "$PCAP_N2" 2>/dev/null | cut -f1))"
echo "    Filtered PCAP : $PCAP_FILTERED  ($(du -h "$PCAP_FILTERED" 2>/dev/null | cut -f1))"
echo "    RFsim PCAP    : $PCAP_RFSIM  ($(du -h "$PCAP_RFSIM" 2>/dev/null | cut -f1))"
echo "    Labels time   : $LABELS_TIME_CSV"
echo "    Labels flow   : $LABELS_FLOW_CSV"
echo "    Capture stats : $CAPTURE_STATS"

echo ""
echo "--- tcpdump capture stats:"
cat "$CAPTURE_STATS"

verify_outputs

OWNER="${SUDO_USER:-$USER}"
sudo_run chown -R "$OWNER":"$(id -gn "$OWNER")" "$RESULTS_DIR" 2>/dev/null || true

echo ""
echo "--- Time-window labels:"
cat "$LABELS_TIME_CSV"
echo ""
echo "--- Flow labels:"
cat "$LABELS_FLOW_CSV"