# 5G Core Network Cyberattacks Dataset (CVE5G)

This repository contains the infrastructure and automation scripts to generate a novel network traffic dataset from a 3GPP-compliant 5G emulation based on the OpenAirInterface (OAI) framework.

The dataset is published on IEEE DataPort: [doi.org/10.21227/9ex2-k094](https://doi.org/10.21227/9ex2-k094).

## Versions

| Version | Scripts | Data on IEEE DataPort | Main changes |
|---|---|---|---|
| **2.0** (current) | [release v2.0](https://github.com/anacarlaquallio/CVE5G/releases/tag/v2.0) | directory `CVE5G-2.0` | Capture without the RF simulator samples, N2 PCAP, benign NGAP signaling, time labels with absolute timestamps, flow labels, filtered PCAP with all IP fragments |
| 1.0 | [release v1.0](https://github.com/anacarlaquallio/CVE5G/releases/tag/v1.0) | directory `CVE5G` | First version |

The `main` branch contains the scripts of the current version. To reproduce version 1.0, use the scripts of [release v1.0](https://github.com/anacarlaquallio/CVE5G/releases/tag/v1.0), whose README describes its outputs.

## Architecture

The 5G Core and access network are orchestrated as Docker containers. The environment captures multi-layer traffic scenarios, integrating:
1. **Realistic Benign Traffic:** traffic generated through large file transfers (HTTPS) and adaptive HTTPS media streaming using `yt-dlp`, plus the NGAP signaling of a UE re-registration.
2. **Conventional Cyberattacks:** a TCP SYN port scan and TCP SYN, UDP, and ICMP flooding attacks launched from a dedicated Kali Linux node.
3. **Core Vulnerability Exploitation:** exploitation of the documented vulnerability [CVE-2025-65805](https://nvd.nist.gov/vuln/detail/CVE-2025-65805). To bypass Radio Access Network (RAN) MTU limitations, the malformed payload is injected directly into the AMF via SCTP using a custom Python script.

![Overview of the proposed 5G testbed architecture](figs/overview.png)

## Experimental Scenarios

The traffic generation is fully automated and temporally organized into three scenarios:
* **Scenario 1:** Benign baseline traffic only.
* **Scenario 2:** Sequential attacks separated by idle intervals, followed by CVE exploitation.
* **Scenario 3:** Overlapping attacks followed by CVE exploitation.

In all scenarios the network is idle for about 30 s; then the UE1 container is restarted, UE1 registers again, and the benign traffic runs until the end of the 300-s experiment. Times in seconds from the first packet of the bridge PCAP (version 2.0):

| Phase | Scenario 1 | Scenario 2 | Scenario 3 |
|---|---|---|---|
| Idle network | 0–28.1 | 0–26.9 | 0–30.5 |
| UE re-registration (NGAP) | 28.1–34.8 | 26.9–33.8 | 30.5–37.2 |
| Benign traffic | 38.8–298.0 | 37.4–296.7 | 41.0–300.8 |
| Port scan | – | 56.6–81.7 | 60.2–80.2 |
| TCP SYN flood | – | 96.7–126.8 | 90.2–120.2 |
| UDP flood | – | 141.8–171.9 | 110.3–140.3 |
| ICMP flood | – | 186.9–217.0 | 130.4–160.5 |
| CVE-2025-65805 exploit | – | 237.0–239.1 | 210.6–212.7 |

## Execution Guide

### Prerequisites
* Linux x86_64 Host
* Docker Engine & Docker Compose plugin
* `tcpdump` and `tshark` installed (`sudo apt-get install tcpdump tshark`)

### Method 1: Automated Pipeline (Recommended)
The easiest way to generate the dataset is using the automated pipeline. It will validate requirements, start the Core and RAN, generate the selected traffic scenario, and safely tear down the environment.

From the root directory, simply run:
```bash
# Run Scenario 2 (default)
sudo ./scripts/run_pipeline.sh

# Or specify a different scenario (e.g., Scenario 3):
SCENARIO=3 sudo -E ./scripts/run_pipeline.sh

```

### Method 2: Manual Step-by-Step (Under the Hood)

If you prefer to maintain the network active for debugging or manual inspection, follow these steps:

#### 1. Clean the environment

Ensure no residual networks or containers are running:

```bash
docker compose -f docker-compose-ran.yml down
docker compose -f docker-compose.yml down

```

#### 2. Start the 5G Core

Bring up the database and the 5G Core functions:

```bash
docker compose -f docker-compose.yml up -d mysql
docker compose -f docker-compose.yml up -d
sleep 15

```

#### 3. Start the RAN

Bring up the gNB and the User Equipment (UE1):

```bash
docker compose -f docker-compose-ran.yml up -d
sleep 15

```

#### 4. Generate the Dataset

Execute the traffic generation script. You can choose the scenario (`1`, `2`, or `3`). The CVE exploitation method defaults to the Python SCTP injection, which guarantees the delivery of the oversized IMSI payload to the AMF.

**Example: Running Scenario 2**

```bash
SCENARIO=2 CVE_METHOD=python sudo -E ./scripts/02_generate_traffic.sh

```

On the first run, the script installs the traffic tools (`wget`, `yt-dlp`) in a sidecar container and saves it as the Docker image `cve5g-traffic-sidecar:ready`, which is reused by the next runs. To reinstall the tools (for example, after a `yt-dlp` update), remove the image with `docker rmi cve5g-traffic-sidecar:ready`.

### Expected Outputs

Upon completion (300 seconds of capture), the script generates the following files in the `results/scenario_X/` directory:

| File | Content |
|---|---|
| `cve5g_sX_bridge.pcap` | Primary capture: all traffic on the Docker bridge except the RF simulator samples (TCP port 4043) |
| `cve5g_sX_capture_stats.txt` | `tcpdump` statistics, including packets dropped by the kernel |
| `cve5g_sX_filtered.pcap` | `http2`, `ngap`, `pfcp`, and `gtp` only, including all IP fragments of the GTP-U packets |
| `cve5g_sX_labels_flow.csv` | Flow rules: `label, proto, src_ip, src_port, dst_ip, dst_port` |
| `cve5g_sX_labels_time.csv` | Time windows: `label, src_ip, dst_ip, t_start, t_end, t_start_epoch, t_end_epoch` |
| `cve5g_sX_n2.pcap` | SCTP/NGAP signaling on the N2 interface |
| `cve5g_sX_rfsim.pcap` | RF simulator traffic between the gNB and UE1 (TCP port 4043) |
| `amf_crash_sX.log` | Last 50 AMF log lines after the exploit (Scenarios 2 and 3). Look for `[ngap] [error] Decode NGAP message failed` followed by `free(): invalid pointer` as the proof of the buffer overflow that terminates the AMF |
| `amf_crash_sX.log.before` | Last 100 AMF log lines before the exploit (Scenarios 2 and 3) |

At the end, the script prints a verification summary: kernel drops, the number of NGAP messages between the gNB and the AMF, and the IP fragments kept in the filtered PCAP.

### Labels

| Label | Type | Description |
|---|---|---|
| `benign_ngap_registration` | Benign | NGAP signaling of the UE1 re-registration |
| `benign_iso_tcp` | Benign | HTTPS Ubuntu ISO download (`wget`) |
| `benign_ytdlp_https` | Benign | HTTPS media download (`yt-dlp`) |
| `attack_portscan` | Attack | Nmap SYN scan |
| `attack_syn_flood` | Attack | hping3 SYN flood |
| `attack_udp_flood` | Attack | hping3 UDP flood |
| `attack_icmp_flood` | Attack | hping3 ICMP flood |
| `attack_cve_65805` | Attack | CVE-2025-65805 exploit |
| `benign_interrupted_by_cve` | Meta | Instant when the AMF stopped after the exploit (written only if the AMF stops) |

The benign user-plane flows can be separated by the TLS Server Name Indication (SNI): `ubuntu.com` for the ISO download, and `youtube.com` or `googlevideo.com` for `yt-dlp`.

## Citation

If you use CVE5G, please cite the dataset: [doi.org/10.21227/9ex2-k094](https://doi.org/10.21227/9ex2-k094).