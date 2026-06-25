# Ingram-Pro

**Network Camera Vulnerability Scanner (Enhanced Edition)**

Based on the original [Ingram](https://github.com/jorhelp/Ingram) framework, Ingram-Pro extends coverage with **40+ POCs targeting CVEs from 2017-2024** and brand-specific weak-password detection modules.

---

## Features

- **CVE Exploitation** — Authenticated and unauthenticated RCE, information disclosure, authentication bypass
- **Weak Password Detection** — Default/weak credential scanning across 15+ camera brands
- **Dahua Deep Interaction** — Integrated DahuaConsole library for advanced Dahua device enumeration, relay control, and event monitoring
- **High Concurrency** — Built on gevent for fast, parallel scanning of large IP ranges
- **Snapshot Capture** — Auto-fetch live snapshots from vulnerable devices when possible

---

## Brands Covered

| Brand | Weak Password | CVE POCs |
|-------|:-------------:|:--------:|
| Hikvision | ✅ | 5 |
| Dahua | ✅ | 6 |
| EZVIZ | ✅ | 1 |
| Reolink | ✅ | 1 |
| Hanwha | ✅ | 1 |
| Uniview | — | 1 |
| Xiongmai | ✅ | 2 |
| Avtech | ✅ | — |
| Axis | ✅ | — |
| GeoVision | ✅ | — |
| Instar | ✅ | — |
| Netwave | ✅ | — |
| NUUO | ✅ | — |
| Reecam | ✅ | — |
| Generic IPC / DVR | ✅ | 3 |

---

## CVEs Covered (2021-2024 Highlights)

| CVE | Target | Type | Year |
|-----|--------|------|------|
| CVE-2024-39943 | Dahua | RCE | 2024 |
| CVE-2023-47221 | — | RCE | 2023 |
| CVE-2023-45222 | — | Info Disclosure | 2023 |
| CVE-2023-28808 | Hikvision | Auth Bypass | 2023 |
| CVE-2023-27359 | — | RCE | 2023 |
| CVE-2023-26801 | — | — | 2023 |
| CVE-2022-30563 | — | — | 2022 |
| CVE-2022-28171 | — | RCE | 2022 |
| CVE-2022-2471 | — | — | 2022 |
| CVE-2022-23459 | — | — | 2022 |
| CVE-2021-36260 | Hikvision | RCE | 2021 |
| CVE-2021-40655 | D-Link | Info Disclosure | 2021 |
| CVE-2021-33045 | Dahua | Auth Bypass | 2021 |
| CVE-2021-33044 | Dahua | Auth Bypass | 2021 |
| + 9 additional legacy CVEs (2017–2020) | | | |

---

## Quick Start

### Requirements

- Python 3.8+
- Linux / Windows / macOS

### Installation

```bash
git clone https://github.com/0x5477/Ingram-Pro.git
cd Ingram-Pro
pip install -r requirements.txt
```

### Usage

```bash
# Scan a single target
python run_ingram_pro.py -i 192.168.1.100

# Scan from a file (one IP per line)
python run_ingram_pro.py -f targets.txt

# Specify output directory
python run_ingram_pro.py -f targets.txt -o ./results

# Enable debug logging
python run_ingram_pro.py -f targets.txt --debug
```

Results are saved to the `out/` directory by default, including vulnerability reports and captured snapshots.

---

## Disclaimer

This tool is intended for **authorized security assessments only**. The authors assume no liability for misuse or damage caused by this program. Always obtain proper permission before scanning.

---

## Credits

- Original [Ingram](https://github.com/jorhelp/Ingram) by jorhelp
- DahuaConsole integration
- Community POC contributors
