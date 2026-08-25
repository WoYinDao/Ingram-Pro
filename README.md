# Ingram-Pro

Network camera vulnerability scanner (enhanced edition of [Ingram](https://github.com/jorhelp/Ingram)).

Authorized assessments only. Do not point this at hosts you do not own or have written permission to test.

## What this fork fixed

Upstream `0x5477/Ingram-Pro` shipped **without `rules.csv`** (`.gitignore` had `*.csv`), so fingerprinting never ran and every POC was dead. This repo restores the rules file, tightens several 2022–2024 modules that were brand-presence checks (false positives), and adds a few CVEs that can actually be confirmed over HTTP.

## Usage

```bash
pip install -r requirements.txt
python run_ingram_pro.py -i targets.txt -o ./out
python run_ingram_pro.py -i 192.168.1.100 -o ./out
python run_ingram_pro.py -i 10.0.0.0/24 -o ./out
```

`-i` accepts a file (one target per line) **or** a single IP / CIDR / range.

| Flag | Meaning |
|------|---------|
| `-i` / `--in_file` | Target list (required) |
| `-o` / `--out_dir` | Output directory (required) |
| `-p` | Extra / override ports |
| `-t` | Concurrency (default 150) |
| `-T` | Timeout seconds (default 3) |
| `-D` | Disable snapshot capture |
| `--no-resume` | Ignore previous scan state |
| `--debug` | Verbose log |

Results: `out/results.csv`, `out/not_vulnerable.csv`, `out/snapshots/`, `out/log.txt`.

## Brands

Hikvision, Dahua / Amcrest, EZVIZ, Reolink, Hanwha, Uniview, Xiongmai, Avtech, Axis, GeoVision, Instar, Netwave, NUUO, Reecam, Foscam, Tenda, D-Link DCS, generic IPC/DVR, LB-Link, TP-Link VIGI/Tapo (fingerprint only).

## CVE modules worth trusting

These `verify()` methods look for a real leak / injection oracle, not just a vendor string:

| CVE / module | Check |
|--------------|--------|
| CVE-2017-7921 | Hikvision `auth=` bypass + config decrypt |
| CVE-2018-9995 | TBK/DVR `Cookie: uid=admin` user list |
| CVE-2020-25078 / CVE-2021-40655 | D-Link `/config/getuser` password leak |
| CVE-2021-33044 / 33045 | Dahua NetKeyboard / sub-stream login bypass |
| CVE-2021-36260 / CVE-2022-28171 | Hikvision `webLanguage` command injection |
| CVE-2023-6895 | Hikvision intercom `/php/ping.php` (`id` → `uid=`) |
| CVE-2024-7029 | AVTECH Factory.cgi time-based command injection (CISA KEV) |
| CVE-2024-12984 | Amcrest `/web_caps/webCapsConfig` leak |
| Uniview disclosure | Unauth `main-cgi` user dump |
| Xiongmai bypass | Empty ONVIF UsernameToken → snapshot URI with creds |
| hikvision-unauth-snapshot | Anonymous JPEG on ONVIF/ISAPI picture URLs |

Several 2022–2024 files remain in `pocs/` for reference (Tapo UAF, VIGI overflow, Hanwha RTSP CI) but **no longer report a hit on brand match** — those bugs have no safe HTTP oracle.

## Credits

- Original [Ingram](https://github.com/jorhelp/Ingram) by jorhelp
- DahuaConsole integration
