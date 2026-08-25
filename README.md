# Ingram-Pro

网络摄像头漏洞扫描器（[Ingram](https://github.com/jorhelp/Ingram) 增强版）。

**仅限授权测试。** 不要扫描你没有权限的设备。

## 本仓库修了什么

上游 `0x5477/Ingram-Pro` 没提交 `rules.csv`（`.gitignore` 把 `*.csv` 忽略了），指纹永远不跑，所有 POC 都是死代码。这里补回了规则文件，收紧了一批只会匹配品牌名的假阳性模块，并加了几个能真正验证的 CVE。

## 用法

```bash
pip install -r requirements.txt
python run_ingram_pro.py -i targets.txt -o ./out
python run_ingram_pro.py -i 192.168.1.100 -o ./out
python run_ingram_pro.py -i 10.0.0.0/24 -o ./out
```

`-i` 可以是文件（一行一个目标），也可以直接是 IP / CIDR / 范围。

| 参数 | 说明 |
|------|------|
| `-i` / `--in_file` | 目标列表（必填） |
| `-o` / `--out_dir` | 输出目录（必填） |
| `-p` | 覆盖默认端口 |
| `-t` | 并发数（默认 150） |
| `-T` | 超时秒数（默认 3） |
| `-D` | 关闭快照 |
| `--no-resume` | 忽略上次进度，从头扫 |
| `--debug` | 输出调试日志 |

输出：`out/results.csv`、`out/not_vulnerable.csv`、`out/snapshots/`、`out/log.txt`。

## 品牌

海康、大华 / Amcrest、萤石、Reolink、韩华、宇视、雄迈、Avtech、Axis、GeoVision、Instar、Netwave、NUUO、Reecam、Foscam、Tenda、D-Link DCS、通用 IPC/DVR、LB-Link、TP-Link VIGI/Tapo（仅指纹）。

## 可信的 CVE 模块

这些 `verify()` 看的是真实泄露 / 注入回显，不是只认厂商字符串：

| CVE / 模块 | 判定 |
|------------|------|
| CVE-2017-7921 | 海康 `auth=` 绕过 + 配置解密 |
| CVE-2018-9995 | TBK/DVR `Cookie: uid=admin` 用户列表 |
| CVE-2020-25078 / CVE-2021-40655 | D-Link `/config/getuser` 密码泄露 |
| CVE-2021-33044 / 33045 | 大华 NetKeyboard / 子码流登录绕过 |
| CVE-2021-36260 / CVE-2022-28171 | 海康 `webLanguage` 命令注入 |
| CVE-2023-6895 | 海康对讲 `/php/ping.php`（`id` → `uid=`） |
| CVE-2024-7029 | AVTECH Factory.cgi 时间盲注（CISA KEV） |
| CVE-2024-12984 | Amcrest `/web_caps/webCapsConfig` 泄露 |
| 宇视 disclosure | 未授权 `main-cgi` 用户导出 |
| 雄迈 bypass | 空 ONVIF UsernameToken → 快照地址带凭据 |
| hikvision-unauth-snapshot | ONVIF/ISAPI 图片接口匿名 JPEG |
| foscam-weak-password | `CGIProxy.fcgi?cmd=logIn` |

`pocs/` 里还留着几个 2022–2024 的参考文件（Tapo UAF、VIGI 溢出、韩华 RTSP 注入），但**不再按品牌字符串报中**——这些洞没有安全的 HTTP 判定，已设 `enabled = False`。

## 部署

### 自己电脑（Windows / macOS / Linux）

```bash
git clone https://github.com/WoYinDao/Ingram-Pro.git
cd Ingram-Pro
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python run_ingram_pro.py -i 192.168.1.100 -o ./out
```

### 服务器（Linux，推荐 Ubuntu/Debian）

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
git clone https://github.com/WoYinDao/Ingram-Pro.git
cd Ingram-Pro
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

跑一个网段，后台挂着：

```bash
nohup python run_ingram_pro.py -i 10.0.0.0/24 -o ./out > run.log 2>&1 &
```

看进度：`tail -f out/log.txt`，结果在 `out/results.csv`。

### Docker（可选）

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["python", "run_ingram_pro.py"]
```

```bash
docker build -t ingram-pro .
docker run --rm -v $(pwd)/out:/app/out ingram-pro -i 192.168.1.100 -o /app/out
```

### 注意

- 大华 CVE-2021-33044/33045 的凭据提取依赖 `pwntools`，Windows 装不上就只影响这两个模块的密码导出，扫描本身不受影响。
- 默认端口含 443/8443，会自动走 HTTPS；其它端口先 HTTP，不通再试 HTTPS。
- 结果 CSV 里有明文密码，别直接传公开地方。

## 致谢

- 原版 [Ingram](https://github.com/jorhelp/Ingram)（jorhelp）
- DahuaConsole 集成
