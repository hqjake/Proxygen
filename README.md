# ⚡ High-Speed HTTP Proxy Scraper & Checker

A lightweight, multi-threaded Python tool designed to scrape public HTTP proxies from reliable sources and validate them in real-time.

## 🚀 Features
* **Parallel Scraping:** All proxy sources are fetched at the same time.
* **High-Concurrency Validation:** A thread pool (200 workers by default) checks proxies in parallel, with a short connect timeout so dead hosts fail fast.
* **Smart Parsing:** Extracts `ip:port` from any line format (including `http://ip:port`), rejects invalid IPs/ports, and deduplicates across sources.
* **Real Checks:** A proxy only counts as alive if the test page actually comes back through it, so captive portals and junk responses are filtered out.
* **HTTPS Support Check:** Every working proxy is also tested through an HTTPS tunnel (with certificate verification), so you know which ones handle `https://` sites.
* **Anonymity Detection:** Each proxy is labelled by what it reveals to the sites you visit:
  * **transparent** — leaks your real IP
  * **anonymous** — hides your IP but adds headers (like `Via` or `X-Forwarded-For`) showing a proxy is in use
  * **elite** — hides your IP and doesn't reveal it's a proxy
* **Failure Cache:** Proxies that failed are remembered for an hour (`.proxygen_cache.json`) and skipped on the next run, which makes repeat scans much faster. Failures aren't cached if your own connection is down.
* **Live Progress:** Progress bar with alive count and ETA, powered by the `Rich` library.
* **Instant Saving:** Working proxies are written to `proxies.txt` as soon as they're found, then the file is re-sorted by latency (fastest first) when the scan ends — even if you stop it early with `Ctrl+C`.

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/hqjake/Proxygen.git
   cd Proxygen
   ```

2. **Install dependencies** (Python 3.9+):
   ```bash
   pip install -r requirements.txt
   ```

## ▶️ Usage

```bash
python proxygen.py
```

Options:

| Flag | Default | Description |
| --- | --- | --- |
| `-t`, `--threads` | `200` | Number of proxies checked at once |
| `--connect-timeout` | `3` | Seconds to wait for a proxy to accept the connection |
| `--timeout` | `5` | Seconds to wait for the response |
| `-o`, `--output` | `proxies.txt` | Where working proxies are saved |
| `--test-url` | `http://httpbin.org/get` | URL fetched through each proxy; must echo your IP and headers for anonymity detection |
| `--https-url` | `https://httpbin.org/ip` | HTTPS URL used to test tunnelling support |
| `--expect` | `origin` | Text the response must contain (pass `""` to disable) |
| `--no-https` | off | Skip the HTTPS check |
| `--require-https` | off | Only save proxies that support HTTPS |
| `--min-anonymity` | all | Only save proxies at least this private: `transparent`, `anonymous` or `elite` |
| `--cache-ttl` | `60` | Minutes to skip a proxy after it fails (`0` disables the cache) |
| `--cache-file` | `.proxygen_cache.json` | Where failed proxies are remembered |
| `-q`, `--quiet` | off | Don't print each working proxy as it's found |

Example — more threads and a stricter timeout to keep only fast proxies:

```bash
python proxygen.py -t 400 --connect-timeout 2 --timeout 3
```

Only keep private proxies that work with HTTPS sites:

```bash
python proxygen.py --require-https --min-anonymity elite
```

Retest everything, ignoring the failure cache:

```bash
python proxygen.py --cache-ttl 0
```

> **Note:** The anonymity level is measured on plain HTTP requests. Over HTTPS the proxy can't read or change your headers, so even a "transparent" proxy won't add your IP to HTTPS traffic, but the site still sees the proxy's IP rather than yours.
