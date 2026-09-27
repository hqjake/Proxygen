# ⚡ High-Speed HTTP Proxy Scraper & Checker

A lightweight, multi-threaded Python tool designed to scrape public HTTP proxies from reliable sources and validate them in real-time.

## 🚀 Features
* **Parallel Scraping:** All proxy sources are fetched at the same time.
* **High-Concurrency Validation:** A thread pool (200 workers by default) checks proxies in parallel, with a short connect timeout so dead hosts fail fast.
* **Smart Parsing:** Extracts `ip:port` from any line format (including `http://ip:port`), rejects invalid IPs/ports, and deduplicates across sources.
* **Real Checks:** A proxy only counts as alive if the test page actually comes back through it, so captive portals and junk responses are filtered out.
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
| `--test-url` | `http://httpbin.org/ip` | URL fetched through each proxy |
| `--expect` | `origin` | Text the response must contain (pass `""` to disable) |
| `-q`, `--quiet` | off | Don't print each working proxy as it's found |

Example — more threads and a stricter timeout to keep only fast proxies:

```bash
python proxygen.py -t 400 --connect-timeout 2 --timeout 3
```
