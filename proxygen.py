import argparse
import os
import re
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

# --- Configuration ---
SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
]

OUTPUT_FILE = "proxies.txt"
THREADS = 200
CONNECT_TIMEOUT = 3
TIMEOUT = 5
SOURCE_TIMEOUT = 10
TEST_URL = "http://httpbin.org/ip"
EXPECT = "origin"  # Substring the test response must contain (catches captive/garbage pages)
MAX_BODY_BYTES = 64 * 1024
USER_AGENT = "Mozilla/5.0"

# Matches ip:port anywhere in a line, so "http://1.2.3.4:8080" and "1.2.3.4:8080 US" both parse.
PROXY_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?!\d)")

console = Console()
_local = threading.local()


def get_session():
    """One Session per worker thread, so connection setup objects are reused."""
    session = getattr(_local, "session", None)
    if session is None:
        session = requests.Session()
        session.trust_env = False  # Skip env/netrc proxy lookups on every request
        session.headers["User-Agent"] = USER_AGENT
        _local.session = session
    return session


def parse_proxies(text):
    """Extract unique, well-formed ip:port pairs from raw source text."""
    found = set()
    for ip, port in PROXY_RE.findall(text):
        if 0 < int(port) <= 65535 and all(int(octet) <= 255 for octet in ip.split(".")):
            found.add(f"{ip}:{int(port)}")
    return found


def source_name(url):
    """Short label for a source: the repo owner for GitHub raw URLs, else the host."""
    parts = urlparse(url)
    if parts.netloc == "raw.githubusercontent.com":
        return parts.path.strip("/").split("/")[0]
    return parts.netloc


def fetch_source(url):
    res = requests.get(url, timeout=SOURCE_TIMEOUT, headers={"User-Agent": USER_AGENT})
    res.raise_for_status()
    return parse_proxies(res.text)


def fetch_all_sources(sources):
    """Fetch every source concurrently and return the deduplicated proxy set."""
    proxies = set()
    with ThreadPoolExecutor(max_workers=len(sources)) as pool:
        futures = {pool.submit(fetch_source, url): url for url in sources}
        for future in as_completed(futures):
            name = source_name(futures[future])
            try:
                extracted = future.result()
                proxies.update(extracted)
                console.print(f"  [green]✓[/green] {name:<20} → {len(extracted)} proxies")
            except Exception as e:
                console.print(f"  [red]✗ {name:<20} → Failed: {str(e)[:60]}[/red]")
    return proxies


def check_proxy(proxy, args):
    """Return latency in ms if the proxy works, otherwise None."""
    session = get_session()
    proxy_url = f"http://{proxy}"
    try:
        start = time.perf_counter()
        with session.get(
            args.test_url,
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=(args.connect_timeout, args.timeout),
            stream=True,
            allow_redirects=False,
        ) as r:
            if r.status_code != 200:
                return None
            # Read a bounded amount so misbehaving proxies can't stream huge bodies at us.
            body = r.raw.read(MAX_BODY_BYTES, decode_content=True)
        latency = round((time.perf_counter() - start) * 1000)
        if args.expect and args.expect.encode() not in body:
            return None
        return latency
    except Exception:
        return None
    finally:
        # requests caches a ProxyManager per proxy URL; drop it so memory and sockets
        # don't grow with every proxy this thread tests.
        for adapter in session.adapters.values():
            manager = adapter.proxy_manager.pop(proxy_url, None)
            if manager is not None:
                manager.clear()


def write_sorted(path, results):
    """Atomically rewrite the output file with working proxies, fastest first."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".proxies-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("# Working HTTP/HTTPS Proxies (sorted by latency, fastest first)\n")
            f.write("# Generated: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
            for proxy, _ in sorted(results, key=lambda item: item[1]):
                f.write(f"{proxy}\n")
        os.replace(tmp_path, path)
    except BaseException:
        os.unlink(tmp_path)
        raise


def parse_args():
    parser = argparse.ArgumentParser(description="Scrape public HTTP proxies and check which ones work.")
    parser.add_argument("-t", "--threads", type=int, default=THREADS, help=f"concurrent checks (default: {THREADS})")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help=f"read timeout in seconds (default: {TIMEOUT})")
    parser.add_argument("--connect-timeout", type=float, default=CONNECT_TIMEOUT,
                        help=f"connect timeout in seconds (default: {CONNECT_TIMEOUT})")
    parser.add_argument("-o", "--output", default=OUTPUT_FILE, help=f"output file (default: {OUTPUT_FILE})")
    parser.add_argument("--test-url", default=TEST_URL, help=f"URL fetched through each proxy (default: {TEST_URL})")
    parser.add_argument("--expect", default=EXPECT,
                        help=f"substring the test response must contain; empty to disable (default: {EXPECT!r})")
    parser.add_argument("-q", "--quiet", action="store_true", help="don't print each working proxy as it's found")
    args = parser.parse_args()
    if args.threads < 1:
        parser.error("--threads must be at least 1")
    return args


def main():
    args = parse_args()

    console.print(Panel("[bold cyan]HTTPS Proxy Scraper[/bold cyan]", expand=False))
    console.print(
        f"[*] Timeout: [bold yellow]{args.connect_timeout}s connect / {args.timeout}s read[/bold yellow]"
        f" | Threads: [bold yellow]{args.threads}[/bold yellow]"
    )

    # 1. Scrape all sources in parallel
    with console.status("[bold white]Fetching proxy lists..."):
        proxies = fetch_all_sources(SOURCES)

    if not proxies:
        console.print("[red]No proxies found from any source![/red]")
        return

    console.print(f"\n[*] Unique proxies to test: [bold cyan]{len(proxies)}[/bold cyan]\n")

    # 2. Open the output file once; each hit is appended and flushed immediately
    try:
        out = open(args.output, "w", encoding="utf-8")
    except OSError as e:
        console.print(f"[red]Failed to create output file: {e}[/red]")
        return
    out.write("# Working HTTP/HTTPS Proxies\n")
    out.write("# Generated: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
    out.flush()

    # 3. Check proxies concurrently
    results = []
    failed = 0
    interrupted = False
    start_run = time.perf_counter()

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold]Testing"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("| [green]{task.fields[alive]} alive"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    )
    pool = ThreadPoolExecutor(max_workers=min(args.threads, len(proxies)))
    try:
        with progress:
            task = progress.add_task("test", total=len(proxies), alive=0)
            futures = {pool.submit(check_proxy, p, args): p for p in proxies}
            for future in as_completed(futures):
                proxy = futures[future]
                latency = future.result()
                if latency is None:
                    failed += 1
                else:
                    results.append((proxy, latency))
                    out.write(f"{proxy}\n")
                    out.flush()
                    if not args.quiet:
                        progress.console.print(
                            f"[bold green][ALIVE][/bold green] {proxy:<22} | [cyan]{latency}ms[/cyan]"
                        )
                progress.update(task, advance=1, alive=len(results))
    except KeyboardInterrupt:
        interrupted = True
        console.print("\n[red]Interrupted — stopping and saving what was found so far...[/red]")
    finally:
        pool.shutdown(wait=not interrupted, cancel_futures=True)
        out.close()

    duration = round(time.perf_counter() - start_run, 2)

    # 4. Rewrite the file sorted by latency so the fastest proxies come first
    if results:
        try:
            write_sorted(args.output, results)
        except OSError as e:
            console.print(f"[yellow]⚠ Could not sort output file ({e}); unsorted results kept.[/yellow]")

    scanned = len(results) + failed
    console.print("\n" + "━" * 50)
    console.print("[bold yellow]⚠ SCANNING INTERRUPTED[/bold yellow]" if interrupted
                  else "[bold green]✓ SCANNING COMPLETE[/bold green]")
    console.print(f"• Total scanned: [bold white]{scanned}[/bold white]")
    console.print(f"• Working proxies: [bold green]{len(results)}[/bold green]")
    console.print(f"• Failed: [bold red]{failed}[/bold red]")
    console.print(f"• Time taken: {duration}s" + (f" ({scanned / duration:.0f} checks/s)" if duration else ""))
    if results:
        fastest = sorted(results, key=lambda item: item[1])[:3]
        console.print(f"[green]✓ Saved {len(results)} proxies to {args.output} (fastest first)[/green]")
        console.print("  Fastest: " + ", ".join(f"{p} ({ms}ms)" for p, ms in fastest))
    else:
        console.print("[red]✗ No working proxies found.[/red]")
    console.print("━" * 50)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Session Aborted.[/red]")
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {e}[/red]")
