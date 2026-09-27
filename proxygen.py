import argparse
import json
import os
import re
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional
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
# Must echo the caller's IP ("origin") and request headers for anonymity detection to work.
TEST_URL = "http://httpbin.org/get"
HTTPS_TEST_URL = "https://httpbin.org/ip"
EXPECT = "origin"  # Substring the test response must contain (catches captive/garbage pages)
MAX_BODY_BYTES = 64 * 1024
USER_AGENT = "Mozilla/5.0"
CACHE_FILE = ".proxygen_cache.json"
CACHE_TTL_MINUTES = 60

# Least to most private. Transparent proxies leak your real IP; anonymous ones hide it
# but announce that a proxy is in use; elite ones do neither.
ANONYMITY_LEVELS = ["transparent", "anonymous", "elite"]
ANONYMITY_STYLES = {"transparent": "red", "anonymous": "yellow", "elite": "bold magenta"}
# Headers a proxy adds that reveal a proxy is being used.
PROXY_HEADERS = {
    "via", "forwarded", "x-forwarded-for", "x-forwarded", "forwarded-for", "x-real-ip",
    "client-ip", "x-client-ip", "x-proxy-id", "proxy-connection", "x-bluecoat-via",
}

# Matches ip:port anywhere in a line, so "http://1.2.3.4:8080" and "1.2.3.4:8080 US" both parse.
PROXY_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?!\d)")

console = Console()
_local = threading.local()


@dataclass
class ProxyResult:
    latency: int  # ms, for the plain HTTP check
    https: Optional[bool]  # None when the HTTPS check was skipped
    anonymity: Optional[str]  # None when your real IP couldn't be determined


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


def get_real_ip(args):
    """Fetch the test URL directly (no proxy).

    Returns (reachable, ip). `reachable` tells us our own connection works, so proxy
    failures are really the proxy's fault; `ip` is needed to spot transparent proxies.
    """
    try:
        r = requests.get(args.test_url, timeout=(args.connect_timeout, args.timeout),
                         headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
    except Exception:
        return False, None
    try:
        origin = r.json().get("origin", "")
    except (ValueError, AttributeError):
        return True, None
    ip = origin.split(",")[0].strip()
    return True, ip or None


def classify_anonymity(body, real_ip):
    """Decide how much a proxy reveals, based on what the test URL echoed back."""
    if real_ip is None:
        return None
    text = body.decode("utf-8", errors="replace")
    if re.search(rf"(?<![\w.:]){re.escape(real_ip)}(?![\w.:])", text):
        return "transparent"
    try:
        data = json.loads(text)
    except ValueError:
        data = {}
    headers = data.get("headers") if isinstance(data, dict) else None
    header_names = {name.lower() for name in headers} if isinstance(headers, dict) else set()
    origin = data.get("origin", "") if isinstance(data, dict) else ""
    # A forwarding header, or a chain of IPs in origin (built from X-Forwarded-For).
    if header_names & PROXY_HEADERS or "," in str(origin):
        return "anonymous"
    return "elite"


def fetch_through(session, url, proxy_url, args):
    """GET `url` through the proxy. Returns (latency_ms, body) on success, else None."""
    try:
        start = time.perf_counter()
        with session.get(
            url,
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
    except Exception:
        return None
    if args.expect and args.expect.encode() not in body:
        return None
    return latency, body


def check_proxy(proxy, args, real_ip):
    """Return a ProxyResult if the proxy works over plain HTTP, otherwise None."""
    session = get_session()
    proxy_url = f"http://{proxy}"
    try:
        result = fetch_through(session, args.test_url, proxy_url, args)
        if result is None:
            return None
        latency, body = result
        https = None
        if not args.no_https:
            # HTTPS goes through a CONNECT tunnel, which many HTTP-only proxies refuse.
            # Certificates are verified, so proxies that tamper with TLS fail here too.
            https = fetch_through(session, args.https_url, proxy_url, args) is not None
        return ProxyResult(latency, https, classify_anonymity(body, real_ip))
    finally:
        # requests caches a ProxyManager per proxy URL; drop it so memory and sockets
        # don't grow with every proxy this thread tests.
        for adapter in session.adapters.values():
            manager = adapter.proxy_manager.pop(proxy_url, None)
            if manager is not None:
                manager.clear()


def passes_filters(result, args):
    if args.require_https and not result.https:
        return False
    if args.min_anonymity and (
        ANONYMITY_LEVELS.index(result.anonymity) < ANONYMITY_LEVELS.index(args.min_anonymity)
    ):
        return False
    return True


def describe(result):
    parts = []
    if result.https is not None:
        parts.append("[green]HTTPS[/green]" if result.https else "[dim]HTTP only[/dim]")
    if result.anonymity:
        parts.append(f"[{ANONYMITY_STYLES[result.anonymity]}]{result.anonymity}[/]")
    return " | ".join(parts)


def load_cache(path, ttl_seconds):
    """Return {proxy: failed_at} for failures newer than the TTL."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    cutoff = time.time() - ttl_seconds
    return {p: t for p, t in data.items() if isinstance(t, (int, float)) and t >= cutoff}


def atomic_write(path, write):
    """Write to a temp file next to `path`, then swap it in so readers never see a partial file."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".proxygen-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            write(f)
        os.replace(tmp_path, path)
    except BaseException:
        os.unlink(tmp_path)
        raise


def write_sorted(path, results):
    """Atomically rewrite the output file with working proxies, fastest first."""
    def write(f):
        f.write("# Working HTTP/HTTPS Proxies (sorted by latency, fastest first)\n")
        f.write("# Generated: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
        for proxy, _ in sorted(results, key=lambda item: item[1].latency):
            f.write(f"{proxy}\n")
    atomic_write(path, write)


def parse_args():
    parser = argparse.ArgumentParser(description="Scrape public HTTP proxies and check which ones work.")
    parser.add_argument("-t", "--threads", type=int, default=THREADS, help=f"concurrent checks (default: {THREADS})")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help=f"read timeout in seconds (default: {TIMEOUT})")
    parser.add_argument("--connect-timeout", type=float, default=CONNECT_TIMEOUT,
                        help=f"connect timeout in seconds (default: {CONNECT_TIMEOUT})")
    parser.add_argument("-o", "--output", default=OUTPUT_FILE, help=f"output file (default: {OUTPUT_FILE})")
    parser.add_argument("--test-url", default=TEST_URL,
                        help=f"URL fetched through each proxy; should echo your IP and headers (default: {TEST_URL})")
    parser.add_argument("--https-url", default=HTTPS_TEST_URL,
                        help=f"HTTPS URL used to test tunnelling support (default: {HTTPS_TEST_URL})")
    parser.add_argument("--expect", default=EXPECT,
                        help=f"substring the test response must contain; empty to disable (default: {EXPECT!r})")
    parser.add_argument("--no-https", action="store_true", help="skip the HTTPS check")
    parser.add_argument("--require-https", action="store_true", help="only save proxies that also support HTTPS")
    parser.add_argument("--min-anonymity", choices=ANONYMITY_LEVELS,
                        help="only save proxies at least this anonymous (default: save all)")
    parser.add_argument("--cache-file", default=CACHE_FILE,
                        help=f"where recently failed proxies are remembered (default: {CACHE_FILE})")
    parser.add_argument("--cache-ttl", type=float, default=CACHE_TTL_MINUTES,
                        help=f"minutes to skip a proxy after it fails; 0 disables the cache (default: {CACHE_TTL_MINUTES})")
    parser.add_argument("-q", "--quiet", action="store_true", help="don't print each working proxy as it's found")
    args = parser.parse_args()
    if args.threads < 1:
        parser.error("--threads must be at least 1")
    if args.require_https and args.no_https:
        parser.error("--require-https can't be combined with --no-https")
    return args


def main():
    args = parse_args()

    console.print(Panel("[bold cyan]HTTPS Proxy Scraper[/bold cyan]", expand=False))
    console.print(
        f"[*] Timeout: [bold yellow]{args.connect_timeout}s connect / {args.timeout}s read[/bold yellow]"
        f" | Threads: [bold yellow]{args.threads}[/bold yellow]"
    )

    # 1. Scrape all sources in parallel, and look up our real IP at the same time
    with console.status("[bold white]Fetching proxy lists..."):
        with ThreadPoolExecutor(max_workers=1) as ip_pool:
            ip_future = ip_pool.submit(get_real_ip, args)
            proxies = fetch_all_sources(SOURCES)
            online, real_ip = ip_future.result()

    if not proxies:
        console.print("[red]No proxies found from any source![/red]")
        return

    if real_ip:
        console.print(f"[*] Your IP: [bold]{real_ip}[/bold] (used to spot transparent proxies)")
    else:
        console.print("[yellow]⚠ Couldn't determine your IP from the test URL; anonymity won't be checked.[/yellow]")
        if args.min_anonymity:
            console.print("[red]--min-anonymity needs a test URL that echoes your IP. Aborting.[/red]")
            return

    # 2. Skip proxies that failed recently. Only record new failures if our own
    #    connection works, so a network outage doesn't blacklist everything.
    use_cache = args.cache_ttl > 0
    cache = load_cache(args.cache_file, args.cache_ttl * 60) if use_cache else {}
    to_test = proxies - cache.keys()
    skipped = len(proxies) - len(to_test)
    if use_cache and not online:
        console.print("[yellow]⚠ Test URL unreachable without a proxy; failures won't be cached this run.[/yellow]")

    console.print(f"\n[*] Unique proxies: [bold cyan]{len(proxies)}[/bold cyan]", end="")
    if skipped:
        console.print(f" | Skipping [bold]{skipped}[/bold] that failed in the last {args.cache_ttl:g} min", end="")
    console.print(f" | Testing [bold cyan]{len(to_test)}[/bold cyan]\n")

    if not to_test:
        console.print("[yellow]Nothing new to test. Lower --cache-ttl or use --cache-ttl 0 to retest everything.[/yellow]")
        return

    # 3. Open the output file once; each hit is appended and flushed immediately
    try:
        out = open(args.output, "w", encoding="utf-8")
    except OSError as e:
        console.print(f"[red]Failed to create output file: {e}[/red]")
        return
    out.write("# Working HTTP/HTTPS Proxies\n")
    out.write("# Generated: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
    out.flush()

    # 4. Check proxies concurrently
    working = []  # every proxy that works, before filters
    saved = []  # the ones that pass --require-https / --min-anonymity
    failed_now = {}
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
    pool = ThreadPoolExecutor(max_workers=min(args.threads, len(to_test)))
    try:
        with progress:
            task = progress.add_task("test", total=len(to_test), alive=0)
            futures = {pool.submit(check_proxy, p, args, real_ip): p for p in to_test}
            for future in as_completed(futures):
                proxy = futures[future]
                result = future.result()
                if result is None:
                    failed_now[proxy] = time.time()
                else:
                    working.append((proxy, result))
                    if passes_filters(result, args):
                        saved.append((proxy, result))
                        out.write(f"{proxy}\n")
                        out.flush()
                        if not args.quiet:
                            progress.console.print(
                                f"[bold green][ALIVE][/bold green] {proxy:<22} | [cyan]{result.latency}ms[/cyan]"
                                f" | {describe(result)}"
                            )
                progress.update(task, advance=1, alive=len(saved))
    except KeyboardInterrupt:
        interrupted = True
        console.print("\n[red]Interrupted — stopping and saving what was found so far...[/red]")
    finally:
        pool.shutdown(wait=not interrupted, cancel_futures=True)
        out.close()

    duration = round(time.perf_counter() - start_run, 2)

    # 5. Rewrite the file sorted by latency so the fastest proxies come first
    if saved:
        try:
            write_sorted(args.output, saved)
        except OSError as e:
            console.print(f"[yellow]⚠ Could not sort output file ({e}); unsorted results kept.[/yellow]")

    # 6. Update the failure cache
    if use_cache and online:
        cache.update(failed_now)
        try:
            atomic_write(args.cache_file, lambda f: json.dump(cache, f))
        except OSError as e:
            console.print(f"[yellow]⚠ Could not write cache file ({e}).[/yellow]")

    scanned = len(working) + len(failed_now)
    console.print("\n" + "━" * 50)
    console.print("[bold yellow]⚠ SCANNING INTERRUPTED[/bold yellow]" if interrupted
                  else "[bold green]✓ SCANNING COMPLETE[/bold green]")
    console.print(f"• Total scanned: [bold white]{scanned}[/bold white]"
                  + (f" (+{skipped} skipped from cache)" if skipped else ""))
    console.print(f"• Working proxies: [bold green]{len(working)}[/bold green]")
    if working and not args.no_https:
        https_count = sum(1 for _, r in working if r.https)
        console.print(f"  ↳ HTTPS-capable: [bold green]{https_count}[/bold green]")
    if working and real_ip:
        levels = Counter(r.anonymity for _, r in working)
        console.print("  ↳ " + " | ".join(
            f"[{ANONYMITY_STYLES[level]}]{level}[/]: {levels[level]}" for level in reversed(ANONYMITY_LEVELS)
        ))
    console.print(f"• Failed: [bold red]{len(failed_now)}[/bold red]")
    console.print(f"• Time taken: {duration}s" + (f" ({scanned / duration:.0f} checks/s)" if duration else ""))
    if saved:
        fastest = sorted(saved, key=lambda item: item[1].latency)[:3]
        filtered_out = len(working) - len(saved)
        console.print(f"[green]✓ Saved {len(saved)} proxies to {args.output} (fastest first)[/green]"
                      + (f" — {filtered_out} filtered out" if filtered_out else ""))
        console.print("  Fastest: " + ", ".join(f"{p} ({r.latency}ms)" for p, r in fastest))
    elif working:
        console.print("[yellow]✗ Proxies worked, but none passed your filters.[/yellow]")
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
