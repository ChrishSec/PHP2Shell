#!/usr/bin/env python3

import argparse
import json
import os
import re
import ssl
import sys
import time
from collections import deque
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

BANNER = r"""
  ____  _   _ ____  ____  ____  _          _ _
 |  _ \| | | |  _ \/ ___||___ \| |__   ___| | |
 | |_) | |_| | |_) \___ \  __) | '_ \ / _ \ | |
 |  __/|  _  |  __/ ___) |/ __/| | | |  __/ | |
 |_|   |_| |_|_|   |____/|_____|_| |_|\___|_|_|

                 PHP2Shell Scanner
       CVE-2026-109618 / CVE-2026-109619
             Developed by ChrishSec
          https://github.com/ChrishSec
"""


def print_banner():
    print(BANNER)


USER_AGENT = "PHP2Shell/1.0"

ANSI_RESET = "\x1b[0m"
STATUS_COLORS = {
    "POTENTIALLY_VULNERABLE": "\x1b[1;31m",  # Bright red
    "LEGACY_AT_RISK": "\x1b[1;31m",           # Bright red
    "PATCHED_UPSTREAM": "\x1b[32m",          # Green
    "INCONCLUSIVE": "\x1b[33m",             # Yellow
    "VERSION_NOT_DISCLOSED": "\x1b[33m",    # Yellow
    "NO_PHP_BANNER": "\x1b[33m",            # Yellow
    "ERROR": "\x1b[31m",                    # Red
}


def color_enabled(stream=None):
    """Enable ANSI colors automatically on compatible terminals."""
    if "NO_COLOR" in os.environ:
        return False
    stream = sys.stdout if stream is None else stream
    return stream.isatty() and os.environ.get("TERM") != "dumb"


def color_status(text, status, enabled):
    """Highlight console results only; JSON output stays plain."""
    color = STATUS_COLORS.get(status) if enabled else None
    return f"{color}{text}{ANSI_RESET}" if color else text

CVES = ["CVE-2026-109618", "CVE-2026-109619"]
FIXED_PATCH = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
MAX_HTML_BYTES = 512 * 1024 
SKIP_LINK_SUFFIXES = (
    ".css", ".js", ".json", ".xml", ".jpg", ".jpeg", ".png",
    ".gif", ".webp", ".svg", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".mp3", ".mp4", ".mov", ".woff", ".woff2",
    ".ttf", ".eot", ".map", ".exe", ".dmg",
)
SKIP_ACTION_PATH = re.compile(
    r"(?:^|/)(?:logout|log-out|signout|sign-out|delete|remove|"
    r"destroy|drop|terminate)(?:/|$)", re.IGNORECASE
)
VERSION_HEADERS = {
    "x-powered-by", "server", "x-php-version", "php-version",
    "x-backend-server", "x-backend", "x-runtime",
}

PHP_VERSION_RE = re.compile(
    r"\bPHP\s*(?:[/=]\s*)?v?(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?"
    r"(RC\d*|alpha\d*|beta\d*|dev)?",
    re.IGNORECASE,
)
BARE_VERSION_RE = re.compile(
    r"^\s*v?(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?"
    r"(RC\d*|alpha\d*|beta\d*|dev)?(?=$|\W)",
    re.IGNORECASE,
)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_url(value):
    value = value.strip()
    if not value:
        raise ValueError("empty target")
    if "://" not in value:
        value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("expected an http(s) URL with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL userinfo is not supported")
    return value


def collect_evidence(headers):
    """Extract PHP versions and non-sensitive versionless PHP hints."""
    found = []
    hints = []
    for header, value in headers:
        name = header.lower()
        if name == "set-cookie":
            if re.search(r"(?:^|[,;\s])PHPSESSID\s*=", value, re.IGNORECASE):
                hints.append("Set-Cookie names PHPSESSID (PHP hint only)")
            continue  # Never print cookie values, which may contain secrets.
        if name not in VERSION_HEADERS:
            continue
        matches = list(PHP_VERSION_RE.finditer(value))
        if not matches and name in ("x-php-version", "php-version"):
            bare = BARE_VERSION_RE.search(value)
            if bare:
                matches = [bare]
        if matches:
            for match in matches:
                major, minor, patch, prerelease = match.groups()
                version = f"{int(major)}.{int(minor)}"
                if patch is not None:
                    version += f".{int(patch)}"
                if prerelease:
                    version += prerelease
                found.append({
                    "header": header,
                    "value": value[:240],
                    "version": version,
                    "major": int(major),
                    "minor": int(minor),
                    "patch": int(patch) if patch is not None else None,
                    "prerelease": bool(prerelease),
                })
        elif re.search(r"\bPHP\b", value, re.IGNORECASE):
            hints.append(f"{header} mentions PHP without a version")
    return found, sorted(set(hints))


def classify_version(evidence):
    major, minor, patch = evidence["major"], evidence["minor"], evidence["patch"]
    branch = (major, minor)
    if evidence["prerelease"]:
        return "INCONCLUSIVE", "Pre-release banner; verify its patch contents"
    if branch in FIXED_PATCH:
        if patch is None:
            return "INCONCLUSIVE", "Patch version not exposed"
        fixed = FIXED_PATCH[branch]
        if patch < fixed:
            return "POTENTIALLY_VULNERABLE", f"Upstream fix starts at {major}.{minor}.{fixed}"
        return "PATCHED_UPSTREAM", f"At or above upstream fix {major}.{minor}.{fixed}"
    if (5, 4) <= branch < (8, 2):
        return "LEGACY_AT_RISK", "Old PHP branch; vendor backports may exist"
    return "INCONCLUSIVE", "Outside the documented version-mapping rules"


def summarize(evidence, hints):
    if not evidence:
        if hints:
            return "VERSION_NOT_DISCLOSED", "PHP indicated, but no version was disclosed", []
        return "NO_PHP_BANNER", "No PHP version in checked response headers", []

    versions = sorted(set(item["version"] for item in evidence))
    assessments = [classify_version(item) for item in evidence]
    statuses = {status for status, _ in assessments}

    if "POTENTIALLY_VULNERABLE" in statuses or "LEGACY_AT_RISK" in statuses:
        status = "POTENTIALLY_VULNERABLE"
        detail = "At least one exposed PHP version is in a potentially affected range"
        cves = CVES
    elif statuses == {"PATCHED_UPSTREAM"}:
        status = "PATCHED_UPSTREAM"
        detail = "Disclosed PHP version(s) meet the upstream fixed-release thresholds"
        cves = []
    else:
        status = "INCONCLUSIVE"
        detail = "Version incomplete, conflicting, pre-release, or not covered by this mapping"
        cves = []

    if len(versions) > 1:
        detail += "; multiple version banners were seen"
    return status, detail, cves


class LinkExtractor(HTMLParser):
    """Collect navigation links; never submit forms or execute scripts."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name and name.lower() == "href" and value:
                self.links.append(value)
                break


def origin_of(url):
    """Strictly identify the scheme, host and port a crawl may visit."""
    parsed = urlsplit(url)
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or default_port


def canonical_url(url):
    """Deduplicate fragments and queries, which can cause unbounded crawling."""
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", ""))


def allowed_crawl_url(url, origin):
    """Only follow same-origin page paths, not external/action/static links."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return None
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            return None
        if origin_of(url) != origin:
            return None
        path = parsed.path.lower()
        if path.endswith(SKIP_LINK_SUFFIXES) or SKIP_ACTION_PATH.search(path):
            return None
        return canonical_url(url)
    except (ValueError, AttributeError):
        return None


def extract_links(html_text, page_url, origin):
    if not html_text:
        return []
    parser = LinkExtractor()
    try:
        parser.feed(html_text)
        parser.close()
    except (ValueError, AssertionError):
        return []
    links = []
    for href in parser.links:
        candidate = allowed_crawl_url(urljoin(page_url, href.strip()), origin)
        if candidate is not None:
            links.append(candidate)
    return list(dict.fromkeys(links))


def get_response(url, timeout=6.0, max_redirects=3, insecure=False, read_html=False,
                 strict_origin=None):
    """One GET, optionally reading a small HTML body for link discovery."""
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    opener = build_opener(NoRedirect(), HTTPSHandler(context=context))
    origin_host = urlsplit(url).hostname.lower()
    current = url

    for hop in range(max_redirects + 1):
        req = Request(
            current,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html, */*", "Accept-Encoding": "identity"},
            method="GET",
        )
        try:
            response = opener.open(req, timeout=timeout)
        except HTTPError as error:
            # 4xx/5xx and 3xx responses can still expose PHP versions.
            response = error
        with response:
            status = response.getcode()
            headers = list(response.headers.items())
            location = response.headers.get("Location")

            if status in (301, 302, 303, 307, 308) and location and hop < max_redirects:
                redirect_url = urljoin(current, location)
                parsed = urlsplit(redirect_url)
                # Preserve the existing same-host redirect policy. Never
                # follow a redirect to a different host or an HTTPS downgrade.
                if (parsed.scheme in ("http", "https")
                        and parsed.hostname and parsed.hostname.lower() == origin_host
                        and parsed.username is None and parsed.password is None
                        and (strict_origin is None or origin_of(redirect_url) == strict_origin)
                        and not (urlsplit(current).scheme == "https" and parsed.scheme == "http")):
                    current = redirect_url
                    continue

            html = None
            content_type = (response.headers.get("Content-Type") or "").lower()
            if read_html and (not content_type or "html" in content_type):
                body = response.read(MAX_HTML_BYTES + 1)
                if len(body) <= MAX_HTML_BYTES:
                    encoding = response.headers.get_content_charset() or "utf-8"
                    try:
                        html = body.decode(encoding, errors="replace")
                    except (LookupError, ValueError):
                        html = body.decode("utf-8", errors="replace")
            return current, status, headers, html

    raise RuntimeError("Unexpected redirect processing state")


def get_headers(url, timeout=6.0, max_redirects=3, insecure=False):
    final_url, status, headers, _ = get_response(url, timeout, max_redirects, insecure)
    return final_url, status, headers


def should_try_http(error):
    """Do not bypass TLS certificate failures by downgrading to HTTP."""
    reason = error.reason if isinstance(error, URLError) else error
    return not isinstance(reason, ssl.SSLCertVerificationError)


def scan_page(raw_url, timeout, redirects, insecure, read_html=False, strict_origin=None):
    result = {
        "target": raw_url, "final_url": None, "http_status": None,
        "status": "ERROR", "php_versions": [], "evidence": [],
        "hints": [], "possible_cves": [], "detail": None,
    }
    html = None
    try:
        url = normalize_url(raw_url)
        # Bare hostnames try HTTPS first, then HTTP on connection errors;
        # explicitly specified https:// URLs never downgrade.
        try:
            final_url, status, headers, html = get_response(
                url, timeout, redirects, insecure, read_html=read_html,
                strict_origin=strict_origin
            )
        except (URLError, OSError, TimeoutError) as error:
            if "://" in raw_url.strip() or not should_try_http(error):
                raise
            http_url = "http://" + raw_url.strip()
            final_url, status, headers, html = get_response(
                http_url, timeout, redirects, insecure, read_html=read_html,
                strict_origin=strict_origin
            )
        found, hints = collect_evidence(headers)
        assessment, detail, cves = summarize(found, hints)
        result.update({
            "final_url": final_url,
            "http_status": status,
            "status": assessment,
            "php_versions": sorted(set(item["version"] for item in found)),
            "evidence": [
                {"header": item["header"], "value": item["value"], "version": item["version"]}
                for item in found
            ],
            "hints": hints,
            "possible_cves": cves,
            "detail": detail,
        })
    except Exception as error:
        result["detail"] = f"{type(error).__name__}: {error}"
    return result, html


def scan_one(raw_url, timeout, redirects, insecure):
    """Backward-compatible check of one URL without crawling."""
    return scan_page(raw_url, timeout, redirects, insecure)[0]


def scan_site(raw_url, timeout, redirects, insecure, crawl=False, depth=2,
              max_pages=30, paths=(), delay=0.0):
              
    first, first_html = scan_page(raw_url, timeout, redirects, insecure, read_html=crawl)
    first["site"] = raw_url
    first["crawl_depth"] = 0
    results = [first]
    if not first["final_url"]:
        return results

    origin = origin_of(first["final_url"])
    root_parts = urlsplit(first["final_url"])
    origin_root = f"{root_parts.scheme}://{root_parts.netloc}/"
    visited = {canonical_url(first["final_url"])}
    queued = set()
    queue = deque()

    def enqueue(url, next_depth):
        canonical = allowed_crawl_url(url, origin)
        if canonical and canonical not in visited and canonical not in queued:
            queued.add(canonical)
            queue.append((canonical, next_depth))

    # User-supplied paths are explicitly authorized seeds, even when not linked.
    for path in paths:
        path = path.strip()
        if path:
            enqueue(urljoin(origin_root, path.lstrip("/")), 0)

    if crawl and depth >= 1:
        for linked_url in extract_links(first_html, first["final_url"], origin):
            enqueue(linked_url, 1)

    while queue and len(results) < max_pages:
        page_url, page_depth = queue.popleft()
        queued.remove(page_url)
        if page_url in visited:
            continue
        visited.add(page_url)
        if delay:
            time.sleep(delay)
        result, html = scan_page(page_url, timeout, redirects, insecure,
                                 read_html=crawl, strict_origin=origin)
        result["site"] = raw_url
        result["crawl_depth"] = page_depth
        results.append(result)
        if result["final_url"]:
            final_canonical = allowed_crawl_url(result["final_url"], origin)
            if final_canonical:
                visited.add(final_canonical)
        if crawl and page_depth < depth and result["final_url"]:
            # Redirects to another origin never contribute crawl links.
            if origin_of(result["final_url"]) == origin:
                for linked_url in extract_links(html, result["final_url"], origin):
                    enqueue(linked_url, page_depth + 1)
    return results


def read_targets(args):
    urls = list(args.url or [])
    for filename in (args.list, args.targets_file):
        if filename:
            with open(filename, "r", encoding="utf-8-sig") as stream:
                for line in stream:
                    target = line.strip()
                    if target and not target.startswith("#"):
                        urls.append(target)
    return list(dict.fromkeys(urls))


def read_paths(args):
    return list(dict.fromkeys(args.path or []))


def display_result(result, color=False):
    versions = ",".join(result["php_versions"]) or "not disclosed"
    line = (f"[{result['status']:<24}] {result['target']}  PHP={versions}"
            f"  HTTP={result['http_status'] if result['http_status'] is not None else '-'}")
    print(color_status(line, result["status"], color))
    print(f"    {result['detail']}")


def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="Passive PHP2Shell version-based scanner (no exploit payloads)."
    )
    parser.add_argument("targets_file", nargs="?", help="Optional subdomains.txt input file")
    parser.add_argument("-u", "--url", action="append", help="Target URL or hostname")
    parser.add_argument("-l", "--list", help="Subdomains file (one host or URL per line)")
    parser.add_argument("--crawl", action="store_true", help="Check linked pages on each target")
    parser.add_argument("--path", action="append", help="Also check a path, e.g. /en/login")
    parser.add_argument("-o", "--output", help="Save results to JSON")
    args = parser.parse_args()

    try:
        targets = read_targets(args)
        paths = read_paths(args)
    except OSError as error:
        parser.error(str(error))
    if not targets:
        parser.error("Specify -u URL, -l subdomains.txt, or a positional subdomains.txt file")

    # Bounded defaults instead of many flags: same-site links, 2 hops, 30 pages.
    scan_paths = args.crawl or bool(paths)
    use_color = color_enabled()
    results = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        if scan_paths:
            futures = [pool.submit(scan_site, url, 6.0, 3, False,
                                   crawl=args.crawl, depth=2, max_pages=30,
                                   paths=paths) for url in targets]
        else:
            futures = [pool.submit(scan_one, url, 6.0, 3, False)
                       for url in targets]
        for future in as_completed(futures):
            pages = future.result() if scan_paths else [future.result()]
            results.extend(pages)
            for result in pages:
                display_result(result, color=use_color)
            if scan_paths:
                site = pages[0]["site"]
                flags = sum(p["status"] == "POTENTIALLY_VULNERABLE" for p in pages)
                print(f"    Site {site}: checked {len(pages)} page(s), "
                      f"{flags} potentially vulnerable page(s)\n")

    if args.output:
        try:
            Path(args.output).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        except OSError as error:
            print(f"Could not write JSON report: {error}", file=sys.stderr)
            return 2
        print(f"\nJSON report: {args.output}")

    totals = {}
    for result in results:
        totals[result["status"]] = totals.get(result["status"], 0) + 1
    print("\nSummary (pages): " + ", ".join(f"{key}={value}" for key, value in sorted(totals.items())))
    if scan_paths:
        affected_sites = {r["site"] for r in results if r["status"] == "POTENTIALLY_VULNERABLE"}
        print(f"Sites with potentially affected page(s): {len(affected_sites)}/{len(targets)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
