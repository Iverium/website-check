"""SSRF-guarded HTTP fetching and report helpers (standard library only, Python 3.8+).

Built for tools where *other people* type an address and your server fetches it: only http(s) on ports 80/443,
the host must resolve to public addresses only, and the connection goes to the exact address that was checked (no
second DNS lookup an attacker could rebind). Redirects are re-checked hop by hop, bodies are capped and
decompression is bounded.

This file is shared, unchanged, by website-check, toegankelijkheid-check and cookie-check
(https://github.com/Iverium). Messages in CheckError are Dutch and meant to be shown to visitors as is.
"""
import http.client
import ipaddress
import socket
import ssl
import time
import zlib
from urllib.parse import urljoin, urlsplit

USER_AGENT = "Mozilla/5.0 (compatible; IveriumChecks/1.0; +https://github.com/Iverium)"
TIMEOUT = 8               # seconds per connection / read
MAX_BYTES = 3000000       # page body cap (after decompression)
SMALL_BYTES = 300000      # robots.txt / sitemap cap
MAX_REDIRECTS = 5
# Only for local command-line use (checking a site on localhost or your intranet). Never enable this in a web
# service where visitors choose the address: it switches the SSRF guard off.
ALLOW_PRIVATE = False

STATUS_POINTS = {"goed": 1.0, "matig": 0.5, "slecht": 0.0}


class CheckError(Exception):
    """A problem explained to the visitor in plain Dutch (the message can be shown as is)."""


# ---------------------------------------------------------------------------------------------------------------
# Safe fetching
# ---------------------------------------------------------------------------------------------------------------
def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise CheckError("Vul het adres van een website in, bijvoorbeeld www.uwbedrijf.nl.")
    if len(raw) > 300:
        raise CheckError("Dit adres is te lang.")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise CheckError("Alleen websites die beginnen met http:// of https:// kunnen we controleren.")
    if not parts.hostname or parts.username or parts.password or ("." not in parts.hostname and not ALLOW_PRIVATE):
        raise CheckError("Dit lijkt geen geldig websiteadres. Probeer bijvoorbeeld www.uwbedrijf.nl.")
    try:
        port = parts.port
    except ValueError:
        raise CheckError("Dit lijkt geen geldig websiteadres. Probeer bijvoorbeeld www.uwbedrijf.nl.")
    if port not in (None, 80, 443) and not ALLOW_PRIVATE:
        raise CheckError("Websites op een afwijkende poort kunnen we niet controleren.")
    return parts.geturl()


def public_address(host, port):
    """Resolve host and return one address, refusing hosts that resolve to anything non-public."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise CheckError("We kunnen de website %s niet vinden. Klopt het adres?" % host)
    addresses = []
    for family, _, _, _, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0].split("%")[0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ALLOW_PRIVATE and (not ip.is_global or ip.is_multicast):
            raise CheckError("Dit adres is niet openbaar bereikbaar en kunnen we daarom niet controleren.")
        addresses.append((family, sockaddr))
    if not addresses:
        raise CheckError("We kunnen de website %s niet vinden. Klopt het adres?" % host)
    # Prefer IPv4: it is what most visitors' connections and most small-business hosting use
    addresses.sort(key=lambda item: item[0] != socket.AF_INET)
    return addresses[0]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, address, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self):
        family, sockaddr = self._address
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(sockaddr[:2] if family == socket.AF_INET else sockaddr)
        self.sock = sock


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, address, port, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._address = address

    def connect(self):
        family, sockaddr = self._address
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(sockaddr[:2] if family == socket.AF_INET else sockaddr)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _decompress(body, encoding, limit):
    encoding = (encoding or "").lower().strip()
    if encoding in ("gzip", "x-gzip", "deflate"):
        wbits = 16 + zlib.MAX_WBITS if "gzip" in encoding else zlib.MAX_WBITS
        try:
            return zlib.decompressobj(wbits).decompress(body, limit)
        except zlib.error:
            if encoding == "deflate":  # some servers send raw deflate
                try:
                    return zlib.decompressobj(-zlib.MAX_WBITS).decompress(body, limit)
                except zlib.error:
                    pass
            raise CheckError("De website stuurde gegevens die we niet konden uitpakken.")
    return body


def request(url, verify=True, limit=MAX_BYTES):
    """One GET without following redirects. Returns a dict with status, headers, body, timings and cookies."""
    parts = urlsplit(url)
    secure = parts.scheme == "https"
    port = parts.port or (443 if secure else 80)
    address = public_address(parts.hostname, port)
    if secure:
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        conn = _PinnedHTTPSConnection(parts.hostname, address, port, TIMEOUT, context)
    else:
        conn = _PinnedHTTPConnection(parts.hostname, address, port, TIMEOUT)
    path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    started = time.monotonic()
    try:
        conn.request("GET", path, headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "nl-NL,nl;q=0.9,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
        })
        response = conn.getresponse()
        first_byte = time.monotonic() - started
        cert_expires = None
        if secure and verify and conn.sock is not None:
            try:
                not_after = (conn.sock.getpeercert() or {}).get("notAfter")
                cert_expires = ssl.cert_time_to_seconds(not_after) if not_after else None
            except (ValueError, AttributeError):
                cert_expires = None
        raw = response.read(limit + 1)
        total = time.monotonic() - started
    finally:
        conn.close()
    headers, cookies = {}, []
    for key, value in response.getheaders():
        key = key.lower()
        if key == "set-cookie":  # joining these with commas would mangle them (cookie dates contain commas)
            cookies.append(value)
        headers[key] = headers[key] + ", " + value if key in headers else value
    body = _decompress(raw[:limit], headers.get("content-encoding"), limit)
    return dict(url=url, status=response.status, headers=headers, body=body, raw_size=len(raw[:limit]),
                truncated=len(raw) > limit, first_byte=first_byte, total=total, cookies=cookies,
                cert_expires=cert_expires)


def fetch(url, limit=MAX_BYTES):
    """GET url following redirects safely. Returns the final response plus the redirect chain and whether the
    TLS certificate was valid (an invalid one is a finding, so we then retry without verification)."""
    chain, chain_cookies = [], []
    cert_ok = True
    for _ in range(MAX_REDIRECTS + 1):
        try:
            response = request(url, verify=True, limit=limit)
        except ssl.SSLCertVerificationError:
            cert_ok = False
            response = request(url, verify=False, limit=limit)
        if response["status"] in (301, 302, 303, 307, 308) and response["headers"].get("location"):
            chain.append((url, response["status"]))
            chain_cookies.extend(response["cookies"])
            url = normalize_url(urljoin(url, response["headers"]["location"].strip()))
            continue
        response["chain"] = chain
        response["cert_ok"] = cert_ok
        response["cookies"] = chain_cookies + response["cookies"]
        return response
    raise CheckError("De website stuurt ons in een kringetje rond via te veel doorverwijzingen.")


def friendly_network_error(error, url):
    host = urlsplit(url).hostname
    if isinstance(error, CheckError):
        return error
    if isinstance(error, (socket.timeout, TimeoutError)):
        return CheckError("De website %s reageerde niet binnen %d seconden." % (host, TIMEOUT))
    if isinstance(error, ssl.SSLError):
        return CheckError("We konden geen veilige verbinding maken met %s (SSL-fout)." % host)
    if isinstance(error, (ConnectionError, OSError, http.client.HTTPException)):
        return CheckError("We konden geen verbinding maken met %s. Staat de website online?" % host)
    return CheckError("Er ging iets mis bij het ophalen van %s." % host)


def fetch_page(raw_url):
    """Fetch an HTML page for a check, turning every failure into a CheckError with a Dutch message."""
    url = normalize_url(raw_url)
    try:
        page = fetch(url)
    except Exception as error:
        raise friendly_network_error(error, url)
    if page["status"] >= 400:
        raise CheckError("De website %s gaf een foutmelding (HTTP %d)." % (urlsplit(page["url"]).hostname,
                                                                          page["status"]))
    content_type = page["headers"].get("content-type", "text/html").lower()
    if "html" not in content_type:
        raise CheckError("Dit adres geeft geen webpagina terug, maar %s." % content_type.split(";")[0])
    return page


# ---------------------------------------------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------------------------------------------
def item(key, group, title, status, detail, advice=None, weight=1.0):
    """One line of a report. status is goed / matig / slecht (scored) or info (not scored)."""
    return dict(key=key, group=group, title=title, status=status, detail=detail, advice=advice, weight=weight)


def score(items):
    """Weighted 0-100 score: goed counts fully, matig half, slecht not at all."""
    scored = [entry for entry in items if entry["status"] in STATUS_POINTS]
    total = sum(entry["weight"] for entry in scored)
    if not total:
        return 100
    return int(round(100 * sum(entry["weight"] * STATUS_POINTS[entry["status"]] for entry in scored) / total))


def format_report(result):
    """Plain-text report grouped like the web version."""
    lines = ["%s  score %d/100" % (result.get("url", ""), result["score"]), ""]
    group = None
    for entry in result["items"]:
        if entry["group"] != group:
            group = entry["group"]
            lines.append(group)
        lines.append("  [%s] %s: %s" % (entry["status"], entry["title"], entry["detail"]))
        if entry.get("advice"):
            lines.append("           -> %s" % entry["advice"])
    return "\n".join(lines)
