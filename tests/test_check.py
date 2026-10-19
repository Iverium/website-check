import os
import sys
import threading
import unittest
from datetime import date
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from website_check import CheckError, analyse, check_website, parse_robots  # noqa: E402
from website_check import _common  # noqa: E402

GOOD_HTML = b"""<!doctype html><html lang="nl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bakker in Zuidlaren | Bakkerij Voorbeeld</title>
<meta name="description" content="Ambachtelijke bakker in Zuidlaren: elke ochtend vers brood, gebak en taarten op bestelling. Bestel online of kom langs.">
<link rel="canonical" href="https://www.voorbeeld.nl/">
<meta property="og:title" content="Bakkerij Voorbeeld"><meta property="og:image" content="https://www.voorbeeld.nl/og.jpg">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Bakery","name":"Bakkerij Voorbeeld"}</script>
</head><body><h1>Bakker in Zuidlaren</h1>
<img src="/brood.jpg" alt="Vers brood" width="400" height="300">
<p>""" + b"Vers brood en gebak uit Zuidlaren. " * 60 + b"""</p>
<p>Stationsweg 1, 9471 AA Zuidlaren. Bel <a href="tel:+31501234567">050 123 4567</a>.</p>
<footer>&copy; 2026 Bakkerij Voorbeeld</footer></body></html>"""

BAD_HTML = b"""<html><head><meta name="robots" content="noindex"></head><body>
<h1>Welkom</h1><h1>Home</h1><img src="http://cdn.example/a.jpg"><p>Hallo</p>
<footer>Copyright 2015</footer></body></html>"""


def page(body, url="https://www.voorbeeld.nl/", headers=None, first_byte=0.2):
    return dict(url=url, status=200, headers=headers or {"content-type": "text/html; charset=utf-8",
                                                          "content-encoding": "gzip"},
                body=body, first_byte=first_byte, cert_ok=True, cert_expires=None, chain=[], cookies=[])


def by_key(result):
    return {entry["key"]: entry for entry in result["items"]}


class Analyse(unittest.TestCase):
    def test_good_page(self):
        result = analyse(page(GOOD_HTML), robots=dict(found=True, blocks_all=False, sitemaps=[]), sitemap_ok=True,
                         http_redirects=True, today=date(2026, 10, 1))
        items = by_key(result)
        self.assertGreaterEqual(result["score"], 95)
        for key in ("https", "viewport", "title", "description", "h1", "indexable", "schema", "tel", "address"):
            self.assertEqual(items[key]["status"], "goed", key)
        self.assertEqual(result["facts"]["copyright_year"], 2026)
        self.assertFalse(result["facts"]["copyright_outdated"])

    def test_bad_page(self):
        result = analyse(page(BAD_HTML, url="http://voorbeeld.nl/", headers={"content-type": "text/html"},
                              first_byte=2.5), today=date(2026, 10, 1))
        items = by_key(result)
        self.assertLess(result["score"], 30)
        self.assertEqual(items["indexable"]["status"], "slecht")
        self.assertEqual(items["https"]["status"], "slecht")
        self.assertEqual(items["h1"]["status"], "matig")
        self.assertEqual(items["server_speed"]["status"], "slecht")
        self.assertTrue(result["facts"]["copyright_outdated"])


class Robots(unittest.TestCase):
    def test_parse(self):
        parsed = parse_robots("User-agent: *\nDisallow: /admin\n# comment\nSitemap: https://x.nl/sitemap.xml\n")
        self.assertEqual(parsed, dict(found=True, blocks_all=False, sitemaps=["https://x.nl/sitemap.xml"]))
        self.assertTrue(parse_robots("User-agent: *\nDisallow: /\n")["blocks_all"])
        self.assertFalse(parse_robots("User-agent: BadBot\nDisallow: /\n")["blocks_all"])


class Guard(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(_common.normalize_url("www.voorbeeld.nl"), "https://www.voorbeeld.nl")
        for raw in ("", "ftp://x.nl", "https://user:pw@x.nl", "https://x.nl:8080", "localhost", "x" * 400):
            with self.assertRaises(CheckError, msg=raw):
                _common.normalize_url(raw)

    def test_private_addresses_refused(self):
        for host in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "0.0.0.0"):
            with self.assertRaises(CheckError, msg=host):
                _common.public_address(host, 80)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/old":
            self.send_response(301)
            self.send_header("Location", "/")
            self.end_headers()
            return
        if self.path == "/robots.txt":
            body, kind = b"User-agent: *\nDisallow:\n", "text/plain"
        elif self.path == "/":
            body, kind = GOOD_HTML, "text/html; charset=utf-8"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class EndToEnd(unittest.TestCase):
    """Runs the real fetching code against a local server (needs ALLOW_PRIVATE, so it also proves the guard)."""

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d/old" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def tearDown(self):
        _common.ALLOW_PRIVATE = False

    def test_guard_blocks_local_server(self):
        with self.assertRaises(CheckError):
            check_website(self.url)

    def test_check_local_server(self):
        _common.ALLOW_PRIVATE = True
        result = check_website(self.url)
        items = by_key(result)
        self.assertTrue(result["url"].endswith("/"))
        self.assertEqual(result["facts"]["redirects"], 1)
        self.assertEqual(items["robots"]["status"], "goed")
        self.assertEqual(items["sitemap"]["status"], "matig")
        self.assertEqual(items["https"]["status"], "slecht")


if __name__ == "__main__":
    unittest.main()
