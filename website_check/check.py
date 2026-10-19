"""Website check for small businesses: scores one page on what matters for being found by local customers.

Fetches the page the way a search engine would, plus robots.txt, the sitemap and the http:// variant, and reports
on security (https, certificate), speed, mobile, Google findability (title, description, headings, noindex,
canonical, alt texts, amount of text) and local signals (LocalBusiness structured data, clickable phone number,
postcode, Open Graph). Reports are in Dutch. Standard library only, Python 3.8+.

The engine behind https://www.iverium.nl/website-check, by Iverium Software.
"""
import json
import re
import time
from datetime import date
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from ._common import (SMALL_BYTES, CheckError, fetch, friendly_network_error, item, normalize_url, request,
                      score as score_items)

PAGE_BUDGET = 20  # seconds for one complete check; optional extras are skipped after this


# ---------------------------------------------------------------------------------------------------------------
# HTML analysis
# ---------------------------------------------------------------------------------------------------------------
class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.lang = None
        self.title = None
        self._in_title = False
        self.meta = {}
        self.canonical = None
        self.h1 = []
        self._h1_depth = 0
        self._h1_text = []
        self.images = 0
        self.images_no_alt = 0
        self.images_no_size = 0
        self.images_lazy = 0
        self.scripts = 0
        self.stylesheets = 0
        self.insecure = 0
        self.jsonld = []
        self._jsonld = None
        self.tel_links = 0
        self.links = []
        self.forms = 0
        self._skip = 0
        self.text = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html":
            self.lang = a.get("lang") or self.lang
        elif tag == "title" and self.title is None:
            self._in_title = True
            self.title = ""
        elif tag == "meta":
            key = (a.get("name") or a.get("property") or a.get("http-equiv") or "").lower()
            if key and key not in self.meta:
                self.meta[key] = a.get("content", "")
        elif tag == "link":
            rel = a.get("rel", "").lower().split()
            if "canonical" in rel and self.canonical is None:
                self.canonical = a.get("href")
            if "stylesheet" in rel:
                self.stylesheets += 1
                if a.get("href", "").startswith("http://"):
                    self.insecure += 1
        elif tag == "h1":
            self._h1_depth += 1
            self._h1_text = []
        elif tag == "img":
            self.images += 1
            if not a.get("alt", "").strip() and a.get("role") != "presentation" and "alt" not in a:
                self.images_no_alt += 1
            if not (a.get("width") and a.get("height")):
                self.images_no_size += 1
            if a.get("loading", "").lower() == "lazy":
                self.images_lazy += 1
            if a.get("src", "").startswith("http://"):
                self.insecure += 1
        elif tag == "script":
            self._skip += 1
            if a.get("type", "").lower() == "application/ld+json":
                self._jsonld = []
            elif a.get("src"):
                self.scripts += 1
                if a["src"].startswith("http://"):
                    self.insecure += 1
        elif tag in ("style", "noscript", "template", "svg"):
            self._skip += 1
        elif tag == "a":
            href = a.get("href", "").strip()
            if href.lower().startswith("tel:"):
                self.tel_links += 1
            elif href:
                self.links.append(href)
        elif tag == "form":
            self.forms += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "h1" and self._h1_depth:
            self._h1_depth -= 1
            self.h1.append(" ".join("".join(self._h1_text).split()))
        elif tag == "script":
            self._skip = max(0, self._skip - 1)
            if self._jsonld is not None:
                self.jsonld.append("".join(self._jsonld))
                self._jsonld = None
        elif tag in ("style", "noscript", "template", "svg"):
            self._skip = max(0, self._skip - 1)

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._jsonld is not None:
            self._jsonld.append(data)
            return
        if self._skip:
            return
        if self._h1_depth:
            self._h1_text.append(data)
        self.text.append(data)


def _schema_types(blocks):
    types = set()

    def walk(node):
        if isinstance(node, list):
            for child in node:
                walk(child)
        elif isinstance(node, dict):
            kind = node.get("@type")
            for value in (kind if isinstance(kind, list) else [kind]):
                if isinstance(value, str):
                    types.add(value)
            for value in node.values():
                if isinstance(value, (list, dict)):
                    walk(value)

    for block in blocks:
        try:
            walk(json.loads(block))
        except ValueError:
            continue
    return types


# schema.org types that tell Google "this is a local business" (LocalBusiness and its common subtypes)
LOCAL_TYPES = {
    "LocalBusiness", "ProfessionalService", "Store", "Restaurant", "FoodEstablishment", "CafeOrCoffeeShop",
    "BarOrPub", "Bakery", "HomeAndConstructionBusiness", "Plumber", "Electrician", "HVACBusiness", "RoofingContractor",
    "GeneralContractor", "HousePainter", "Locksmith", "AutoRepair", "AutomotiveBusiness", "HealthAndBeautyBusiness",
    "BeautySalon", "HairSalon", "DaySpa", "MedicalBusiness", "Dentist", "Physician", "MedicalClinic", "Optician",
    "Pharmacy", "LodgingBusiness", "Hotel", "BedAndBreakfast", "Campground", "Resort", "LegalService", "Attorney",
    "AccountingService", "FinancialService", "RealEstateAgent", "SportsActivityLocation", "ExerciseGym",
    "EntertainmentBusiness", "ChildCare", "VeterinaryCare", "TravelAgency", "EmploymentAgency", "MovingCompany",
    "Florist", "ClothingStore", "HomeGoodsStore", "GardenStore", "HardwareStore", "BikeStore", "PetStore",
    "FurnitureStore", "ElectronicsStore", "JewelryStore", "ShoeStore", "SportingGoodsStore", "BookStore",
}

PLATFORMS = [
    ("WordPress", re.compile(r"wp-content|wp-includes|wordpress", re.I)),
    ("Wix", re.compile(r"wixstatic\.com|static\.parastorage\.com|X-Wix", re.I)),
    ("Duda (sitebouwer)", re.compile(r"window\._currentDevice|cdn-website\.com|dmAlbum|duda", re.I)),
    ("Squarespace", re.compile(r"squarespace", re.I)),
    ("Jimdo", re.compile(r"jimdo", re.I)),
    ("Shopify", re.compile(r"cdn\.shopify\.com|shopify", re.I)),
    ("Webflow", re.compile(r"webflow", re.I)),
    ("Joomla", re.compile(r"/media/jui/|joomla", re.I)),
    ("Drupal", re.compile(r"drupal", re.I)),
    ("Lightspeed", re.compile(r"lightspeed|webshopapp\.com", re.I)),
    ("WooCommerce", re.compile(r"woocommerce", re.I)),
]

POSTCODE = re.compile(r"\b[1-9][0-9]{3} ?(?!SA|SD|SS)[A-Z]{2}\b")
COPYRIGHT_YEAR = re.compile(r"(?:©|&copy;|copyright)\s*(?:[^0-9<]{0,40})((?:19|20)\d{2})(?:\s*[-–]\s*((?:19|20)\d{2}))?", re.I)


def analyse(page, robots=None, sitemap_ok=None, http_redirects=None, today=None):
    """Turn a fetched page (+ extras) into check items, a 0-100 score and a few facts for the research."""
    today = today or date.today()
    headers = page["headers"]
    content_type = headers.get("content-type", "")
    charset = "utf-8"
    match = re.search(r"charset=([\w-]+)", content_type, re.I) or re.search(rb'<meta[^>]+charset=["\']?([\w-]+)',
                                                                             page["body"][:4096], re.I)
    if match:
        charset = match.group(1).decode() if isinstance(match.group(1), bytes) else match.group(1)
    try:
        html = page["body"].decode(charset, errors="replace")
    except LookupError:
        html = page["body"].decode("utf-8", errors="replace")
    parser = _PageParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # HTMLParser is lenient, but never let a weird page break the report
        pass
    text = " ".join(" ".join(parser.text).split())
    words = len(text.split())
    final_url = page["url"]
    secure = final_url.startswith("https://")
    items = []

    # --- Basis & veiligheid ---
    if secure and page["cert_ok"]:
        items.append(item("https", "Basis en veiligheid", "Beveiligde verbinding (https)", "goed",
                           "De website gebruikt https met een geldig certificaat.", weight=2))
    elif secure:
        items.append(item("https", "Basis en veiligheid", "Beveiligde verbinding (https)", "slecht",
                           "De website gebruikt https, maar het certificaat is ongeldig of verlopen. Browsers tonen "
                           "bezoekers dan een waarschuwing.", "Vernieuw het SSL-certificaat (bij de meeste hosters "
                           "gratis via Let's Encrypt).", weight=2))
    else:
        items.append(item("https", "Basis en veiligheid", "Beveiligde verbinding (https)", "slecht",
                           "De website gebruikt geen https. Browsers markeren hem als 'Niet veilig', en Google geeft "
                           "de voorkeur aan beveiligde websites.", "Zet een (gratis) SSL-certificaat aan en stuur "
                           "http door naar https.", weight=2))
    if secure and page["cert_ok"] and page.get("cert_expires"):
        days = int((page["cert_expires"] - time.time()) // 86400)
        items.append(item("cert_expiry", "Basis en veiligheid", "Geldigheid van het certificaat",
                           "goed" if days >= 14 else "matig" if days >= 0 else "slecht",
                           "Het certificaat is nog %d dagen geldig." % days if days >= 0 else "Het certificaat is verlopen.",
                           None if days >= 14 else "Vernieuw het certificaat op tijd, of zet automatisch vernieuwen aan.",
                           weight=0.5))
    if secure and http_redirects is not None:
        items.append(item("http_redirect", "Basis en veiligheid", "Doorsturen van http naar https",
                           "goed" if http_redirects else "matig",
                           "Wie het oude http://-adres gebruikt, komt automatisch op de veilige versie."
                           if http_redirects else "Het http://-adres stuurt niet door naar https. Zo kunnen er twee "
                           "versies van uw website bestaan.",
                           None if http_redirects else "Stel een permanente doorverwijzing (301) in van http naar "
                           "https.", weight=1))
    if secure:
        items.append(item("mixed", "Basis en veiligheid", "Geen onveilige onderdelen", "goed" if not parser.insecure
                           else "matig", "Alle afbeeldingen, scripts en stijlen worden veilig geladen."
                           if not parser.insecure else "%d onderdelen worden nog via http:// geladen." % parser.insecure,
                           None if not parser.insecure else "Laad alle afbeeldingen en scripts via https.", weight=0.5))

    # --- Snelheid ---
    fb = page["first_byte"]
    items.append(item("server_speed", "Snelheid", "Reactietijd van de server",
                       "goed" if fb < 0.8 else "matig" if fb < 1.8 else "slecht",
                       "De server begon na %s seconden met antwoorden." % ("%.1f" % fb).replace(".", ","),
                       None if fb < 0.8 else "Een sneller hostingpakket of caching kan dit flink verkorten.",
                       weight=1.5))
    size_kb = len(page["body"]) / 1024.0
    items.append(item("html_size", "Snelheid", "Omvang van de pagina (HTML)",
                       "goed" if size_kb < 200 else "matig" if size_kb < 600 else "slecht",
                       "De HTML van de pagina is %d kB." % size_kb,
                       None if size_kb < 200 else "Een kleinere pagina laadt sneller, zeker op mobiel. Kijk naar "
                       "ingebouwde code van pagebuilders en plugins.", weight=0.5))
    encoding = headers.get("content-encoding", "").lower()
    compressed = any(name in encoding for name in ("gzip", "br", "deflate", "zstd"))
    items.append(item("compression", "Snelheid", "Compressie (gzip/brotli)", "goed" if compressed else "matig",
                       "De server comprimeert de pagina." if compressed else "De server stuurt de pagina "
                       "ongecomprimeerd.", None if compressed else "Zet gzip- of brotli-compressie aan op de server.",
                       weight=0.5))
    if parser.images:
        no_size = parser.images_no_size / float(parser.images)
        items.append(item("image_sizes", "Snelheid", "Afmetingen bij afbeeldingen",
                           "goed" if no_size <= 0.2 else "matig",
                           "%d van de %d afbeeldingen hebben geen breedte en hoogte." % (parser.images_no_size,
                                                                                          parser.images),
                           None if no_size <= 0.2 else "Geef afbeeldingen een breedte en hoogte, zodat de pagina "
                           "niet verspringt tijdens het laden.", weight=0.5))

    # --- Mobiel ---
    viewport = parser.meta.get("viewport", "").replace(" ", "").lower()
    # Either setting makes a phone render the page at its own width (site builders often only set initial-scale)
    mobile = "width=device-width" in viewport or "initial-scale=1" in viewport
    items.append(item("viewport", "Mobiel", "Geschikt voor mobiel (viewport)", "goed" if mobile else "slecht",
                       "De pagina past zich aan het scherm van een telefoon aan." if mobile else "De pagina mist de "
                       "mobiele viewport-instelling en wordt op een telefoon waarschijnlijk klein en onhandig "
                       "weergegeven.", None if mobile else "Gebruik een responsief ontwerp met <meta name=\"viewport\" "
                       "content=\"width=device-width, initial-scale=1\">.", weight=2))

    # --- Google-vindbaarheid ---
    title = " ".join((parser.title or "").split())
    if not title:
        items.append(item("title", "Vindbaarheid in Google", "Paginatitel", "slecht", "De pagina heeft geen titel.",
                           "Geef elke pagina een unieke titel met uw dienst en plaats, bijvoorbeeld 'Kapper in "
                           "Zuidlaren | Uw Bedrijf'.", weight=2))
    else:
        good = 20 <= len(title) <= 65
        items.append(item("title", "Vindbaarheid in Google", "Paginatitel", "goed" if good else "matig",
                           "'%s' (%d tekens)." % (title[:90], len(title)),
                           None if good else "Een titel van 20 tot 65 tekens met uw belangrijkste dienst en plaats "
                           "werkt het best in Google.", weight=2))
    description = " ".join(parser.meta.get("description", "").split())
    if not description:
        items.append(item("description", "Vindbaarheid in Google", "Metabeschrijving", "slecht",
                           "De pagina heeft geen metabeschrijving. Google kiest dan zelf een stukje tekst.",
                           "Schrijf een beschrijving van 70 tot 160 tekens die vertelt wat u doet en waar.",
                           weight=1))
    else:
        good = 70 <= len(description) <= 170
        items.append(item("description", "Vindbaarheid in Google", "Metabeschrijving", "goed" if good else "matig",
                           "%d tekens." % len(description),
                           None if good else "Een beschrijving van 70 tot 160 tekens wordt het best getoond.",
                           weight=1))
    h1 = [h for h in parser.h1 if h]
    items.append(item("h1", "Vindbaarheid in Google", "Hoofdkop (H1)",
                       "goed" if len(h1) == 1 else "matig",
                       "Precies één hoofdkop: '%s'." % h1[0][:80] if len(h1) == 1 else
                       "Geen hoofdkop gevonden." if not h1 else "%d hoofdkoppen gevonden." % len(h1),
                       None if len(h1) == 1 else "Gebruik één duidelijke H1 per pagina die zegt wat u aanbiedt.",
                       weight=1))
    robots_meta = (parser.meta.get("robots", "") + " " + headers.get("x-robots-tag", "")).lower()
    noindex = "noindex" in robots_meta
    items.append(item("indexable", "Vindbaarheid in Google", "Mag in Google verschijnen",
                       "slecht" if noindex else "goed",
                       "De pagina vraagt Google uitdrukkelijk om hem NIET op te nemen (noindex)." if noindex else
                       "De pagina mag door Google worden opgenomen.",
                       "Haal de 'noindex'-instelling weg. Vaak blijft die na de bouw per ongeluk aan staan."
                       if noindex else None, weight=3))
    if robots is not None:
        blocked = robots.get("blocks_all", False)
        items.append(item("robots", "Vindbaarheid in Google", "robots.txt",
                           "slecht" if blocked else "goed" if robots.get("found") else "matig",
                           "robots.txt blokkeert de hele website voor zoekmachines." if blocked else
                           "robots.txt is aanwezig." if robots.get("found") else "Er is geen robots.txt.",
                           "Pas robots.txt aan zodat zoekmachines de website mogen bekijken." if blocked else
                           None if robots.get("found") else "Een robots.txt met een verwijzing naar uw sitemap helpt "
                           "zoekmachines op weg.", weight=2 if blocked else 0.5))
    if sitemap_ok is not None:
        items.append(item("sitemap", "Vindbaarheid in Google", "Sitemap", "goed" if sitemap_ok else "matig",
                           "Er is een sitemap gevonden." if sitemap_ok else "We vonden geen sitemap.",
                           None if sitemap_ok else "Een sitemap.xml helpt Google al uw pagina's te vinden. Meld hem "
                           "aan in Google Search Console.", weight=1))
    items.append(item("canonical", "Vindbaarheid in Google", "Canonieke URL", "goed" if parser.canonical else "matig",
                       "De pagina geeft aan wat het voorkeursadres is." if parser.canonical else
                       "De pagina geeft geen voorkeursadres (canonical) op.",
                       None if parser.canonical else "Een canonical-tag voorkomt dat Google dubbele versies van een "
                       "pagina ziet.", weight=0.5))
    if parser.images:
        items.append(item("alt", "Vindbaarheid in Google", "Alt-teksten bij afbeeldingen",
                           "goed" if parser.images_no_alt == 0 else "matig" if parser.images_no_alt <= parser.images / 2
                           else "slecht", "%d van de %d afbeeldingen hebben geen alt-tekst." % (
                               parser.images_no_alt, parser.images),
                           None if parser.images_no_alt == 0 else "Beschrijf afbeeldingen in de alt-tekst. Dat helpt "
                           "Google Afbeeldingen en bezoekers met een schermlezer.", weight=0.5))
    items.append(item("content", "Vindbaarheid in Google", "Hoeveelheid tekst",
                       "goed" if words >= 250 else "matig" if words >= 100 else "slecht",
                       "Ongeveer %d woorden op de pagina." % words,
                       None if words >= 250 else "Google heeft tekst nodig om te begrijpen wat u doet. Beschrijf uw "
                       "diensten, uw werkgebied en wat u onderscheidt.", weight=1))
    items.append(item("lang", "Vindbaarheid in Google", "Taal van de pagina", "goed" if parser.lang else "matig",
                       "Taal ingesteld: %s." % parser.lang if parser.lang else "De taal van de pagina is niet "
                       "ingesteld.", None if parser.lang else "Zet lang=\"nl\" op het html-element.", weight=0.3))

    # --- Lokaal & klanten ---
    schema = _schema_types(parser.jsonld)
    local_schema = bool(schema & LOCAL_TYPES)
    items.append(item("schema", "Lokaal gevonden worden", "Bedrijfsgegevens voor Google (structured data)",
                       "goed" if local_schema else "matig" if schema else "slecht",
                       "Google krijgt uw bedrijfsgegevens in een vast formaat (%s)." % ", ".join(sorted(schema &
                       LOCAL_TYPES)[:3]) if local_schema else "Er is structured data (%s), maar geen LocalBusiness."
                       % ", ".join(sorted(schema)[:3]) if schema else "Er zijn geen bedrijfsgegevens voor Google "
                       "(structured data) gevonden.",
                       None if local_schema else "Voeg LocalBusiness-gegevens toe met uw naam, adres, telefoon en "
                       "openingstijden.", weight=1))
    items.append(item("tel", "Lokaal gevonden worden", "Klikbaar telefoonnummer", "goed" if parser.tel_links else
                       "matig", "Bezoekers op een telefoon kunnen u met één tik bellen." if parser.tel_links else
                       "We vonden geen klikbaar telefoonnummer.", None if parser.tel_links else "Maak uw "
                       "telefoonnummer klikbaar (tel:-link). Veel lokale klanten bellen liever dan dat ze mailen.",
                       weight=1))
    has_postcode = bool(POSTCODE.search(text))
    items.append(item("address", "Lokaal gevonden worden", "Adres of postcode op de pagina",
                       "goed" if has_postcode else "matig",
                       "We vonden een adres of postcode op de pagina." if has_postcode else
                       "We vonden geen postcode op deze pagina.", None if has_postcode else "Zet uw adres (of "
                       "werkgebied) zichtbaar op de website, bijvoorbeeld in de footer.", weight=0.5))
    og = bool(parser.meta.get("og:title") and parser.meta.get("og:image"))
    items.append(item("social", "Lokaal gevonden worden", "Voorbeeld bij delen (Open Graph)", "goed" if og else
                       "matig", "Wie uw website deelt via WhatsApp of Facebook, ziet een nette titel en afbeelding."
                       if og else "Bij delen via WhatsApp of Facebook ontbreekt een nette titel of afbeelding.",
                       None if og else "Voeg og:title en og:image toe.", weight=0.3))

    score = score_items(items)

    years = []
    for match in COPYRIGHT_YEAR.finditer(html):
        years.extend(int(year) for year in match.groups() if year)
    copyright_year = max(years) if years else None
    platform = next((name for name, pattern in PLATFORMS
                     if pattern.search(html[:200000]) or pattern.search(" ".join(headers.values()))), None)
    facts = dict(final_url=final_url, status=page["status"], first_byte=round(fb, 2), html_kb=int(size_kb),
                 words=words, platform=platform, copyright_year=copyright_year,
                 copyright_outdated=bool(copyright_year and copyright_year < today.year - 1),
                 schema_types=sorted(schema), redirects=len(page.get("chain", [])))
    return dict(score=score, items=items, facts=facts)


# ---------------------------------------------------------------------------------------------------------------
# One complete check
# ---------------------------------------------------------------------------------------------------------------
def parse_robots(text):
    """Return dict(found, blocks_all, sitemaps) for the text of a robots.txt."""
    sitemaps, blocks_all, applies = [], False, False
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        field, value = (part.strip() for part in line.split(":", 1))
        field = field.lower()
        if field == "sitemap" and value:
            sitemaps.append(value)
        elif field == "user-agent":
            applies = value == "*"
        elif field == "disallow" and applies and value == "/":
            blocks_all = True
    return dict(found=True, blocks_all=blocks_all, sitemaps=sitemaps)


def _robots(base):
    try:
        response = fetch(base + "/robots.txt", limit=SMALL_BYTES)
    except Exception:
        return dict(found=False, blocks_all=False, sitemaps=[])
    if response["status"] != 200 or b"<html" in response["body"][:500].lower():
        return dict(found=False, blocks_all=False, sitemaps=[])
    return parse_robots(response["body"].decode("utf-8", errors="replace"))


def _sitemap_ok(base, robots):
    candidates = (robots or {}).get("sitemaps", [])[:2] + [base + "/sitemap.xml", base + "/sitemap_index.xml"]
    for candidate in candidates:
        try:
            url = normalize_url(urljoin(base + "/", candidate))
            response = fetch(url, limit=SMALL_BYTES)
        except Exception:
            continue
        head = response["body"][:2000].lower()
        if response["status"] == 200 and (b"<urlset" in head or b"<sitemapindex" in head):
            return True
    return False


def check_website(raw_url, extras=True):
    """Run a complete check. Raises CheckError with a visitor-friendly message when the site can't be checked."""
    url = normalize_url(raw_url)
    started = time.monotonic()
    try:
        page = fetch(url)
    except Exception as error:
        raise friendly_network_error(error, url)
    if page["status"] >= 400:
        raise CheckError("De website %s gaf een foutmelding (HTTP %d)." % (urlsplit(page["url"]).hostname,
                                                                          page["status"]))
    content_type = page["headers"].get("content-type", "").lower()
    if content_type and "html" not in content_type:
        raise CheckError("Dit adres geeft geen webpagina terug, maar %s." % content_type.split(";")[0])
    final = urlsplit(page["url"])
    base = "%s://%s" % (final.scheme, final.netloc)
    robots = sitemap = http_redirects = None
    if extras and time.monotonic() - started < PAGE_BUDGET:
        robots = _robots(base)
    if extras and time.monotonic() - started < PAGE_BUDGET:
        sitemap = _sitemap_ok(base, robots)
    if extras and final.scheme == "https" and time.monotonic() - started < PAGE_BUDGET:
        try:
            plain = request("http://%s%s" % (final.netloc, final.path or "/"), limit=SMALL_BYTES)
            location = plain["headers"].get("location", "")
            http_redirects = plain["status"] in (301, 302, 307, 308) and location.startswith("https://")
        except Exception:
            http_redirects = None
    result = analyse(page, robots, sitemap, http_redirects)
    result["url"] = page["url"]
    result["host"] = final.hostname
    result["duration"] = round(time.monotonic() - started, 1)
    return result
