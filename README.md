# website-check

Een website-check voor ondernemers: scoort één webpagina op wat telt om gevonden te worden door klanten in de buurt, met een rapport in begrijpelijk Nederlands.

Dit is de motor achter de gratis [Website-check op iverium.nl](https://www.iverium.nl/website-check). We gebruikten hem ook voor ons [onderzoek naar de online vindbaarheid van ondernemers](https://www.iverium.nl/onderzoek).

- Alleen de Python-standaardbibliotheek, Python 3.8 of nieuwer
- Score van 0 tot 100, met per punt uitleg en advies
- Veilig te gebruiken in een webdienst waar bezoekers zelf een adres invullen (SSRF-bescherming)

## Wat wordt gecontroleerd

| Onderdeel | Controles |
| --- | --- |
| Basis en veiligheid | https met geldig certificaat, resterende geldigheid, doorsturen van http naar https, onveilige (http://) onderdelen |
| Snelheid | reactietijd van de server, omvang van de HTML, gzip/brotli-compressie, breedte en hoogte bij afbeeldingen |
| Mobiel | viewport-instelling |
| Vindbaarheid in Google | paginatitel, metabeschrijving, één H1, noindex, robots.txt, sitemap, canonical, alt-teksten, hoeveelheid tekst, taal |
| Lokaal gevonden worden | LocalBusiness structured data, klikbaar telefoonnummer, adres of postcode, Open Graph |

Daarnaast verzamelt de check een paar feiten: het platform (WordPress, Wix, Shopify, ...), het copyrightjaar in de footer, de schema.org-types en het aantal doorverwijzingen.

## Installeren

```bash
pip install git+https://github.com/Iverium/website-check
```

## Gebruik

```bash
website-check www.voorbeeld.nl
website-check www.voorbeeld.nl --json
website-check www.voorbeeld.nl --min-score 80
```

Met `--min-score` stopt het programma met exitcode 1 als de score lager is. Zo kunt u de check in een CI-pipeline zetten. Een website op uw eigen computer of intranet controleren kan met `--allow-private`.

Vanuit Python:

```python
from website_check import CheckError, check_website

try:
    result = check_website("www.voorbeeld.nl")
except CheckError as error:
    print(error)  # Nederlandse melding, geschikt om aan bezoekers te tonen
else:
    print(result["score"])
    for item in result["items"]:
        print(item["status"], item["title"], item["detail"], item["advice"])
```

Elk item heeft `key`, `group`, `title`, `status` (`goed`, `matig` of `slecht`), `detail`, `advice` en `weight`. De score is het gewogen gemiddelde: goed telt volledig, matig half en slecht niet.

Heeft u de pagina al opgehaald? Dan kunt u `analyse(page)` direct aanroepen.

## Veilig in een webdienst

Als bezoekers een adres invullen en uw server dat adres ophaalt, kan iemand proberen uw interne netwerk te bereiken. Dit heet server-side request forgery (SSRF). Daarom gelden deze regels:

- alleen http en https, en alleen de poorten 80 en 443;
- de hostnaam moet uitsluitend naar openbare IP-adressen verwijzen;
- de verbinding gaat naar precies het gecontroleerde adres, dus een tweede DNS-opzoeking (DNS rebinding) kan dat niet omzeilen;
- elke doorverwijzing wordt opnieuw gecontroleerd;
- de grootte van antwoorden en het uitpakken van gecomprimeerde antwoorden zijn begrensd.

Zet `ALLOW_PRIVATE` alleen aan voor gebruik op de opdrachtregel, nooit in een webdienst. Wilt u de check publiek aanbieden? Zet er dan ook een limiet per IP-adres op.

## English

`website-check` scores a single web page (0-100) on what matters for local search: https, speed, mobile, titles and meta descriptions, noindex, robots.txt, sitemap, canonical, alt texts, LocalBusiness structured data, a clickable phone number and Open Graph. Reports are in Dutch. It uses only the standard library and needs Python 3.8+. The fetcher is SSRF-safe, so you can offer the check publicly: it allows public addresses only, pins the connection to the checked IP and re-checks every redirect. Install with `pip install git+https://github.com/Iverium/website-check` and run `website-check example.com --json`.

## Andere tools

- [toegankelijkheid-check](https://github.com/Iverium/toegankelijkheid-check): automatische WCAG-controle
- [cookie-check](https://github.com/Iverium/cookie-check): tracking en cookies vóór toestemming
- [google-reviewlink](https://github.com/Iverium/google-reviewlink): van een Google Maps-link naar een directe reviewlink
- [tinyqr](https://github.com/Iverium/tinyqr): QR-codes als SVG of PNG zonder afhankelijkheden

## Licentie

MIT. Gemaakt door [Iverium Software](https://www.iverium.nl), webontwikkeling en vindbaarheid voor ondernemers in Groningen en Drenthe.
