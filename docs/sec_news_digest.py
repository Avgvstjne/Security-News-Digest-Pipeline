#!/usr/bin/env python3
"""
Daily cybersecurity news digest. Python 3.8+, standard library only.

What it does:
  1. Pulls RSS/Atom feeds + the CISA Known Exploited Vulnerabilities (KEV) list
  2. Keeps items from the last LOOKBACK_HOURS you haven't seen before
  3. Scores them against your KEYWORDS so relevant items float to the top
  4. Writes a dated HTML file to ./digests/ and opens it in your browser

Usage:
  python sec_digest.py              # build digest and open it
  python sec_digest.py --no-open    # build only, don't open the browser
  python sec_digest.py --email      # also email the digest (used by GitHub Actions)
  python sec_digest.py --hours 72   # widen the lookback window
"""
import argparse
import html
import json
import os
import re
import smtplib
import sys
import webbrowser
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.request import Request, urlopen

# ----------------------------- CONFIG ---------------------------------------
# Feed URLs change occasionally. If one prints a warning, check the site's
# footer for its current RSS link and update it here.
FEEDS = {
    "Microsoft MSRC": "https://msrc.microsoft.com/blog/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "SANS ISC": "https://isc.sans.edu/rssfeed.xml",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
}

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")

# Weight = how much you care. Edit freely to match your focus areas.
KEYWORDS = {
    "zero-day": 5, "0-day": 5, "actively exploited": 5, "exploited in the wild": 5,
    "ransomware": 3, "rce": 3, "remote code execution": 3, "cve-": 2,
    "privilege escalation": 3, "authentication bypass": 3,
    "active directory": 3, "entra": 3, "azure": 2, "aws": 2, "kubernetes": 2,
    "edr": 2, "siem": 2, "splunk": 2, "sentinel": 2, "mitre att&ck": 3,
    "phishing": 2, "supply chain": 3, "vmware": 3, "esxi": 3, "virtualbox": 2,
    "chrome": 1, "edge": 1, "windows": 1, "patch tuesday": 3,
    "pentest": 2, "red team": 2, "blue team": 2, "incident response": 2,
    "certification": 1, "hiring": 1,
}

LOOKBACK_HOURS = 36
MAX_ITEMS = 40
TIMEOUT = 20
# -----------------------------------------------------------------------------

BASE = Path(__file__).resolve().parent
SEEN_FILE = BASE / "seen.json"
OUT_DIR = BASE / "digests"
UA = "Mozilla/5.0 (compatible; sec-digest/1.0)"


def fetch(url):
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=TIMEOUT) as r:
        return r.read()


def local(tag):
    """Strip XML namespace."""
    return tag.rsplit("}", 1)[-1]


def child_text(el, *names):
    for c in el:
        if local(c.tag) in names and (c.text or "").strip():
            return c.text.strip()
    return ""


def parse_date(s):
    if not s:
        return None
    try:
        d = parsedate_to_datetime(s)
    except (TypeError, ValueError):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def clean(text, limit=300):
    text = html.unescape(re.sub(r"<[^>]+>", " ", text or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("..." if len(text) > limit else "")

def parse_xml(xml_bytes):
    try:
        return ET.fromstring(xml_bytes)
    except ET.ParseError:
        text = xml_bytes.decode("utf-8", errors="replace")
        text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)             # drop XML declaration
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)   # illegal control chars
        text = re.sub(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)", "&amp;", text)  # bare &
        return ET.fromstring(text)

def parse_feed(xml_bytes, source):
    root = parse_xml(xml_bytes)
    items = []
    for el in root.iter():
        kind = local(el.tag)
        if kind not in ("item", "entry"):
            continue
        link = child_text(el, "link")
        if not link:  # Atom stores the URL in an href attribute
            for c in el:
                if local(c.tag) == "link" and c.get("href"):
                    link = c.get("href")
                    break
        items.append({
            "source": source,
            "title": clean(child_text(el, "title"), 200),
            "link": link,
            "date": parse_date(child_text(el, "pubDate", "published", "updated", "date")),
            "summary": clean(child_text(el, "description", "summary", "content", "encoded")),
        })
    return items


def get_kev(cutoff):
    data = json.loads(fetch(KEV_URL))
    items = []
    for v in data.get("vulnerabilities", []):
        d = parse_date(v.get("dateAdded", "") + "T00:00:00+00:00")
        if not d or d < cutoff - timedelta(days=1):
            continue
        items.append({
            "source": "CISA KEV (exploited in the wild)",
            "title": f'{v["cveID"]}: {v.get("vendorProject", "")} {v.get("product", "")} - '
                     f'{v.get("vulnerabilityName", "")}',
            "link": f'https://nvd.nist.gov/vuln/detail/{v["cveID"]}',
            "date": d,
            "summary": clean(v.get("shortDescription", "")),
            "bonus": 6,  # KEV entries are always high priority
        })
    return items


def score(item):
    text = f'{item["title"]} {item["summary"]}'.lower()
    s = item.get("bonus", 0)
    hits = []
    for kw, w in KEYWORDS.items():
        if kw in text:
            s += w
            hits.append(kw)
    return s, hits


def load_seen():
    try:
        return set(json.loads(SEEN_FILE.read_text()))
    except (FileNotFoundError, ValueError):
        return set()


def save_seen(seen):
    SEEN_FILE.write_text(json.dumps(sorted(seen)[-3000:]))


def render(items, hours, warnings):
    now = datetime.now().strftime("%A %d %B %Y, %H:%M")
    rows = []
    for it in items:
        tags = "".join(f'<span class="tag">{html.escape(h)}</span>' for h in it["hits"][:5])
        when = it["date"].astimezone().strftime("%d %b %H:%M") if it["date"] else ""
        cls = "hot" if it["score"] >= 6 else ""
        rows.append(
            f'<div class="item {cls}"><a href="{html.escape(it["link"])}">{html.escape(it["title"])}</a>'
            f'<div class="meta">{html.escape(it["source"])} &middot; {when} &middot; score {it["score"]}</div>'
            f'<div class="sum">{html.escape(it["summary"])}</div>{tags}</div>'
        )
    warn = "".join(f"<li>{html.escape(w)}</li>" for w in warnings)
    warn_block = f'<details><summary>{len(warnings)} source warning(s)</summary><ul>{warn}</ul></details>' if warnings else ""
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security digest {now}</title><style>
body{{font-family:system-ui,Segoe UI,sans-serif;max-width:820px;margin:2rem auto;padding:0 1rem;line-height:1.45}}
.item{{padding:.8rem 1rem;margin:.6rem 0;border:1px solid #8884;border-radius:8px}}
.hot{{border-left:5px solid #d33}}
.meta{{font-size:.8rem;opacity:.7;margin:.2rem 0}}
.sum{{font-size:.92rem}}
.tag{{display:inline-block;font-size:.72rem;background:#8882;border-radius:4px;padding:1px 6px;margin:.4rem .3rem 0 0}}
a{{font-weight:600;text-decoration:none}}
</style></head><body>
<h1>Security digest</h1><p>{now} &middot; last {hours}h &middot; {len(items)} new items</p>
{''.join(rows) or '<p>Nothing new.</p>'}{warn_block}</body></html>"""


def send_email(subject, html_body):
    """Send via Gmail SMTP. Credentials come from environment variables only."""
    user = os.environ["GMAIL_USER"]
    password = os.environ["GMAIL_APP_PASSWORD"].replace(" ", "")
    to = os.environ.get("DIGEST_TO") or user
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, user, to
    msg.set_content("Your mail client does not support HTML. Open the digest in a browser.")
    msg.add_alternative(html_body, subtype="html")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=TIMEOUT) as smtp:
        smtp.login(user, password)
        smtp.send_message(msg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-open", action="store_true")
    ap.add_argument("--email", action="store_true", help="email the digest")
    ap.add_argument("--hours", type=int, default=LOOKBACK_HOURS)
    args = ap.parse_args()

    cutoff = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    seen = load_seen()
    collected, warnings = [], []

    for name, url in FEEDS.items():
        try:
            collected += parse_feed(fetch(url), name)
        except Exception as e:  # keep going if one source is down
            warnings.append(f"{name}: {type(e).__name__}: {e}")
    try:
        collected += get_kev(cutoff)
    except Exception as e:
        warnings.append(f"CISA KEV: {type(e).__name__}: {e}")

    fresh = []
    for it in collected:
        if not it["link"] or it["link"] in seen:
            continue
        if it["date"] and it["date"] < cutoff:
            continue
        it["score"], it["hits"] = score(it)
        fresh.append(it)

    epoch = datetime.min.replace(tzinfo=timezone.utc)
    fresh.sort(key=lambda i: (i["score"], i["date"] or epoch), reverse=True)
    fresh = fresh[:MAX_ITEMS]

    OUT_DIR.mkdir(exist_ok=True)
    out = OUT_DIR / f'digest_{datetime.now():%Y-%m-%d_%H%M}.html'
    page = render(fresh, args.hours, warnings)
    out.write_text(page, encoding="utf-8")

    if args.email:
        # Only mark items as seen if the email actually went out.
        try:
            send_email(f"Security digest: {len(fresh)} new items ({datetime.now():%d %b})", page)
            print("Email sent.")
        except Exception as e:
            print(f"EMAIL FAILED: {type(e).__name__}: {e}", file=sys.stderr)
            sys.exit(1)

    seen.update(i["link"] for i in fresh)
    save_seen(seen)

    print(f"Wrote {out} ({len(fresh)} items, {len(warnings)} warnings)")
    for w in warnings:
        print("  warning:", w, file=sys.stderr)
    if not args.no_open:
        webbrowser.open(out.as_uri())


if __name__ == "__main__":
    main()
