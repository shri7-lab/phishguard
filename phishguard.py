#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.1.0"

SENSITIVE_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "account", "update", "secure", "security", "password", "passwd",
    "otp", "bank", "refund", "expired", "suspend", "suspended",
    "confirm", "activate", "bonus", "free", "winner", "claim",
    "recharge", "kyc", "wallet", "credential",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz",
    "icu", "click", "loan", "work", "rest", "cfd", "buzz",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly",
    "cutt.ly", "rb.gy", "s.id", "lnkd.in", "bl.ink", "shorturl.at",
}

TRUSTED_DOMAINS = {
    "google.com", "github.com", "microsoft.com", "apple.com",
    "cloudflare.com", "wikipedia.org", "youtube.com", "instagram.com",
    "facebook.com", "whatsapp.com", "hackerone.com", "hackthebox.com",
    "tryhackme.com", "stackoverflow.com", "openai.com", "anthropic.com",
    "mozilla.org", "python.org", "npmjs.com", "pypi.org",
    "github.io", "raw.githubusercontent.com", "gitlab.com", "x.com",
    "reddit.com", "discord.com", "telegram.org", "linkedin.com",
}

BRANDS = [
    "google", "github", "paypal", "facebook", "instagram", "whatsapp",
    "netflix", "amazon", "apple", "microsoft", "twitter", "linkedin",
    "tiktok", "snapchat", "reddit", "discord", "telegram", "coinbase",
    "binance", "paytm", "phonepe", "googlepay", "irctc", "hdfc",
    "icici", "flipkart", "myntra", "zomato", "swiggy", "hotstar",
    "spotify", "youtube", "airtel",
]

LOOKALIKES = {
    "а": "a", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c",
    "і": "i", "ї": "i", "ԁ": "d", "к": "k", "м": "m", "т": "t",
    "х": "x", "у": "y", "ѕ": "s", "в": "b", "н": "h", "і": "i",
    "ο": "o", "α": "a", "ɑ": "a", "ɡ": "g", "ε": "e", "ι": "i",
    "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "κ": "k", "γ": "y",
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a",
}

LINK_RE = re.compile(
    r"https?://[^\s<>\"')\]]+"
    r"|www\.[^\s<>\"')\]]+"
    r"|\b[a-z0-9][a-z0-9-]{0,62}\.[a-z]{2,24}(?:/[^\s<>\"')\]]*)?",
    re.IGNORECASE,
)

RESET = "\033[0m"
COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "cyan": "\033[96m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}

use_color = sys.stdout.isatty()


def c(name, text):
    if use_color and name in COLORS:
        return COLORS[name] + text + RESET
    return text


def normalize(url):
    url = url.strip().rstrip(".,;:!?")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.IGNORECASE):
        url = "http://" + url
    return url


def levenshtein(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def map_lookalikes(s):
    return "".join(LOOKALIKES.get(ch, ch) for ch in s.lower())


def brand_in_domain(host):
    mapped = map_lookalikes(host)
    for brand in BRANDS:
        if brand in mapped:
            return brand
    for label in mapped.split("."):
        if len(label) < 4:
            continue
        for brand in BRANDS:
            if len(brand) >= 4 and levenshtein(label, brand) <= 2:
                return brand
    return None


def scan_message(text):
    findings = []
    points = 0

    blobs = re.findall(r"[A-Za-z0-9+/_-]{24,}={0,2}", text)
    for blob in blobs:
        decoded = ""
        try:
            import base64 as _b64
            pad = "=" * (-len(blob) % 4)
            for decoder in (_b64.b64decode, _b64.urlsafe_b64decode):
                try:
                    decoded = (decoder(blob + pad) or b"").decode("utf-8", "ignore")
                    break
                except Exception:
                    continue
        except Exception:
            decoded = ""
        if "http" in decoded.lower():
            findings.append((30, f"hidden URL inside an encoded blob → {decoded.strip()[:90]}"))
            points += 30
            break

    for blob in re.findall(r"(?:[0-9a-fA-F]{2}){20,}", text):
        try:
            decoded = bytes.fromhex(blob).decode("utf-8", "ignore")
        except Exception:
            continue
        if "http" in decoded.lower():
            findings.append((30, f"hidden URL inside hex-encoded data → {decoded.strip()[:90]}"))
            points += 30
            break

    for domain in re.findall(r"@([a-z0-9][a-z0-9.-]+\.[a-z]{2,24})", text, re.IGNORECASE):
        domain = domain.lower().strip(".")
        if any(domain == d or domain.endswith("." + d) for d in TRUSTED_DOMAINS):
            continue
        brand = brand_in_domain(domain)
        if brand:
            findings.append((25, f"email domain pretends to be {brand} ({domain})"))
            points += 25
        else:
            labels = domain.split(".")
            if labels and labels[-1] in SUSPICIOUS_TLDS:
                findings.append((20, f"email on high-risk TLD '.{labels[-1]}' ({domain})"))
                points += 20

    match = re.search(r"([A-Za-z][A-Za-z0-9 ._'-]{2,40})\s*<\s*[^<>\s]+@[^<>\s]+\s*>", text)
    if match:
        display = match.group(1)
        sender_domain = re.search(r"@([^<>\s>]+)", text)
        dom = sender_domain.group(1).lower() if sender_domain else ""
        for brand in BRANDS:
            if brand in display.lower() and not any(
                dom == d or dom.endswith("." + d) for d in TRUSTED_DOMAINS
            ):
                findings.append((
                    25,
                    f"display name says '{display.strip()}' but sender is {dom or 'unknown'}",
                ))
                points += 25
                break

    return findings, min(50, points)


def extract_links(text):
    seen = []
    for match in LINK_RE.findall(text):
        url = match.rstrip(".,;:!?")
        if url not in seen:
            seen.append(url)
    return seen


def score_url(url):
    findings = []
    score = 0
    normalized = normalize(url)
    parsed = urllib.parse.urlsplit(normalized)
    host = (parsed.hostname or "").lower()
    path_and_query = (parsed.path + "?" + (parsed.query or "")).lower()
    full = normalized.lower()

    try:
        ipaddress_less = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host)
    except Exception:
        ipaddress_less = None

    trusted = any(host == d or host.endswith("." + d) for d in TRUSTED_DOMAINS)

    if ipaddress_less:
        score += 35
        findings.append((35, "raw IP address instead of a real domain"))

    if "@" in normalized:
        score += 25
        findings.append((25, "'@' in URL (credentials trick to fake the host)"))

    if parsed.scheme == "http":
        score += 10
        findings.append((10, "plain HTTP — no encryption"))

    if parsed.port and parsed.port not in (80, 443):
        score += 10
        findings.append((10, f"unusual port :{parsed.port}"))

    labels = host.split(".")
    if labels and labels[-1] in SUSPICIOUS_TLDS:
        score += 20
        findings.append((20, f"high-risk top-level domain '.{labels[-1]}'"))

    if "xn--" in host:
        score += 25
        findings.append((25, "punycode/IDN host — possible homograph spoof"))

    if host.count("-") >= 3:
        score += 10
        findings.append((10, "3+ hyphens in domain (brand-stuffing pattern)"))

    if host.count(".") >= 4:
        score += 12
        findings.append((12, "deeply nested subdomains"))

    if len(normalized) > 180:
        score += 15
        findings.append((15, "extremely long URL (payload hiding)"))
    elif len(normalized) > 100:
        score += 8
        findings.append((8, "unusually long URL"))

    if any(host == s or host.endswith("." + s) for s in SHORTENER_DOMAINS):
        score += 15
        findings.append((15, f"link shortener hides the real destination ({labels[0] if labels else host})"))

    keyword_hits = sorted({k for k in SENSITIVE_KEYWORDS if k in full})
    if keyword_hits:
        kw_points = min(30, 8 * len(keyword_hits))
        score += kw_points
        findings.append((kw_points, "scare/urgency keywords: " + ", ".join(keyword_hits[:6])))

    if trusted:
        score -= 25
        findings.append((-25, "matches a well-known trusted domain"))
    else:
        if any(ord(ch) > 127 for ch in host):
            score += 25
            findings.append((25, "unicode look-alike characters in domain"))
        brand = brand_in_domain(host)
        if brand:
            score += 25
            findings.append((25, f"domain uses '{brand}' branding but is not the real site"))

    score = max(0, min(100, score))
    if trusted and score < 45:
        verdict = "SAFE"
    elif score >= 60:
        verdict = "PHISHING"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
    return score, verdict, findings


def ask_ollama(text):
    base = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    model = os.environ.get("PHISHGUARD_MODEL", "gemma3:2b")
    prompt = (
        "You are a careful phishing analyst. Analyze this message or URL: "
        + text
        + ' Respond with ONLY a JSON object like {"verdict":"SAFE|SUSPICIOUS|PHISHING","reason":"one short line"}.'
    )
    body = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(
        base + "/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            data = json.loads(resp.read().decode())
        reply = (data.get("response") or "").strip()
        match = re.search(r"\{.*\}", reply, re.DOTALL)
        if match:
            parsed = json.loads(match.group(0))
            verdict = str(parsed.get("verdict", "")).upper()
            if verdict in ("SAFE", "SUSPICIOUS", "PHISHING"):
                return {
                    "verdict": verdict,
                    "reason": str(parsed.get("reason", ""))[:200],
                    "model": model,
                }
    except Exception:
        return None
    return None


def analyze(text):
    links = extract_links(text)
    msg_findings, msg_points = scan_message(text)

    worst_score = 0
    worst_verdict = "SAFE"
    order = {"SAFE": 0, "SUSPICIOUS": 1, "PHISHING": 2}
    link_results = []
    for url in links:
        score, verdict, findings = score_url(url)
        link_results.append({
            "url": url,
            "score": score,
            "verdict": verdict,
            "findings": [{"points": p, "detail": d} for p, d in findings],
        })
        if order[verdict] > order[worst_verdict] or (
            verdict == worst_verdict and score > worst_score
        ):
            worst_verdict = verdict
            worst_score = score

    combined = min(100, worst_score + msg_points)
    if combined >= 60:
        worst_verdict = "PHISHING"
    elif combined >= 30:
        worst_verdict = "SUSPICIOUS"
    else:
        worst_verdict = "SAFE"
    worst_score = combined

    ai = None
    ai_error = None
    if not os.environ.get("PHISHGUARD_NO_AI"):
        ai = ask_ollama(text)
        if ai is None:
            ai_error = "local AI unavailable (start 'ollama serve') or reply unparseable — heuristic-only mode"
        elif order[ai["verdict"]] > order[worst_verdict]:
            worst_verdict = ai["verdict"]

    note = None
    if not links and not msg_findings:
        note = (
            "no link/payload found — local AI weighed in on the text"
            if ai
            else "no link found in input — heuristic scan only"
        )

    return {
        "input": text,
        "verdict": worst_verdict,
        "score": worst_score,
        "links": link_results,
        "message_findings": [{"points": p, "detail": d} for p, d in msg_findings],
        "ai": ai,
        "ai_error": ai_error,
        "note": note,
    }


def verdict_style(verdict):
    if verdict == "PHISHING":
        return c("red", "🔴 PHISHING")
    if verdict == "SUSPICIOUS":
        return c("yellow", "🟠 SUSPICIOUS")
    return c("green", "✅ SAFE")


def render_text(result, as_json=False):
    if as_json:
        return json.dumps(result, indent=2)
    lines = []
    lines.append(c("bold", "PhishGuard v" + VERSION))
    lines.append(c("dim", "-" * 46))
    lines.append("Input   : " + result["input"][:120])
    lines.append("Verdict : " + verdict_style(result["verdict"]) + c("dim", f"  (score {result['score']}/100)"))
    if result.get("note"):
        lines.append(c("dim", "note    : " + result["note"]))
    for link in result["links"]:
        lines.append("")
        lines.append(c("cyan", "  link: " + link["url"]))
        for f in link["findings"]:
            pts = f["points"]
            color = "red" if pts > 0 else "green"
            sign = "+" if pts > 0 else ""
            lines.append(f"    {c(color, sign + str(pts) + 'p'):>0}  {f['detail']}")
        if not link["findings"]:
            lines.append(c("dim", "    no suspicious signals"))
    if result.get("message_findings"):
        lines.append("")
        lines.append(c("cyan", "  message:"))
        for f in result["message_findings"]:
            lines.append(f"    {c('red', '+' + str(f['points']) + 'p')}  {f['detail']}")
    if result.get("ai"):
        ai = result["ai"]
        lines.append("")
        lines.append(c("cyan", f"  AI ({ai['model']}): {ai['verdict']} — {ai['reason']}"))
    elif result.get("ai_error"):
        lines.append("")
        lines.append(c("dim", "  AI: " + result["ai_error"]))
    lines.append(c("dim", "-" * 46))
    if result["verdict"] == "PHISHING":
        lines.append(c("red", "  ⚠  Do NOT click. Do NOT enter credentials. Report + block."))
    elif result["verdict"] == "SUSPICIOUS":
        lines.append(c("yellow", "  ?  Verify with the sender on a trusted channel first."))
    else:
        lines.append(c("green", "  Looks clean — still think before you click."))
    return "\n".join(lines)


PAGE_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin:0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
 background:#0d1117; color:#e6edf3; min-height:100vh; display:flex;
 flex-direction:column; align-items:center; padding:48px 16px; }
h1 { font-size:28px; margin:0 0 6px; }
.sub { color:#8b949e; margin-bottom:32px; font-size:14px; }
form { display:flex; gap:8px; width:100%; max-width:680px; }
input[type=text] { flex:1; padding:14px 16px; font-size:15px; border-radius:10px;
 border:1px solid #30363d; background:#161b22; color:#e6edf3; outline:none; }
input[type=text]:focus { border-color:#58a6ff; }
button { padding:14px 22px; font-size:15px; font-weight:700; border:none;
 border-radius:10px; background:#238636; color:#fff; cursor:pointer; }
button:hover { background:#2ea043; }
.result { margin-top:28px; width:100%; max-width:680px; background:#161b22;
 border:1px solid #30363d; border-radius:12px; padding:22px; }
.badge { display:inline-block; padding:6px 14px; border-radius:999px;
 font-weight:800; font-size:14px; }
.PHISHING { background:#3d1418; color:#ff7b72; border:1px solid #f85149; }
.SUSPICIOUS { background:#341a05; color:#e3b341; border:1px solid #d29922; }
.SAFE { background:#12261e; color:#56d364; border:1px solid #238636; }
.score { color:#8b949e; font-size:13px; margin-left:10px; }
ul { padding-left:18px; }
li { margin:6px 0; font-size:14px; }
.ai { margin-top:14px; color:#79c0ff; font-size:14px; }
.hint { color:#8b949e; font-size:13px; margin-top:18px; line-height:1.5; }
a { color:#58a6ff; }
"""


def render_html(result):
    items = []
    ai_html = ""
    note = ""
    if result:
        for link in result["links"]:
            items.append(f'<p style="color:#58a6ff;word-break:break-all">{link["url"]}</p><ul>')
            if not link["findings"]:
                items.append("<li>no suspicious signals</li>")
            for f in link["findings"]:
                color = "#ff7b72" if f["points"] > 0 else "#56d364"
                sign = "+" if f["points"] > 0 else ""
                items.append(f'<li style="color:{color}">{sign}{f["points"]}p &mdash; {f["detail"]}</li>')
            items.append("</ul>")
        if result.get("message_findings"):
            items.append('<p style="color:#58a6ff">message signals</p><ul>')
            for f in result["message_findings"]:
                items.append(f'<li style="color:#ff7b72">+{f["points"]}p &mdash; {f["detail"]}</li>')
            items.append("</ul>")
        if result.get("ai"):
            ai_html = f'<div class="ai">🤖 Local AI ({result["ai"]["model"]}): {result["ai"]["verdict"]} &mdash; {result["ai"]["reason"]}</div>'
        elif result.get("ai_error"):
            ai_html = f'<div class="hint">ℹ️ {result["ai_error"]}</div>'
        if result.get("note"):
            note = f'<div class="hint">{result["note"]}</div>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishGuard — local-first phishing checker</title>
<style>{PAGE_CSS}</style></head><body>
<h1>🛡️ PhishGuard</h1>
<p class="sub">Paste a suspicious link or message &mdash; it never leaves your machine.</p>
<form method="post" action="/check">
<input type="text" name="q" placeholder="https://bit.ly/free-recharge-win ..." required autofocus>
<button>Check</button>
</form>
{'<div class="result"><span class="badge ' + result['verdict'] + '">' + result['verdict'] + '</span><span class="score">score ' + str(result['score']) + '/100</span>' + note + ''.join(items) + ai_html + '</div>' if result else ''}
<p class="hint">Open-source &middot; zero Python dependencies &middot; optional local AI via <a href="https://ollama.com">Ollama</a><br>
Built for Hacktoberfest 2026 &middot; <a href="https://github.com/shri7-lab/phishguard">github.com/shri7-lab/phishguard</a></p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body, status=200):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        q = (params.get("q") or [""])[0][:2000]
        result = analyze(q) if q.strip() else None
        self._send(render_html(result))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode(errors="replace")
        params = urllib.parse.parse_qs(raw)
        q = (params.get("q") or [""])[0][:2000]
        result = analyze(q) if q.strip() else None
        self._send(render_html(result))


def cmd_check(args):
    global use_color
    if args.no_color:
        use_color = False
    text = " ".join(args.text).strip() if args.text else ""
    if not text and not sys.stdin.isatty():
        text = sys.stdin.read().strip()
    if not text:
        print("usage: phishguard.py check \"<url or message>\"", file=sys.stderr)
        sys.exit(2)
    if args.no_ai:
        os.environ["PHISHGUARD_NO_AI"] = "1"
    result = analyze(text)
    print(render_text(result, as_json=args.json))
    sys.exit(1 if result["verdict"] == "PHISHING" else 0)


def cmd_web(args):
    port = int(os.environ.get("PORT") or args.port)
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"PhishGuard web demo → http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="Local-first phishing & scam link checker (zero deps, optional Ollama AI).",
    )
    sub = parser.add_subparsers(dest="command")

    p_check = sub.add_parser("check", help="scan a URL or message")
    p_check.add_argument("text", nargs="*", help="url or message to scan")
    p_check.add_argument("--no-ai", action="store_true", help="skip local LLM")
    p_check.add_argument("--json", action="store_true", help="machine-readable output")
    p_check.add_argument("--no-color", action="store_true")
    p_check.set_defaults(func=cmd_check)

    p_web = sub.add_parser("web", help="run the browser demo")
    p_web.add_argument("--port", type=int, default=8080)
    p_web.set_defaults(func=cmd_web)

    if len(sys.argv) > 1 and sys.argv[1] not in ("check", "web", "-h", "--help"):
        sys.argv.insert(1, "check")

    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        sys.exit(0)
    args.func(args)


if __name__ == "__main__":
    main()
