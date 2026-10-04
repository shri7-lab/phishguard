# My friend almost got phished — so I built him a local AI bodyguard in one weekend

> 🏷️ Tags: `hf26challenge` `devchallenge` `weekendchallenge` `security` `ai` `opensource` `python`
> 📅 DEV Weekend Challenge: **Build for a Friend** · Hacktoberfest 2026
> 🔗 Repo: https://github.com/shri7-lab/phishguard
> 🌐 **Live demo:** https://phishguard-oi4y.onrender.com

## Prize Categories

- **Best Use of Gemma** — `gemma3:2b` (Google's open-weight model) runs the local AI second-opinion via Ollama
- **Best Use of Render** — the PhishGuard web demo is hosted on Render (link above)

---

**Friday night, 11:47 PM.** My friend's WhatsApp lights up:

> ⚠️ *"Your IES College fee payment FAILED. Within 24 hrs your registration will be cancelled.
> Re-verify now: `bit.ly/fee-refund-2026`"*

He was about to tap it. He's not "bad with tech" — he's just tired, it's late, and the message
sounds *official*. That's exactly how phishing works. It doesn't hack your computer. **It hacks
your 3 AM brain.**

I asked him to send me the link first. I opened three different "is this safe?" websites… and
then stopped. Wait — I'm pasting a **suspicious link into a random cloud service?** Now
*someone else's server* has the link, my query, and a timestamp. Security people call this a
bad habit. I call it Tuesday.

So the friend request became a weekend project:

**PhishGuard — a phishing checker that never phones home.**

![PhishGuard CLI — phishing verdict with score breakdown](https://raw.githubusercontent.com/shri7-lab/phishguard/main/assets/terminal.png)

## What it actually does

Paste any URL or full message (WhatsApp forward, SMS, Discord DM). PhishGuard gives you:

1. A verdict — `✅ SAFE` / `🟠 SUSPICIOUS` / `🔴 PHISHING`
2. **A score breakdown**, not a black box:

```
Verdict : 🔴 PHISHING  (score 75/100)
  link: http://192.168.0.1/bank-login-verify?otp=update-account
    +35p  raw IP address instead of a real domain
    +10p  plain HTTP — no encryption
    +30p  scare/urgency keywords: account, bank, login, otp, update, verify
```

No mystery score. Every point has a reason your friend can *understand*.

And because phishing in 2026 doesn't stop at shady URLs, the scanner also catches the
sneaky ones — all **offline, zero network calls**:

- **Brand spoofing:** `paypal-secure.tk`, `g00gle-login.com` → flagged for using a brand
  they don't own (with digit + Cyrillic look-alike normalization, `g00gle` → `google`)
- **Hidden URLs:** base64/hex blobs in a message that decode to `http://evil...`
- **Email spoofing:** `PayPal Security <secure@paypa1-support.xyz>` → display name and
  sender domain disagree

```
  message:
    +30p  hidden URL inside an encoded blob → http://evil.test/login
    +25p  display name says 'PayPal Security' but sender is paypa1-support.xyz
```

## The architecture: rules + open-source AI

Pure blocklists miss novel scams. Pure LLMs hallucinate and need your data to leave the
machine. PhishGuard uses both, layered:

```
 message ──► Link extractor ──► Heuristic engine (deterministic, ~15 signals)
                    │
                    └──────────► Local LLM second opinion (Ollama + gemma3:2b, 100% offline)
                                        │
                                  final verdict (worst of both wins)
```

**The AI core is fully open-source and runs on my laptop.** [Ollama](https://ollama.com)
serves open-weight models like `gemma3:2b` over a local HTTP API — no API key, no telemetry,
no "your data may be used to improve our services."

The funniest part: the AI and the rules **disagree sometimes**, and that's a feature. When a
WhatsApp forward *reads* legitimate but contains a shortened URL to a `.top` domain, the rules
catch what the language model politely overlooks. When the message is pure social engineering
with no bad keywords, the model catches what regex can't.

```python
def ask_ollama(text):
    body = json.dumps({"model": "gemma3:2b", "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(OLLAMA + "/api/generate", data=body, ...)
    with urllib.request.urlopen(req, timeout=12) as resp:
        return json.loads(resp.read().decode())["response"]
```

If Ollama isn't running, PhishGuard says so and falls back to heuristics — it never
pretends to be smarter than it is.

## Why open innovation matters here

This tool's whole promise is *"your data never leaves your machine."* That promise is only
possible because the AI underneath is **open and local**: an open-weight model (Gemma) served
by an open-source runtime (Ollama) inside a zero-dependency script. Swap the closed version of
this — paste the suspicious link into a hosted "AI scam checker" — and you've just handed a
stranger the exact thing you were suspicious about, plus your query history.

Open also means **auditable**: anyone can read the 15 scoring rules, disagree with one, and
send a PR. Try that with a proprietary fraud score. And it means my friend can run it on a
laptop with the Wi-Fi off — which, for a security tool, is the point.

## Zero dependencies, on purpose

`phishguard.py` is **one file, Python standard library only.** No `pip install`, no virtualenv
drama, no `node_modules` of doom. My friend — the same one who almost clicked — ran it with:

```bash
git clone https://github.com/shri7-lab/phishguard.git
python3 phishguard.py check "bit.ly/fee-refund-2026"
```

There's also a browser mode for people who won't open a terminal:

```bash
python3 phishguard.py web   # dark-themed UI on localhost:8080
```

![PhishGuard browser demo — paste link, get an explained verdict](https://raw.githubusercontent.com/shri7-lab/phishguard/main/assets/web-result.png)

## The build, honestly

- **Saturday morning:** link extractor + heuristic scoring (the 15 signals table in the README)
- **Saturday night:** Ollama integration + graceful degradation
- **Sunday:** web UI, README, and this article — plus testing on every scam link I could find
  in my WhatsApp archive (yes, I have a folder. yes, it's depressing.)

What surprised me: **most phishing detection advice online is "look for the lock icon and check
the spelling."** My friends don't do that at 11 PM. They need a *second pair of eyes that
answers in 2 seconds* — not a lecture.

Everything above runs on **11 stdlib `unittest` tests** (`python3 -m unittest discover -s tests`)
— scoring thresholds, homoglyph spoofs, hidden blobs, email fakes. When I changed a score
value at 1 AM, the suite caught the regression before I did. For a "one file, no dependencies"
tool, tests felt like the grown-up thing to have.

## What's next (steal these ideas if you want)

- Homoglyph detection (visual similarity to real brands)
- QR-code scam poster decoding
- Indian UPI/vishing number patterns
- A `pre-commit` hook so you can't even commit your own credentials by accident

---

I'm a first-year CSE student who spends nights on Hack The Box instead of Instagram.
If PhishGuard saves one friend from a "fee refund" scam, it beat every star count on GitHub.

**Try it, break it, send a PR. Happy Hacktoberfest! 🎃**

`#hf26challenge` `#weekendchallenge` `#ai` `#opensource` `#security`

---

### 📝 Publishing checklist (edit before submitting on DEV)

- [ ] Replace "My friend" details if you want the real first name
- [x] Screenshots inserted (terminal + web demo, auto-hosted from repo)
- [ ] Optional GIF: record paste → verdict (free tools: **Kap** on Mac, **ScreenToGif** on Windows, `asciinema` + `agg` on Linux)
- [ ] Cover image: use `assets/terminal.png`
- [ ] On DEV: paste article, add tags `hf26challenge` `devchallenge` `weekendchallenge` (+ `security`, `ai`, `opensource`)
- [ ] Link the repo in the first 3 lines
- [ ] Submit at the challenge page before the deadline
