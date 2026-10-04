# My friend almost got phished — so I built him a local AI bodyguard in one weekend

> 📅 DEV Weekend Challenge: **Build for a Friend** · Hacktoberfest 2026
> 🔗 Repo: https://github.com/shri7-lab/phishguard
> 🌐 Live demo: https://phishguard-oi4y.onrender.com

## Prize Categories

- **Best Use of Gemma** — `gemma3:2b` runs as the local AI second-opinion through Ollama
- **Best Use of Render** — the web demo is hosted on Render (link above)

---

Friday night, 11:47 PM. A friend forwards this on WhatsApp:

> "URGENT: Your IES College fee payment FAILED. Registration will be cancelled in 24 hours. Re-verify now: `bit.ly/fee-refund-2026`"

He was about to tap it. He's not careless with tech, he was just tired. And honestly that message would fool half our college group — it *looks* official.

I told him to send it to me first. Then I opened a couple of those "is this link safe?" websites... and stopped midway. Wait — I'm about to paste a *suspicious* link into some random cloud service? Now their server has the link, my query, everything. That's like a cop announcing his own address during a raid. Anyway.

Closed those tabs, told him: give me the weekend.

**PhishGuard — a phishing checker that doesn't phone home.**

![PhishGuard CLI — phishing verdict with score breakdown](https://raw.githubusercontent.com/shri7-lab/phishguard/main/assets/terminal.png)

## What it actually does

Paste a URL, or dump the whole message — WhatsApp forward, SMS, Discord DM, whatever. You get one of three verdicts (`✅ SAFE` / `🟠 SUSPICIOUS` / `🔴 PHISHING`) plus the maths behind it:

```
Verdict : 🔴 PHISHING  (score 75/100)
  link: http://192.168.0.1/bank-login-verify?otp=update-account
    +35p  raw IP address instead of a real domain
    +10p  plain HTTP — no encryption
    +30p  scare/urgency keywords: account, bank, login, otp, update, verify
```

No black box. Every point maps to a reason an actual human can read.

Scams in 2026 aren't just dirty URLs anymore though, so the scanner handles those too — and all of this runs offline, zero network calls:

- brands being used by domains that don't own them — `paypal-secure.tk`, `g00gle-login.com` (digits get normalized, `g00gle` → `google`, and Cyrillic look-alikes like `gооgle` get caught too)
- a base64 or hex blob sitting in the message that decodes to a hidden `http://...`
- fake sender identities — `PayPal Security <secure@paypa1-support.xyz>`, where the display name and the actual domain disagree

```
  message:
    +30p  hidden URL inside an encoded blob → http://evil.test/login
    +25p  display name says 'PayPal Security' but sender is paypa1-support.xyz
```

## Rules + a local LLM, layered

I didn't want to pick one. Blocklists alone miss brand-new scams. LLMs alone hallucinate, and they want your data sitting on someone else's computer. So it runs both:

```
 message ──► Link extractor ──► Heuristic engine (deterministic, ~15 signals)
                    │
                    └──────────► Local LLM second opinion (Ollama + gemma3:2b, offline)
                                        │
                                  final verdict (worst of both wins)
```

The AI part runs on my laptop through [Ollama](https://ollama.com) using an open-weight model (`gemma3:2b`). No API key, no telemetry, nothing leaves the machine.

Best part — they disagree sometimes, and that's useful. A forward that reads fine but hides a `.top` shortener: rules catch it. A message with zero suspicious keywords that just *feels* wrong ("your SIM will be deactivated, call 198 now"): rules give it 0/100, the model straight up says PHISHING. That exact example is in "Try it yourself" below, try it yourself.

The AI call, the whole thing, is honestly just this:

```python
def ask_ollama(text):
    body = json.dumps({"model": "gemma3:2b", "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(OLLAMA + "/api/generate", data=body, ...)
    with urllib.request.urlopen(req, timeout=45) as resp:
        return json.loads(resp.read().decode())["response"]
```

If Ollama isn't running, it tells you and falls back to the rules. No pretending to be smarter than it is.

## Why open innovation matters (the prompt asked, so here's my honest answer)

The whole product promise is *"your data never leaves your machine."* That promise only exists because the model underneath is open and local. Swap it for a closed API — even a good one — and PhishGuard becomes the exact thing I was warning my friend about: paste your suspicious thing here and trust us.

Open also means readable. Those ~15 scoring rules live in one Python file. Someone can disagree with rule #7 tonight and send a PR tomorrow. Try doing that with a fraud score buried inside a banking app.

And practically — my friend runs it with the Wi-Fi off. For a security tool, that kind of matters.

## Try it yourself

No install needed (heuristic engine, hosted on Render):

👉 https://phishguard-oi4y.onrender.com

With the AI — about 30 seconds of setup. This is the part the hosted demo deliberately skips, because your suspicious link shouldn't be travelling anywhere:

```bash
git clone https://github.com/shri7-lab/phishguard.git && cd phishguard
brew install ollama && ollama pull gemma3:2b    # Linux: curl -fsSL https://ollama.com/install.sh | sh
python3 phishguard.py check "Your SIM will be deactivated today. Call 198 to re-validate"
```

```
Verdict : 🔴 PHISHING  (score 0/100)
note    : no link/payload found — local AI weighed in on the text
  AI: PHISHING — SIM deactivation threat and urgency to call a number
  are not genuine, potentially suspicious activity.
```

The rules scored that message 0/100 — SAFE. The open-weight model caught it. That one example is basically the entire architecture.

Tests are there too: `python3 -m unittest discover -s tests` → `Ran 12 tests ... OK`. Yeah, unit tests in a weekend project — I changed a score value at 1 AM, broke two verdicts without noticing, and then the suite earned its place permanently.

## Zero dependencies (this was non-negotiable)

`phishguard.py` is one file, Python standard library only. No pip install, no virtualenv drama, no node_modules. My friend — the same guy who almost clicked the link — ran exactly this much:

```bash
git clone https://github.com/shri7-lab/phishguard.git
python3 phishguard.py check "bit.ly/fee-refund-2026"
```

There's a browser mode as well, for people who won't open a terminal:

```bash
python3 phishguard.py web   # localhost:8080
```

![PhishGuard browser demo — paste link, get an explained verdict](https://raw.githubusercontent.com/shri7-lab/phishguard/main/assets/web-result.png)

I handed it over to him on Sunday over a screen-share. He pasted that same `bit.ly/fee-refund-2026` forward into it, got `🟠 SUSPICIOUS — link shortener hides the real destination`, and said:

> "Bhai, ab click karne se pehle yahi check karunga — screenshot wali baat samajh aa gayi."

That one line made the whole weekend worth it.

## How the weekend actually went

Saturday morning: link extractor plus the scoring rules (full table is in the README). Saturday night turned into the Ollama integration — making the JSON reply behave took longer than the scoring engine did, I'm not joking. Sunday was the web UI, the README and this post, and testing on every scam message sitting in my WhatsApp archive (yes, I have a folder for them, yes, it's depressing).

What surprised me: almost all the advice online is "check the lock icon, check the spelling." Nobody does that at 11 PM. People just need a second pair of eyes that answers in 2 seconds.

## Things I'm leaving on the table (steal these)

- QR-code decoding for those "scan to pay" scam posters
- Indian UPI / vishing number patterns — we get these daily
- A browser extension wrapper
- A pre-commit hook so you can't push your own API keys by accident

---

I'm 18, first year CSE, and I spend nights on Hack The Box instead of Instagram. If PhishGuard saves even one person from a "fee refund" scam, that beats any star count on GitHub.

Try it, break it, send a PR. Happy Hacktoberfest 🎃

`#hf26challenge` `#weekendchallenge` `#ai`
