# Honeypot Hunter
**Pre-Flight Stunt-Double Browser Sandbox for AI Agents — Built on Vultr**

> **Vultr: Agent Rush Hackathon — Challenge 01: Blast Radius Zero**  
> **Live Studio:** [https://139.84.149.182.nip.io](https://139.84.149.182.nip.io) *(Vultr VC2 Ubuntu 24.04 · Bangalore · Let's Encrypt TLS)*  
> **AI Triage Engine:** Vultr Serverless Inference (`llama-3.3-70b-instruct` · ~2.1s latency)

---

## The Problem (In 2 Sentences)
AI browser agents have zero gut instinct: a fake Okta login, a page hiding invisible CSS prompt injections, and a real website all look like standard HTML. Waiting until an agent types a real API key or hits internal cloud metadata (`169.254.169.254`) means the breach already happened.

## What Honeypot Hunter Does
Before an AI agent (or human) opens an untrusted link, **Honeypot Hunter** visits it first inside a zero-secret disposable Chromium sandbox on **Vultr** (`0` secrets mounted, `512MB` RAM cap) and returns an **Ed25519 cryptographically signed verdict** in ~7.5 seconds:

* **1. Canary Credential Baiting + SSRF Wiretap:** Injects tracked fake credentials (`canary.<id>@vault-honeypot.internal`) into login forms. The millisecond the page tries to exfiltrate them or probe `169.254.169.254` / private IPs, the wiretap captures the packet and **aborts the socket in flight (`0 bytes` leaked)**.
* **2. Hidden Prompt-Injection Stripping:** Diffs computed CSS (`opacity: 0`, `font-size: 0px`, offscreen nodes) against raw DOM text to strip invisible agent-hijacking instructions before your LLM reads the page.
* **3. JS Memory Bomb Containment:** Supervises the Chromium process tree every 150ms (`512MB` RAM / `256MB` V8 heap cap) and fires an immediate `SIGKILL` + profile wipe on runaway scripts.
* **4. 0% False-Positive Abstention + Ed25519 Receipts:** Proves restraint on clean sites (`example.com` -> `SAFE_VERIFIED_ABSTENTION`) and signs SHA-256 hashes of all screenshots, wire packets, and timelines with an RFC 8032 Ed25519 key (verifiable via the live **1-Click Tamper Test**).

---

## How It Works in Practice

```text
[ AI Agent / User ] ──► POST /api/investigate {"url": "https://untrusted-link.example"}
                              │
                              ▼
             [ Honeypot Hunter on Vultr VC2 (139.84.149.182) ]
              ├─ 1. Pre-flight DNS/SSRF Gate (Blocks 169.254.169.254 & RFC1918)
              ├─ 2. Ephemeral Chromium Sandbox (0 secrets, 512MB cap, tini reaper)
              ├─ 3. Active Canary Baiting + CSS Visibility Diff + L7 Socket Wiretap
              ├─ 4. Vultr Serverless Inference (llama-3.3-70b-instruct triage in ~2.1s)
              └─ 5. RFC 8032 Ed25519 Signature + SHA-256 Evidence Bundle
                              │
                              ▼
             [ Signed Verdict ] ──► Agent blocks trap / SOC views live HUD / Browser Extension (Next)
```

1. **Agent Pre-Flight API (`POST /api/investigate`):** Agents call the API before visiting an external URL.
2. **Live SOC Studio (`https://139.84.149.182.nip.io`):** 1-click trap detonation, arbitrary live URL scanner, wiretap inspector, and live **Ed25519 Tamper Test**.
3. **Browser Extension (Next Step):** Routes unfamiliar Slack/email links through the Vultr stunt-double automatically in the background.

---

## Run Locally in 30 Seconds

```bash
git clone https://github.com/reachmeghanashyam-coder/honeypot-hunter.git && cd honeypot-hunter
pip install -r requirements.txt && playwright install chromium
pytest -v && uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

Open **`http://localhost:8000`** *(works out-of-the-box; set `VULTR_INFERENCE_API_KEY` in `.env` for live Vultr Serverless Inference).*

---

## Verified Boundaries & Technical Scope

| Capability | Verified Implementation | Scope Boundary |
| :--- | :--- | :--- |
| **Canary & SSRF Wiretap** | Injects `canary.<id>@vault-honeypot.internal` and aborts exfiltration + `169.254.169.254`/RFC1918 requests in flight. | Browser L7 network interception + pre-flight DNS resolution. |
| **Prompt-Injection Diff** | Strips hidden DOM nodes (`opacity:0`, `font-size:0`, `display:none`, offscreen, `aria-hidden`). | DOM/CSS layer; returns clean `sanitized_visible_text`. |
| **Sandbox Containment** | Non-root user (`investigator`), `no-new-privileges`, `init: true` (`tini`), `512MB` RAM cap, process-tree `SIGKILL`. | Container + browser process isolation on Vultr Ubuntu 24.04 VM. |
| **Ed25519 Attestation** | Signs SHA-256 digests of screenshots, wire payloads, timeline, and verdict (`POST /api/verify-signature`). | Verifiable in-browser via the **1-Click Tamper Test**. |

## License
MIT License. Built for the Vultr Agent Rush Hackathon 2026.
