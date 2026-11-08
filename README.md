# Honeypot Hunter
**Pre-Flight Stunt-Double Browser Sandbox for AI Agents & Security Teams — Built on Vultr**

> **Vultr: Agent Rush Hackathon 2026 — Challenge 01: Blast Radius Zero**  
> **Live Production Studio:** [https://139.84.149.182.nip.io](https://139.84.149.182.nip.io) *(Vultr VC2 Ubuntu 24.04 LTS · Bangalore · Verified Let's Encrypt TLS)*  
> **Cognitive Triage Engine:** Vultr Serverless Inference (`llama-3.3-70b-instruct` via `api.vultrinference.com`)

---

## Why We Built This

When you give an autonomous browser agent (Claude Computer Use, OpenAI Operator, Playwright/LangChain agents) access to the open web, it has no gut instinct. To an LLM agent, a spoofed Okta SSO page, a supplier portal laced with invisible CSS prompt injections, and a real login screen all look like valid HTML forms.

Static URL blocklists miss freshly spun-up domains, and waiting until an agent leaks a real session token or hits internal cloud metadata (`169.254.169.254`) means the breach already happened.

We built **Honeypot Hunter** to act as an **active pre-flight stunt-double browser**. Before an AI agent—or a human clicking an unfamiliar link—touches an untrusted URL with real credentials or context, Honeypot Hunter opens that URL inside a zero-secret disposable Chromium sandbox on Vultr, actively interacts with the page to force hidden traps to show their hand, and returns an **RFC 8032 Ed25519 cryptographically signed verdict** in ~7.5 seconds.

---

## What the Stunt-Double Actually Catches (The 4 Core Capabilities)

Unlike a passive URL scanner or a simple phishing checker, Honeypot Hunter actively probes four distinct classes of web attacks inside an isolated sandbox (`0` host secrets mounted, `512MB` RAM ceiling, `256MB` V8 heap cap, `tini` PID reaper):

1. **Credential-Harvesting Phishing & Cloud Metadata SSRF (`169.254.169.254`)**
   When the stunt-double finds a login or credential form, it doesn't just screenshot it—it generates a run-specific **synthetic canary credential** (`canary.<run_id>@vault-honeypot.internal`), types it into the inputs, and submits the form while wiretapping every outbound network frame. The exact millisecond the page tries to POST that canary token to an external drop server—or probe AWS/Vultr link-local metadata (`169.254.169.254`) or RFC1918 private networks—the wiretap captures the raw payload as forensic proof and **aborts the socket in flight (`0 bytes` leave the host)**.
2. **Invisible DOM Prompt-Injection Stripping**
   Pages targeting AI agents often hide malicious system instructions (`IGNORE ALL PREVIOUS INSTRUCTIONS...`) inside invisible DOM nodes (`opacity: 0`, `font-size: 0px`, `display: none`, `aria-hidden="true"`, or off-screen coordinates like `left: -9999px`). Honeypot Hunter diffs computed CSS styles against raw DOM text across every element, catches the hidden payload, and strips it out so a downstream LLM only receives clean, visible text.
3. **Runaway JavaScript Memory & CPU Bomb Containment (`SIGKILL` Supervisor)**
   Hostile pages frequently use infinite allocation loops or obfuscated `eval()` / `atob()` payloads to hang headless agent workers. Our async resource supervisor polls the entire Chromium process tree every 150ms; the moment a page trips the memory or execution ceiling, the supervisor fires a deterministic `SIGKILL` across all child PIDs and wipes the temporary profile directory clean.
4. **0% False-Positive Verifiable Abstention + Ed25519 Signed Evidence**
   A security tool that flags every website as dangerous is useless in production. On clean live websites (e.g., `https://example.com`), Honeypot Hunter proves restraint (`SAFE_VERIFIED_ABSTENTION` with `0` false alerts). Every single run—whether hostile or clean—bundles the SHA-256 hashes of the captured viewport frames, wiretapped network requests, and event timeline into canonical JSON and signs it with an **asymmetric RFC 8032 Ed25519 private key**. Anyone can click the **Tamper Test** button in the live UI to flip a single byte of the report and watch client-side verification immediately flag the forgery.

---

## How It Fits Into Real Workflows

```
[ 1. Pre-Flight Agent API (MCP / REST) ]
       │  AI Agent calls POST /api/investigate {"url": "https://untrusted-link.example"}
       ▼
[ 2. Honeypot Hunter Sandbox on Vultr Cloud Compute (139.84.149.182) ]
       ├──► Pre-flight DNS/SSRF Gate: Blocks 169.254.169.254, loopback, RFC1918 & IPv6-mapped local IPs
       ├──► Ephemeral Chromium Stunt-Double: Spawns clean browser profile (0 secrets, 512MB RAM cap)
       ├──► DOM Visibility Diff: Extracts hidden CSS prompt injections (opacity:0 / offscreen)
       ├──► Active Canary Baiting: Injects synthetic canary credentials & submits suspect forms
       ├──► L7 Egress Wiretap: Captures exfiltration packets & aborts outbound sockets in flight
       ├──► Vultr Serverless Inference: llama-3.3-70b-instruct synthesizes forensic triage (~2.1s)
       └──► Ed25519 Attestation: Signs SHA-256 digest of screenshots + wire captures + timeline
       │
       ▼
[ 3. Verifiable Output ]
       ├──► For Autonomous Agents: JSON verdict + sanitized text + Ed25519 receipt
       ├──► For Security Analysts & Judges: Live 100vh SOC Command Studio (https://139.84.149.182.nip.io)
       └──► Next Step (Browser Extension): Intercepts Slack/email link clicks automatically in the background
```

* **For AI Agents (`POST /api/investigate`):** Works as a drop-in pre-flight gate before an agent navigates to an external URL. If the verdict comes back `HOSTILE_CONTAINED`, the agent never visits the site with real credentials. If the site had hidden prompt injections, the agent reads the `sanitized_visible_text` field instead of raw HTML.
* **For Security Analysts & Hackathon Judges (`https://139.84.149.182.nip.io`):** A zero-scroll `100vh` SOC Command Studio where you can detonate live traps in one click, test any arbitrary public URL on the internet, inspect the intercepted wire packets, and run the live **Ed25519 Tamper Test**.
* **Where We're Taking It Next (Enterprise Browser Extension):** Nobody wants to manually copy-paste every link into a dashboard all day. Because the entire detonation engine already runs behind a stateless API (`POST /api/investigate`), the natural human-facing wrapper is a lightweight Chrome/Brave extension that automatically routes unfamiliar links clicked in Slack or email through the Vultr stunt-double in the background.

---

## Quickstart: Run Locally in 30 Seconds

You can clone the repo and run the full automated test suite (8 end-to-end tests covering SSRF blocking, credential trap detonation, prompt injection stripping, memory bomb teardown, clean-site abstention, and Ed25519 tamper detection) in three commands:

```bash
git clone https://github.com/reachmeghanashyam-coder/honeypot-hunter.git && cd honeypot-hunter
pip install -r requirements.txt && playwright install chromium
pytest -v && uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

Then open **`http://localhost:8000`** in your browser.  
*(Runs out-of-the-box with zero configuration; add `VULTR_INFERENCE_API_KEY` to `.env` to enable live synthesis via Vultr Serverless Inference).*

---

## How Vultr Powers the Stack

| Layer | Vultr Service | Role in Honeypot Hunter |
| :--- | :--- | :--- |
| **Sandbox & Control Plane** | **Vultr Cloud Compute (VC2 Ubuntu 24.04 LTS)** | Hosts the FastAPI control plane, Caddy automatic TLS reverse proxy, and isolated Docker container (`init: true`, `512MB` memory limit, `pids_limit: 256`) at `139.84.149.182`. |
| **Cognitive Forensic Triage** | **Vultr Serverless Inference (`llama-3.3-70b-instruct`)** | Synthesizes raw DOM diffs, wiretapped HTTP payloads, and script signals into a structured threat classification (`MITRE ATT&CK` mapping + remediation actions) via `https://api.vultrinference.com/v1/chat/completions` in ~2.1 seconds. |

---

## Engineering Honesty & Verified Boundaries

We believe security tools should state exactly what they enforce and where their boundaries sit:

| Capability | What Is Verified in Code & Production | Honest Scope / Boundary |
| :--- | :--- | :--- |
| **Canary Credential Wiretap** | Injects unique `canary.<id>@vault-honeypot.internal` tokens into forms and aborts outbound requests carrying the token or targeting attacker collectors. | Interception runs at the browser network layer (Playwright request routing). For native binary execution outside Chromium, pair with an OS-level egress firewall. |
| **DOM Prompt-Injection Filter** | Compares computed CSS visibility (`opacity`, `font-size`, `display`, `visibility`, offscreen coordinates, `aria-hidden`) against raw text to strip hidden instructions. | Catches CSS/DOM-hidden prompt injections; does not claim to defeat steganographic image prompts without a vision pass. |
| **Pre-Flight SSRF & Metadata Guard** | Resolves DNS `A`/`AAAA` records pre-flight and blocks `169.254.169.254`, `127.0.0.0/8`, RFC1918 private subnets, CGNAT, and IPv4-mapped IPv6 addresses. | Protects both pre-flight resolution and in-browser sub-requests; full sub-second DNS-rebinding immunity on untrusted networks requires an external forward proxy. |
| **Process & Memory Containment** | Enforces non-root execution (`investigator`), `no-new-privileges: true`, `tini` zombie reaping, `512MB` container ceiling, and process-tree `SIGKILL` + profile wipe on every run. | Container and browser-process sandbox; not a hardware hypervisor microVM (e.g., Firecracker). |
| **Ed25519 Cryptographic Receipts** | Signs canonical JSON binding SHA-256 digests of viewport screenshots, wire captures, timeline, and verdict using RFC 8032 Ed25519 (`POST /api/verify-signature`). | Proves cryptographic integrity and origin authenticity from the Vultr node; verified live via the in-browser 1-click Tamper Test. |
| **End-to-End Speed** | Measured across live runs on `https://139.84.149.182.nip.io`. | Completes full browser detonation, Vultr `llama-3.3-70b-instruct` inference, and Ed25519 signing in **~7.5 seconds** on average. |

---

## Deploying to Your Own Vultr VM

```bash
export VULTR_INFERENCE_API_KEY="your_vultr_serverless_inference_key"
bash deploy_vultr.sh
```

## License
MIT License. Built for the Vultr Agent Rush Hackathon 2026.
