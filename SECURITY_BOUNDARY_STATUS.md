# HONEYPOT HUNTER — SECURITY BOUNDARY STATUS
**Document Version:** 1.0 (Definitive Truth-First Disclosure)  
**Target:** Vultr Agent Rush Hackathon — Challenge 01 (Blast Radius Zero)

---

## 1. Executive Security Posture

In accordance with rigorous adversarial audit standards, this document defines the exact boundaries, guarantees, and known architectural limitations of HONEYPOT HUNTER. We reject deceptive marketing claims and report the concrete technical mechanics of our containment implementation.

---

## 2. Boundary 1: SSRF & DNS Rebinding Protection

### Current Architecture
HONEYPOT HUNTER employs a two-tier network validation architecture:
1. **Pre-flight DNS & IP Range Validation (`backend/ssrf_guard.py`):**
   - Resolves target hostnames using `socket.getaddrinfo()`.
   - Rejects non-HTTP(S) schemes, unresolvable hosts, and all IP addresses falling within RFC 1918 (private subnets), RFC 3927 (link-local `169.254.0.0/16`), RFC 5735 (loopback `127.0.0.0/8`), and cloud metadata services.
2. **In-Flight Browser Interception (`backend/sandbox_runner.py`):**
   - Playwright route interception (`page.route("**/*")`) monitors all outgoing HTTP requests issued by the browser.
   - Any attempt to transmit data to an unapproved origin (e.g., cross-origin `POST` with credentials) is explicitly aborted with `route.abort()`.

### Boundary Limitation & Disclosure (The TOCTOU Gap)
- **Time-of-Check / Time-of-Use (TOCTOU):** Pre-flight DNS validation occurs in Python space prior to launching the browser connection. A sophisticated attacker employing sub-second DNS rebinding (low TTL switching from a public IP to `127.0.0.1` between pre-flight check and browser socket connect) could potentially cause the browser's internal network stack to resolve the second IP address.
- **Truthful Claim:** HONEYPOT HUNTER provides strong protection against direct SSRF, metadata access, and common credential harvesting channels. It **does not claim complete cryptographic DNS rebinding immunity**, which would require a kernel-level DNS-pinning proxy or network namespace egress filter mapping the socket directly to the validated IP.

---

## 3. Boundary 2: Sandbox Process vs. Hypervisor Isolation

### Current Architecture
- **Host Infrastructure:** Linux Compute Instance running on Vultr Cloud Compute (`139.84.149.182` / `https://139.84.149.182.nip.io`).
- **Containerization:** Docker container deployed with:
  - Non-root user (`USER sandboxuser`, UID 10001)
  - `security_opt: ["no-new-privileges:true"]`
  - `cap_drop: ["ALL"]` (all Linux kernel capabilities dropped)
  - Strict resource cgroups: `512MB` memory ceiling, `128` PID limit
  - Process-level environment isolation: The Playwright Chromium process is launched with a stripped environment dictionary (`PATH`, `HOME`, `DISPLAY`, `LANG`), explicitly removing `VULTR_INFERENCE_API_KEY` and host tokens from `/proc/[pid]/environ`.

### Boundary Limitation & Disclosure (Shared Container Execution)
- **Shared Kernel & Container Environment:** The FastAPI orchestrator and the Playwright headless browser execute within the same Linux container runtime.
- **Kernel Attack Surface:** Because both processes share the host Linux kernel, an 0-day kernel privilege escalation or container breakout vulnerability could theoretically allow code escaping the browser to interact with the container filesystem.
- **Distinction from MicroVMs:** HONEYPOT HUNTER uses **container-level cgroups and capability dropping**, NOT a hardware-isolated microVM (such as AWS Firecracker) or user-space kernel (such as Google gVisor).
- **Truthful Claim:** We provide effective multi-layered process containment, memory quotas, and secret stripping suitable for automated web threat analysis, while acknowledging that dedicated multi-tenant isolation in enterprise production would benefit from microVM isolation at the virtualization layer.

---

## 4. Boundary 3: Cryptographic Evidence Integrity (Ed25519 & HMAC)

### Current Architecture
Upon conclusion of every investigation run, HONEYPOT HUNTER generates a cryptographic evidence receipt:
1. **Asymmetric Signing:** Ed25519 (RFC 8032) using an ed25519 private key initialized at server boot in the host control-plane memory. The corresponding public key is exposed at `/api/public-key`.
2. **Canonical Manifest Digest:** The signed payload is constructed deterministically via RFC-compliant JSON canonicalization (`sort_keys=True`, `separators=(',', ':')`):
   ```json
   {
     "run_id": "hh-7a58dd65d9",
     "target_url": "https://example.com",
     "verdict": "HOSTILE_CONTAINED",
     "risk_score": 85,
     "containment_triggered": true,
     "requests_aborted_count": 1,
     "exfiltration_attempts_count": 1,
     "prompt_injections_count": 0,
     "screenshot_sha256": "4a7b...",
     "intercepted_payload_sha256": "c3f1...",
     "timeline_sha256": "e9a2...",
     "sandbox_destroyed": true,
     "secrets_mounted": 0
   }
   ```
3. **Evidence Artifact Binding:** The SHA-256 hashes of the full-page screenshot, intercepted exfiltration payload, and chronological execution timeline are embedded directly within the signed manifest before the signature is computed.

### What This Mathematically Proves
- **Immutability of Evidence:** Proves conclusively that neither the verdict, the score, the containment metrics, nor the associated artifacts have been altered or tampered with since the host control-plane signed them.
- **Offline Zero-Trust Verifiability:** An evaluator or external auditor can verify the signature using standard cryptographic libraries without contacting or trusting the running server.
- **Tamper Detection:** Altering even a single byte of the intercepted payload or changing the verdict immediately causes signature verification to fail.

### What This Does NOT Prove
- **Real-World Ground Truth:** An Ed25519 digital signature proves data integrity and origin authenticity relative to the signing key. It does not provide external physical proof that the web server visited by the sandbox was genuinely owned by a malicious third party or that the events recorded were not simulated. It cryptographically binds what the sensor observed and decided.
