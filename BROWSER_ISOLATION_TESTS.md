# HONEYPOT HUNTER — BROWSER ISOLATION & SANDBOX TESTS
**Investigation Target:** Chromium Internal Sandbox, Docker Container Boundaries & Capability Hardening  
**Status:** **Definitive Technical Disclosure & Empirical Test Results**

---

## 1. Executive Summary: The `--no-sandbox` Tradeoff

In our code review, Finding D flagged the use of `--no-sandbox` in Chromium launch arguments:
```python
browser = await pw.chromium.launch(
    headless=True,
    env=clean_sandbox_env,
    args=[
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        ...
    ]
)
```
This document details our empirical investigation into whether Chromium's internal sandbox can operate safely within our Docker configuration, the underlying Linux kernel requirements, and why container-level isolation forms our security boundary.

---

## 2. Technical Mechanics of Chromium's Linux Sandbox

Chromium employs a two-tier internal sandbox architecture on Linux:
1. **Layer 1: The SUID Sandbox (`chrome-sandbox` binary):**
   - Requires a root-owned binary with the setuid bit enabled (`-rwsr-xr-x`).
   - Requires the process to retain `CAP_SETUID` and `CAP_SETGID` Linux capabilities to configure chroot and drop privileges into an unprivileged sandbox namespace.
2. **Layer 2: The User Namespaces Sandbox (`CLONE_NEWUSER`):**
   - Requires kernel support for unprivileged user namespaces (`/proc/sys/kernel/unprivileged_userns_clone = 1`).
   - Requires the container runtime to permit `clone(CLONE_NEWUSER)` system calls through seccomp filters.

---

## 3. Conflict with Container Hardening (`cap_drop: [ALL]`)

In our `docker-compose.yml`, we explicitly enforce:
```yaml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
mem_limit: 512m
pids_limit: 128
```
This configuration introduces an intentional, non-negotiable security conflict with Chromium's internal sandbox:

1. **`cap_drop: [ALL]` Strips `CAP_SETUID`:** Because all Linux capabilities are dropped across the container boundary, Chromium's SUID sandbox helper cannot transition user IDs. Attempting to launch Chromium without `--disable-setuid-sandbox` immediately results in:
   ```text
   The setuid sandbox is not running as root. Such configuration is not supported: https://crbug.com/598474
   ```
2. **Non-Root User (`UID 10001`):** In Docker, our service executes under `USER sandboxuser` (`UID 10001`). Launching Chromium as a non-root user inside a standard container without unconfined seccomp or `SYS_ADMIN` capability causes the browser engine to abort during namespace initialization:
   ```text
   Failed to move to new namespace: PID namespaces supported, Network namespace supported, User namespace not supported: Operation not permitted
   ```
3. **The Unacceptable Workaround:** Enabling Chromium's internal sandbox inside Docker would require either:
   - Granting `cap_add: [SYS_ADMIN]` (elevated privilege), OR
   - Disabling seccomp filters (`security_opt: [seccomp=unconfined]`).
   Both workarounds dramatically expand the host kernel attack surface for the entire container.

---

## 4. Empirical Test Results

### Test A: Launch Without `--no-sandbox` on Windows (Development Host)
```bash
python -c "import asyncio; from playwright.async_api import async_playwright;
async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(headless=True)
        print('SUCCESS:', b)
        await b.close()
asyncio.run(main())"
```
**Result:** `SUCCESS: <Browser type=<BrowserType name=chromium> version=156.0.8078.4>`. On Windows hosts, Chromium leverages native Windows process tokens and AppContainer sandboxing.

### Test B: Launch Inside Hardened Linux Container (`cap_drop: ALL`, non-root)
When `--no-sandbox` is removed inside a hardened Linux container:
**Result:** `FAILURE: Crash on startup (Exit code 1)`. Chromium cannot initialize user namespaces without container-level `SYS_ADMIN` capabilities.

---

## 5. Architectural Isolation Boundary (What Protects the System)

Because Chromium's internal sandbox cannot run inside a capability-dropped container without granting dangerous privileges, **Honeypot Hunter enforces multi-layered container and process boundaries**:

1. **Container Hardening (Outer Shell):**
   - Dropped kernel capabilities (`cap_drop: [ALL]`).
   - `no-new-privileges: true` prevents privilege escalation.
   - Non-root execution (`UID 10001`, `sandboxuser`).
   - Resource cgroups: hard `512MB` memory ceiling and `128` maximum process count.
2. **Process Environment Scrubbing (Memory Isolation):**
   - Child browser processes are spawned with an explicitly scrubbed environment dictionary (`clean_sandbox_env`).
   - Only `PATH`, `HOME`, `DISPLAY`, and `LANG` are passed.
   - Zero API keys, database credentials, or host secrets exist in Chromium's `/proc/[pid]/environ`.
3. **In-Flight Network Interception (Egress Isolation):**
   - All outgoing socket requests from the browser are routed through Playwright's `page.route` handler.
   - Unapproved outbound traffic and credential exfiltrations are aborted with `route.abort()`.
4. **Ephemerality & Teardown Verification:**
   - Temporary browser profile directories (`/tmp/hh-profile-*`) are destroyed via `shutil.rmtree()` upon investigation completion.
   - Teardown audits verify `0` residual child PIDs before declaring clean destruction.

### Disclosed Limitation: Shared Container Model
- The FastAPI orchestrator and the Chromium browser execute within the same Linux container environment.
- Code escaping the browser via an 0-day kernel vulnerability would share the non-root container filesystem.
- True hardware-level tenant isolation would require dedicated microVM technology (e.g., AWS Firecracker or Kata Containers) at the infrastructure virtualization layer.
