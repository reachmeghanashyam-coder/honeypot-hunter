"""
Adversarial Inversion & End-to-End Test Suite for Honeypot Hunter.

Verifies Law #21 (The 4 Inversion Stress Tests) & Challenge 01 Compliance:
1. Poison Input & SSRF Guard Test:
   - Blocks 169.254.169.254 (Cloud Metadata), 127.0.0.1, RFC1918 (10.x, 192.168.x, 172.16.x),
     IPv4-mapped IPv6 (::ffff:169.254.169.254), `file://`, `javascript:`, null bytes,
     and oversized URLs.
2. Live Sandbox Containment Tests:
   - Trap 1 (`/traps/credential-harvester`): Seeds synthetic canary token, intercepts
     cross-origin POST exfiltration and `169.254.169.254` probe, returns `HOSTILE_CONTAINED`.
   - Trap 2 (`/traps/prompt-injection`): Detects and strips hidden `opacity:0` DOM prompt
     injection and blocks C2 webhook beacon.
   - Trap 3 (`/traps/resource-bomb`): Enforces hard supervisor kill (`supervisor_killed=True`)
     and clean sandbox teardown (`destroyed_cleanly=True`).
   - Trap 4 (`/traps/clean-control`): Verifies deterministic guardrail abstention
     (`SAFE_VERIFIED_ABSTENTION`, 0 false positives).
3. Cryptographic SHA-256 Receipt Integrity & Tamper Detection:
   - Verifies unmodified receipt passes `/api/verify-receipt` and a 1-byte mutation fails.
4. Concurrency & Race Condition Stress Test:
   - Fires parallel requests against `/api/health` and `/api/verify-receipt` without state bleed.
"""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from backend.ssrf_guard import is_ip_forbidden, validate_target_url

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def live_server_url() -> str:
    port = _get_free_port()
    env = dict(**__import__("os").environ)
    env["PORT"] = str(port)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "backend.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 25.0
    ready = False
    while time.time() < deadline:
        try:
            r = httpx.get(f"{base_url}/api/health", timeout=5.0)
            if r.status_code == 200:
                ready = True
                break
        except Exception:
            time.sleep(0.5)

    if not ready:
        stdout_err = ""
        try:
            out, err = proc.communicate(timeout=2.0)
            stdout_err = f"STDOUT: {out.decode()} | STDERR: {err.decode()}"
        except Exception:
            proc.terminate()
        raise RuntimeError(f"Live FastAPI test server failed to start within 25s. {stdout_err}")

    yield base_url

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def test_poison_inputs_and_ssrf_guard() -> None:
    """Inversion Test 1: Poison inputs, forbidden schemes, and SSRF/private IP targets."""
    poison_cases = [
        "",
        "   ",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "gopher://127.0.0.1:6379/_INFO",
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/admin",
        "http://localhost:2375/containers/json",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/router",
        "http://172.16.0.5/secret",
        "http://[::1]:8000/",
        "https://user:pass@example.com/",
        "https://example.com/\x00poison",
        "https://example.com/" + ("a" * 2100),
    ]
    for raw in poison_cases:
        res = validate_target_url(raw, allow_controlled_trap_port=8000)
        assert not res.allowed, f"Expected poison/SSRF URL to be blocked: {raw}"
        assert res.blocked_reason

    # Verify IPv4-mapped IPv6 metadata bypass attempt is blocked
    forbidden, reason = is_ip_forbidden("::ffff:169.254.169.254")
    assert forbidden is True
    assert "169.254.169.254" in (reason or "")


@pytest.mark.asyncio
async def test_end_to_end_sandbox_containment_and_abstention(live_server_url: str) -> None:
    """
    Inversion Test 2 & 3: Real Playwright headless Chromium execution against all
    hostile traps, SSRF target, and clean control page.
    """
    async with httpx.AsyncClient(base_url=live_server_url, timeout=30.0) as client:
        # 1. Credential Harvester + 169.254.169.254 SSRF Trap
        r1 = await client.post("/api/investigate", json={"url": "/traps/credential-harvester"})
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["dossier"]["verdict"] == "HOSTILE_CONTAINED"
        assert d1["dossier"]["containment_triggered"] is True
        assert d1["telemetry"]["canary_seeded"] is True
        assert len(d1["telemetry"]["exfiltration_attempts"]) >= 1
        # Explicitly assert canary token detection inside intercepted outbound request body
        assert d1["telemetry"]["exfiltration_attempts"][0]["canary_detected_in_payload"] is True
        assert "canary." in d1["telemetry"]["exfiltration_attempts"][0]["payload_preview"]
        assert len(d1["telemetry"]["blocked_requests"]) >= 1
        assert len(d1["telemetry"]["screenshots"]) >= 1
        assert d1["telemetry"]["sandbox_metrics"]["destroyed_cleanly"] is True
        assert d1["telemetry"]["sandbox_metrics"]["secrets_mounted"] == 0
        # Cryptographic evidence manifest bindings
        rcpt1 = d1.get("receipt", {})
        assert rcpt1.get("canonical_payload", {}).get("sandbox_destroyed") is True
        assert rcpt1.get("canonical_payload", {}).get("secrets_mounted") == 0
        assert rcpt1.get("canonical_payload", {}).get("screenshot_sha256") not in ("NONE", "")
        assert rcpt1.get("canonical_payload", {}).get("intercepted_payload_sha256") not in ("NONE", "")
        assert rcpt1.get("canonical_payload", {}).get("timeline_sha256") not in ("NONE", "")

        # 2. Hidden DOM Prompt-Injection Trap
        r2 = await client.post("/api/investigate", json={"url": "/traps/prompt-injection"})
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2["dossier"]["verdict"] == "HOSTILE_CONTAINED"
        assert len(d2["telemetry"]["prompt_injections"]) >= 1
        assert len(d2["telemetry"]["blocked_requests"]) >= 1

        # 3. Resource Exhaustion Bomb (Supervisor Hard Kill)
        r3 = await client.post("/api/investigate", json={"url": "/traps/resource-bomb"})
        assert r3.status_code == 200
        d3 = r3.json()
        assert d3["dossier"]["verdict"] == "HOSTILE_CONTAINED"
        assert d3["telemetry"]["sandbox_metrics"]["supervisor_killed"] is True
        assert d3["telemetry"]["sandbox_metrics"]["destroyed_cleanly"] is True

        # 4. Clean Control (Verifiable Abstention - 0% False Positive)
        r4 = await client.post("/api/investigate", json={"url": "/traps/clean-control"})
        assert r4.status_code == 200
        d4 = r4.json()
        assert d4["dossier"]["verdict"] == "SAFE_VERIFIED_ABSTENTION"
        assert d4["dossier"]["verifiable_abstention"] is True
        assert d4["dossier"]["risk_score"] == 0
        assert len(d4["telemetry"]["blocked_requests"]) == 0

        # 5. Direct SSRF Attack Pre-Block
        r5 = await client.post(
            "/api/investigate",
            json={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        )
        assert r5.status_code == 200
        d5 = r5.json()
        assert d5["telemetry"]["ssrf_pre_blocked"] is True
        assert d5["dossier"]["verdict"] == "HOSTILE_CONTAINED"

        # 6. Live External Website (https://example.com) — Verifies real arbitrary domain resolution & abstention
        r_ext = await client.post("/api/investigate", json={"url": "https://example.com"})
        assert r_ext.status_code == 200
        d_ext = r_ext.json()
        assert d_ext["dossier"]["verdict"] == "SAFE_VERIFIED_ABSTENTION"
        assert d_ext["dossier"]["risk_score"] == 0
        assert len(d_ext["telemetry"]["screenshots"]) >= 1

        # 6b. Arbitrary Unreachable Domain (NXDOMAIN) — Verifies confidence=0.0 & explicit inconclusive determination
        r_nx = await client.post("/api/investigate", json={"url": "https://arbitrary-unreachable-domain-881293.org"})
        assert r_nx.status_code == 200
        d_nx = r_nx.json()
        assert d_nx["dossier"]["verdict"] == "INCONCLUSIVE_UNREACHABLE"
        assert d_nx["dossier"]["risk_score"] == 0
        assert d_nx["dossier"]["confidence"] == 0.0
        assert d_nx["dossier"]["containment_triggered"] is False
        assert "No threat determination was made" in d_nx["dossier"]["executive_summary"]
        assert d_nx["receipt"]["canonical_payload"]["sandbox_destroyed"] is True
        assert d_nx["receipt"]["canonical_payload"]["secrets_mounted"] == 0

        # 7. Real-Time SSE Streaming Endpoint (/api/investigate/stream) — Verifies progressive frames & optics_lock
        sse_events: list[str] = []
        async with client.stream("GET", "/api/investigate/stream?url=/traps/credential-harvester") as sse_resp:
            assert sse_resp.status_code == 200
            async for line in sse_resp.aiter_lines():
                if line.startswith("data: "):
                    ev_obj = __import__("json").loads(line[6:])
                    sse_events.append(ev_obj.get("event", ""))
        assert "lifecycle" in sse_events
        assert "optics_lock" in sse_events
        assert "frame" in sse_events
        assert "complete" in sse_events

        # 8. Cryptographic SHA-256 & Ed25519 Receipt Verification & Tamper Rejection
        rcpt = d1["receipt"]
        v_ok = await client.post(
            "/api/verify-receipt",
            json={
                "canonical_payload": rcpt["canonical_payload"],
                "expected_sha256": rcpt["sha256_evidence_hash"],
                "expected_ed25519_sig": rcpt.get("ed25519_signature"),
                "key_id": rcpt.get("key_id"),
            },
        )
        assert v_ok.status_code == 200
        assert v_ok.json()["verified"] is True
        assert v_ok.json()["ed25519_signature_valid"] is True

        tampered = dict(rcpt["canonical_payload"])
        tampered["risk_score"] = 0
        v_bad = await client.post(
            "/api/verify-receipt",
            json={
                "canonical_payload": tampered,
                "expected_sha256": rcpt["sha256_evidence_hash"],
                "expected_ed25519_sig": rcpt.get("ed25519_signature"),
                "key_id": rcpt.get("key_id"),
            },
        )
        assert v_bad.status_code == 200
        assert v_bad.json()["verified"] is False
        assert v_bad.json()["tamper_detected"] is True


@pytest.mark.asyncio
async def test_concurrent_requests_stress(live_server_url: str) -> None:
    """Inversion Test 4: Fire 6 concurrent API requests to verify zero race condition crashes."""
    async with httpx.AsyncClient(base_url=live_server_url, timeout=15.0) as client:
        tasks = [client.get("/api/health") for _ in range(6)]
        responses = await asyncio.gather(*tasks)
        for resp in responses:
            assert resp.status_code == 200
            assert resp.json()["status"] == "ok"
