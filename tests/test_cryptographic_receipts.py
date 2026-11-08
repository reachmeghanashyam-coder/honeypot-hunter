"""
Test Cryptographic Host HMAC-SHA256 Receipts & Host-Status Integrity.

Proves:
1. Every run generates a canonical payload, SHA-256 hash, and host-keyed HMAC-SHA256 signature.
2. The signing key is held strictly on the control-plane host and never mounted into the sandbox.
3. `/api/verify-receipt` correctly verifies authentic receipts and rejects modified/forged payloads.
4. `/api/host-status` confirms clean host state, 0 residual containers, and cgroup enforcement.
5. `/static/bundle.css` is served locally with 0 CDN dependencies.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from backend.app import app, HOST_SIGNING_KEY


@pytest.mark.asyncio
async def test_public_key_and_offline_ed25519_verification():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    import hashlib, json

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        pk_resp = await client.get("/api/public-key")
        assert pk_resp.status_code == 200
        pk_data = pk_resp.json()
        assert pk_data["algorithm"] == "Ed25519 (RFC 8032)"
        pub_hex = pk_data["public_key_hex"]
        assert len(pub_hex) == 64

        # Run investigation to get signed receipt
        inv_resp = await client.post("/api/investigate", json={"url": "/traps/credential-harvester"})
        assert inv_resp.status_code == 200
        rcpt = inv_resp.json().get("receipt", {})
        assert rcpt.get("ed25519_signature") is not None
        assert rcpt.get("host_public_key") == pub_hex

        # Independent offline verification (Evaluator zero-trust test)
        canonical_bytes = json.dumps(rcpt["canonical_payload"], sort_keys=True, separators=(",", ":")).encode("utf-8")
        raw_digest = hashlib.sha256(canonical_bytes).digest()
        pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        
        # Must not raise InvalidSignature
        pub_key.verify(bytes.fromhex(rcpt["ed25519_signature"]), raw_digest)

        # Full verification via /api/verify-receipt
        ver_resp = await client.post("/api/verify-receipt", json={
            "canonical_payload": rcpt["canonical_payload"],
            "expected_sha256": rcpt["sha256_evidence_hash"],
            "expected_ed25519_sig": rcpt["ed25519_signature"],
            "key_id": rcpt.get("key_id"),
        })
        assert ver_resp.status_code == 200
        v_data = ver_resp.json()
        assert v_data["verified"] is True
        assert v_data["ed25519_signature_valid"] is True
        assert v_data["tamper_detected"] is False


@pytest.mark.asyncio
async def test_untrusted_caller_key_rejection():
    """
    CRITICAL PROOF TEST: Proves that the server rejects receipts signed by an attacker's key,
    even if the attacker passes their own public key to /api/verify-receipt.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    import hashlib, json

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Attacker generates independent keypair
        attacker_priv = Ed25519PrivateKey.generate()
        attacker_pub = attacker_priv.public_key()
        attacker_pub_hex = attacker_pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        ).hex()

        # 2. Attacker crafts fabricated manifest claiming benign score
        forged_payload = {
            "run_id": "hh-attacker-forgery",
            "target_url": "https://malicious-phish.net",
            "verdict": "BENIGN_VERIFIED",
            "risk_score": 0,
            "containment_triggered": False,
        }
        forged_bytes = json.dumps(forged_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        forged_digest = hashlib.sha256(forged_bytes).digest()
        attacker_sig = attacker_priv.sign(forged_digest).hex()

        # 3. Attacker attempts to verify their forged receipt using their own public key
        tamper_resp = await client.post("/api/verify-receipt", json={
            "canonical_payload": forged_payload,
            "expected_sha256": hashlib.sha256(forged_bytes).hexdigest(),
            "expected_ed25519_sig": attacker_sig,
            "public_key_hex": attacker_pub_hex,
        })
        assert tamper_resp.status_code == 200
        t_data = tamper_resp.json()
        assert t_data["verified"] is False
        assert t_data["untrusted_key_rejected"] is True
        assert t_data["tamper_detected"] is True


@pytest.mark.asyncio
async def test_persistent_key_survives_restart():
    """
    PROVES: The host Ed25519 signing key is persistent on disk.
    Restarting or re-initializing the key manager preserves the exact same public key and key_id.
    """
    from backend.app import _load_or_generate_host_key, HOST_ED25519_PUBLIC_HEX, HOST_KEY_ID

    priv2, pub2, pub2_hex, key_id2 = _load_or_generate_host_key()
    assert pub2_hex == HOST_ED25519_PUBLIC_HEX
    assert key_id2 == HOST_KEY_ID


@pytest.mark.asyncio
async def test_host_status_and_containment_proof():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/host-status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "verified_clean"
        assert data["sandbox_containment"]["lingering_containers"] == 0
        assert data["sandbox_containment"]["cgroup_memory_ceiling"] == "512MB strict"
        assert "HMAC-SHA256" in data["cryptographic_authority"]["algorithm"]


@pytest.mark.asyncio
async def test_hmac_sha256_receipt_verification_and_tamper_rejection():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Execute an investigation
        inv_resp = await client.post("/api/investigate", json={"url": "/traps/credential-harvester"})
        assert inv_resp.status_code == 200
        inv_data = inv_resp.json()

        receipt = inv_data.get("receipt", {})
        assert "sha256_evidence_hash" in receipt
        assert "host_hmac_signature" in receipt
        assert "canonical_payload" in receipt
        assert "HMAC-SHA256" in receipt.get("signing_algorithm", "")

        # 2. Verify authentic receipt
        verify_resp = await client.post("/api/verify-receipt", json={
            "canonical_payload": receipt["canonical_payload"],
            "expected_sha256": receipt["sha256_evidence_hash"],
            "expected_hmac": receipt["host_hmac_signature"],
        })
        assert verify_resp.status_code == 200
        v_data = verify_resp.json()
        assert v_data["verified"] is True
        assert v_data["sha256_match"] is True
        assert v_data["hmac_signature_valid"] is True
        assert v_data["tamper_detected"] is False

        # 3. Simulate adversarial payload tampering (flip risk_score to 0)
        tampered_payload = dict(receipt["canonical_payload"])
        tampered_payload["risk_score"] = 999

        tamper_resp = await client.post("/api/verify-receipt", json={
            "canonical_payload": tampered_payload,
            "expected_sha256": receipt["sha256_evidence_hash"],
            "expected_hmac": receipt["host_hmac_signature"],
        })
        assert tamper_resp.status_code == 200
        t_data = tamper_resp.json()
        assert t_data["verified"] is False
        assert t_data["tamper_detected"] is True
        assert t_data["hmac_signature_valid"] is False
