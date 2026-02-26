# AegisLog — Tamper‑Evident Forensic Logging System

AegisLog is a prototype tamper‑evident logging system designed to produce append‑only local logs and to export signed, encrypted log entries to a remote archival server. The primary goal is forensic integrity — provide verifiable evidence that log entries were produced in a particular order and that any modification is detectable. This project is not intended as a prevention system (it does not stop log deletion or server compromise), but as a means to detect tampering after the fact.

## Key features (concise)
- Local append‑only log format with per‑entry SHA‑256 chaining.
- Local verification routine to detect the first tampered entry.
- Client -> server export using RSA for key transport, AES‑GCM for confidentiality/integrity and RSA‑PSS for signing.
- Server maintains its own chained state and persisting last‑hash checkpoint.
- Minimal, auditable data formats and deterministic canonicalization for hashing.

## Motivation and threat model
Logs are a primary source of digital evidence. If adversaries with local access can edit or reorder logs, forensic confidence is lost. AegisLog targets scenarios where detection of tampering is required — e.g., post‑incident forensic analysis, audits or chain‑of‑custody verification. The design assumes an attacker may read or modify local files, may obtain local credentials, and may attempt to replay or inject logs. It does not defend against physical destruction of storage or full compromise of the server and signing keys.

Threat model:
- Attacker capabilities: read, edit, delete local logs; intercept network traffic; escalate privileges on host client.
- Assumed trusted components: signing key remains uncompromised; server private key remains uncompromised; secure out‑of‑band key distribution.
- Defenses provided: tamper evidence (chain breakage), signature verification, encrypted transport to a trusted server.

## Architecture overview
AegisLog has two main runtime roles — client (log producer) and server (archival validator). The client creates human‑readable chained log lines and optionally sends signed and encrypted copies to the server for independent archival and continuous verification. The server verifies authenticity, appends received logs to an append‑only binary file, updates a binary chain state, and acts as a stronger source of validation.

Components:
- `AegisLog.ipynb` — client code & notebook demonstrating log generation, local chain verification and client network export logic.
- `Key_Generator.py` — utility to create RSA keys for server and client.
- `Server/server.py` — TCP receiver that decrypts session keys, verifies signatures, stores logs and updates server state.
- `Server/*` — storage directory for server PEM keys, `remote_logs.log` (binary) and `server_state.bin` (32 bytes raw hash).

## Data formats and canonicalization
Paragraph: Deterministic canonicalization is critical to consistent hashing and verification. A consistent separator, ISO‑8601 UTC timestamps, and no newlines in messages ensure reproducible inputs to SHA‑256.

Local log line:
- Format: `username|ISO8601_UTC_timestamp|LEVEL|message|previous_hash|current_hash`
- Example: `alice|2026-02-11T14:32:08Z|INFO|User logged in|<prev_hex>|<curr_hex>`
- `GENESIS_HASH`: "0" repeated 64 characters used as previous_hash for the first entry.
- `current_hash`: `hex( SHA256( username|timestamp|level|message|previous_hash ) )`

Client -> Server (network):
- Initial: `4‑byte big‑endian length || RSA‑OAEP(encrypted AES key)`
- Per log packet:
  - Plaintext payload: `4‑byte big‑endian len(log_bytes) || log_bytes || signature_bytes`
  - Encrypted packet: `nonce (12 bytes)` || `AES‑GCM.encrypt(nonce, payload)`
  - Sent as: 4‑byte big‑endian packet_len || packet

Server state:
- `Server/server_state.bin` — raw 32 byte SHA‑256 last_hash (initially b"\x00"*32)
- `Server/remote_logs.log` — appended binary log_entry + newline

## Cryptographic choices and rationale
Choices favor widely deployed, well‑understood primitives with clear separation of roles: RSA for key transport and signatures, AES‑GCM for symmetric authenticated encryption, SHA‑256 for hashing.

- Hash: SHA‑256 for entry chaining and server checkpointing.
- Signature: RSA‑PSS (SHA‑256) for probabilistic, secure signatures resistant to classical attacks.
- Key transport: RSA‑OAEP (SHA‑256) — safe mechanism to encrypt ephemeral AES session key.
- Symmetric AE: AES‑GCM (256) — provides confidentiality and authenticated integrity for payloads.
- Key sizes: RSA 2048 in Key_Generator.py (sufficient for prototype; consider 3072+ for long lived systems).

Security note: If the client private signing key is compromised, an attacker can forge forwarded logs. For production use, use hardware-backed keys (HSM/TPM) and key rotation.

## Algorithms (stepwise)
Local generation and append:
1. Read last current_hash from LOG_FILE (or GENESIS_HASH).
2. Build canonical string: username|timestamp|level|message|prev_hash.
3. curr_hash = SHA256(canonical_string) → hex digest.
4. Append line: canonical_string|curr_hash + newline.

Local verification:
1. expected_prev = GENESIS_HASH
2. Iterate lines:
   - skip empty lines
   - split by '|' into exactly 6 fields
   - check stored_prev_hash == expected_prev
   - recompute SHA256(username|timestamp|level|message|stored_prev_hash) and compare stored_curr_hash
   - set expected_prev = stored_curr_hash
3. Report first failure or success.

Client export (network):
1. Generate AES session key (AESGCM.generate_key).
2. Encrypt AES key with server public RSA (OAEP), send with 4‑byte length prefix.
3. For each log:
   - signature = Sign(log_bytes, client_private_key, RSA‑PSS+SHA256)
   - payload = 4‑byte len(log) || log || signature
   - ciphertext = AESGCM.encrypt(nonce, payload)
   - send 4‑byte packet_len || nonce || ciphertext

Server receive and archive:
1. Receive and RSA‑decrypt AES key → create AESGCM.
2. Loop per packet:
   - read packet_len, read packet, split nonce and ciphertext.
   - plaintext = AESGCM.decrypt(nonce, ciphertext)
   - parse 4‑byte log_len, extract log_entry, signature.
   - verify signature using client public key (RSA‑PSS).
   - server_timestamp = int(time.time())
   - new_hash = SHA256( last_hash || log_entry || pack_uint64_be(server_timestamp) )
   - append log_entry to remote_logs.log and update server_state.bin with new_hash.

## How to run (Windows)
1. Create venv and install dependencies:
   - python -m venv .venv
   - .venv\Scripts\activate
   - pip install cryptography
2. Generate keys (one‑time):
   - python Key_Generator.py
   - Move `server_private_key.pem` and `server_public_key.pem` into the `Server/` directory.
   - Keep `client_private_key.pem` and `client_public_key.pem` with client code.
3. Start the server:
   - python Server\server.py
4. Run client workflow:
   - Open AegisLog.ipynb in Jupyter or run an equivalent client script that loads `Server/server_public_key.pem` and `client_private_key.pem`.
   - Ensure LOG_FILE path and key locations are correct.

## Testing and verification
Unit tests should cover canonicalization, hashing, and verification logic. Integration tests should simulate client → server interactions, including signature failures, corrupted ciphertext, truncated packets, and replayed packets.

Suggested tests:
- Canonicalization determinism: same inputs produce identical canonical string.
- Local verification: detect malformed lines, prev_hash mismatch, recomputed hash failures.
- Network: server rejects packets with invalid signatures, rejects AES‑GCM tampered ciphertext, and persists valid logs.
- State persistence: server_state.bin updates and survives restart.

## Limitations and considerations
- Key compromise: possession of client private key allows forging. Use hardware keys for production.
- Replay attacks: attacker may replay previously captured encrypted packets; server chain semantics mitigate some effects but explicit anti‑replay counters/IDs are advisable.
- Non‑repudiation and retention: server must protect its private key and logs; consider periodic checkpoints signed by server and external timestamping/anchoring.
- Deletion: this design provides evidence of tampering but does not prevent deletion of local files.

## Extensibility and improvements
- Key management: implement rotation, trust anchors, and mutual authentication.
- Replay protection: add per‑entry monotonic counters or unique nonces validated by the server.
- Checkpointing: server signs chain head periodically; publish checkpoints to an external immutable store (blockchain/timestamping service).
- Transport hardening: migrate to TLS with mutual authentication for client/server channel, remove custom framing where possible.
- Persistence: store structured logs (e.g., JSON) with optional compression and indexing for efficient queries.

## File layout (project root)
- AegisLog.ipynb — client notebook with generation, verification, and client network code.
- Key_Generator.py — RSA key generation helper.
- Server/
  - server.py — TCP server code.
  - server_private_key.pem, server_public_key.pem — server keys (move after generation).
  - client_public_key.pem — client public key used by server for signature verification.
  - remote_logs.log — binary appended logs.
  - server_state.bin — 32 byte raw SHA‑256 last_hash.

## Operational recommendations
- Protect private keys with filesystem permissions and consider hardware protection.
- Keep periodic, signed checkpoints of the server_state.bin and distribute them to independent parties.
- Monitor server logs for signature verification failures and abnormal client behavior.
- Maintain a secure backup plan and an incident response process for compromised keys or servers.

For questions or clarifications, open an issue in the repository with reproduction steps and expected behavior.