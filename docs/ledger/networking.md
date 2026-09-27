# TraceCrypt Air-Gapped LAN Networking & Transport Protocol

## 1. Zero External Network Policy

TraceCrypt operates in **100% air-gapped forensic environments**. The networking subsystem strictly enforces:

- **NO Public DNS Requests:** Nodes never attempt domain name resolution.
- **NO Cloud Discovery:** No AWS, GCP, Azure, or remote seed nodes.
- **NO Public Blockchain Endpoints:** Zero RPC or web3 dependencies.
- **NO Telemetry / Outbound HTTP:** No external analytics, telemetry, or crash reporting.
- **NO Remote Clock Sync (NTP):** Consensus safety does not depend on wall-clock synchrony.

---

## 2. P2P Transport Layer

All validator communication is strictly point-to-point over local LAN TCP connections between explicitly configured static peers:

```
node-1: 127.0.0.1:9101 <---> node-2: 127.0.0.1:9102
  ^       \             /       ^
  |        \           /        |
  |         \         /         |
  v          v       v          v
node-3: 127.0.0.1:9103 <---> node-4: 127.0.0.1:9104
```

---

## 3. Binary Wire Framing & Integrity

Every message sent across the network is framed with length prefixes and SHA3-256 integrity digests:

```
+-------------------+-----------------------------------+--------------------+
| Length (4 Bytes)  | SHA3-256 Checksum (32 Bytes)     | Payload (N Bytes)  |
| Big-Endian uint32 | Hash of payload bytes             | Raw JSON or Bytes  |
+-------------------+-----------------------------------+--------------------+
```

### Framing Invariants:
1. `length <= MAX_FRAME_SIZE` (16 MB).
2. Frame reader verifies `computed_checksum == header_checksum` before deserializing.
3. Deserialization strictly uses Pydantic JSON validation.
4. Python `pickle` is **strictly forbidden** across the network boundary to eliminate remote code execution vulnerabilities.
