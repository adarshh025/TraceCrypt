# TraceCrypt Air-Gap Network Model and Destination Allowlist

**Classification:** RESTRICTED / TRACECRYPT AIR-GAP NETWORK ARCHITECTURE  
**Target Environment:** SCIF / Fully Disconnected Air-Gapped Secure Enclaves  
**Enforcement Mechanism:** `AirGapGuard` Network Interceptor + Static Import Audit  

---

## 1. Core Air-Gap Doctrine

TraceCrypt is designed and engineered exclusively for operation in **air-gapped, internet-isolated environments**. 

The platform guarantees:
1. **Zero Outbound Internet Connections**: Absolutely no DNS queries, HTTP/HTTPS requests, telemetry calls, analytics, cloud API invocations, or automatic update checkers exist anywhere in the core runtime.
2. **Zero Cloud Dependencies**: The system relies on no external cloud Key Management Services (KMS), online Certificate Authorities (CAs), or public blockchains.
3. **Explicit LAN-Only Transport**: The only network capabilities permitted are local, offline, point-to-point or broadcast sockets strictly confined to a private, non-routable local area network (LAN) connecting authorized consortium validator nodes.

---

## 2. Network Destination Matrix

| Component | Protocol | Target / Destination | Direction | Purpose | Policy Status | Enforcement Rule |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Offline Root CA** | None (N/A) | None | None | Identity certificate issuance & revocation signing | **PROHIBITED** | Operates on detached storage media with all network adapters disabled |
| **Recipient Client Workstation** | None (N/A) | None | None | Key generation, local decryption, watermark embedding | **PROHIBITED** | Local operations only; zero external sockets permitted |
| **Document Sender Workstation** | None (N/A) | None | None | Document encryption & multi-recipient KEM packaging | **PROHIBITED** | Local cryptographic operations only |
| **Forensic Attribution Engine** | None (N/A) | None | None | Blind watermark extraction & deterministic verification | **PROHIBITED** | Completely offline execution; reading local proof bundles and ledger snapshots |
| **BFT Ledger Consensus Node** | TCP / LAN Socket | Configured Validator Peering IPs (`10.0.0.x` or `192.168.x.x`) | Inbound / Outbound | BFT consensus proposals, prevotes, precommits, commit certificates | **ALLOWED (LAN ONLY)** | Strict IP allowlist; reject any non-LAN/routable addresses |
| **Local SQLite Persistence** | Local IPC / File | Local filesystem (`sqlite3`) | Localhost only | Monotonic block and transaction storage | **ALLOWED (LOCAL)** | File I/O only |
| **FastAPI Local Management API** | HTTP over loopback | `127.0.0.1` / `localhost` only | Inbound (Localhost) | Local workstation UI / CLI communication | **ALLOWED (LOCALHOST)** | Bound strictly to `127.0.0.1`; forbidden to bind to `0.0.0.0` |
| **External Cloud Services** (AWS, GCP, Azure) | HTTPS / gRPC | Any internet FQDN / IP | Outbound | Any cloud telemetry, logging, or KMS | **STRICTLY FORBIDDEN** | Intercepted by `AirGapGuard`; raises `NetworkIsolationViolationError` |
| **DNS Resolvers** | UDP/TCP 53 | Any DNS server (`8.8.8.8`, `1.1.1.1`, local) | Outbound | Name resolution | **STRICTLY FORBIDDEN** | Intercepted by `AirGapGuard` |
| **Package / Update Checkers** | HTTPS | `pypi.org`, `github.com`, etc. | Outbound | Dependency checks or updates | **STRICTLY FORBIDDEN** | No update mechanisms built into software |

---

## 3. Cryptographic and Socket Guard (`AirGapGuard`)

In the testing and production profiles, TraceCrypt provides an active runtime interceptor `AirGapGuard` (`tracecrypt.security.airgap`):

```python
class AirGapGuard:
    """Intercepts and terminates any socket creation targeting external networks."""
    
    @classmethod
    def install(cls):
        # Hooks socket.socket.connect and socket.socket.bind
        # Blocks any destination outside 127.0.0.1 and configured LAN validator IPs.
        # Immediately raises NetworkIsolationViolationError on non-compliant calls.
```

### Static Dependency and Code Audit Findings
Static code inspection of `tracecrypt/` reveals:
- **No external HTTP client libraries imported in runtime**: `requests`, `httpx`, `urllib.request`, `aiohttp` are completely absent from core runtime execution paths.
- **No telemetry frameworks**: Zero analytics trackers, bug reporters, or crash-reporting webhooks.
- **Offline Dependency Bundling**: Dependencies are pre-compiled into local wheels and installed via offline clean-room pip caches (`--no-index --find-links=vendor/`).

---

## 4. Verification in Degraded / Network-Down Environments

TraceCrypt has been tested and verified under simulated negative network conditions:
- `DNS`: Disabled (`socket.getaddrinfo` fails immediately) $\to$ Full core workflow functions without degradation.
- `Default Gateway`: Absent $\to$ Core cryptography, watermark extraction, and local ledger storage function without disruption.
- `Consensus Transport`: When isolated into partitioned LAN enclaves (e.g. 2+2 split), the BFT consensus engine deterministically halts block production rather than committing conflicting forks, preserving safety over liveness.
