# Air-Gap Enforcement Policy & Technical Controls

## 1. Threat Definition
In a classified or isolated facility, accidental software network calls (telemetry, automatic update checks, cloud SDK lookups, external DNS queries) can leak confidential operational data or compromise air-gap compliance.

## 2. In-Process Defense: `AirGapGuard`
TraceCrypt provides a software-level interception guard (`tracecrypt.security.airgap.AirGapGuard`):
* **Hooked Primitives:** `socket.socket.connect` and `socket.getaddrinfo`.
* **Policy:** Only addresses explicitly whitelisted (by default `127.0.0.1`, `localhost`, `::1`) are allowed.
* **Fail-Closed Behavior:** Any connection attempt to a non-whitelisted address immediately raises `AirGapViolation` and aborts the operation.
* **DNS Prevention:** Hostname resolution calls outside localhost are intercepted and blocked.

## 3. Host and Infrastructure Limitations
Software-level interception in Python does not replace physical infrastructure controls:
1. **Physical Disconnection:** Workstations must have physical Ethernet cables disconnected from public routers and wireless adapters disabled.
2. **OS Packet Filtering:** Windows Filtering Platform (WFP) or Linux `iptables` must be configured to drop all non-local packets.
3. **Data Diode / Transfer Policy:** Media transfer (e.g., USB keys, optical disks) into the air-gapped facility must follow strict dual-custody verification.
