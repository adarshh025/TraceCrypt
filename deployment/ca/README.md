# Environment A: Root CA / Identity Authority

## Purpose
The Offline Root Certificate Authority (CA) operates exclusively on a strictly air-gapped machine with no network interfaces. It is responsible for:
- Initializing the master post-quantum root of trust (NIST FIPS 204 ML-DSA-65).
- Issuing certified KEM public key credentials (`KeyPurpose.KEY_ENCAPSULATION`) to authorized document recipients.
- Issuing certified DSA public key credentials (`KeyPurpose.DIGITAL_SIGNATURE`) for signing canonical attribution events.
- Issuing certified validator credentials (`KeyPurpose.CONSENSUS_VALIDATION`) for BFT consensus nodes.
- Publishing offline CRL revocation epochs.

## Operational Workflow
```bash
# 1. Initialize Root CA
python deployment/ca/init_ca.py init --ca-id ca-root-airgap-primary --output-dir data/ca

# 2. Inspect Root CA Status
python -m tracecrypt ca status

# 3. Issue Recipient Credentials
python -m tracecrypt identity generate --recipient-id rcp-FIELD-OPERATIVE-01 --passphrase <SECURE_KEYSTORE_PASSPHRASE> --ca-passphrase <ROOT_CA_PASSPHRASE>
```
