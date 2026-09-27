"""Unit tests for Genesis Configuration and Deterministic Hashing."""

import pytest

from tracecrypt.crypto.pqc_dsa import generate_mldsa_keypair
from tracecrypt.errors import ValidationError
from tracecrypt.identity.ca import OfflineRootCA
from tracecrypt.ledger.genesis import GenesisConfig
from tracecrypt.ledger.validator import ValidatorInfo, ValidatorSet
from tracecrypt.utils.identifiers import ValidatorID
from tracecrypt.utils.timestamps import utc_now_micros


def make_dummy_validators(count: int = 4):
    ca = OfflineRootCA.initialize("ca-genesis-test")
    vals = []
    for i in range(count):
        vid = ValidatorID.generate()
        pk, _ = generate_mldsa_keypair()
        cert = ca.issue_validator_certificate(
            subject_id=str(vid),
            public_key=pk,
            organization="Test Org",
            role="ConsensusValidator",
        )
        vals.append(ValidatorInfo.from_certificate(vid, cert, voting_power=1))
    return vals


@pytest.mark.unit
def test_deterministic_genesis_hash():
    vals = make_dummy_validators(4)
    val_set = ValidatorSet(validators=vals)
    t = 1727280000000000

    gen1 = GenesisConfig(
        chain_id="tracecrypt-test-net",
        genesis_time=t,
        validator_set=val_set,
        initial_state_root="sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
    )
    gen2 = GenesisConfig(
        chain_id="tracecrypt-test-net",
        genesis_time=t,
        validator_set=val_set,
        initial_state_root="sha3-256:0000000000000000000000000000000000000000000000000000000000000000",
    )

    hash1 = gen1.compute_genesis_hash()
    hash2 = gen2.compute_genesis_hash()

    assert hash1 == hash2
    assert hash1.startswith("sha3-256:")


@pytest.mark.unit
def test_genesis_hash_changes_with_different_chain_id():
    vals = make_dummy_validators(4)
    val_set = ValidatorSet(validators=vals)
    t = 1727280000000000

    gen1 = GenesisConfig(chain_id="chain-a", genesis_time=t, validator_set=val_set)
    gen2 = GenesisConfig(chain_id="chain-b", genesis_time=t, validator_set=val_set)

    assert gen1.compute_genesis_hash() != gen2.compute_genesis_hash()


@pytest.mark.unit
def test_genesis_rejects_fewer_than_4_validators():
    vals = make_dummy_validators(3)
    val_set = ValidatorSet(validators=vals)

    gen = GenesisConfig(chain_id="test-chain", genesis_time=utc_now_micros(), validator_set=val_set)
    with pytest.raises(ValidationError, match="at least 4 validators"):
        gen.validate_genesis()


@pytest.mark.unit
def test_genesis_rejects_duplicate_validator_id():
    vals = make_dummy_validators(4)
    # Duplicate first validator
    vals_with_dup = vals + [vals[0]]
    val_set = ValidatorSet(validators=vals_with_dup)

    gen = GenesisConfig(chain_id="test-chain", genesis_time=utc_now_micros(), validator_set=val_set)
    with pytest.raises(ValidationError, match="Duplicate validator ID"):
        gen.validate_genesis()


@pytest.mark.unit
def test_genesis_rejects_empty_chain_id():
    vals = make_dummy_validators(4)
    val_set = ValidatorSet(validators=vals)

    gen = GenesisConfig(chain_id="   ", genesis_time=utc_now_micros(), validator_set=val_set)
    with pytest.raises(ValidationError, match="chain_id cannot be empty"):
        gen.validate_genesis()
