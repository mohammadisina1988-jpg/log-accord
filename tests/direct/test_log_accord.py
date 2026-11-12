from base64 import b64decode, b64encode
from hashlib import sha256
import json
from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[2]
DATA = json.loads((ROOT / 'fixtures/argon.json').read_text())
SIGNED = DATA['anchor']
SIZE = SIGNED['tree_size']
ANCHOR = ('https://raw.githubusercontent.com/mohammadisina1988-jpg/log-accord/'
          + 'a' * 40 + '/anchors/argon.json')
LOG = 'https://ct.googleapis.com/logs/us1/argon2026h2/ct/v1/'
PREFIX_URL = LOG + f'get-sth-consistency?first=3&second={SIZE}'
LEAF_URL = LOG + f'get-entry-and-proof?leaf_index=0&tree_size={SIZE}'
SMALL_URL = LOG + 'get-entry-and-proof?leaf_index=0&tree_size=3'


def mock(vm, **values):
    sources = {ANCHOR: SIGNED, LOG + 'get-sth': SIGNED, PREFIX_URL: DATA['prefix'],
               LEAF_URL: DATA['originalLeaf'], SMALL_URL: DATA['small']}
    sources.update(values)
    vm.clear_mocks()
    for url, body in sources.items():
        vm.mock_web('^' + re.escape(url) + '$', {'status': 200, 'body': json.dumps(body).encode()})


def deploy(direct_deploy, prefix=0):
    return direct_deploy('contracts/log_accord.py', ANCHOR, prefix, sdk_version='v0.2.16')


def test_authenticated_prefix_advances_to_signed_head(direct_vm, direct_deploy, direct_accounts):
    ledger = deploy(direct_deploy, 3)
    mock(direct_vm)
    direct_vm.sender = direct_accounts[1]
    ledger.seed()
    assert direct_vm.run_validator() is True
    baseline = ledger.get_checkpoint(3)
    assert baseline['head']['signature'] is None
    assert baseline['attestation']['size'] == SIZE
    assert len(baseline['proof']) > 0
    ledger.sync(3)
    assert direct_vm.run_validator() is True
    assert ledger.get_state()['head']['size'] == SIZE
    assert ledger.get_state()['checkpoints'] == 2
    assert ledger.get_checkpoint(SIZE)['previous_size'] == 3
    assert ledger.get_checkpoint(SIZE)['proof'] == baseline['proof']
    assert ledger.get_checkpoint(3) == baseline
    with direct_vm.expect_revert('Stale CT checkpoint'):
        ledger.sync(3)


def test_real_historical_prefix_and_actual_leaf(direct_vm, direct_deploy):
    ledger = deploy(direct_deploy)
    mock(direct_vm)
    ledger.seed()
    ledger.record_prefix(3, SIZE)
    assert direct_vm.run_validator() is True
    prefix = ledger.get_prefix(3)
    assert prefix['anchor_root'] == b64decode(SIGNED['sha256_root_hash']).hex()
    ledger.record_leaf(0, SIZE)
    assert direct_vm.run_validator() is True
    raw = b64decode(DATA['originalLeaf']['leaf_input'])
    record = ledger.get_leaf(0)
    assert record['leaf_hash'] == sha256(b'\x00' + raw).hexdigest()
    assert record['timestamp'] == int.from_bytes(raw[2:10], 'big')
    assert ledger.get_state()['prefix_count'] == ledger.get_state()['leaf_count'] == 1
    with direct_vm.expect_revert('CT leaf already recorded'):
        ledger.record_leaf(0, SIZE)


@pytest.mark.parametrize('field', ['sha256_root_hash', 'tree_size', 'timestamp'])
def test_signature_binds_all_head_fields(direct_vm, direct_deploy, field):
    ledger = deploy(direct_deploy)
    changed = dict(SIGNED)
    if field == 'sha256_root_hash':
        changed[field] = b64encode(b'\xff' * 32).decode()
    else:
        changed[field] += 1
    mock(direct_vm, **{ANCHOR: changed})
    with direct_vm.expect_revert('CT head signature invalid'):
        ledger.seed()
    assert ledger.get_state()['head'] is None


def test_validator_refetches_and_rejects_changed_consistency_proof(direct_vm, direct_deploy):
    ledger = deploy(direct_deploy, 3)
    mock(direct_vm)
    ledger.seed()
    ledger.sync(3)
    bad = list(DATA['prefix']['consistency'])
    bad[0] = b64encode(b'\xff' * 32).decode()
    mock(direct_vm, **{PREFIX_URL: {'consistency': bad}})
    assert direct_vm.run_validator() is False


def test_tampered_leaf_is_rejected_without_state_change(direct_vm, direct_deploy):
    ledger = deploy(direct_deploy)
    mock(direct_vm)
    ledger.seed()
    raw = bytearray(b64decode(DATA['originalLeaf']['leaf_input']))
    raw[-1] ^= 1
    tampered = {**DATA['originalLeaf'], 'leaf_input': b64encode(raw).decode()}
    mock(direct_vm, **{LEAF_URL: tampered})
    with direct_vm.expect_revert('CT leaf proof invalid'):
        ledger.record_leaf(0, SIZE)
    assert ledger.get_state()['leaf_count'] == 0


def test_equal_size_does_not_advance_checkpoint(direct_vm, direct_deploy):
    ledger = deploy(direct_deploy)
    mock(direct_vm)
    ledger.seed()
    with direct_vm.expect_revert('CT head has not advanced'):
        ledger.sync(SIZE)
    assert ledger.get_state()['checkpoints'] == 1
