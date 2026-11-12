# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from base64 import b64decode
from hashlib import sha256
import json
import re


LOG = 'https://ct.googleapis.com/logs/us1/argon2026h2/ct/v1/'
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
KEY = (0x2A3A678BFEBA0C862B4A518AE917FE7BA17673FDBC654BC327BF4DF35FA0CA29,
       0x8011203278D67EF934608C75A0F535509CA1D3494D13D53B6A0EEA459D241322)
LIMIT = (1 << 63) - 1
ANCHOR = (r'https://raw\.githubusercontent\.com/[A-Za-z0-9-]{1,39}/'
          r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}/[a-f0-9]{40}/anchors/[a-z0-9_-]{1,32}\.json')


def fail(message):
    raise gl.vm.UserError(message)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def unique_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON key')
        value[key] = item
    return value


def fetch_json(url, limit):
    try:
        response = gl.nondet.web.get(url)
        if response.status == 200 and len(response.body) <= limit:
            return json.loads(response.body.decode('utf-8'), object_pairs_hook=unique_keys)
    except Exception:
        pass
    fail('CT evidence unavailable or invalid')


def add_point(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    u, v = right
    if x == u:
        if (y + v) % P == 0:
            return None
        slope = (3 * x * x - 3) * pow(2 * y, -1, P) % P
    else:
        slope = (v - y) * pow(u - x, -1, P) % P
    first = (slope * slope - x - u) % P
    return first, (slope * (x - first) - y) % P


def scalar_point(scalar, point):
    result = None
    while scalar:
        if scalar & 1:
            result = add_point(result, point)
        point = add_point(point, point)
        scalar >>= 1
    return result


def signature_pair(signature):
    if (not 12 <= len(signature) <= 76 or signature[:2] != b'\x04\x03'
            or int.from_bytes(signature[2:4], 'big') != len(signature) - 4
            or signature[4] != 0x30 or signature[5] != len(signature) - 6):
        fail('Invalid CT signature encoding')
    values = []
    offset = 6
    for _ in range(2):
        if offset + 2 > len(signature) or signature[offset] != 2:
            fail('Invalid CT signature encoding')
        length = signature[offset + 1]
        part = signature[offset + 2:offset + 2 + length]
        if (not 1 <= length <= 33 or len(part) != length or part[0] & 128
                or (length > 1 and part[0] == 0 and part[1] < 128)):
            fail('Invalid CT signature encoding')
        number = int.from_bytes(part, 'big')
        if not 0 < number < N:
            fail('Invalid CT signature encoding')
        values.append(number)
        offset += 2 + length
    if offset != len(signature):
        fail('Invalid CT signature encoding')
    return values


def verify_head(size, timestamp, root, signature):
    if (type(size) is not int or not 1 <= size <= LIMIT or type(timestamp) is not int
            or not 1 <= timestamp <= LIMIT or len(root) != 32):
        fail('Invalid CT tree head')
    r, s = signature_pair(signature)
    message = b'\x00\x01' + timestamp.to_bytes(8, 'big') + size.to_bytes(8, 'big') + root
    z = int.from_bytes(sha256(message).digest(), 'big')
    inverse = pow(s, -1, N)
    point = add_point(scalar_point(z * inverse % N, G), scalar_point(r * inverse % N, KEY))
    if point is None or point[0] % N != r:
        fail('CT head signature invalid')
    return {'size': size, 'timestamp': timestamp, 'root': root.hex(), 'signature': signature.hex()}


def read_head(url):
    value = fetch_json(url, 2048)
    try:
        size, timestamp = value['tree_size'], value['timestamp']
        root = b64decode(value['sha256_root_hash'], validate=True)
        signature = b64decode(value['tree_head_signature'], validate=True)
    except (KeyError, TypeError, ValueError):
        fail('Invalid CT tree head')
    return verify_head(size, timestamp, root, signature)


def validate_candidate(head):
    if not isinstance(head, dict) or set(head) != {'size', 'timestamp', 'root', 'signature'}:
        fail('Invalid CT candidate')
    root, sig = head['root'], head['signature']
    if (not isinstance(root, str) or not re.fullmatch(r'[0-9a-f]{64}', root)
            or not isinstance(sig, str) or not re.fullmatch(r'(?:[0-9a-f]{2}){12,76}', sig)):
        fail('Invalid CT candidate')
    return verify_head(head['size'], head['timestamp'], bytes.fromhex(root), bytes.fromhex(sig))


def parent(left, right):
    return sha256(b'\x01' + left + right).digest()


def consistency(old_size, new_size, old_root, new_root, proof):
    if old_size == new_size:
        return not proof and old_root == new_root
    if not 0 < old_size < new_size:
        return False
    first, second = old_size - 1, new_size - 1
    while first & 1:
        first >>= 1
        second >>= 1
    if first == 0:
        left = right = old_root
    else:
        if not proof:
            return False
        left = right = proof[0]
        proof = proof[1:]
    for node in proof:
        if second == 0:
            return False
        if first & 1 or first == second:
            left = parent(node, left)
            right = parent(node, right)
            while first and not first & 1:
                first >>= 1
                second >>= 1
        else:
            right = parent(right, node)
        first >>= 1
        second >>= 1
    return second == 0 and left == old_root and right == new_root


def inclusion_root(index, size, leaf, proof):
    first, second = index, size - 1
    for node in proof:
        if second == 0:
            return None
        if first & 1 or first == second:
            leaf = parent(node, leaf)
            while first and not first & 1:
                first >>= 1
                second >>= 1
        else:
            leaf = parent(leaf, node)
        first >>= 1
        second >>= 1
    return leaf if second == 0 else None


def proof_nodes(value):
    if not isinstance(value, list) or len(value) > 64:
        fail('Invalid CT proof shape')
    try:
        nodes = [b64decode(item, validate=True) for item in value]
    except (TypeError, ValueError):
        fail('Invalid CT proof shape')
    if any(len(node) != 32 for node in nodes):
        fail('Invalid CT proof shape')
    return nodes


def fetch_link(old, new):
    if old['size'] == new['size']:
        if old['root'] != new['root']:
            fail('CT same-size root conflict')
        return []
    if old['size'] > new['size']:
        fail('CT checkpoint rollback')
    query = 'get-sth-consistency?first=' + str(old['size']) + '&second=' + str(new['size'])
    value = fetch_json(LOG + query, 8192)
    proof = proof_nodes(value.get('consistency') if isinstance(value, dict) else None)
    if not consistency(old['size'], new['size'], bytes.fromhex(old['root']), bytes.fromhex(new['root']), proof):
        fail('CT prefix proof invalid')
    return [node.hex() for node in proof]


def equal_verifier(sample):
    def verify(leader):
        try:
            local = sample()
        except gl.vm.UserError as error:
            return not isinstance(leader, gl.vm.Return) and getattr(leader, 'message', None) == error.message
        except Exception:
            return False
        return isinstance(leader, gl.vm.Return) and local == leader.calldata
    return verify


def observe_anchor(url):
    def sample():
        return read_head(url)

    return gl.vm.run_nondet_unsafe(sample, equal_verifier(sample))


def observe_extension(old):
    def sample():
        candidate = read_head(LOG + 'get-sth')
        if candidate['size'] <= old['size']:
            if candidate['size'] == old['size'] and candidate['root'] != old['root']:
                fail('CT same-size root conflict')
            fail('CT head has not advanced')
        if candidate['timestamp'] < old['timestamp']:
            fail('CT timestamp rollback')
        return {'head': candidate, 'proof': fetch_link(old, candidate)}

    def verify(leader):
        if not isinstance(leader, gl.vm.Return):
            return equal_verifier(sample)(leader)
        try:
            proposed = leader.calldata
            if not isinstance(proposed, dict) or set(proposed) != {'head', 'proof'}:
                return False
            candidate = validate_candidate(proposed['head'])
            if candidate['size'] <= old['size'] or candidate['timestamp'] < old['timestamp']:
                return False
            if fetch_link(old, candidate) != proposed['proof']:
                return False
            # Validators may see a newer or older signed head than the leader.
            local = read_head(LOG + 'get-sth')
            if local['size'] <= candidate['size']:
                fetch_link(local, candidate)
            else:
                fetch_link(candidate, local)
            return True
        except Exception:
            return False

    return gl.vm.run_nondet_unsafe(sample, verify)


def fetch_entry(index, size):
    query = 'get-entry-and-proof?leaf_index=' + str(index) + '&tree_size=' + str(size)
    value = fetch_json(LOG + query, 65536)
    try:
        raw = b64decode(value['leaf_input'], validate=True)
    except (KeyError, TypeError, ValueError):
        fail('Invalid CT leaf')
    if not 12 <= len(raw) <= 8192 or raw[:2] != b'\x00\x00':
        fail('Invalid CT leaf')
    path = value.get('audit_path')
    if size == 1 and index == 0 and path is None:
        return raw, []
    return raw, proof_nodes(path)


def observe_leaf(index, head):
    def sample():
        raw, nodes = fetch_entry(index, head['size'])
        timestamp = int.from_bytes(raw[2:10], 'big')
        entry_type = int.from_bytes(raw[10:12], 'big')
        if entry_type not in (0, 1) or timestamp > head['timestamp']:
            fail('Invalid CT leaf metadata')
        digest = sha256(b'\x00' + raw).digest()
        if inclusion_root(index, head['size'], digest, nodes) != bytes.fromhex(head['root']):
            fail('CT leaf proof invalid')
        return {'index': index, 'size': head['size'], 'root': head['root'], 'leaf_hash': digest.hex(),
                'timestamp': timestamp, 'entry_type': entry_type, 'proof': [node.hex() for node in nodes]}

    return gl.vm.run_nondet_unsafe(sample, equal_verifier(sample))


def observe_prefix(prefix_size, head):
    def sample():
        raw, nodes = fetch_entry(0, prefix_size)
        root = inclusion_root(0, prefix_size, sha256(b'\x00' + raw).digest(), nodes)
        if root is None:
            fail('CT prefix path invalid')
        prefix = {'size': prefix_size, 'root': root.hex()}
        return {**prefix, 'anchor_size': head['size'], 'anchor_root': head['root'],
                'proof': fetch_link(prefix, head)}

    return gl.vm.run_nondet_unsafe(sample, equal_verifier(sample))


class LogAccord(gl.Contract):
    anchor_url: str
    anchor_prefix_size: u256
    head: str
    links: TreeMap[u256, str]
    leaves: TreeMap[u256, str]
    prefixes: TreeMap[u256, str]
    checkpoints: u256
    leaf_count: u256
    prefix_count: u256

    def __init__(self, anchor_url: str, anchor_prefix_size: int):
        if not re.fullmatch(ANCHOR, anchor_url):
            fail('CT anchor must use a pinned GitHub commit')
        if not 0 <= anchor_prefix_size <= LIMIT:
            fail('Invalid CT anchor prefix')
        self.anchor_url = anchor_url
        self.anchor_prefix_size = u256(anchor_prefix_size)
        self.head = 'null'
        self.checkpoints = u256(0)
        self.leaf_count = u256(0)
        self.prefix_count = u256(0)

    @gl.public.write
    def seed(self) -> None:
        if self.head != 'null':
            fail('CT anchor already set')
        signed = observe_anchor(self.anchor_url)
        head = signed
        link = {'previous_size': None, 'proof': [], 'attestation': None}
        prefix_size = int(self.anchor_prefix_size)
        if prefix_size:
            if prefix_size >= signed['size']:
                fail('CT anchor prefix outside signed head')
            prefix = observe_prefix(prefix_size, signed)
            head = {'size': prefix_size, 'timestamp': signed['timestamp'],
                    'root': prefix['root'], 'signature': None}
            link['attestation'] = signed
            link['proof'] = prefix['proof']
        self.head = encode(head)
        self.links[u256(head['size'])] = encode({**link, 'head': head})
        self.checkpoints = u256(1)

    @gl.public.write
    def sync(self, expected_size: int) -> None:
        old = json.loads(self.head)
        if old is None:
            fail('CT anchor required')
        if expected_size != old['size']:
            fail('Stale CT checkpoint')
        extension = observe_extension(old)
        head = extension['head']
        self.links[u256(head['size'])] = encode({**extension, 'previous_size': old['size'], 'attestation': None})
        self.head = encode(head)
        self.checkpoints = u256(int(self.checkpoints) + 1)

    @gl.public.write
    def record_leaf(self, index: int, size: int) -> None:
        head = json.loads(self.head)
        if head is None or size != head['size']:
            fail('Stale CT checkpoint')
        if not 0 <= index < size:
            fail('CT leaf index outside checkpoint')
        key = u256(index)
        if key in self.leaves:
            fail('CT leaf already recorded')
        self.leaves[key] = encode(observe_leaf(index, head))
        self.leaf_count = u256(int(self.leaf_count) + 1)

    @gl.public.write
    def record_prefix(self, prefix_size: int, size: int) -> None:
        head = json.loads(self.head)
        if head is None or size != head['size']:
            fail('Stale CT checkpoint')
        if not 1 <= prefix_size < size:
            fail('CT prefix outside checkpoint')
        key = u256(prefix_size)
        if key in self.prefixes:
            fail('CT prefix already recorded')
        self.prefixes[key] = encode(observe_prefix(prefix_size, head))
        self.prefix_count = u256(int(self.prefix_count) + 1)

    @gl.public.view
    def get_state(self) -> dict:
        return {'anchor_url': self.anchor_url, 'anchor_prefix_size': int(self.anchor_prefix_size),
                'head': json.loads(self.head),
                'checkpoints': int(self.checkpoints), 'leaf_count': int(self.leaf_count),
                'prefix_count': int(self.prefix_count)}

    @gl.public.view
    def get_checkpoint(self, size: int) -> dict:
        if not 1 <= size <= LIMIT:
            fail('Invalid CT checkpoint size')
        key = u256(size)
        return json.loads(self.links[key]) if key in self.links else {}

    @gl.public.view
    def get_leaf(self, index: int) -> dict:
        if not 0 <= index <= LIMIT:
            fail('Invalid CT leaf index')
        key = u256(index)
        return json.loads(self.leaves[key]) if key in self.leaves else {}

    @gl.public.view
    def get_prefix(self, size: int) -> dict:
        if not 1 <= size <= LIMIT:
            fail('Invalid CT prefix size')
        key = u256(size)
        return json.loads(self.prefixes[key]) if key in self.prefixes else {}
