const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {root, assert, equal, digest, sourceHash, invoke, read, rpc, receipt, receiptSummary, save} = require('./transport.cjs');
const {decodeReceipt} = require('./receipt-calldata.cjs');
const fixture = require('../fixtures/argon.json');

const LOG = 'https://ct.googleapis.com/logs/us1/argon2026h2/ct/v1/';
const SPKI = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKjpni/66DIYrSlGK6Rf+e6F2c/28ZUvDJ79N81+gyimAESAyeNZ++TRgjHWg9TVQnKHTSU0T1TtqDupFnSQTIg==';
const key = crypto.createPublicKey({key: Buffer.from(SPKI, 'base64'), format: 'der', type: 'spki'});
const hash = parts => Buffer.from(digest(Buffer.concat(parts)), 'hex');
const parent = (a, b) => hash([Buffer.from([1]), a, b]);
const leafHash = body => hash([Buffer.from([0]), Buffer.from(body.leaf_input, 'base64')]);
const nodes = path => path.map(node => Buffer.from(node, 'base64'));

function checkSignature(head) {
  const message = Buffer.alloc(50);
  message[1] = 1;
  message.writeBigUInt64BE(BigInt(head.timestamp), 2);
  message.writeBigUInt64BE(BigInt(head.size), 10);
  Buffer.from(head.root, 'hex').copy(message, 18);
  const raw = Buffer.from(head.signature, 'hex');
  assert(raw[0] === 4 && raw[1] === 3 && raw.readUInt16BE(2) === raw.length - 4
    && crypto.verify('sha256', message, key, raw.subarray(4)), 'OpenSSL rejected the tree head signature');
}

function normalized(head) {
  const out = {size: head.tree_size, timestamp: head.timestamp, root: Buffer.from(head.sha256_root_hash, 'base64').toString('hex'),
    signature: Buffer.from(head.tree_head_signature, 'base64').toString('hex')};
  checkSignature(out);
  return out;
}

function prefixRoot(body) {
  return nodes(body.audit_path).reduce(parent, leafHash(body));
}

function checkLink(old, current, proof) {
  const expected = Buffer.from(old.root, 'hex');
  let position = 0;
  function take() {
    assert(position < proof.length, 'Truncated consistency proof');
    return Buffer.from(proof[position++], 'hex');
  }
  function split(m, n, known) {
    if (m === n) {
      const root = known ? expected : take();
      return [root, root];
    }
    let k = 1;
    while (2 * k < n) k *= 2;
    if (m <= k) {
      const [first, second] = split(m, k, known);
      return [first, parent(second, take())];
    }
    const [first, second] = split(m - k, n - k, false);
    const sibling = take();
    return [parent(sibling, first), parent(sibling, second)];
  }
  assert(old.size > 0 && old.size < current.size, 'Invalid consistency range');
  const [left, right] = split(old.size, current.size, true);
  assert(position === proof.length && left.equals(expected) && right.toString('hex') === current.root, 'Wrong CT roots');
}

async function get(query) {
  for (let i = 0; i < 3; i++) {
    try {
      const res = await fetch(LOG + query, {signal: AbortSignal.timeout(20000)});
      assert(res.ok, 'CT HTTP ' + res.status);
      return await res.json();
    } catch (error) {
      if (i === 2) throw error;
    }
  }
}

async function main() {
  const scenario = process.env.ACCORD_SCENARIO;
  assert(['valid', 'forged'].includes(scenario), 'Choose a supported scenario');
  const revision = process.env.GITHUB_SHA || '';
  assert(/^[a-f0-9]{40}$/.test(revision), 'Missing public anchor revision');
  const valid = scenario === 'valid';
  const prefix = scenario + '-';
  const anchor = 'https://raw.githubusercontent.com/mohammadisina1988-jpg/log-accord/' + revision
    + '/anchors/' + (valid ? 'argon' : 'forged') + '.json';
  const start = valid ? 3 : 0;
  const wallets = JSON.parse(process.env.ACCORD_ACCOUNTS || '[]');
  assert(wallets.length === 2 && wallets[0].address !== wallets[1].address, 'Two independent wallets required');
  const code = fs.readFileSync(path.join(root, 'contracts/log_accord.py'));
  const expected = {anchor_url: anchor, anchor_prefix_size: start, head: null, checkpoints: 0, leaf_count: 0, prefix_count: 0};
  assert(await rpc('eth_chainId', []) === '0xf22f', 'StudioNet only');

  process.env.ACCORD_ACCOUNT = wallets[0].name;
  const deployment = await invoke(prefix + 'deploy', ['deploy', '--contract', 'contracts/log_accord.py', '--args', anchor, String(start)]);
  const deployed = await receipt(prefix + 'deploy', deployment, true);
  const contract = deployed.to_address || deployed.recipient;
  assert(/^0x[0-9a-f]{40}$/i.test(contract), 'Missing deployed contract');
  assert(code.equals(Buffer.from(deployed.data.contract_code, 'base64')), 'Deployed source mismatch');
  const report = {scenario, contract, deployment, revision, source_sha256: sourceHash, trace: [], records: {}};

  async function view(label, method, args = []) {
    const cli = ['call', contract, method];
    if (args.length) cli.push('--args', ...args.map(String));
    return read(prefix + label, cli);
  }

  async function verify(label, raw, actor, args, error = null) {
    const info = receiptSummary(raw);
    assert((raw.from_address || raw.sender).toLowerCase() === wallets[actor].address, 'Wrong receipt sender');
    assert((raw.to_address || raw.recipient).toLowerCase() === contract.toLowerCase(), 'Wrong receipt recipient');
    assert(equal(await decodeReceipt(raw), args), 'Unexpected signed calldata');
    if (error) {
      const payload = Buffer.from(raw.consensus_data.leader_receipt[0].result, 'base64');
      assert(payload[0] === 1 && payload.subarray(1).toString() === error, 'Wrong revert reason: ' + label);
    }
    const state = await view(label + '-state', 'get_state');
    if (!equal(state, expected)) save(prefix + 'state-mismatch', {label, state, expected});
    assert(equal(state, expected), 'Unexpected state after ' + label);
    report.trace.push({label, ...info, signer: wallets[actor].address, args, error, state});
    save(prefix + 'progress', report);
  }
  await verify('deploy', deployed, 0, {args: [anchor, start]});

  async function write(label, actor, method, args, error, update = () => {}) {
    process.env.ACCORD_ACCOUNT = wallets[actor].name;
    const cli = ['write', contract, method];
    if (args.length) cli.push('--args', ...args.map(String));
    const tx = await invoke(prefix + label, cli);
    const raw = await receipt(prefix + label, tx, !error);
    await update();
    await verify(label, raw, actor, {method, args}, error);
  }
  await write('before-anchor', 1, 'sync', [3], 'CT anchor required');
  if (!valid) {
    await write('forged-anchor', 1, 'seed', [], 'CT head signature invalid');
  } else {
    const signed = normalized(fixture.anchor);
    const baseline = {size: 3, root: prefixRoot(fixture.small).toString('hex'),
      timestamp: signed.timestamp, signature: null};
    const initialProof = nodes(fixture.prefix.consistency).map(node => node.toString('hex'));
    checkLink(baseline, signed, initialProof);
    await write('seed', 1, 'seed', [], null, () => { expected.head = baseline; expected.checkpoints = 1; });
    report.records.anchor = await view('read-anchor', 'get_checkpoint', [3]);
    assert(equal(report.records.anchor, {head: baseline, previous_size: null, attestation: signed,
      proof: initialProof}), 'Initial prefix is not anchored to the signed tree');
    await write('sync', 0, 'sync', [3], null, async () => {
      const state = await view('live-head', 'get_state');
      const live = state.head;
      checkSignature(live);
      assert(live.size >= signed.size && live.timestamp >= signed.timestamp, 'Live head precedes the fixture');
      const link = await view('read-link', 'get_checkpoint', [live.size]);
      const api = await get('get-sth-consistency?first=3&second=' + live.size);
      const proof = nodes(api.consistency).map(node => node.toString('hex'));
      checkLink(baseline, live, proof);
      assert(equal(link, {head: live, previous_size: 3, attestation: null, proof}), 'Wrong checkpoint transition');
      report.records.live = link;
      expected.head = live;
      expected.checkpoints = 2;
    });
    const live = expected.head;
    const sourceLeaf = await get('get-entry-and-proof?leaf_index=0&tree_size=' + live.size);
    const digestLeaf = leafHash(sourceLeaf).toString('hex');
    const rawLeaf = Buffer.from(sourceLeaf.leaf_input, 'base64');
    assert(prefixRoot(sourceLeaf).toString('hex') === live.root, 'Independent leaf proof failed');
    await write('leaf', 1, 'record_leaf', [0, live.size], null, () => { expected.leaf_count = 1; });
    report.records.leaf = await view('read-leaf', 'get_leaf', [0]);
    assert(equal(report.records.leaf, {index: 0, size: live.size, root: live.root, leaf_hash: digestLeaf,
      timestamp: Number(rawLeaf.readBigUInt64BE(2)), entry_type: rawLeaf.readUInt16BE(10),
      proof: nodes(sourceLeaf.audit_path).map(node => node.toString('hex'))}), 'Wrong leaf record');
    await write('duplicate-leaf', 0, 'record_leaf', [0, live.size], 'CT leaf already recorded');
    await write('prefix', 1, 'record_prefix', [1, live.size], null, () => { expected.prefix_count = 1; });
    report.records.prefix = await view('read-prefix', 'get_prefix', [1]);
    const prefixProof = nodes((await get('get-sth-consistency?first=1&second=' + live.size)).consistency)
      .map(node => node.toString('hex'));
    checkLink({size: 1, root: digestLeaf}, live, prefixProof);
    assert(equal(report.records.prefix, {size: 1, root: digestLeaf, anchor_size: live.size,
      anchor_root: live.root, proof: prefixProof}), 'Wrong historical prefix');
    await write('stale', 0, 'sync', [3], 'Stale CT checkpoint');
  }
  assert(code.equals(Buffer.from(await rpc('gen_getContractCode', [contract]), 'base64')), 'Fresh source read mismatch');
  save(prefix + 'verified', report);
  console.log(JSON.stringify({scenario, contract, deployment, receipts: report.trace.length, state: expected}));
}

main().catch(error => { console.error(error.stack); process.exitCode = 1; });
