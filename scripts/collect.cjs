const fs = require('node:fs');
const path = require('node:path');
const {root, assert, digest, equal, sourceHash, receiptSummary, save} = require('./transport.cjs');

const runs = process.argv.slice(2);
const cases = {
  valid: ['deploy', 'before-anchor', 'seed', 'sync', 'leaf', 'duplicate-leaf', 'prefix', 'stale'],
  forged: ['deploy', 'before-anchor', 'forged-anchor'],
};
const errors = {
  'before-anchor': 'CT anchor required', 'duplicate-leaf': 'CT leaf already recorded',
  stale: 'Stale CT checkpoint', 'forged-anchor': 'CT head signature invalid',
};
const explorer = 'https://explorer-studio.genlayer.com/';
const repo = 'https://github.com/mohammadisina1988-jpg/log-accord';
assert(runs.length === 2 && runs.every(id => /^\d+$/.test(id)) && runs[0] !== runs[1],
  'Pass the completed valid and forged run IDs');

const instances = [];
const files = [];
let successes = 0;
let rejections = 0;
let revision;
for (const [i, [scenario, labels]] of Object.entries(cases).entries()) {
  const folder = path.join(root, '.proof-journal', 'run-' + runs[i]);
  const read = label => JSON.parse(fs.readFileSync(path.join(folder, scenario + '-' + label + '.json')));
  const report = read('verified');
  revision ??= report.revision;
  assert(report.scenario === scenario && report.source_sha256 === sourceHash && report.revision === revision,
    'Proof source or fixture mismatch');
  assert(equal(report.trace.map(step => step.label), labels), 'Unexpected receipt order');
  let previous;
  for (const step of report.trace) {
    const raw = read(step.label + '-receipt');
    const summary = receiptSummary(raw);
    assert(summary.hash === step.hash && summary.status === 'FINALIZED' && summary.result === 'MAJORITY_AGREE'
      && summary.agree > (summary.agree + summary.disagree + summary.idle) / 2, 'Finalized strict majority required');
    assert((raw.from_address || raw.sender).toLowerCase() === step.signer
      && (raw.to_address || raw.recipient).toLowerCase() === report.contract.toLowerCase(), 'Receipt identity mismatch');
    if (step.label === 'deploy') {
      assert(summary.hash === report.deployment && digest(Buffer.from(raw.data.contract_code, 'base64')) === sourceHash,
        'Deployment source mismatch');
    }
    const error = errors[step.label];
    if (error) {
      const payload = Buffer.from(raw.consensus_data.leader_receipt[0].result, 'base64');
      assert(summary.execution === 'ERROR' && payload[0] === 1 && payload.subarray(1).toString() === error
        && equal(step.state, previous), 'Expected rejection with unchanged state');
      rejections++;
    } else {
      assert(['SUCCESS', 'FINISHED_WITH_RETURN'].includes(summary.execution), 'Expected successful execution');
      successes++;
    }
    previous = step.state;
    files.push([scenario + '-' + step.label + '-receipt', raw]);
  }
  if (scenario === 'valid') {
    const {anchor, live, leaf, prefix} = report.records;
    assert(report.trace[0].signer !== report.trace[2].signer && anchor.head.size === 3
      && live.previous_size === 3 && live.head.size >= anchor.attestation.size
      && live.head.root === previous.head.root && leaf.size === live.head.size && leaf.root === live.head.root
      && prefix.size === 1 && prefix.root === leaf.leaf_hash && prefix.anchor_root === live.head.root
      && previous.checkpoints === 2 && previous.leaf_count === 1 && previous.prefix_count === 1, 'Wrong verified records');
  } else {
    assert(previous.head === null && previous.checkpoints === 0, 'Forged anchor modified state');
  }
  const result = report.trace.find(step => step.label === (scenario === 'valid' ? 'sync' : 'forged-anchor'));
  instances.push({scenario, contract: report.contract, deployment: report.deployment, result: result.hash,
    head: previous.head, records: report.records, workflow: repo + '/actions/runs/' + runs[i]});
  files.push([scenario + '-verified', report]);
}

for (const [name, value] of files) save(name, value);
save('index', {source_sha256: sourceHash, revision, successes, rejections, instances});
const rows = instances.map(x => '| ' + [
  x.scenario, '[Contract](' + explorer + 'address/' + x.contract + ')',
  '[Deploy](' + explorer + 'tx/' + x.deployment + ')',
  '[Result](' + explorer + 'tx/' + x.result + ')', '[Run](' + x.workflow + ')',
].join(' | ') + ' |');
fs.writeFileSync(path.join(root, 'proofs/README.md'), [
  '# LogAccord StudioNet proofs', '',
  'Verified ' + (successes + rejections) + ' finalized receipts across two deployments, with '
    + successes + ' successful calls and ' + rejections + ' expected rejections.', '',
  '| Scenario | Address | Deployment | Result | Workflow |', '|---|---|---|---|---|', ...rows, '',
  'The valid instance advanced from three leaves to ' + instances[0].head.size.toLocaleString('en-US')
    + ' leaves, then verified one public CT entry and an earlier prefix.',
  'The forged instance rejected the modified root and retained zero checkpoints.', '',
  'Source SHA-256: `' + sourceHash + '`.', 'Fixture commit: `' + revision + '`.', '',
].join('\n'));
console.log(JSON.stringify({sourceHash, successes, rejections, instances: instances.map(x => ({
  scenario: x.scenario, contract: x.contract, deployment: x.deployment, result: x.result, head: x.head, workflow: x.workflow,
}))}, null, 2));
