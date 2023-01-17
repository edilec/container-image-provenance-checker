import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyProvenance, validPolicy, TOOL_ID, RULES, LIMITS } from '../src/index.mjs';
import { inspectJsonKeys } from '../src/json-keys.mjs';
import { runCli } from '../src/cli.mjs';

const manifest = Buffer.from('{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":2},"layers":[]}');
const digest = `sha256:${createHash('sha256').update(manifest).digest('hex')}`;
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const policy = { schemaVersion: '1', expectedDigest: digest, expectedSourceCommit: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', allowedBuilders: ['synthetic-builder'], trustedKeys: [{ keyId: 'synthetic-key', publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) }] };
const payload = { schemaVersion: '1', subjectDigest: digest, sourceCommit: policy.expectedSourceCommit, builder: 'synthetic-builder' };
const signed = object => { const bytes = Buffer.from(JSON.stringify(object)); return { keyId: 'synthetic-key', payloadBase64: bytes.toString('base64'), signatureBase64: sign(null, bytes, privateKey).toString('base64') }; };
const bundle = { schemaVersion: '1', complete: true, attestations: [signed(payload)] };

test('genuine offline signature and exact OCI manifest digest pass', () => {
  const report = verifyProvenance(manifest, bundle, policy);
  assert.equal(TOOL_ID, 'container-image-provenance-checker');
  assert.equal(report.status, 'pass');
  assert.equal(report.summary.checked, 1);
  assert.equal(JSON.stringify(report).includes('synthetic-key'), false);
});

test('mismatched artifact digest fails independently of valid signature', () => {
  const report = verifyProvenance(manifest, bundle, { ...policy, expectedDigest: `sha256:${'0'.repeat(64)}` });
  assert.equal(report.status, 'fail');
  assert.ok(report.findings.some(f => f.ruleId === 'artifact-digest-mismatch'));
});

test('missing material is incomplete; tampered signature fails', () => {
  assert.equal(verifyProvenance(manifest, { ...bundle, attestations: [] }, policy).status, 'incomplete');
  const bad = structuredClone(bundle);
  bad.attestations[0].signatureBase64 = Buffer.alloc(64).toString('base64');
  const report = verifyProvenance(manifest, bad, policy);
  assert.equal(report.status, 'fail');
  assert.ok(report.findings.some(f => f.ruleId === 'signature-invalid'));
});

test('signed source or builder mismatch fails; unknown trust root cannot pass', () => {
  assert.equal(verifyProvenance(manifest, { ...bundle, attestations: [signed({ ...payload, sourceCommit: 'c'.repeat(40) })] }, policy).status, 'fail');
  assert.equal(verifyProvenance(manifest, { ...bundle, attestations: [signed({ ...payload, builder: 'unknown-builder' })] }, policy).status, 'fail');
  const unknown = structuredClone(bundle); unknown.attestations[0].keyId = 'unknown-key';
  assert.equal(verifyProvenance(manifest, unknown, policy).status, 'incomplete');
});

test('manifest byte and attestation count N/N+1 are enforced', () => {
  const atLimit = { ...bundle, attestations: Array(20).fill(bundle.attestations[0]) };
  assert.equal(verifyProvenance(manifest, atLimit, policy).status, 'pass');
  assert.equal(verifyProvenance(manifest, { ...bundle, attestations: Array(21).fill(bundle.attestations[0]) }, policy).status, 'incomplete');
  const oversized = Buffer.alloc(8 * 1024 * 1024 + 1);
  assert.equal(verifyProvenance(oversized, bundle, policy).status, 'incomplete');
});

test('injected deadline and depth are enforced', () => {
  assert.equal(verifyProvenance(manifest, bundle, policy, { now: () => 5000, deadline: 5000 }).status, 'pass');
  assert.equal(verifyProvenance(manifest, bundle, policy, { now: () => 5001, deadline: 5000 }).status, 'incomplete');
  const nested = n => Buffer.from('['.repeat(n) + '{}' + ']'.repeat(n));
  assert.equal(verifyProvenance(nested(17), bundle, policy).status, 'incomplete');
});

test('CLI passes valid files and refuses ambiguous or out-of-root evidence', () => {
  const root = mkdtempSync(join(tmpdir(), 'provenance-'));
  const outside = mkdtempSync(join(tmpdir(), 'provenance-outside-'));
  const output = () => { let stdout = ''; let stderr = ''; return { io: { stdout: { write: s => { stdout += s; } }, stderr: { write: s => { stderr += s; } } }, get stdout() { return stdout; }, get stderr() { return stderr; } }; };
  try {
    writeFileSync(join(root, 'manifest.json'), manifest);
    writeFileSync(join(root, 'policy.json'), JSON.stringify(policy));
    writeFileSync(join(root, 'bundle.json'), JSON.stringify(bundle));
    const args = ['--root', root, '--policy', 'policy.json', '--manifest', 'manifest.json', '--bundle', 'bundle.json'];
    let o = output(); assert.equal(runCli(args, o.io), 0); assert.equal(JSON.parse(o.stdout).status, 'pass');
    writeFileSync(join(root, 'bundle.json'), JSON.stringify(bundle).replace('"complete":true', '"complete":false,"complete":true'));
    o = output(); assert.equal(runCli(args, o.io), 2); assert.equal(JSON.parse(o.stdout).status, 'incomplete');
    writeFileSync(join(root, 'bundle.json'), JSON.stringify(bundle).replace('"complete":true', '"compl\\u0065te":false,"complete":true'));
    o = output(); assert.equal(runCli(args, o.io), 2); assert.equal(JSON.parse(o.stdout).status, 'incomplete');
    writeFileSync(join(outside, 'bundle.json'), JSON.stringify(bundle)); symlinkSync(join(outside, 'bundle.json'), join(root, 'linked.json'));
    o = output(); assert.equal(runCli(['--root', root, '--policy', 'policy.json', '--manifest', 'manifest.json', '--bundle', 'linked.json'], o.io), 2); assert.equal(o.stdout, '');
    o = output(); assert.equal(runCli(['--root', join(root, 'policy.json'), '--policy', 'policy.json', '--manifest', 'manifest.json', '--bundle', 'bundle.json'], o.io), 2); assert.equal(o.stdout, '');
  } finally { rmSync(root, { recursive: true, force: true }); rmSync(outside, { recursive: true, force: true }); }
});

test('signed duplicate fields and secret canaries never pass or leak', () => {
  const raw = Buffer.from('{"schemaVersion":"1","subjectDigest":"' + digest + '","sourceCommit":"' + policy.expectedSourceCommit + '","builder":"bad-canary","builder":"synthetic-builder"}');
  const attestation = { keyId: 'synthetic-key', payloadBase64: raw.toString('base64'), signatureBase64: sign(null, raw, privateKey).toString('base64') };
  const result = verifyProvenance(manifest, { ...bundle, attestations: [attestation] }, policy);
  assert.equal(result.status, 'incomplete');
  assert.equal(JSON.stringify(result).includes('bad-canary'), false);
  assert.equal(inspectJsonKeys('{"complete":false,"compl\\u0065te":true}', LIMITS.depth), 'duplicate');
});

test('declared depth and payload byte boundaries are exact', () => {
  const nested = n => '['.repeat(n) + 'null' + ']'.repeat(n);
  assert.equal(inspectJsonKeys(nested(16), LIMITS.depth), null);
  assert.equal(inspectJsonKeys(nested(17), LIMITS.depth), 'depth');
  const mk = length => { const raw = Buffer.alloc(length, 0x20); return { keyId: 'synthetic-key', payloadBase64: raw.toString('base64'), signatureBase64: sign(null, raw, privateKey).toString('base64') }; };
  const n = verifyProvenance(manifest, { ...bundle, attestations: [mk(LIMITS.payloadBytes)] }, policy);
  assert.equal(n.findings.some(f => f.ruleId === 'limit-exceeded'), false);
  const n1 = verifyProvenance(manifest, { ...bundle, attestations: [mk(LIMITS.payloadBytes + 1)] }, policy);
  assert.ok(n1.findings.some(f => f.ruleId === 'limit-exceeded'));
});

test('a trust root must be an Ed25519 public key, not a private key', () => {
  const secretPolicy = structuredClone(policy);
  secretPolicy.trustedKeys[0].publicKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.equal(validPolicy(secretPolicy), false);
});

test('rule severities are pinned in both directions', () => {
  assert.deepEqual(RULES, { 'artifact-digest-mismatch':'error', 'signature-invalid':'error', 'source-commit-mismatch':'error', 'builder-not-allowed':'error', 'verification-material-missing':'warning', 'trust-root-unknown':'warning', 'evidence-invalid':'warning', 'limit-exceeded':'warning', 'deadline-exceeded':'warning', 'policy-invalid':'warning' });
});

test('CLI byte boundaries for policy, bundle, and manifest distinguish N from N+1', () => {
  const root = mkdtempSync(join(tmpdir(), 'provenance-bounds-'));
  const capture = () => { let stdout = ''; return { io: { stdout: { write: s => { stdout += s; } }, stderr: { write() {} } }, get stdout() { return stdout; } }; };
  try {
    const base = { 'policy.json': JSON.stringify(policy), 'bundle.json': JSON.stringify(bundle), 'manifest.json': manifest.toString('utf8') };
    const args = ['--root', root, '--policy', 'policy.json', '--manifest', 'manifest.json', '--bundle', 'bundle.json'];
    for (const [name, limit] of [['policy.json', LIMITS.policyBytes], ['bundle.json', LIMITS.bundleBytes], ['manifest.json', LIMITS.manifestBytes]]) {
      for (const delta of [0, 1]) {
        for (const [file, content] of Object.entries(base)) writeFileSync(join(root, file), content);
        const content = base[name]; writeFileSync(join(root, name), content + ' '.repeat(limit + delta - Buffer.byteLength(content)));
        const o = capture(), code = runCli(args, o.io);
        if (name === 'policy.json') { assert.equal(code === 2 && o.stdout === '', delta === 1); }
        else { assert.equal(JSON.parse(o.stdout).findings.some(f => f.ruleId === 'limit-exceeded'), delta === 1); }
      }
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
