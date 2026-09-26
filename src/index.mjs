import { createHash, createPublicKey, verify } from 'node:crypto';
import { inspectJsonKeys } from './json-keys.mjs';

export const TOOL_ID = 'container-image-provenance-checker';
export const LIMITS = Object.freeze({ manifestBytes: 8 * 1024 * 1024, bundleBytes: 1024 * 1024, policyBytes: 65536, payloadBytes: 65536, attestations: 20, depth: 16, milliseconds: 5000 });
export const RULES = Object.freeze({
  'artifact-digest-mismatch': 'error', 'signature-invalid': 'error', 'source-commit-mismatch': 'error', 'builder-not-allowed': 'error',
  'verification-material-missing': 'warning', 'trust-root-unknown': 'warning', 'evidence-invalid': 'warning', 'limit-exceeded': 'warning', 'deadline-exceeded': 'warning', 'policy-invalid': 'warning'
});
const hex = value => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const b64 = value => typeof value === 'string' && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value) && Buffer.from(value, 'base64').toString('base64') === value;
const only = (value, names) => Object.keys(value).every(k => names.includes(k));
const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
function report(findings, checked) {
  findings.sort((a, b) => compare(a.location.file, b.location.file) || compare(a.location.pointer, b.location.pointer) || compare(a.ruleId, b.ruleId));
  const status = findings.some(f => f.severity === 'warning') ? 'incomplete' : findings.some(f => f.severity === 'error') ? 'fail' : checked ? 'pass' : 'incomplete';
  return { schemaVersion: '1', tool: TOOL_ID, status, summary: { checked, errors: findings.filter(f => f.severity === 'error').length, warnings: findings.filter(f => f.severity === 'warning').length }, findings };
}
export function makeFinding(ruleId, file, pointer, message) {
  if (!(ruleId in RULES)) throw new Error('Unknown rule');
  return { ruleId, severity: RULES[ruleId], message, location: { file, pointer } };
}
export function validPolicy(policy) {
  if (!object(policy) || !only(policy, ['schemaVersion', 'expectedDigest', 'expectedSourceCommit', 'allowedBuilders', 'trustedKeys']) || policy.schemaVersion !== '1' || !hex(policy.expectedDigest) || !/^[0-9a-f]{40}$/.test(policy.expectedSourceCommit) || !Array.isArray(policy.allowedBuilders) || !policy.allowedBuilders.length || !policy.allowedBuilders.every(s => typeof s === 'string' && /^[A-Za-z0-9._-]{1,128}$/.test(s)) || !Array.isArray(policy.trustedKeys) || !policy.trustedKeys.length || policy.trustedKeys.length > 20) return false;
  const seen = new Set();
  try {
    return policy.trustedKeys.every(k => {
      if (!object(k) || !only(k, ['keyId', 'publicKeyPem']) || typeof k.keyId !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(k.keyId) || seen.has(k.keyId) || typeof k.publicKeyPem !== 'string' || !/^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n$/.test(k.publicKeyPem)) return false;
      seen.add(k.keyId);
      const key = createPublicKey(k.publicKeyPem);
      return key.asymmetricKeyType === 'ed25519';
    });
  } catch { return false; }
}
export function verifyProvenance(manifestBytes, bundle, policy, { now = Date.now, deadline = now() + LIMITS.milliseconds } = {}) {
  const findings = [];
  const add = (id, file, pointer, message) => findings.push(makeFinding(id, file, pointer, message));
  if (!validPolicy(policy)) { add('policy-invalid', '@policy', '', 'Trust policy is invalid or incomplete.'); return report(findings, 0); }
  if (!Buffer.isBuffer(manifestBytes) || manifestBytes.length > LIMITS.manifestBytes) { add('limit-exceeded', '@manifest', '', 'Manifest is absent or exceeds byte limit.'); return report(findings, 0); }
  if (now() > deadline) { add('deadline-exceeded', '@manifest', '', 'Verification deadline exceeded.'); return report(findings, 0); }
  let manifest;
  try { const raw = new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes); manifest = JSON.parse(raw); if (inspectJsonKeys(raw, LIMITS.depth)) throw new Error('Ambiguous manifest'); } catch { add('evidence-invalid', '@manifest', '', 'Manifest is not unambiguous UTF-8 JSON within depth limit.'); return report(findings, 0); }
  if (!object(manifest) || manifest.schemaVersion !== 2 || manifest.mediaType !== 'application/vnd.oci.image.manifest.v1+json' || !object(manifest.config) || !hex(manifest.config.digest) || !Number.isSafeInteger(manifest.config.size) || manifest.config.size < 0 || !Array.isArray(manifest.layers) || !manifest.layers.every(x => object(x) && hex(x.digest) && Number.isSafeInteger(x.size) && x.size >= 0)) { add('evidence-invalid', '@manifest', '', 'OCI manifest shape is unsupported or invalid.'); return report(findings, 0); }
  const digest = `sha256:${createHash('sha256').update(manifestBytes).digest('hex')}`;
  if (digest !== policy.expectedDigest) add('artifact-digest-mismatch', '@manifest', '', 'Manifest bytes do not match configured artifact digest.');
  if (!object(bundle) || !only(bundle, ['schemaVersion', 'complete', 'attestations']) || bundle.schemaVersion !== '1' || bundle.complete !== true || !Array.isArray(bundle.attestations)) { add('verification-material-missing', '@bundle', '', 'Complete signature bundle is required.'); return report(findings, 0); }
  if (bundle.attestations.length > LIMITS.attestations) { add('limit-exceeded', '@bundle', '/attestations', 'Attestation count exceeds limit.'); return report(findings, 0); }
  if (bundle.attestations.length === 0) { add('verification-material-missing', '@bundle', '/attestations', 'At least one attestation is required.'); return report(findings, 0); }
  let checked = 0;
  for (let i = 0; i < bundle.attestations.length; i++) {
    if (now() > deadline) { add('deadline-exceeded', '@bundle', `/attestations/${i}`, 'Verification deadline exceeded.'); break; }
    const a = bundle.attestations[i], at = `/attestations/${i}`;
    if (!object(a) || !only(a, ['keyId', 'payloadBase64', 'signatureBase64']) || !b64(a.payloadBase64) || !b64(a.signatureBase64)) { add('evidence-invalid', '@bundle', at, 'Attestation encoding is invalid.'); continue; }
    const payloadBytes = Buffer.from(a.payloadBase64, 'base64'), signature = Buffer.from(a.signatureBase64, 'base64');
    if (payloadBytes.length > LIMITS.payloadBytes) { add('limit-exceeded', '@bundle', `${at}/payloadBase64`, 'Signed payload exceeds byte limit.'); continue; }
    if (signature.length !== 64) { add('evidence-invalid', '@bundle', `${at}/signatureBase64`, 'Signature size is invalid.'); continue; }
    const trusted = policy.trustedKeys.find(k => k.keyId === a.keyId);
    if (!trusted) { add('trust-root-unknown', '@bundle', `${at}/keyId`, 'Attestation key is not in configured trust roots.'); continue; }
    if (!verify(null, payloadBytes, createPublicKey(trusted.publicKeyPem), signature)) { add('signature-invalid', '@bundle', `${at}/signatureBase64`, 'Signature does not verify for signed payload.'); continue; }
    let payload;
    try { const raw = new TextDecoder('utf-8', { fatal: true }).decode(payloadBytes); payload = JSON.parse(raw); if (inspectJsonKeys(raw, LIMITS.depth)) throw new Error('Ambiguous signed payload'); } catch { add('evidence-invalid', '@bundle', `${at}/payloadBase64`, 'Signed payload is not unambiguous UTF-8 JSON within depth limit.'); continue; }
    if (!object(payload) || !only(payload, ['schemaVersion', 'subjectDigest', 'sourceCommit', 'builder']) || payload.schemaVersion !== '1' || !hex(payload.subjectDigest) || !/^[0-9a-f]{40}$/.test(payload.sourceCommit) || typeof payload.builder !== 'string') { add('evidence-invalid', '@bundle', `${at}/payloadBase64`, 'Signed provenance shape is invalid.'); continue; }
    checked++;
    if (payload.subjectDigest !== digest) add('artifact-digest-mismatch', '@bundle', `${at}/payloadBase64`, 'Signed subject digest does not match manifest bytes.');
    if (payload.sourceCommit !== policy.expectedSourceCommit) add('source-commit-mismatch', '@bundle', `${at}/payloadBase64`, 'Signed source commit differs from policy.');
    if (!policy.allowedBuilders.includes(payload.builder)) add('builder-not-allowed', '@bundle', `${at}/payloadBase64`, 'Signed builder is not permitted by policy.');
  }
  if (!checked && !findings.length) add('verification-material-missing', '@bundle', '', 'No verifiable attestation was checked.');
  return report(findings, checked);
}
