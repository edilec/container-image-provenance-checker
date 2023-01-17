# Container Image Provenance Checker

Offline, read-only check of an exported OCI image manifest against a caller-supplied expected SHA-256 digest and an Ed25519-signed provenance bundle. It never contacts a registry, pulls an image, discovers trust roots, or signs anything. The trust policy must contain the public keys the operator already trusts. A signature over the wrong digest, source commit, or builder is not a pass.

Requires Node.js 22 or newer; zero runtime dependencies. `TOOL_ID` and `verifyProvenance(manifestBytes, bundle, policy, {now, deadline})` are exported from `src/index.mjs`. The CLI reads only local files:

```sh
node bin/container-image-provenance-checker.mjs --root examples --policy policy.json --manifest manifest.json --bundle bundle.json
node bin/container-image-provenance-checker.mjs --root examples --policy failing-policy.json --manifest manifest.json --bundle bundle.json
```

The first command exits 0; the second exits 1 with `artifact-digest-mismatch`. Fixtures use synthetic source identifiers and a public-only test key. The private fixture signing key was ephemeral and is not packaged.

## Input contract

The manifest is exact UTF-8 JSON bytes of an OCI image manifest (`schemaVersion: 2`, OCI image-manifest media type, config descriptor and layer descriptors). `expectedDigest` is SHA-256 of **all exact manifest file bytes**, including whitespace. The bundle is JSON `{schemaVersion:"1",complete:true,attestations:[{keyId,payloadBase64,signatureBase64}]}`. Each canonical-base64 Ed25519 signature covers the exact decoded payload bytes. The payload is JSON `{schemaVersion:"1",subjectDigest,sourceCommit,builder}`. Policy is JSON `{schemaVersion:"1",expectedDigest,expectedSourceCommit,allowedBuilders,trustedKeys:[{keyId,publicKeyPem}]}`; keys must parse as Ed25519 public keys. Unknown policy fields are rejected. All digest and commit values are lowercase hex. `complete` must be explicitly true. Every listed attestation is checked; unverifiable evidence prevents a pass.

| Rule ID | Severity | Result |
| --- | --- | --- |
| artifact-digest-mismatch | error | fail |
| signature-invalid | error | fail |
| source-commit-mismatch | error | fail |
| builder-not-allowed | error | fail |
| verification-material-missing | warning | incomplete |
| trust-root-unknown | warning | incomplete |
| evidence-invalid | warning | incomplete |
| limit-exceeded | warning | incomplete |
| deadline-exceeded | warning | incomplete |
| policy-invalid | warning | incomplete (library; CLI rejects config with empty stdout) |

Reports follow the v1 envelope with `status` pass/fail/incomplete, summary counts, and code-unit-sorted findings. `@policy`, `@manifest`, and `@bundle` are fixed logical source roles, not host paths; JSON pointers and zero-based attestation ordinals locate evidence in the files named at invocation. No input values, file paths, key material, signed payloads, or raw parse errors appear in reports. Exit codes: 0 pass; 1 completed policy failure; 2 incomplete evidence or invalid configuration. Invalid usage/policy/path writes only a bounded stderr diagnostic and leaves stdout empty. Unreadable/invalid subject input writes an incomplete JSON report on stdout. The root must be a directory; all input paths must be relative and realpath-confined to it.

## Bounds and non-goals

Manifest ≤8 MiB; bundle ≤1 MiB; policy ≤64 KiB; signed payload ≤64 KiB; ≤20 attestations; JSON nesting depth ≤16; injected verification deadline 5 seconds. A bound breach is incomplete, not truncated. UTF-8 decoding is strict and duplicate JSON object keys, including escaped aliases, are rejected. CLI `now` and library `now` are injectable for deterministic deadline tests. The checker does not validate a registry's live tag-to-digest mapping, image layer bytes, source repository contents, CI identity, certificate chains, transparency logs, revocation, or builder provenance beyond the configured exact strings. The operator must independently establish that their policy key and expected values are trustworthy.

Run `npm run check` for syntax and tests. No network is needed.
