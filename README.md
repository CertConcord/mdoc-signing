# mdoc Signing Certificates

Issuer-certified document keys and signing purposes carried by mdoc credentials, with distinct issuer authentication, holder authentication and document signatures.

**Draft 03. Experimental PQ mdoc extension; no ISO algorithm-suite conformance, stable release or upstream adoption is claimed.**

[Draft](draft.md) defines the technical scope and limits. [Sources](sources.json) pins the upstream documents. [Cases](cases.json) identifies the positive and negative evaluation cases.

This repository can be reviewed and used independently of the CertConcord framework. It does not require the framework's authority hierarchy, operation objects or deployment. The framework selects this work through a pinned dependency and adds its own integration policy.

The base reference owns CBOR, ML-DSA issuerAuth/MSO and certificate-path checks, certified key and purpose rules, explicit issuer authorization and status interfaces, and detached COSE document signatures. A separate [holder-authentication primitive](reference/holder-auth.mjs) verifies a session-bound ML-DSA DeviceSigned signature with the MSO device key; it grants no document-signing authority. [Complete PQ vectors](vectors/pqc-base.json) contain a synthetic ML-DSA certificate path, credential, holder proof, document signature and signed status token with rejection cases. [PQ issuer-header vectors](vectors/pqc-issuer-headers.json) isolate exact received protected bytes and valid or invalid ML-DSA issuer signatures without granting issuer authority. [PQ identifier vectors](vectors/pqc-identifiers.json) pair distinct and reused subject/credential identifiers under otherwise valid signed credentials and documents. [PQ status-binding vectors](vectors/pqc-status-binding.json) pin a complete credential and mathematically valid status tokens rejected for wrong URI claims, an alternate PQ signer, stale `ttl` or missing knowledge time. [PQ document-header vectors](vectors/pqc-document-headers.json) pin canonical critical labels and mathematically valid rejected alternatives for the detached-signature primitive. [Holder vectors](vectors/holder-auth.json) test the separate device proof. [Historical v2 vectors](vectors/base.json) remain available only through an explicit classical-legacy option. Their [manifest](vectors/manifest.json) pins exact bytes. [CBOR text vectors](vectors/cbor-text.json) cover exact Unicode text, distinct keys and malformed encodings. The [PQC source note](reference/pqc-research-2026-11-25.md) distinguishes published cryptographic encodings from the reviewed public WG10 working text and this experimental extension. No full ISO conformance or independent security assessment is claimed.

[PQ certificate-path key-role vectors](vectors/pqc-ca-key-role.json) show a distinct document key and reject mathematically valid document signatures made with the selected root or intermediate CA key.

[PQ holder/CA key-role vectors](vectors/pqc-holder-ca-key-role.json) retain mathematically valid device and document signatures while rejecting a holder key reused from the selected root or intermediate CA path.

[CBOR map-key encoder vectors](vectors/cbor-encode-map-keys.json) retain the bytes formerly emitted for duplicate integer labels and an unselected byte-string label, alongside valid distinct labels. The encoder now refuses inputs that its selected decoder would reject for those key violations.

Run with Node.js 24.15 or later:

    npm run check
    npm test

Original text is licensed under [CC BY 4.0](LICENSES/CC-BY-4.0.txt), software under [Apache-2.0](LICENSE), and original synthetic vectors under [CC0](LICENSES/CC0-1.0.txt). Upstream material is referenced under its own terms. See [NOTICE](NOTICE) and [contributions](CONTRIBUTING.md).
