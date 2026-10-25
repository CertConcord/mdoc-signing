# mdoc Signing Certificates

Issuer-certified document keys and signing purposes carried by mdoc credentials, with distinct issuer authentication, holder authentication and document signatures.

**Draft 02. No stable release or upstream adoption is claimed.**

[Draft](draft.md) defines the technical scope and limits. [Sources](sources.json) pins the upstream documents. [Cases](cases.json) identifies the positive and negative evaluation cases.

This repository can be reviewed and used independently of the CertConcord framework. It does not require the framework's authority hierarchy, operation objects or deployment. The framework selects this work through a pinned dependency and adds its own integration policy.

The base reference owns CBOR, issuerAuth/MSO checks, certified key and purpose rules, explicit authorization/status interfaces, and detached COSE signatures. [Serialized vectors](vectors/base.json) contain complete credentials, signatures, documents, certificates and signed status fixtures; their [manifest](vectors/manifest.json) pins exact bytes. [CBOR text vectors](vectors/cbor-text.json) cover exact Unicode text, distinct keys and malformed encodings. The published ISO 2021 baseline and the separately reviewed public WG10 working text are distinguished in the draft. No full ISO conformance or independent security assessment is claimed.

Run with Node.js 24.15 or later:

    npm run check
    npm test

Original text is licensed under [CC BY 4.0](LICENSES/CC-BY-4.0.txt), software under [Apache-2.0](LICENSE), and original synthetic vectors under [CC0](LICENSES/CC0-1.0.txt). Upstream material is referenced under its own terms. See [NOTICE](NOTICE) and [contributions](CONTRIBUTING.md).
