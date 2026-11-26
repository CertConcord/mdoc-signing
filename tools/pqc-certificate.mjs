import { createPublicKey, sign, X509Certificate } from 'node:crypto';

// Synthetic RFC 9881 certificate fixtures. This small DER writer is used only
// by vector builders; application certificate validation remains external.
const length = size => size < 128 ? Buffer.from([size]) : (() => {
  const bytes = [];
  for (let value = size; value; value = Math.floor(value / 256)) bytes.unshift(value & 255);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
})();
const tlv = (tag, value) => Buffer.concat([Buffer.from([tag]), length(value.length), value]);
const seq = (...values) => tlv(0x30, Buffer.concat(values));
const set = (...values) => tlv(0x31, Buffer.concat(values));
const octet = value => tlv(0x04, value);
const bitString = (value, unused = 0) => tlv(0x03, Buffer.concat([Buffer.from([unused]), value]));
const utf8 = value => tlv(0x0c, Buffer.from(value, 'utf8'));
const bool = value => tlv(0x01, Buffer.from([value ? 0xff : 0]));
const integer = value => {
  const bytes = [];
  for (let number = value; number; number = Math.floor(number / 256)) bytes.unshift(number & 255);
  if (!bytes.length || bytes[0] & 0x80) bytes.unshift(0);
  return tlv(0x02, Buffer.from(bytes));
};
const oid = dotted => {
  const arcs = dotted.split('.').map(Number);
  const encodeArc = value => {
    const bytes = [value & 127];
    for (let n = Math.floor(value / 128); n; n = Math.floor(n / 128)) bytes.unshift((n & 127) | 0x80);
    return bytes;
  };
  return tlv(0x06, Buffer.from([...encodeArc(arcs[0] * 40 + arcs[1]), ...arcs.slice(2).flatMap(encodeArc)]));
};
const name = value => seq(set(seq(oid('2.5.4.3'), utf8(value))));
const utc = seconds => {
  const date = new Date(seconds * 1000).toISOString();
  return tlv(0x17, Buffer.from(date.slice(2, 4) + date.slice(5, 7) + date.slice(8, 10) +
    date.slice(11, 13) + date.slice(14, 16) + date.slice(17, 19) + 'Z'));
};
const extension = (id, value) => seq(oid(id), bool(true), octet(value));
const signatureAlgorithm = seq(oid('2.16.840.1.101.3.4.3.18'));

export function syntheticPqcCertificate({ subjectKey, signerKey, subject, issuer, serial, at, ca }) {
  if (subjectKey.asymmetricKeyType !== 'ml-dsa-65' || signerKey.asymmetricKeyType !== 'ml-dsa-65')
    throw new Error('Synthetic certificate requires ML-DSA-65 keys');
  const extensions = [
    extension('2.5.29.19', ca ? seq(bool(true)) : seq()),
    extension('2.5.29.15', ca ? bitString(Buffer.from([0x06]), 1) : bitString(Buffer.from([0x80]), 7)),
  ];
  if (!ca) extensions.push(extension('2.5.29.37', seq(oid('1.0.18013.5.1.2'))));
  const tbs = seq(tlv(0xa0, integer(2)), integer(serial), signatureAlgorithm, name(issuer),
    seq(utc(at - 60), utc(at + 86400)), name(subject),
    subjectKey.export({ type: 'spki', format: 'der' }), tlv(0xa3, seq(...extensions)));
  const der = seq(tbs, signatureAlgorithm, bitString(sign(null, tbs, signerKey)));
  const certificate = new X509Certificate(der);
  if (!certificate.verify(createPublicKey(signerKey)))
    throw new Error('Synthetic certificate self-check failed');
  return der;
}
