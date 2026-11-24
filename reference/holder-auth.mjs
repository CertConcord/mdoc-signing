import { verify } from 'node:crypto';
import { Tag, decode, embedded, encode, get } from './cbor.mjs';
import { SIGNING_DOCTYPE, verifyIssuerSigned } from './base.mjs';
import { requireThat } from './errors.mjs';

const same = (a, b) => Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.equals(b);
const emptyNameSpaces = () => embedded(new Map());
const protectedBytes = encode(new Map([[1, -7]]));

function transcript(bytes) {
  requireThat(Buffer.isBuffer(bytes), 'MDOC_SESSION_TRANSCRIPT');
  const retained = Buffer.from(bytes), value = decode(retained);
  requireThat(Array.isArray(value) && value.length === 3 && value[2] !== null && same(encode(value), retained), 'MDOC_SESSION_TRANSCRIPT');
  return value;
}

function deviceAuthentication(sessionTranscript, docType, nameSpaces) {
  requireThat(typeof docType === 'string' && docType.length > 0, 'MDOC_HOLDER_DOCTYPE');
  return encode(embedded(['DeviceAuthentication', transcript(sessionTranscript), docType, nameSpaces]));
}

function signatureInput(sessionTranscript, docType, nameSpaces, receivedProtected = protectedBytes) {
  const payload = deviceAuthentication(sessionTranscript, docType, nameSpaces);
  return encode(['Signature1', receivedProtected, Buffer.alloc(0), payload]);
}

// This selected proof carries no device namespace claims. The caller supplies the
// exact session transcript and is responsible for its challenge and freshness.
export function prepareHolderAuthentication(sessionTranscript, { holderPublicKey, docType = SIGNING_DOCTYPE } = {}) {
  requireThat(holderPublicKey?.asymmetricKeyType === 'ec' && holderPublicKey.asymmetricKeyDetails.namedCurve === 'prime256v1', 'MDOC_HOLDER_KEY');
  const nameSpaces = emptyNameSpaces(), tbs = signatureInput(sessionTranscript, docType, nameSpaces);
  return { tbs: Buffer.from(tbs), finish(signature) {
    requireThat(Buffer.isBuffer(signature) && signature.length === 64 && verify('sha256', tbs, { key: holderPublicKey, dsaEncoding: 'ieee-p1363' }, signature), 'MDOC_HOLDER_SIGNATURE');
    return encode({ nameSpaces, deviceAuth: { deviceSignature: [protectedBytes, new Map(), null, Buffer.from(signature)] } });
  } };
}

// Holder control at one session transcript is separate from issuer authorization,
// credential status and the document-signing key's detached COSE signature.
export function verifyHolderAuthentication(deviceSigned, credential, {
  issuerKey, certificate, at, sessionTranscript, docType = SIGNING_DOCTYPE,
} = {}) {
  requireThat(Buffer.isBuffer(deviceSigned) && Buffer.isBuffer(credential), 'MDOC_HOLDER_BYTES');
  const facts = verifyIssuerSigned(Buffer.from(credential), { issuerKey, certificate, at, docType });
  const value = decode(Buffer.from(deviceSigned));
  requireThat(value instanceof Map && value.size === 2 && value.has('nameSpaces') && value.has('deviceAuth'), 'MDOC_DEVICE_SIGNED');
  const nameSpaces = get(value, 'nameSpaces'), auth = get(value, 'deviceAuth');
  requireThat(nameSpaces instanceof Tag && nameSpaces.tag === 24 && Buffer.isBuffer(nameSpaces.value), 'MDOC_DEVICE_NAMESPACES');
  const deviceNameSpaces = decode(nameSpaces.value);
  requireThat(deviceNameSpaces instanceof Map && same(nameSpaces.value, encode(deviceNameSpaces)), 'MDOC_DEVICE_NAMESPACES');
  requireThat(deviceNameSpaces.size === 0, 'MDOC_DEVICE_NAMESPACES_UNSUPPORTED', 'UNSUPPORTED');
  requireThat(auth instanceof Map, 'MDOC_HOLDER_AUTH');
  requireThat(!auth.has('deviceMac'), 'MDOC_HOLDER_MAC_UNSUPPORTED', 'UNSUPPORTED');
  requireThat(auth.size === 1 && auth.has('deviceSignature'), 'MDOC_HOLDER_AUTH');
  const cose = auth.get('deviceSignature');
  requireThat(Array.isArray(cose) && cose.length === 4 && Buffer.isBuffer(cose[0]) && cose[1] instanceof Map && cose[1].size === 0 && cose[2] === null && Buffer.isBuffer(cose[3]), 'MDOC_HOLDER_COSE');
  const headers = decode(cose[0]);
  requireThat(headers instanceof Map && headers.get(1) === -7, 'MDOC_HOLDER_ALGORITHM');
  const tbs = signatureInput(sessionTranscript, docType, nameSpaces, cose[0]);
  requireThat(cose[3].length === 64 && verify('sha256', tbs, { key: facts.holderPublicKey, dsaEncoding: 'ieee-p1363' }, cose[3]), 'MDOC_HOLDER_SIGNATURE');
  requireThat(same(cose[0], protectedBytes), 'MDOC_HOLDER_HEADERS');
  return { issuerFacts: facts, holderProof: { tbs, signature: Buffer.from(cose[3]) } };
}
