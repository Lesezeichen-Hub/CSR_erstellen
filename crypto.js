import * as asn1js from "asn1js";
import {
  Attribute, AttributeTypeAndValue, CertificationRequest, CryptoEngine,
  Extension, Extensions, ExtKeyUsage, GeneralName, GeneralNames,
  PublicKeyInfo, RelativeDistinguishedNames, setEngine,
} from "pkijs";

export const presets = Object.freeze({
  LIVE: Object.freeze(["tect.prod.d001.loc", "bek-cta-fv-012.v001.tk.loc", "tect.v001.tk.loc", "tect"]),
  LABOR: Object.freeze(["tect-labor.prod.d001.loc", "bek-cta-ft-012.v008.tk.loc", "tect-labor.v008.tk.loc"]),
});

export function validDNS(name) {
  return typeof name === "string" && name.length > 0 && name.length <= 253 && name.split(".").every((label) => /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i.test(label));
}

export function configuration({ stage, bits, cn, sans }) {
  if (!Object.hasOwn(presets, stage)) throw new Error("Bitte LIVE oder LABOR auswaehlen.");
  if (![2048, 3072, 4096].includes(bits)) throw new Error("Die RSA-Key-Laenge muss 2048, 3072 oder 4096 sein.");
  if (!validDNS(cn)) throw new Error("Der Common Name muss ein gueltiger DNS-Name sein.");
  if (!Array.isArray(sans) || sans.length === 0 || sans.length > 100 || !sans.every(validDNS)) throw new Error("Bitte 1 bis 100 gueltige alternative DNS-Namen angeben.");
  const names = new Set(sans.map((name) => name.toLowerCase()));
  if (names.size !== sans.length) throw new Error("Alternative DNS-Namen duerfen nicht doppelt vorkommen.");
  if (!names.has(cn.toLowerCase())) throw new Error("Der Common Name muss auch in den alternativen DNS-Namen enthalten sein.");
  return `[ req ]
default_bits       = ${bits}
default_md         = sha256
prompt             = no
encrypt_key        = no
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
C  = DE
O  = T-Systems International GmbH
0.OU = Barmer Infrastruktur
1.OU = Serverdienste
CN = ${cn}

[ req_ext ]
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = @alt_names

[ alt_names ]
${sans.map((name, index) => `DNS.${index + 1} = ${name}`).join("\n")}
`;
}

function encodePEM(type, buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const body = btoa(binary).match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${type}-----\n${body}\n-----END ${type}-----\n`;
}

export async function generateArtifacts(input) {
  const config = configuration(input);
  if (!globalThis.crypto?.subtle) throw new Error("Browser-Kryptografie ist nicht verfuegbar. Bitte den Hub ueber localhost, 127.0.0.1 oder HTTPS oeffnen.");
  const nativeCrypto = globalThis.crypto;
  setEngine("WebCrypto", nativeCrypto, new CryptoEngine({ name: "WebCrypto", crypto: nativeCrypto, subtle: nativeCrypto.subtle }));
  const pair = await nativeCrypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: input.bits, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const publicDER = await nativeCrypto.subtle.exportKey("spki", pair.publicKey);
  const publicSchema = asn1js.fromBER(publicDER);
  if (publicSchema.offset === -1) throw new Error("Der oeffentliche Schluessel konnte nicht gelesen werden.");
  const subject = [
    ["2.5.4.6", new asn1js.PrintableString({ value: "DE" })],
    ["2.5.4.10", new asn1js.Utf8String({ value: "T-Systems International GmbH" })],
    ["2.5.4.11", new asn1js.Utf8String({ value: "Barmer Infrastruktur" })],
    ["2.5.4.11", new asn1js.Utf8String({ value: "Serverdienste" })],
    ["2.5.4.3", new asn1js.Utf8String({ value: input.cn })],
  ];
  const extensions = [
    new Extension({ extnID: "2.5.29.15", critical: true, extnValue: new asn1js.BitString({ unusedBits: 5, valueHex: new Uint8Array([0xa0]).buffer }).toBER(false) }),
    new Extension({ extnID: "2.5.29.37", extnValue: new ExtKeyUsage({ keyPurposes: ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"] }).toSchema().toBER(false) }),
    new Extension({ extnID: "2.5.29.17", extnValue: new GeneralNames({ names: input.sans.map((name) => new GeneralName({ type: 2, value: name })) }).toSchema().toBER(false) }),
  ];
  const csr = new CertificationRequest({
    version: 0,
    subject: new RelativeDistinguishedNames({ typesAndValues: subject.map(([type, value]) => new AttributeTypeAndValue({ type, value })) }),
    subjectPublicKeyInfo: new PublicKeyInfo({ schema: publicSchema.result }),
    attributes: [new Attribute({ type: "1.2.840.113549.1.9.14", values: [new Extensions({ extensions }).toSchema()] })],
  });
  await csr.sign(pair.privateKey, "SHA-256");
  const privateDER = await nativeCrypto.subtle.exportKey("pkcs8", pair.privateKey);
  try {
    return { config, key: encodePEM("PRIVATE KEY", privateDER), csr: encodePEM("CERTIFICATE REQUEST", csr.toSchema().toBER(false)) };
  } finally { new Uint8Array(privateDER).fill(0); }
}