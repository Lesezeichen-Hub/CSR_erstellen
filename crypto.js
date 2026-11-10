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

export async function inspectCSR(pem) {
  const body = pem.replace("-----BEGIN CERTIFICATE REQUEST-----", "").replace("-----END CERTIFICATE REQUEST-----", "").replace(/\s/g, "");
  const bytes = Uint8Array.from(atob(body), (character) => character.charCodeAt(0));
  const schema = asn1js.fromBER(bytes.buffer);
  if (schema.offset === -1 || schema.offset !== bytes.length) throw new Error("Der CSR konnte nicht gelesen werden.");
  const request = new CertificationRequest({ schema: schema.result });
  const verified = await request.verify();
  const subjectNames = { "2.5.4.6": "C", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.3": "CN" };
  const subject = request.subject.typesAndValues.map((part) => `${subjectNames[part.type] || part.type} = ${part.value.valueBlock.value}`).join(", ");
  const publicKey = asn1js.fromBER(request.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView).result;
  const [modulusValue, exponentValue] = publicKey.valueBlock.value;
  const encodedModulus = modulusValue.valueBlock.valueHexView;
  const modulus = encodedModulus[0] === 0 ? encodedModulus.subarray(1) : encodedModulus;
  const bits = (modulus.length - 1) * 8 + Math.floor(Math.log2(modulus[0])) + 1;
  const exponent = exponentValue.valueBlock.valueHexView.reduce((value, byte) => value * 256 + byte, 0);
  const hexLines = (value, indent) => {
    const hex = Array.from(value, (byte) => byte.toString(16).padStart(2, "0"));
    const lines = [];
    for (let offset = 0; offset < hex.length; offset += 15) lines.push(`${indent}${hex.slice(offset, offset + 15).join(":")}`);
    return lines.join("\n");
  };
  const lines = [
    "Pruefung lokal im Browser (PKIjs/Web Crypto; OpenSSL-aehnliches Format)",
    verified ? "Certificate request self-signature verify OK" : "Certificate request self-signature verify FAILURE",
    "Certificate Request:",
    "    Data:",
    `        Version: ${request.version + 1} (0x${request.version.toString(16)})`,
    `        Subject: ${subject}`,
    "        Subject Public Key Info:",
    `            Public Key Algorithm: ${request.subjectPublicKeyInfo.algorithm.algorithmId === "1.2.840.113549.1.1.1" ? "rsaEncryption" : request.subjectPublicKeyInfo.algorithm.algorithmId}`,
    `                Public-Key: (${bits} bit)`,
    "                Modulus:",
    hexLines(encodedModulus, "                    "),
    `                Exponent: ${exponent} (0x${exponent.toString(16)})`,
    "        Attributes:",
    "            Requested Extensions:",
  ];
  for (const attribute of request.attributes || []) {
    if (attribute.type !== "1.2.840.113549.1.9.14") continue;
    for (const extension of new Extensions({ schema: attribute.values[0] }).extensions) {
      const value = asn1js.fromBER(extension.extnValue.valueBlock.valueHexView).result;
      const critical = extension.critical ? " critical" : "";
      if (extension.extnID === "2.5.29.15") {
        const usageNames = ["Digital Signature", "Non Repudiation", "Key Encipherment", "Data Encipherment", "Key Agreement", "Certificate Sign", "CRL Sign", "Encipher Only", "Decipher Only"];
        const usages = usageNames.filter((name, index) => value.valueBlock.valueHexView[Math.floor(index / 8)] & (0x80 >> (index % 8)));
        lines.push(`                X509v3 Key Usage:${critical}`, `                    ${usages.join(", ")}`);
      } else if (extension.extnID === "2.5.29.37") {
        const purposes = { "1.3.6.1.5.5.7.3.1": "TLS Web Server Authentication", "1.3.6.1.5.5.7.3.2": "TLS Web Client Authentication" };
        const usages = new ExtKeyUsage({ schema: value }).keyPurposes.map((purpose) => purposes[purpose] || purpose);
        lines.push(`                X509v3 Extended Key Usage:${critical}`, `                    ${usages.join(", ")}`);
      } else if (extension.extnID === "2.5.29.17") {
        const names = new GeneralNames({ schema: value }).names.map((name) => `${name.type === 2 ? "DNS" : `GeneralName[${name.type}]`}:${name.value}`);
        lines.push(`                X509v3 Subject Alternative Name:${critical}`, `                    ${names.join(", ")}`);
      }
    }
  }
  lines.push(
    `    Signature Algorithm: ${request.signatureAlgorithm.algorithmId === "1.2.840.113549.1.1.11" ? "sha256WithRSAEncryption" : request.signatureAlgorithm.algorithmId}`,
    "    Signature Value:",
    hexLines(request.signatureValue.valueBlock.valueHexView, "        "),
  );
  return `${lines.join("\n")}\n`;
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
  const csrPEM = encodePEM("CERTIFICATE REQUEST", csr.toSchema().toBER(false));
  const verification = await inspectCSR(csrPEM);
  const privateDER = await nativeCrypto.subtle.exportKey("pkcs8", pair.privateKey);
  try {
    return { config, key: encodePEM("PRIVATE KEY", privateDER), csr: csrPEM, verification };
  } finally { new Uint8Array(privateDER).fill(0); }
}