import test from "node:test";
import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import * as asn1js from "asn1js";
import { CertificationRequest, Extensions, ExtKeyUsage, GeneralNames } from "pkijs";
import { configuration, generateArtifacts, presets } from "./crypto.js";

function input(stage = "LIVE", bits = 2048) {
  return { stage, bits, cn: presets[stage][0], sans: [...presets[stage]] };
}

function parseCSR(pem) {
  const encoded = pem.replace(/-----[^\n]+-----/g, "").replace(/\s/g, "");
  const bytes = Uint8Array.from(Buffer.from(encoded, "base64"));
  return new CertificationRequest({ schema: asn1js.fromBER(bytes.buffer).result });
}

test("LIVE/LABOR: neue Schluessel, korrekte Signatur, SAN, Subject und Extensions", async () => {
  let previous;
  for (const [stage, bits] of [["LIVE", 2048], ["LIVE", 2048], ["LABOR", 2048], ["LIVE", 4096], ["LABOR", 3072]]) {
    const request = input(stage, bits);
    const result = await generateArtifacts(request);
    assert.notEqual(result.key, previous);
    previous = result.key;
    const key = createPrivateKey(result.key);
    assert.equal(key.asymmetricKeyDetails.modulusLength, bits);
    const csr = parseCSR(result.csr);
    assert.equal(await csr.verify(), true);
    assert.equal(csr.signatureAlgorithm.algorithmId, "1.2.840.113549.1.1.11");
    const expectedPublic = createPublicKey(key).export({ type: "spki", format: "der" });
    assert.deepEqual(Buffer.from(csr.subjectPublicKeyInfo.toSchema().toBER(false)), expectedPublic);
    const values = csr.subject.typesAndValues;
    assert.deepEqual(values.map((part) => [part.type, part.value.valueBlock.value]), [
      ["2.5.4.6", "DE"], ["2.5.4.10", "T-Systems International GmbH"],
      ["2.5.4.11", "Barmer Infrastruktur"], ["2.5.4.11", "Serverdienste"], ["2.5.4.3", request.cn],
    ]);
    const attribute = csr.attributes.find((item) => item.type === "1.2.840.113549.1.9.14");
    const extensions = new Extensions({ schema: attribute.values[0] }).extensions;
    assert.equal(extensions.length, 3);
    const san = extensions.find((extension) => extension.extnID === "2.5.29.17");
    const names = new GeneralNames({ schema: asn1js.fromBER(san.extnValue.valueBlock.valueHexView).result });
    assert.deepEqual(names.names.map((name) => name.value), request.sans);
    const usage = extensions.find((extension) => extension.extnID === "2.5.29.15");
    assert.equal(usage.critical, true);
    const bitString = asn1js.fromBER(usage.extnValue.valueBlock.valueHexView).result;
    assert.equal(bitString.valueBlock.unusedBits, 5);
    assert.equal(bitString.valueBlock.valueHexView[0], 0xa0);
    const extended = extensions.find((extension) => extension.extnID === "2.5.29.37");
    assert.deepEqual(new ExtKeyUsage({ schema: asn1js.fromBER(extended.extnValue.valueBlock.valueHexView).result }).keyPurposes, ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"]);
    request.sans.forEach((name, index) => assert.ok(result.config.includes(`DNS.${index + 1} = ${name}\n`)));
    assert.ok(result.config.includes(`default_bits       = ${bits}`));
  }
});

test("CN, SAN, Stage und RSA-Laenge werden validiert", () => {
  for (const name of ["", "x\n[req]", "a;echo", "*.example.org", "-bad", "bad.", "a_b", "a".repeat(64), "http://example.org"]) {
    assert.throws(() => configuration({ ...input(), cn: name }));
    assert.throws(() => configuration({ ...input(), sans: [...presets.LIVE, name] }));
  }
  assert.throws(() => configuration({ ...input(), stage: "OTHER" }));
  assert.throws(() => configuration({ ...input(), bits: 1024 }));
  assert.throws(() => configuration({ ...input(), sans: [] }));
  assert.throws(() => configuration({ ...input(), sans: ["other.example.org"] }));
  assert.throws(() => configuration({ ...input(), sans: [...presets.LIVE, presets.LIVE[0].toUpperCase()] }));
});