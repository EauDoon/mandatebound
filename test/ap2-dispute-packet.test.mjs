import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import {
  AP2_DISPUTE_NETWORK_LABELS,
  AP2_DISPUTE_PACKET_CATEGORIES,
  buildAp2DisputeResponsePacket,
  packAp2DisputeEvidence,
  renderAp2DisputeResponsePacketMarkdown,
  verifyAp2DisputeEvidencePack,
} from "../dist/ap2-dispute.js";
import { CLI_EXIT, runCli } from "../dist/cli.js";
import { makeFixture, makePackInput } from "./ap2-dispute-fixture.mjs";

const OTHER_DIGEST = `sha256:${"0".repeat(64)}`;
const GOLDEN_120 = new URL("./fixtures/ap2-evidence-pack-1.2.0.json", import.meta.url);

function collector() {
  let value = "";
  return {
    stream: new Writable({ write(chunk, _encoding, next) { value += chunk; next(); } }),
    value: () => value,
  };
}

async function cli(argv, input) {
  const stdout = collector();
  const stderr = collector();
  const code = await runCli(argv, { stdin: Readable.from([input]), stdout: stdout.stream, stderr: stderr.stream });
  return { code, stdout: stdout.value(), stderr: stderr.value() };
}

function packFor(options, revocationStatus) {
  return packAp2DisputeEvidence(makePackInput(makeFixture(options), revocationStatus));
}

function states(packet) {
  return Object.fromEntries(packet.facts.map(({ fact, state }) => [fact, state]));
}

test("a verified, consistent Pack supports every in-Pack fact of each category", () => {
  const pack = packFor();
  const verification = verifyAp2DisputeEvidencePack(pack, { expectedPackDigest: pack.packDigest });
  assert.equal(verification.status, "verified");
  for (const category of AP2_DISPUTE_PACKET_CATEGORIES) {
    const packet = buildAp2DisputeResponsePacket(pack, { expectedPackDigest: pack.packDigest, category });
    assert.equal(packet.schemaId, "MandateBoundAp2DisputeResponsePacket/v1");
    assert.equal(packet.category, category);
    assert.equal(packet.packContribution, "supports_listed_facts", category);
    assert.equal(packet.verificationReportDigest, verification.reportDigest);
    assert.equal(packet.disputeOutcome, "not-determined");
    assert.equal(packet.legalEffect, "not-determined");
    assert.equal(packet.agentSpecificNetworkRule, "none-modelled");
    assert.deepEqual(packet.networkLabels, AP2_DISPUTE_NETWORK_LABELS[category]);
    for (const entry of packet.facts) {
      assert.ok(["supported", "outside_pack"].includes(entry.state), `${category} ${entry.fact}`);
      if (entry.state === "outside_pack") assert.deepEqual(entry.evidence, []);
      else assert.ok(entry.evidence.length > 0);
    }
    // The digests to cite are exactly the four artifacts the resolution selected.
    assert.deepEqual(
      packet.attachments,
      verification.resolution.selectedArtifacts.map(({ kind, digest }) => ({ kind, digest })),
    );
  }
  const notAuthorized = buildAp2DisputeResponsePacket(pack, {
    expectedPackDigest: pack.packDigest,
    category: "not_authorized",
  });
  assert.deepEqual(states(notAuthorized), {
    user_approved_signed_checkout: "supported",
    payment_authorized_for_checkout: "supported",
    payment_matches_checkout: "supported",
    payment_processed: "supported",
    mandates_reported_not_revoked: "supported",
    prior_undisputed_transactions: "outside_pack",
    device_or_network_match: "outside_pack",
    agent_identity: "outside_pack",
  });
  const again = buildAp2DisputeResponsePacket(pack, { expectedPackDigest: pack.packDigest, category: "not_authorized" });
  assert.equal(again.packetDigest, notAuthorized.packetDigest);
  assert.equal(Object.isFrozen(notAuthorized), true);
});

test("a payment that does not match the signed Checkout contradicts the packet where it matters", () => {
  const pack = packFor({ paymentClaims: { payment_amount: { currency: "USD", amount: 999_999 } } });
  const options = { expectedPackDigest: pack.packDigest };
  assert.equal(verifyAp2DisputeEvidencePack(pack, options).status, "verified");
  const notAuthorized = buildAp2DisputeResponsePacket(pack, { ...options, category: "not_authorized" });
  assert.equal(states(notAuthorized).payment_matches_checkout, "contradicted");
  assert.equal(notAuthorized.packContribution, "contradicting");
  const described = buildAp2DisputeResponsePacket(pack, { ...options, category: "not_as_described" });
  assert.equal(described.packContribution, "contradicting");
  // Not-received does not ask about the amount, so the mismatch does not enter it.
  const received = buildAp2DisputeResponsePacket(pack, { ...options, category: "not_received" });
  assert.equal(received.packContribution, "supports_listed_facts");
});

test("an authentic Error Payment Receipt contradicts payment_processed", () => {
  const pack = packFor({ paymentReceiptStatus: "Error" });
  const options = { expectedPackDigest: pack.packDigest };
  assert.equal(verifyAp2DisputeEvidencePack(pack, options).status, "verified");
  const packet = buildAp2DisputeResponsePacket(pack, { ...options, category: "not_received" });
  assert.equal(states(packet).payment_processed, "contradicted");
  assert.equal(states(packet).merchant_accepted_checkout, "supported");
  assert.equal(packet.packContribution, "contradicting");
});

test("a tampered, mis-anchored, revoked or unresolved Pack contributes nothing", () => {
  const pack = packFor();
  const cases = [
    [{ ...pack, createdAt: "2026-07-22T23:00:00.000Z" }, pack.packDigest],
    [pack, OTHER_DIGEST],
    [packFor({}, "revoked"), null],
    [packFor({ checkoutMerchantId: "merchant-2" }), null],
  ];
  for (const [value, anchor] of cases) {
    const expectedPackDigest = anchor ?? value.packDigest;
    const packet = buildAp2DisputeResponsePacket(value, { expectedPackDigest, category: "not_authorized" });
    assert.equal(packet.verificationStatus, "unresolved");
    assert.equal(packet.packContribution, "none");
    assert.deepEqual(packet.attachments, []);
    for (const entry of packet.facts) {
      assert.ok(["not_established", "outside_pack"].includes(entry.state), entry.fact);
      assert.deepEqual(entry.evidence, []);
    }
  }
  const invalid = buildAp2DisputeResponsePacket({}, { expectedPackDigest: OTHER_DIGEST, category: "not_received" });
  assert.equal(invalid.packDigest, null);
  assert.equal(invalid.transactionId, null);
  assert.equal(invalid.packContribution, "none");
});

test("the packet rejects an unknown category", () => {
  const pack = packFor();
  for (const category of [undefined, "fraud", "10.4", ""]) {
    assert.throws(
      () => buildAp2DisputeResponsePacket(pack, { expectedPackDigest: pack.packDigest, category }),
      TypeError,
    );
  }
});

test("the packet never echoes amounts, party ids, items or tokens", () => {
  const fixture = makeFixture({
    checkoutMerchantId: "merchant-secret-41",
    allowedMerchantId: "merchant-secret-41",
    paymentClaims: {
      payee: { id: "merchant-secret-41", name: "Secret Payee" },
      payment_amount: { currency: "USD", amount: 2_500 },
      payment_instrument: { id: "instrument-secret-5", type: "card" },
    },
  });
  const pack = packAp2DisputeEvidence(makePackInput(fixture));
  for (const category of AP2_DISPUTE_PACKET_CATEGORIES) {
    const options = { expectedPackDigest: pack.packDigest, category };
    const rendered = JSON.stringify(buildAp2DisputeResponsePacket(pack, options)) +
      renderAp2DisputeResponsePacketMarkdown(pack, options);
    for (const secret of [
      "merchant-secret-41", "Secret Payee", "instrument-secret-5", "sku-1", "Synthetic item",
      fixture.checkoutJwt, fixture.checkoutMandate, fixture.paymentMandate, fixture.paymentReceipt,
    ]) {
      assert.equal(rendered.includes(secret), false, `${category} ${secret.slice(0, 24)}`);
    }
  }
});

test("the frozen 1.2.0 golden Pack builds a supporting packet", () => {
  const pack = JSON.parse(readFileSync(GOLDEN_120, "utf8"));
  const packet = buildAp2DisputeResponsePacket(pack, { expectedPackDigest: pack.packDigest, category: "not_authorized" });
  assert.equal(packet.verificationStatus, "verified");
  assert.equal(packet.packContribution, "supports_listed_facts");
});

test("ap2-dispute packet prints JSON or Markdown and exits by contribution", async () => {
  const pack = packFor();
  const input = JSON.stringify(pack);
  const anchor = ["--expected-pack-digest", pack.packDigest];

  const json = await cli(["ap2-dispute", "packet", "-", ...anchor, "--category", "not_authorized"], input);
  assert.equal(json.code, CLI_EXIT.SUCCESS, json.stdout);
  const envelope = JSON.parse(json.stdout);
  assert.equal(envelope.ok, true);
  assert.equal(envelope.result.packContribution, "supports_listed_facts");

  const markdown = await cli(
    ["ap2-dispute", "packet", "-", ...anchor, "--category", "not_received", "--format", "markdown"],
    input,
  );
  assert.equal(markdown.code, CLI_EXIT.SUCCESS);
  assert.match(markdown.stdout, /^# AP2 Dispute Response Packet\n/u);
  // Markdown text escapes punctuation, so match the escaped forms.
  assert.ok(markdown.stdout.includes("- visa 13\\.1: Merchandise/Services Not Received"), markdown.stdout);
  assert.ok(markdown.stdout.includes("| outside\\_pack |"));

  const mismatch = packFor({ paymentClaims: { payee: { id: "other-merchant", name: "Other" } } });
  const conflict = await cli(
    ["ap2-dispute", "packet", "-", "--expected-pack-digest", mismatch.packDigest, "--category", "not_authorized"],
    JSON.stringify(mismatch),
  );
  assert.equal(conflict.code, CLI_EXIT.CONFLICT);
  assert.equal(JSON.parse(conflict.stdout).result.packContribution, "contradicting");

  const missingCategory = await cli(["ap2-dispute", "packet", "-", ...anchor], input);
  assert.equal(missingCategory.code, CLI_EXIT.USAGE);
  const badCategory = await cli(["ap2-dispute", "packet", "-", ...anchor, "--category", "fraud"], input);
  assert.equal(badCategory.code, CLI_EXIT.USAGE);
  const missingAnchor = await cli(["ap2-dispute", "packet", "-", "--category", "not_authorized"], input);
  assert.equal(missingAnchor.code, CLI_EXIT.USAGE);
  const invalid = await cli(["ap2-dispute", "packet", "-", ...anchor, "--category", "not_authorized"], "{}");
  assert.equal(invalid.code, CLI_EXIT.INVALID);
  const html = await cli(["ap2-dispute", "packet", "-", ...anchor, "--category", "not_authorized", "--format", "html"], input);
  assert.equal(html.code, CLI_EXIT.USAGE);
});
