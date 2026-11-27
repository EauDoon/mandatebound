import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { CLI_EXIT, runCli } from "../dist/cli.js";
import {
  VERIFIABLE_INTENT_CONSTRAINT_SUPPORT,
  VERIFIABLE_INTENT_PROFILE,
  verifyVerifiableIntentChain,
} from "../dist/verifiable-intent.js";
import { ITEMS, MERCHANTS, NOW, makeViChain, snapshot } from "./vi-fixture.mjs";

const golden = JSON.parse(readFileSync(
  new URL("./fixtures/verifiable-intent-v0.1-reference-sdk-golden.json", import.meta.url),
  "utf8",
));
const GOLDEN_DIGEST = `sha256:${"a".repeat(64)}`;
const goldenSnapshot = (jwk) => ({
  kid: jwk.kid,
  jwk,
  sourceDigest: GOLDEN_DIGEST,
  capturedAt: "2026-11-01T00:00:00Z",
  validUntil: "2027-11-01T00:00:00Z",
});
const goldenBase = {
  issuerKeySnapshot: goldenSnapshot(golden.issuerJwk),
  expectedIssuerKeySourceDigest: GOLDEN_DIGEST,
  merchantKeySnapshot: goldenSnapshot(golden.merchantJwk),
  expectedMerchantKeySourceDigest: GOLDEN_DIGEST,
  asOf: golden.asOf,
};
const auto = golden.autonomous;
const immediateInput = () => ({
  ...goldenBase,
  l1: golden.immediate.l1,
  l2: golden.immediate.l2,
  expected: { l2Audience: golden.immediate.l2Audience, l2Nonce: golden.immediate.l2Nonce },
});
const autonomousInput = () => ({
  ...goldenBase,
  l1: auto.l1,
  l2: auto.l2,
  l2PaymentPresentation: auto.l2PaymentPresentation,
  l2CheckoutPresentation: auto.l2CheckoutPresentation,
  l3Payment: auto.l3Payment,
  l3Checkout: auto.l3Checkout,
  expected: {
    l2Audience: auto.l2Audience,
    l2Nonce: auto.l2Nonce,
    l3PaymentAudience: auto.l3PaymentAudience,
    l3PaymentNonce: auto.l3PaymentNonce,
    l3CheckoutAudience: auto.l3CheckoutAudience,
    l3CheckoutNonce: auto.l3CheckoutNonce,
  },
});
const codes = (report) => report.issues.map((entry) => entry.code);
const statusOf = (report, type) => report.constraints.find((entry) => entry.type === type);

test("profile pins the reference commit and names its constraint split", () => {
  assert.equal(VERIFIABLE_INTENT_PROFILE.commit, golden.generator.commit);
  assert.equal(VERIFIABLE_INTENT_PROFILE.id, `verifiable-intent-v0.1+${golden.generator.commit}`);
  assert.equal(VERIFIABLE_INTENT_PROFILE.legalEffect, "not-determined");
  assert.deepEqual(VERIFIABLE_INTENT_CONSTRAINT_SUPPORT.networkEnforced, [
    "mandate.payment.agent_recurrence",
    "mandate.payment.budget",
    "mandate.payment.recurrence",
  ]);
  assert.equal(Object.isFrozen(VERIFIABLE_INTENT_CONSTRAINT_SUPPORT.evaluated), true);
});

test("reference SDK Immediate chain verifies with the merchant checkout signature", () => {
  const report = verifyVerifiableIntentChain(immediateInput());
  assert.equal(report.chainStatus, "verified", JSON.stringify(report.issues));
  assert.equal(report.mode, "immediate");
  assert.deepEqual(report.gates, {
    issuerCredential: "passed",
    userMandate: "passed",
    agentPayment: "not_applicable",
    agentCheckout: "not_applicable",
    crossReference: "not_applicable",
    checkoutJwtSignature: "passed",
    audienceAndNonce: "passed",
  });
  assert.equal(report.transaction.checkoutHash, golden.checkoutHash);
  assert.equal(report.transaction.transactionId, golden.checkoutHash);
  assert.deepEqual(report.transaction.paymentAmount, { currency: "USD", amount: 27999 });
  assert.equal(report.transaction.payeeId, "merchant-uuid-1");
  assert.equal(report.constraintsResult, "not_applicable");
  assert.equal(report.disputeOutcome, "not-determined");
  assert.equal(report.legalEffect, "not-determined");
});

test("reference SDK Autonomous chain verifies and reports each constraint honestly", () => {
  const report = verifyVerifiableIntentChain(autonomousInput());
  assert.equal(report.chainStatus, "verified", JSON.stringify(report.issues));
  assert.equal(report.mode, "autonomous");
  assert.equal(report.gates.agentPayment, "passed");
  assert.equal(report.gates.agentCheckout, "passed");
  assert.equal(report.gates.crossReference, "passed");
  assert.equal(report.gates.checkoutJwtSignature, "passed");
  assert.deepEqual(
    report.constraints.map(({ type, status, reason }) => [type, status, reason]),
    [
      // The SDK's checkout_jwt carries decimal prices and no merchant id.
      ["mandate.checkout.allowed_merchants", "not_evaluable", "checkout_jwt_unreadable"],
      // The SDK's L3b carries no line_items fulfillment.
      ["mandate.checkout.line_items", "not_evaluable", "fulfillment_line_items_missing"],
      ["mandate.payment.amount_range", "satisfied", "within_range"],
      ["mandate.payment.allowed_payees", "satisfied", "id_in_disclosed_allowlist"],
      ["mandate.payment.recurrence", "not_evaluable", "network_enforced"],
      ["mandate.payment.reference", "satisfied", "binds_disclosed_checkout_mandate"],
    ],
  );
  assert.equal(report.constraintsResult, "incomplete");
});

test("a network-side view with only the payment presentation and L3a verifies its half", () => {
  const input = autonomousInput();
  const report = verifyVerifiableIntentChain({
    ...input,
    l2: auto.l2PaymentPresentation,
    l3Checkout: undefined,
    l2CheckoutPresentation: undefined,
    expected: { ...input.expected, l3CheckoutAudience: undefined, l3CheckoutNonce: undefined },
  });
  assert.equal(report.chainStatus, "verified", JSON.stringify(report.issues));
  assert.deepEqual(report.disclosed, { checkoutMandate: false, paymentMandate: true });
  assert.equal(report.gates.agentCheckout, "not_presented");
  assert.equal(report.gates.crossReference, "not_checked");
  assert.equal(report.gates.checkoutJwtSignature, "not_presented");
  assert.equal(statusOf(report, "mandate.payment.reference").reason, "checkout_mandate_not_disclosed");
  assert.equal(report.transaction.checkoutHash, null);
  assert.equal(report.transaction.transactionId, golden.checkoutHash);
});

test("reports never echo presentations, holder data, or instrument identifiers", () => {
  for (const report of [
    verifyVerifiableIntentChain(immediateInput()),
    verifyVerifiableIntentChain(autonomousInput()),
  ]) {
    const text = JSON.stringify(report);
    for (const secret of ["holder@example.com", "f199c3dd-7106-478b-9b5f-7af9ca725170", "eyJ", "Mastercard **** 1234"]) {
      assert.equal(text.includes(secret), false, secret);
    }
    assert.match(report.presentationDigests.l1, /^sha256:[0-9a-f]{64}$/u);
    assert.equal(Object.isFrozen(report), true);
    assert.equal(Object.isFrozen(report.issues), true);
  }
});

test("the report is deterministic and binds its own digest", () => {
  const first = verifyVerifiableIntentChain(autonomousInput());
  const second = verifyVerifiableIntentChain(autonomousInput());
  assert.equal(first.reportDigest, second.reportDigest);
  assert.match(first.reportDigest, /^sha256:[0-9a-f]{64}$/u);
});

test("signatures cover the exact received segments, not a re-encoding", () => {
  // Re-encode the golden L1 payload with whitespace and keep the signature.
  // The reference SDK re-serializes the parsed payload before verifying, so it
  // would accept this; MandateBound verifies the bytes it was given.
  const [jwt, ...rest] = auto.l1.split("~");
  const [header, payload, signature] = jwt.split(".");
  const spaced = Buffer.from(JSON.stringify(JSON.parse(Buffer.from(payload, "base64url").toString()), null, 1)).toString("base64url");
  const report = verifyVerifiableIntentChain({ ...autonomousInput(), l1: [`${header}.${spaced}.${signature}`, ...rest].join("~") });
  assert.equal(report.chainStatus, "invalid");
  assert.deepEqual(codes(report), ["VI_L1_SIGNATURE_INVALID"]);
});

test("broken bindings between layers fail closed", () => {
  const swappedL1 = verifyVerifiableIntentChain({ ...autonomousInput(), l1: golden.immediate.l1 });
  assert.deepEqual(codes(swappedL1), ["VI_L2_INVALID"]);
  assert.match(swappedL1.issues[0].message, /sd_hash/u);

  const wrongPresentation = verifyVerifiableIntentChain({
    ...autonomousInput(),
    l2CheckoutPresentation: auto.l2PaymentPresentation,
  });
  assert.deepEqual(codes(wrongPresentation), ["VI_L3_CHECKOUT_INVALID"]);

  const swappedL3 = verifyVerifiableIntentChain({ ...autonomousInput(), l3Payment: auto.l3Checkout });
  assert.deepEqual(codes(swappedL3), ["VI_L3_PAYMENT_INVALID"]);

  const strayDisclosure = verifyVerifiableIntentChain({
    ...autonomousInput(),
    l2: `${auto.l2}${golden.immediate.l2.split("~")[1]}~`,
  });
  assert.deepEqual(codes(strayDisclosure), ["VI_L2_INVALID"]);
  assert.equal(strayDisclosure.mode, null);
  assert.equal(strayDisclosure.transaction.transactionId, null);
  assert.deepEqual(strayDisclosure.constraints, []);
  assert.equal(strayDisclosure.constraintsResult, "not_evaluated");
});

test("audience and nonce anchors gate eligibility, and a mismatch is invalid", () => {
  const unanchored = verifyVerifiableIntentChain({ ...autonomousInput(), expected: undefined });
  assert.equal(unanchored.chainStatus, "ineligible");
  assert.equal(unanchored.upstreamValid, true);
  assert.equal(unanchored.gates.audienceAndNonce, "not_checked");
  assert.deepEqual(new Set(codes(unanchored)), new Set(["VI_ANCHOR_UNCHECKED"]));
  assert.equal(unanchored.issues.length, 6);

  const input = autonomousInput();
  const mismatch = verifyVerifiableIntentChain({ ...input, expected: { ...input.expected, l3PaymentNonce: "other" } });
  assert.equal(mismatch.chainStatus, "invalid");
  assert.deepEqual(codes(mismatch), ["VI_ANCHOR_MISMATCH"]);
  assert.equal(mismatch.gates.audienceAndNonce, "failed");
});

test("evaluation time and key snapshots are enforced", () => {
  const late = verifyVerifiableIntentChain({ ...autonomousInput(), asOf: golden.asOf + 3600 });
  assert.deepEqual(codes(late), ["VI_L3_PAYMENT_INVALID"]);
  assert.match(late.issues[0].message, /expired/u);

  const early = verifyVerifiableIntentChain({ ...immediateInput(), asOf: golden.asOf - 7200 });
  assert.deepEqual(codes(early), ["VI_L2_INVALID"]);

  const stale = verifyVerifiableIntentChain({
    ...immediateInput(),
    issuerKeySnapshot: { ...goldenBase.issuerKeySnapshot, validUntil: "2026-11-02T00:00:00Z" },
  });
  assert.equal(stale.chainStatus, "ineligible");
  assert.deepEqual(codes(stale), ["INTEROP_KEY_SNAPSHOT_STALE"]);

  const unpinned = verifyVerifiableIntentChain({ ...immediateInput(), expectedIssuerKeySourceDigest: `sha256:${"c".repeat(64)}` });
  assert.deepEqual(codes(unpinned), ["INTEROP_KEY_SOURCE_PIN_MISMATCH"]);

  const wrongMerchant = verifyVerifiableIntentChain({ ...immediateInput(), merchantKeySnapshot: goldenSnapshot({ ...golden.agentJwk, kid: "merchant-key-1" }) });
  assert.deepEqual(codes(wrongMerchant), ["VI_CHECKOUT_JWT_SIGNATURE_INVALID"]);
  assert.equal(wrongMerchant.gates.checkoutJwtSignature, "failed");

  const noMerchantKey = verifyVerifiableIntentChain({ ...immediateInput(), merchantKeySnapshot: undefined });
  assert.equal(noMerchantKey.chainStatus, "verified");
  assert.equal(noMerchantKey.gates.checkoutJwtSignature, "not_checked");

  const badAsOf = verifyVerifiableIntentChain({ ...immediateInput(), asOf: "yesterday" });
  assert.deepEqual(codes(badAsOf), ["VI_AS_OF_INVALID"]);
  assert.equal(badAsOf.asOf, null);
});

test("malformed input returns an invalid report instead of throwing", () => {
  for (const value of [null, 7, "chain", [], {}]) {
    const report = verifyVerifiableIntentChain(value);
    assert.equal(report.chainStatus, "invalid");
    assert.equal(report.legalEffect, "not-determined");
  }
});

test("a fully disclosed synthetic chain evaluates every evaluated constraint", () => {
  const chain = makeViChain({
    checkoutMerchant: { id: "merchant-1", name: "Court Supply" },
    l3LineItems: [{ id: "SKU-1", quantity: 1 }],
  });
  const report = verifyVerifiableIntentChain(chain.input);
  assert.equal(report.chainStatus, "verified", JSON.stringify(report.issues));
  assert.equal(report.constraintsResult, "satisfied");
  assert.deepEqual(report.constraints.map((entry) => entry.status), ["satisfied", "satisfied", "satisfied", "satisfied", "satisfied"]);
  assert.equal(statusOf(report, "mandate.checkout.allowed_merchants").reason, "id_in_disclosed_allowlist");
});

test("an out-of-bounds agent act stays a verified chain with violated constraints", () => {
  const over = verifyVerifiableIntentChain(makeViChain({ amount: 45000 }).input);
  assert.equal(over.chainStatus, "verified");
  assert.equal(over.constraintsResult, "violated");
  assert.equal(statusOf(over, "mandate.payment.amount_range").reason, "above_maximum");

  const currency = verifyVerifiableIntentChain(makeViChain({
    tweak: { finalPayment: (payment) => { payment.payment_amount.currency = "EUR"; } },
  }).input);
  assert.equal(statusOf(currency, "mandate.payment.amount_range").reason, "currency_mismatch");

  const stranger = { id: "merchant-9", name: "Elsewhere", website: "https://elsewhere.example" };
  const outsider = verifyVerifiableIntentChain(makeViChain({ payee: stranger }).input);
  assert.equal(statusOf(outsider, "mandate.payment.allowed_payees").status, "violated");
  assert.equal(statusOf(outsider, "mandate.payment.allowed_payees").reason, "id_not_in_allowlist");
});

test("allowlists match by id only and never claim a match they cannot see", () => {
  // Same name and website as an allowed merchant, but no id: the reference SDK
  // falls back to name plus website; this profile does not.
  const lookalike = verifyVerifiableIntentChain(makeViChain({ payee: { name: MERCHANTS[0].name, website: MERCHANTS[0].website } }).input);
  assert.equal(statusOf(lookalike, "mandate.payment.allowed_payees").reason, "selected_party_id_missing");

  // The paid merchant is merchant-2, but L2 discloses only merchant-1's entry.
  const chain = makeViChain({ payee: MERCHANTS[1] });
  const full = chain.input.l2.split("~").filter(Boolean);
  const [jwt, merchantOne, , ...others] = full;
  const partial = verifyVerifiableIntentChain({ ...chain.input, l2: `${[jwt, merchantOne, ...others].join("~")}~` });
  assert.equal(partial.chainStatus, "verified", JSON.stringify(partial.issues));
  assert.equal(statusOf(partial, "mandate.payment.allowed_payees").reason, "may_match_undisclosed_or_unidentified_entry");
  assert.equal(partial.constraintsResult, "incomplete");

  const empty = verifyVerifiableIntentChain(makeViChain({
    tweak: { paymentMandate: (mandate) => { mandate.constraints[1].allowed = []; } },
  }).input);
  assert.equal(statusOf(empty, "mandate.payment.allowed_payees").reason, "allowlist_empty_or_malformed");
});

test("line items honour acceptable ids, quantity caps, and exact match mode", () => {
  const evaluate = (lineItems, tweakCheckout) => statusOf(
    verifyVerifiableIntentChain(makeViChain({
      l3LineItems: lineItems,
      ...(tweakCheckout === undefined ? {} : { tweak: { checkoutMandate: tweakCheckout } }),
    }).input),
    "mandate.checkout.line_items",
  );
  assert.equal(evaluate([{ id: "SKU-1", quantity: 1 }]).status, "satisfied");
  assert.equal(evaluate([{ sku: "SKU-2", quantity: 1 }]).status, "satisfied");
  assert.equal(evaluate([{ id: "SKU-9", quantity: 1 }]).reason, "item_not_acceptable");
  assert.equal(evaluate([{ id: "SKU-1", quantity: 2 }]).reason, "total_quantity_exceeds_limit");
  assert.equal(evaluate([]).reason, "fulfillment_line_items_empty_or_malformed");
  assert.equal(evaluate([{ id: "SKU-1", quantity: "1" }]).reason, "fulfillment_line_items_empty_or_malformed");
  const exact = (mandate, { itemDisclosures }) => {
    mandate.constraints[1] = {
      type: "mandate.checkout.line_items",
      items: [
        { id: "line-1", acceptable_items: [{ "...": itemDisclosures[0].digest }], quantity: 1 },
        { id: "line-2", acceptable_items: [{ "...": itemDisclosures[1].digest }], quantity: 1 },
      ],
      match_mode: "exact",
    };
  };
  assert.equal(evaluate([{ id: "SKU-1", quantity: 1 }], exact).reason, "exact_match_requirement_missing");
  assert.equal(evaluate([{ id: "SKU-1", quantity: 1 }, { id: "SKU-2", quantity: 1 }], exact).status, "satisfied");
  const wildcard = (mandate) => {
    mandate.constraints[1].items[0].acceptable_items = [];
  };
  assert.equal(evaluate([{ id: "SKU-7", quantity: 1 }], wildcard).status, "satisfied");
  assert.equal(ITEMS.length, 2);
});

test("unknown open-mandate constraints are violations, network-enforced ones are not evaluable", () => {
  const report = verifyVerifiableIntentChain(makeViChain({
    tweak: {
      paymentMandate: (mandate) => {
        mandate.constraints.push({ type: "mandate.payment.budget", currency: "USD", max: 100000 });
        mandate.constraints.push({ type: "mandate.payment.custom_rule" });
      },
    },
  }).input);
  assert.equal(statusOf(report, "mandate.payment.budget").reason, "network_enforced");
  assert.equal(statusOf(report, "mandate.payment.custom_rule").reason, "unknown_type_in_open_mandate");
  assert.equal(report.constraintsResult, "violated");
});

test("structural rules of the pinned spec fail closed", () => {
  const cases = [
    ["L3 lifetime over one hour", { tweak: { l3a: (claims) => { claims.exp = NOW + 3601; } } }, "VI_L3_PAYMENT_INVALID"],
    ["L3 carrying cnf", { tweak: { l3a: (claims) => { claims.cnf = { jwk: {} }; } } }, "VI_L3_PAYMENT_INVALID"],
    ["L3 kid not the delegated kid", { tweak: { l3aHeader: (header) => { header.kid = "other-kid"; } } }, "VI_L3_PAYMENT_INVALID"],
    ["agent cnf without kid", {
      tweak: {
        checkoutMandate: (mandate) => { mandate.cnf = { jwk: { ...mandate.cnf.jwk, kid: undefined } }; },
        paymentMandate: (mandate) => { mandate.cnf = { jwk: { ...mandate.cnf.jwk, kid: undefined } }; },
      },
    }, "VI_L2_AUTONOMOUS_INVALID"],
    ["payment reference to another checkout", {
      tweak: { paymentMandate: (mandate) => { mandate.constraints[2].conditional_transaction_id = "A".repeat(43); } },
    }, "VI_L2_AUTONOMOUS_INVALID"],
    ["open checkout without line_items", {
      tweak: { checkoutMandate: (mandate) => { mandate.constraints.splice(1, 1); } },
    }, "VI_L2_AUTONOMOUS_INVALID"],
    ["L3a instrument not the authorized one", {
      tweak: { finalPayment: (payment) => { payment.payment_instrument = { ...payment.payment_instrument, id: "card-ref-2" }; } },
    }, "VI_L3_PAYMENT_INVALID"],
    ["L3b checkout_hash not the hash of checkout_jwt", {
      tweak: { finalCheckout: (checkout) => { checkout.checkout_hash = "A".repeat(43); } },
    }, "VI_L3_CHECKOUT_INVALID"],
    ["L1 card_id not the payment instrument", { tweak: { l1: (claims) => { claims.card_id = "card-ref-2"; } } }, "VI_L2_MANDATES_INVALID"],
    ["L1 wrong credential type", { tweak: { l1: (claims) => { claims.vct = "https://example.com/other"; } } }, "VI_L1_INVALID"],
    ["more than one mandate pair", {
      tweak: { l2: (claims, { checkoutDisclosure }) => { claims.delegate_payload.push({ "...": checkoutDisclosure.digest.replace(/^./u, "Z") }); } },
    }, "VI_L2_MANDATES_INVALID"],
  ];
  for (const [name, options, code] of cases) {
    const report = verifyVerifiableIntentChain(makeViChain(options).input);
    assert.equal(report.chainStatus, "invalid", name);
    assert.deepEqual(codes(report), [code], name);
  }
});

test("L3a and L3b that disagree on the transaction fail the cross-reference", () => {
  const report = verifyVerifiableIntentChain(makeViChain({
    tweak: { finalPayment: (payment) => { payment.transaction_id = "B".repeat(43); } },
  }).input);
  assert.equal(report.gates.agentPayment, "passed");
  assert.equal(report.gates.agentCheckout, "passed");
  assert.equal(report.gates.crossReference, "failed");
  assert.deepEqual(codes(report), ["VI_CROSS_REFERENCE_MISMATCH"]);
});

test("Immediate mode rules fail closed", () => {
  const ok = verifyVerifiableIntentChain(makeViChain({ mode: "immediate" }).input);
  assert.equal(ok.chainStatus, "verified", JSON.stringify(ok.issues));

  const withAgent = makeViChain({ mode: "immediate" });
  const agentLayer = verifyVerifiableIntentChain({ ...withAgent.input, l3Payment: auto.l3Payment });
  assert.deepEqual(codes(agentLayer), ["VI_L2_IMMEDIATE_INVALID"]);

  const unbound = verifyVerifiableIntentChain(makeViChain({
    mode: "immediate",
    tweak: { paymentMandate: (mandate) => { mandate.transaction_id = "C".repeat(43); } },
  }).input);
  assert.deepEqual(codes(unbound), ["VI_L2_IMMEDIATE_INVALID"]);

  const withCnf = verifyVerifiableIntentChain(makeViChain({
    mode: "immediate",
    tweak: { checkoutMandate: (mandate) => { mandate.cnf = { jwk: {} }; } },
  }).input);
  assert.deepEqual(codes(withCnf), ["VI_L2_IMMEDIATE_INVALID"]);

  const wrongIssuer = verifyVerifiableIntentChain({
    ...makeViChain({ mode: "immediate" }).input,
    issuerKeySnapshot: snapshot(makeViChain().keys.issuer),
  });
  assert.deepEqual(codes(wrongIssuer), ["VI_L1_SIGNATURE_INVALID"]);
});

async function cli(args, input) {
  let stdout = "";
  const code = await runCli(args, {
    stdin: Readable.from([input]),
    stdout: new Writable({ write(chunk, _encoding, next) { stdout += chunk; next(); } }),
    stderr: new Writable({ write(_chunk, _encoding, next) { next(); } }),
  });
  return { code, body: JSON.parse(stdout) };
}

test("verifiable-intent verify exits 0, 5 and 3 as documented", async () => {
  const satisfied = makeViChain({
    checkoutMerchant: { id: "merchant-1" },
    l3LineItems: [{ id: "SKU-1", quantity: 1 }],
  }).input;
  const ok = await cli(["verifiable-intent", "verify", "-"], JSON.stringify(satisfied));
  assert.equal(ok.code, CLI_EXIT.SUCCESS);
  assert.equal(ok.body.ok, true);
  assert.equal(ok.body.result.constraintsResult, "satisfied");

  const immediate = await cli(["verifiable-intent", "verify", "-"], JSON.stringify(immediateInput()));
  assert.equal(immediate.code, CLI_EXIT.SUCCESS);

  // The reference SDK chain verifies, but its recurrence constraint is network
  // enforced, so the constraint result is incomplete and needs review.
  const incomplete = await cli(["verifiable-intent", "verify", "-"], JSON.stringify(autonomousInput()));
  assert.equal(incomplete.code, CLI_EXIT.CONFLICT);
  assert.equal(incomplete.body.result.chainStatus, "verified");

  const violated = await cli(["verifiable-intent", "verify", "-"], JSON.stringify(makeViChain({ amount: 45000 }).input));
  assert.equal(violated.code, CLI_EXIT.CONFLICT);

  const invalid = await cli(["verifiable-intent", "verify", "-"], JSON.stringify({ ...immediateInput(), l1: auto.l1 }));
  assert.equal(invalid.code, CLI_EXIT.INVALID);
  assert.equal(invalid.body.result.chainStatus, "invalid");

  const shape = await cli(["verifiable-intent", "verify", "-"], JSON.stringify({ ...immediateInput(), extra: true }));
  assert.equal(shape.code, CLI_EXIT.INVALID);
  assert.equal(shape.body.error.message, "Verifiable Intent chain input is invalid.");

  const option = await cli(["verifiable-intent", "verify", "-", "--category", "not_authorized"], "{}");
  assert.equal(option.code, CLI_EXIT.USAGE);
});
