# Verifiable Intent v0.1 chain evidence

Verifiable Intent (VI) is a layered SD-JWT credential format maintained by
Mastercard in the
[`agent-intent/verifiable-intent`](https://github.com/agent-intent/verifiable-intent)
repository. MandateBound verifies one preserved VI chain for dispute evidence.
It does not issue VI credentials, take part in a live authorization, or decide
a dispute.

## Pinned profile

| Field | Value |
| --- | --- |
| Profile ID | `verifiable-intent-v0.1+356c29635f1c44df7de02edb58699ca9f29bece6` |
| Specification | VI v0.1, as published at commit `356c29635f1c44df7de02edb58699ca9f29bece6` |
| Algorithm | ES256 only, `sha-256` disclosure digests |
| Issuer credential type | `https://credentials.mastercard.com/card` |
| Modes | Immediate (L1 and L2) and Autonomous (L1, L2, L3a and L3b) |
| Mandate pairs | One checkout mandate and one payment mandate per L2 |
| Network access | None; every key is a caller-pinned snapshot |

The pin is a repository commit, not a numbered release. Tag `v0.1.0` predates
the field alignment with AP2 (`checkout_jwt`, `checkout_hash`,
`transaction_id`, `payment_amount`), and this profile follows the aligned field
set. A later VI release needs a new profile.

## What one verification checks

`verifyVerifiableIntentChain` (CLI: `mandatebound verifiable-intent verify`)
replays the chain at `asOf`, the instant the chain was presented. Use the
authorization time, not the review date: an L3 credential lives about five
minutes, so a review-date `asOf` correctly reports it expired.

1. **L1 issuer credential.** `typ` is `sd+jwt`, `vct` is the pinned card type,
   the signature verifies with the pinned issuer key snapshot over the exact
   received segments, `iat` and `exp` hold at `asOf`, and `cnf.jwk` yields the
   user key.
2. **L2 user mandate.** The signature verifies with the L1 `cnf.jwk` key, and
   `sd_hash` equals the SHA-256 of the exact L1 presentation. Every disclosure
   is referenced by the signed payload. Open mandates
   (`mandate.checkout.open.1`, `mandate.payment.open.1`) make the chain
   Autonomous with `typ` `kb-sd-jwt+kb`; final mandates make it Immediate with
   `typ` `kb-sd-jwt`. Mixing the two fails.
3. **Immediate mode.** Both mandates are disclosed, neither carries `cnf`,
   `checkout_hash` is the SHA-256 of `checkout_jwt`, and `transaction_id`
   equals `checkout_hash`. An agent layer is not accepted.
4. **Autonomous mode.** Every disclosed open mandate delegates to the same
   agent key, and that `cnf.jwk` carries a `kid`. The open checkout mandate has
   a `line_items` constraint. The open payment mandate has a `reference`
   constraint whose `conditional_transaction_id` is the digest of the checkout
   mandate disclosure, plus a `payment_instrument` with `id` and `type`.
5. **L3a and L3b agent fulfillments.** Each has `typ` `kb-sd-jwt`, no `cnf`,
   the delegated `kid`, and a signature by the agent key. Each `sd_hash` equals
   the SHA-256 of the exact L2 presentation that recipient saw, and that
   presentation is the same signed L2 JWT and includes the matching L2 mandate.
   `exp` is required and is at most one hour after `iat`. L3a carries a closed
   payment mandate whose instrument equals the one L2 authorized; L3b carries
   `checkout_jwt` and a `checkout_hash` that is its SHA-256.
6. **Cross-reference.** When both L3 credentials are presented, L3a
   `transaction_id` must equal L3b `checkout_hash`.
7. **L1 `card_id`.** When present, it must equal the disclosed L2 payment
   instrument `id`.
8. **Merchant checkout signature.** With an optional pinned merchant key
   snapshot, the `checkout_jwt` signature is verified over its exact segments.
9. **Audience and nonce.** Each `expected` value is compared. A value that is
   not supplied leaves the chain `ineligible` with `VI_ANCHOR_UNCHECKED`.

A presentation may be selective. A network that holds only the payment-side L2
presentation and L3a gets a verified payment half, with the checkout gates
`not_presented` and the cross-reference `not_checked`.

## Stricter than the reference SDK

These choices make a report harder to pass than the reference verifier, on
purpose:

- Signatures are checked over the exact received segments. The reference SDK
  re-serializes the parsed header and payload before checking, so it accepts a
  re-encoded segment that this profile rejects.
- Merchants and payees match by `id` only. The reference SDK falls back to name
  and website when an `id` is missing.
- An allowlist entry that stays an undisclosed reference, or a disclosed entry
  without an `id`, could be the selected party. A miss against the rest is
  `not_evaluable`, never `satisfied` and never `violated`.
- The agent `cnf.jwk` must carry a `kid`, and L3 `exp` is required.
- `checkout_hash` in L3b is recomputed from `checkout_jwt`.
- Payloads and disclosures are parsed as strict JSON, which accepts only safe
  integers. A disclosure with a decimal number fails the chain.

## Constraint evaluation

Only Autonomous chains have constraints. Each disclosed open mandate's
constraints are reported as `satisfied`, `violated` or `not_evaluable` with a
fixed reason code, and `constraintsResult` rolls them up: `violated` when any
is violated, otherwise `incomplete` when any is not evaluable, otherwise
`satisfied`. A verified chain with violated constraints is the dispute-relevant
case where the agent acted outside the user's mandate; the chain stays
`verified` because the signatures prove who signed what.

| Constraint | Fulfillment source | Notes |
| --- | --- | --- |
| `mandate.payment.amount_range` | L3a `payment_amount` | Integer minor units and an exact currency match. |
| `mandate.payment.allowed_payees` | L3a `payee.id` | Matched against disclosed L2 merchant entries by `id`. |
| `mandate.payment.reference` | L2 checkout disclosure | Satisfied by the binding check; `not_evaluable` when the checkout mandate is not disclosed. |
| `mandate.checkout.allowed_merchants` | `merchant.id` in the `checkout_jwt` payload | The VI spec requires this identifier when the constraint is used. A payload that strict JSON cannot read, such as the reference SDK's decimal prices, is `checkout_jwt_unreadable`. |
| `mandate.checkout.line_items` | L3b `line_items` | The spec's fulfillment source. The `checkout_jwt` cart schema is implementation defined in v0.1 and is never read instead, so a missing `line_items` is `fulfillment_line_items_missing`. |
| `mandate.payment.budget`, `mandate.payment.recurrence`, `mandate.payment.agent_recurrence` | None | Network enforced across transactions; always `not_evaluable` with `network_enforced`. |

Any other constraint type in an open mandate is `violated` with
`unknown_type_in_open_mandate`, because an unknown constraint leaves the
agent's authority unbounded.

## Report

`MandateBoundVerifiableIntentChainReport/v1` carries `chainStatus`
(`verified`, `ineligible` or `invalid`), per-layer gates, which mandates were
disclosed, the checkout hash, transaction ID, payment amount and payee `id`,
the constraint results, SHA-256 digests of every presentation, bounded issues,
and a `reportDigest` over the rest. It never carries a presentation, holder
data such as the L1 email, or a payment instrument identifier.
`disputeOutcome` and `legalEffect` are always `not-determined`.

## Golden fixture

`test/fixtures/verifiable-intent-v0.1-reference-sdk-golden.json` holds one
Immediate chain and one Autonomous chain generated by the reference SDK at the
pinned commit with
`test/fixtures/generators/verifiable-intent-golden.py`. The generator runs the
reference `verify_chain` on both chains before writing them, so the fixture is
known to pass the reference verifier. Synthetic chains in `test/vi-fixture.mjs`
cover the negative and constraint cases the SDK does not emit.

## Boundaries

- One mandate pair per L2. Multi-pair L2 credentials fail with
  `VI_L2_MANDATES_INVALID`.
- Key snapshots are caller pinned, as for AP2. This profile does not fetch a
  JWKS or decide which issuer to trust.
- The chain proves who signed which values. It does not prove delivery,
  product quality, or that the card network accepted the transaction.
- Network dispute rules specific to agent-initiated transactions are not
  modelled. See the [legal boundary](LEGAL_BOUNDARY.md).
