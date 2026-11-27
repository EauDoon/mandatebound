"""Generate the Verifiable Intent golden chains used by the MandateBound tests.

Run from a checkout of https://github.com/agent-intent/verifiable-intent at
commit 356c29635f1c44df7de02edb58699ca9f29bece6:

    python3 -I verifiable-intent-golden.py <path-to-verifiable-intent-checkout> > out.json

The script calls only the reference SDK's own issuance functions, then runs the
reference verify_chain on every chain right after issuance, so the
fixture is known to pass the reference verifier before MandateBound reads it.
Timestamps come from the clock at generation time, and salts and ECDSA
signatures are random, so each run produces different bytes; the committed
fixture is the frozen output of one run, and asOf records its evaluation time.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

PIN = "356c29635f1c44df7de02edb58699ca9f29bece6"
NOW = int(time.time())
AS_OF = NOW + 60


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    if head != PIN:
        raise SystemExit(f"expected verifiable-intent commit {PIN}, found {head}")
    sys.path.insert(0, str(root / "src"))
    sys.path.insert(0, str(root / "examples"))

    import helpers
    from verifiable_intent.crypto.disclosure import build_selective_presentation, hash_bytes
    from verifiable_intent.crypto.sd_jwt import decode_sd_jwt
    from verifiable_intent.issuance.agent import create_layer3_checkout, create_layer3_payment
    from verifiable_intent.issuance.issuer import create_layer1
    from verifiable_intent.issuance.user import create_layer2_autonomous, create_layer2_immediate
    from verifiable_intent.models.agent_mandate import (
        CheckoutL3Mandate,
        FinalCheckoutMandate,
        FinalPaymentMandate,
        PaymentL3Mandate,
    )
    from verifiable_intent.models.constraints import (
        AllowedMerchantConstraint,
        AllowedPayeeConstraint,
        CheckoutLineItemsConstraint,
        PaymentAmountConstraint,
        PaymentRecurrenceConstraint,
    )
    from verifiable_intent.models.issuer_credential import IssuerCredential
    from verifiable_intent.models.user_mandate import (
        CheckoutMandate,
        MandateMode,
        PaymentMandate,
        UserMandate,
    )
    from verifiable_intent.verification.chain import verify_chain

    issuer = helpers.get_issuer_keys()
    user = helpers.get_user_keys()
    agent = helpers.get_agent_keys()
    merchant = helpers.get_merchant_keys()
    merchant_entry = helpers.MERCHANTS[0]
    racket = helpers.find_product("BAB86345")

    def layer1():
        return create_layer1(
            IssuerCredential(
                iss="https://www.mastercard.com",
                sub="user-fixture-001",
                iat=NOW - 86400,
                exp=NOW + 365 * 86400,
                aud="https://wallet.example.com",
                cnf_jwk=user.public_jwk,
                email="holder@example.com",
                pan_last_four="1234",
                scheme="Mastercard",
                card_id=helpers.PAYMENT_INSTRUMENT["id"],
            ),
            issuer.private_key,
        )

    checkout_jwt = helpers.create_checkout_jwt([{"sku": racket["sku"], "quantity": 1}], merchant)
    checkout_hash = helpers.checkout_hash_from_jwt(checkout_jwt)

    # Immediate mode: the user signs final checkout and payment values.
    l1_immediate = layer1()
    l2_immediate = create_layer2_immediate(
        UserMandate(
            nonce="fixture-immediate-l2-nonce",
            aud="https://www.mastercard.com",
            iat=NOW,
            iss="https://wallet.example.com",
            exp=NOW + 900,
            mode=MandateMode.IMMEDIATE,
            sd_hash=hash_bytes(l1_immediate.serialize().encode("ascii")),
            checkout_mandate=CheckoutMandate(vct="mandate.checkout.1", checkout_jwt=checkout_jwt),
            payment_mandate=PaymentMandate(
                vct="mandate.payment.1",
                payment_instrument=helpers.PAYMENT_INSTRUMENT,
                payee=merchant_entry,
                currency="USD",
                amount=racket["price"],
            ),
        ),
        user.private_key,
    )

    # Autonomous mode: open mandates with constraints, then split L3a and L3b.
    l1_autonomous = layer1()
    l2_autonomous = create_layer2_autonomous(
        UserMandate(
            nonce="fixture-autonomous-l2-nonce",
            aud="https://agent.example.com",
            iat=NOW - 3600,
            iss="https://wallet.example.com",
            exp=NOW + 86400,
            mode=MandateMode.AUTONOMOUS,
            sd_hash=hash_bytes(l1_autonomous.serialize().encode("ascii")),
            prompt_summary="Buy a tennis racket under 400 USD",
            checkout_mandate=CheckoutMandate(
                vct="mandate.checkout.open.1",
                cnf_jwk=agent.public_jwk,
                cnf_kid=agent.kid,
                constraints=[
                    AllowedMerchantConstraint(allowed=helpers.MERCHANTS),
                    CheckoutLineItemsConstraint(
                        items=[{"id": "line-item-1", "acceptable_items": helpers.ACCEPTABLE_ITEMS, "quantity": 1}],
                    ),
                ],
            ),
            payment_mandate=PaymentMandate(
                vct="mandate.payment.open.1",
                cnf_jwk=agent.public_jwk,
                cnf_kid=agent.kid,
                payment_instrument=helpers.PAYMENT_INSTRUMENT,
                constraints=[
                    PaymentAmountConstraint(currency="USD", min=10000, max=40000),
                    AllowedPayeeConstraint(allowed=helpers.MERCHANTS),
                    PaymentRecurrenceConstraint(
                        frequency="YEAR", start_date="2026-01-01", end_date="2028-01-01", number=3
                    ),
                ],
            ),
            merchants=helpers.MERCHANTS,
            acceptable_items=helpers.ACCEPTABLE_ITEMS,
        ),
        user.private_key,
    )

    def find(sd_jwt, predicate):
        for encoded, decoded in zip(sd_jwt.disclosures, sd_jwt.disclosure_values):
            if predicate(decoded[-1]):
                return encoded
        raise SystemExit("disclosure not found")

    l2_base = l2_autonomous.serialize().split("~")[0]
    payment_disc = find(l2_autonomous, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.payment.open.1")
    checkout_disc = find(l2_autonomous, lambda v: isinstance(v, dict) and v.get("vct") == "mandate.checkout.open.1")
    merchant_disc = find(l2_autonomous, lambda v: isinstance(v, dict) and v.get("id") == merchant_entry["id"])
    item_disc = find(l2_autonomous, lambda v: isinstance(v, dict) and v.get("id") == racket["sku"])

    l3_payment = create_layer3_payment(
        PaymentL3Mandate(
            nonce="fixture-l3-payment-nonce",
            aud="https://www.mastercard.com",
            iat=NOW,
            iss="https://agent.example.com",
            exp=NOW + 300,
            final_payment=FinalPaymentMandate(
                transaction_id=checkout_hash,
                payee=merchant_entry,
                payment_amount={"currency": "USD", "amount": racket["price"]},
                payment_instrument=helpers.PAYMENT_INSTRUMENT,
            ),
            final_merchant=merchant_entry,
        ),
        agent.private_key,
        l2_base,
        payment_disc,
        merchant_disc,
    )
    l3_checkout = create_layer3_checkout(
        CheckoutL3Mandate(
            nonce="fixture-l3-checkout-nonce",
            aud="https://tennis-warehouse.com",
            iat=NOW,
            iss="https://agent.example.com",
            exp=NOW + 300,
            final_checkout=FinalCheckoutMandate(checkout_jwt=checkout_jwt, checkout_hash=checkout_hash),
        ),
        agent.private_key,
        l2_base,
        checkout_disc,
        item_disc,
    )
    l2_payment_presentation = build_selective_presentation(l2_base, [payment_disc, merchant_disc])
    l2_checkout_presentation = build_selective_presentation(l2_base, [checkout_disc, item_disc])

    # Prove each chain passes the reference verifier, which reads the live clock.
    immediate_result = verify_chain(
        decode_sd_jwt(l1_immediate.serialize()),
        decode_sd_jwt(l2_immediate.serialize()),
        issuer_public_key=issuer.public_key,
        l1_serialized=l1_immediate.serialize(),
        l2_serialized=l2_immediate.serialize(),
    )
    autonomous_result = verify_chain(
        decode_sd_jwt(l1_autonomous.serialize()),
        decode_sd_jwt(l2_autonomous.serialize()),
        l3_payment=decode_sd_jwt(l3_payment.serialize()),
        l3_checkout=decode_sd_jwt(l3_checkout.serialize()),
        issuer_public_key=issuer.public_key,
        l1_serialized=l1_autonomous.serialize(),
        l2_serialized=l2_autonomous.serialize(),
        l2_payment_serialized=l2_payment_presentation,
        l2_checkout_serialized=l2_checkout_presentation,
    )
    if not immediate_result.valid or not autonomous_result.valid:
        raise SystemExit(f"reference verify_chain failed: {immediate_result.errors} {autonomous_result.errors}")

    def public(key_pair):
        return {**key_pair.public_jwk, "kid": key_pair.kid}

    json.dump(
        {
            "generator": {
                "repository": "agent-intent/verifiable-intent",
                "commit": PIN,
                "sdk": "src/verifiable_intent",
                "script": "test/fixtures/generators/verifiable-intent-golden.py",
                "referenceVerifier": "verify_chain passed for both chains at asOf",
            },
            "asOf": AS_OF,
            "issuerJwk": public(issuer),
            "merchantJwk": public(merchant),
            "agentJwk": public(agent),
            "checkoutHash": checkout_hash,
            "immediate": {
                "l1": l1_immediate.serialize(),
                "l2": l2_immediate.serialize(),
                "l2Audience": "https://www.mastercard.com",
                "l2Nonce": "fixture-immediate-l2-nonce",
            },
            "autonomous": {
                "l1": l1_autonomous.serialize(),
                "l2": l2_autonomous.serialize(),
                "l2PaymentPresentation": l2_payment_presentation,
                "l2CheckoutPresentation": l2_checkout_presentation,
                "l3Payment": l3_payment.serialize(),
                "l3Checkout": l3_checkout.serialize(),
                "l2Audience": "https://agent.example.com",
                "l2Nonce": "fixture-autonomous-l2-nonce",
                "l3PaymentAudience": "https://www.mastercard.com",
                "l3PaymentNonce": "fixture-l3-payment-nonce",
                "l3CheckoutAudience": "https://tennis-warehouse.com",
                "l3CheckoutNonce": "fixture-l3-checkout-nonce",
            },
        },
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
