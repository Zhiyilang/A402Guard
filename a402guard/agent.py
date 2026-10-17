"""The A402 buyer agent -- stdlib only, deterministic.

Loop (one purchase attempt):

    GET resource -> 402 + Payment-Needed
        -> decode bill -> structural gate
        -> verify seller signature
        -> spend firewall (guard)
        -> pay (out of band) -> Payment-Proof
        -> retry GET with proof -> resource + receipt

The model is nowhere in this loop.  An LLM may *propose* which resource to
fetch; it never decides whether the bill may be paid.  That split is the whole
product: proposal is cheap and fuzzy, the spend decision is arithmetic plus
deterministic rules.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Optional

from . import bill as bill_codec
from .guard import ALLOW, DENY, NEEDS_HUMAN, evaluate_bill
from .ledger import Ledger

DEFAULT_TIMEOUT = 10.0


class A402Error(RuntimeError):
    pass


class BuyerAgent(object):
    def __init__(self, ledger: Ledger, seller_secret: str,
                 pay: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
                 timeout: float = DEFAULT_TIMEOUT,
                 known_payees: Optional[set] = None):
        self.ledger = ledger
        self.seller_secret = seller_secret
        self._pay = pay or self._default_pay
        self.timeout = timeout
        self.known_payees = known_payees or set()

    # -- pluggable payment step -----------------------------------------
    def _default_pay(self, bill_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Default payer: POST to the seller's /pay endpoint.

        Overridable so the whole loop can be exercised offline against a mock.
        """
        endpoint = str(bill_obj.get("pay_endpoint", ""))
        if not endpoint:
            raise A402Error("bill carries no pay_endpoint")
        payload = json.dumps({
            "out_trade_no": bill_obj.get("out_trade_no"),
            "amount": bill_obj.get("amount"),
            "currency": bill_obj.get("currency"),
        }).encode("utf-8")
        request = urllib.request.Request(
            endpoint, data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    # -- the loop --------------------------------------------------------
    def buy(self, url: str, resource_text: str = "") -> Dict[str, Any]:
        """Attempt one purchase.  Returns a decision record, never raises for
        seller misbehaviour -- a hostile seller is the expected input."""
        request = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                # 200 without a 402: nothing to pay, nothing to guard.
                return {"status": "free",
                        "body": response.read().decode("utf-8", "replace")}
        except urllib.error.HTTPError as error:
            if error.code != 402:
                return {"status": "error",
                        "reason": "unexpected-status:%d" % error.code}
            needed = error.headers.get("Payment-Needed") or error.headers.get("payment-needed")
            if not needed:
                return {"status": "error", "reason": "402-without-payment-needed"}
            return self._handle_bill(url, needed, resource_text, error)

    def _handle_bill(self, url: str, needed: str, resource_text: str,
                     error: urllib.error.HTTPError) -> Dict[str, Any]:
        try:
            bill_obj = bill_codec.decode_bill(needed)
        except bill_codec.BillError as exc:
            return {"status": "error", "reason": "undecodable-bill:%s" % exc}

        try:
            bill_codec.validate_bill(bill_obj)
        except bill_codec.BillError as exc:
            self.ledger.record_refused(bill_obj if isinstance(bill_obj, dict) else {},
                                       0, DENY, ["malformed-bill:%s" % exc])
            return {"status": "denied", "reason": "malformed-bill",
                    "detail": str(exc)}

        if not bill_codec.verify_bill(bill_obj, self.seller_secret):
            self.ledger.record_refused(bill_obj, 0, DENY,
                                       ["signature-mismatch:untrusted-seller"])
            return {"status": "denied", "reason": "signature-mismatch"}

        payee = str(bill_obj.get("seller_id", "") or bill_obj.get("payee", ""))
        known = (not self.known_payees) or (payee in self.known_payees)

        decision = evaluate_bill(
            bill_obj,
            resource_text=resource_text,
            remaining_cents=self.ledger.remaining_cents(),
            known_payee=known,
        )

        if decision.action == DENY:
            self.ledger.record_refused(bill_obj, decision.amount_cents, DENY,
                                       decision.reasons)
            return {"status": "denied", "reasons": decision.reasons,
                    "findings": decision.findings,
                    "out_trade_no": bill_obj.get("out_trade_no")}

        if decision.action == NEEDS_HUMAN:
            self.ledger.record_refused(bill_obj, decision.amount_cents, NEEDS_HUMAN,
                                       decision.reasons)
            return {"status": "needs_human", "reasons": decision.reasons,
                    "out_trade_no": bill_obj.get("out_trade_no")}

        amount_cents = bill_codec.amount_cents(bill_obj)

        # Idempotency gate BEFORE the money moves.  Checking afterwards would
        # mean the second charge already happened -- the exact failure this
        # ledger exists to prevent.
        if self.ledger.seen(str(bill_obj.get("out_trade_no", ""))):
            self.ledger.record_refused(bill_obj, amount_cents, DENY,
                                       ["duplicate:already-settled-before-charge"],
                                       duplicate=True)
            return {"status": "duplicate_suppressed",
                    "out_trade_no": bill_obj.get("out_trade_no"),
                    "charged": False}

        try:
            proof = self._pay(dict(bill_obj))
        except Exception as exc:  # noqa: BLE001
            self.ledger.record_refused(bill_obj, amount_cents, DENY,
                                       ["payment-failed:%s" % exc])
            return {"status": "error", "reason": "payment-failed", "detail": str(exc)}

        entry = self.ledger.record_paid(bill_obj, amount_cents, decision.reasons, proof)
        if entry.get("duplicate"):  # pragma: no cover - defensive
            return {"status": "duplicate_suppressed",
                    "out_trade_no": bill_obj.get("out_trade_no"), "charged": False}

        retry = urllib.request.Request(
            url, method="GET",
            headers={"Payment-Proof": bill_codec.encode_proof({
                "payment_proof": proof.get("payment_proof", ""),
                "trade_no": proof.get("trade_no", ""),
                "client_session": self.ledger.session_id,
            })},
        )
        try:
            with urllib.request.urlopen(retry, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001
            body = ""
            entry["delivery_error"] = str(exc)
        entry["resource"] = body[:200]
        return {"status": "paid", "body": body,
                "out_trade_no": bill_obj.get("out_trade_no"),
                "amount_cents": amount_cents,
                "remaining_cents": self.ledger.remaining_cents()}
