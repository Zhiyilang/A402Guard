"""A402 protocol codec -- HTTP 402 Payment Required, stdlib only.

Official shape (per Alipay AI Pay docs, Machine Pay / A402):

  * seller answers an uncredentialed request with HTTP 402 and a
    ``Payment-Needed`` header holding Base64URL(JSON bill)
  * the buyer retries with a ``Payment-Proof`` header holding Base64(JSON proof)

Bill fields used here: ``out_trade_no``/``amount``/``currency``/``resource_id``/
``pay_before``/``seller_signature``.

DELTA FROM OFFICIAL: the official seller signature is RSA2.  Python's stdlib has
no RSA, so ``sign_bill``/``verify_bill`` use HMAC-SHA256 as a **stand-in** with
the identical call shape.  Swapping in RSA2 is a single function replacement and
does not touch the agent, guard or ledger.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any, Dict

REQUIRED_BILL_FIELDS = (
    "out_trade_no",
    "amount",
    "currency",
    "resource_id",
    "pay_before",
)

_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?Z?)?$")
_AMOUNT = re.compile(r"^(0|[1-9]\d*)(\.\d{1,2})?$")


class BillError(ValueError):
    """Raised when a Payment-Needed / Payment-Proof payload is unusable."""


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or not text:
        raise BillError("empty base64url payload")
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:  # noqa: BLE001
        raise BillError("malformed base64url: %s" % exc)


def encode_json(obj: Any) -> str:
    return _b64url_encode(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def decode_json(text: str) -> Any:
    try:
        return json.loads(_b64url_decode(text).decode("utf-8"))
    except BillError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise BillError("payload is not json: %s" % exc)


def encode_bill(bill: Dict[str, Any]) -> str:
    """Serialize a bill into the ``Payment-Needed`` header value."""
    if not isinstance(bill, dict):
        raise BillError("bill must be a mapping")
    return encode_json(bill)


def decode_bill(text: str) -> Dict[str, Any]:
    """Parse a ``Payment-Needed`` header value back into a bill."""
    obj = decode_json(text)
    if not isinstance(obj, dict):
        raise BillError("bill payload is not an object")
    return obj


def validate_bill(bill: Dict[str, Any]) -> None:
    """Structural gate.  Raises BillError on the first problem found.

    Order matters: missing field -> wrong type -> out-of-range value.  A bill
    that fails this gate never reaches the guard, the ledger or the network.
    """
    for field in REQUIRED_BILL_FIELDS:
        if field not in bill:
            raise BillError("missing field: %s" % field)
    if not isinstance(bill["out_trade_no"], str) or not bill["out_trade_no"].strip():
        raise BillError("out_trade_no must be a non-empty string")
    amount = bill["amount"]
    if isinstance(amount, bool) or not isinstance(amount, (int, float, str)):
        raise BillError("amount must be numeric or a numeric string")
    if not _AMOUNT.match(str(amount)):
        raise BillError("amount is not a currency-shaped value: %r" % (amount,))
    if float(amount) <= 0:
        raise BillError("amount must be positive")
    if not isinstance(bill["currency"], str) or not re.match(r"^[A-Z]{3}$", bill["currency"]):
        raise BillError("currency must be a 3-letter upper-case code")
    if not isinstance(bill["resource_id"], str) or not bill["resource_id"].strip():
        raise BillError("resource_id must be a non-empty string")
    if not isinstance(bill["pay_before"], str) or not _ISO.match(bill["pay_before"]):
        raise BillError("pay_before must look like an ISO date/datetime")


def amount_cents(bill: Dict[str, Any]) -> int:
    """Integer cents -- the only representation the ledger is allowed to use.

    Float money is how budgets drift.  Everything downstream compares cents.
    """
    return int(round(float(bill["amount"]) * 100))


def sign_bill(bill: Dict[str, Any], secret: str) -> str:
    """HMAC-SHA256 stand-in for the official RSA2 seller signature."""
    payload = encode_json({k: bill.get(k) for k in REQUIRED_BILL_FIELDS})
    return hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).hexdigest()


def attach_signature(bill: Dict[str, Any], secret: str) -> Dict[str, Any]:
    out = dict(bill)
    out["seller_signature"] = sign_bill(bill, secret)
    return out


def verify_bill(bill: Dict[str, Any], secret: str) -> bool:
    sig = bill.get("seller_signature")
    if not isinstance(sig, str) or not sig:
        return False
    return hmac.compare_digest(sig, sign_bill(bill, secret))


def encode_proof(proof: Dict[str, Any]) -> str:
    """Serialize a proof into the ``Payment-Proof`` header value (plain Base64)."""
    return base64.b64encode(
        json.dumps(proof, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def decode_proof(text: str) -> Dict[str, Any]:
    try:
        obj = json.loads(base64.b64decode(text).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise BillError("malformed payment proof: %s" % exc)
    if not isinstance(obj, dict):
        raise BillError("payment proof is not an object")
    return obj
