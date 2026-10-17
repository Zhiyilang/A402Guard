"""Idempotent spend ledger -- stdlib only, integer cents, append-only.

Three properties the agent depends on:

  * **idempotent** -- the same ``out_trade_no`` can never be charged twice,
    no matter how many times the seller (or a retry) presents the bill
  * **budgeted** -- a session ceiling in integer cents; once exhausted every
    further bill is denied by arithmetic, not by policy
  * **receipted** -- every decision, paid or refused, produces a receipt line
    with the guard's reasons attached

Float money never enters this file.  Everything is cents.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional


class Ledger(object):
    def __init__(self, session_budget_cents: int, session_id: str = "session"):
        if session_budget_cents < 0:
            raise ValueError("session budget cannot be negative")
        self.session_budget_cents = int(session_budget_cents)
        self.session_id = session_id
        self._entries: List[Dict[str, Any]] = []
        self._by_trade: Dict[str, Dict[str, Any]] = {}

    # -- queries ---------------------------------------------------------
    def spent_cents(self) -> int:
        return sum(int(e["amount_cents"]) for e in self._entries if e["paid"])

    def remaining_cents(self) -> int:
        return self.session_budget_cents - self.spent_cents()

    def seen(self, out_trade_no: str) -> bool:
        return out_trade_no in self._by_trade

    def entries(self) -> List[Dict[str, Any]]:
        return [dict(e) for e in self._entries]

    def paid_count(self) -> int:
        return sum(1 for e in self._entries if e["paid"])

    def refused_count(self) -> int:
        """Real refusals only -- a suppressed replay is not a refusal.

        Conflating the two makes the receipt lie: a seller hammering the same
        bill would look like a guard doing work, when in fact no decision was
        made at all.
        """
        return sum(1 for e in self._entries
                   if not e["paid"] and e["action"] == "deny" and not e.get("duplicate"))

    def needs_human_count(self) -> int:
        return sum(1 for e in self._entries if not e["paid"] and e["action"] == "needs_human")

    def duplicate_suppressed_count(self) -> int:
        """How many times a re-presented bill was refused as already settled."""
        return sum(1 for e in self._entries if e.get("duplicate"))

    # -- mutation --------------------------------------------------------
    def _append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        entry["ts"] = time.time()
        entry["session_id"] = self.session_id
        self._entries.append(entry)
        return entry

    def record_paid(self, bill: Dict[str, Any], amount_cents: int,
                    decision_reasons: List[str], proof: Optional[Dict[str, Any]] = None,
                    resource: str = "") -> Dict[str, Any]:
        out_trade_no = str(bill.get("out_trade_no", ""))
        if not out_trade_no:
            raise ValueError("cannot record a payment without out_trade_no")
        if self.seen(out_trade_no):
            # Idempotency is not an optimisation, it is the safety property:
            # a seller that replays a bill must not be able to drain the budget.
            return self._append({
                "out_trade_no": out_trade_no,
                "amount_cents": 0,
                "currency": str(bill.get("currency", "")),
                "resource_id": str(bill.get("resource_id", "")),
                "action": "deny",
                "paid": False,
                "duplicate": True,
                "reasons": ["duplicate:already-settled"],
            })
        if amount_cents > self.remaining_cents():
            return self._append({
                "out_trade_no": out_trade_no,
                "amount_cents": amount_cents,
                "currency": str(bill.get("currency", "")),
                "resource_id": str(bill.get("resource_id", "")),
                "action": "deny",
                "paid": False,
                "duplicate": False,
                "reasons": ["ledger:over-budget"],
            })
        entry = {
            "out_trade_no": out_trade_no,
            "amount_cents": amount_cents,
            "currency": str(bill.get("currency", "")),
            "resource_id": str(bill.get("resource_id", "")),
            "action": "allow",
            "paid": True,
            "duplicate": False,
            "reasons": list(decision_reasons),
            "proof_trade_no": str((proof or {}).get("trade_no", "")),
            "resource": resource[:200],
        }
        self._by_trade[out_trade_no] = entry
        return self._append(entry)

    def record_refused(self, bill: Dict[str, Any], amount_cents: int,
                       action: str, decision_reasons: List[str],
                       duplicate: bool = False) -> Dict[str, Any]:
        return self._append({
            "duplicate": bool(duplicate),
            "out_trade_no": str(bill.get("out_trade_no", "")),
            "amount_cents": amount_cents,
            "currency": str(bill.get("currency", "")),
            "resource_id": str(bill.get("resource_id", "")),
            "action": action,
            "paid": False,
            "reasons": list(decision_reasons),
        })

    # -- output ----------------------------------------------------------
    def receipt(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "budget_cents": self.session_budget_cents,
            "spent_cents": self.spent_cents(),
            "remaining_cents": self.remaining_cents(),
            "paid": self.paid_count(),
            "refused": self.refused_count(),
            "needs_human": self.needs_human_count(),
            "duplicates_suppressed": self.duplicate_suppressed_count(),
            "entries": self.entries(),
        }

    def receipt_text(self) -> str:
        """Human-readable decision trail -- the artifact a judge can read."""
        data = self.receipt()
        lines = [
            "A402Guard receipt  session=%s" % data["session_id"],
            "budget=%d cents  spent=%d  remaining=%d"
            % (data["budget_cents"], data["spent_cents"], data["remaining_cents"]),
            "paid=%d refused=%d needs_human=%d duplicates_suppressed=%d"
            % (data["paid"], data["refused"], data["needs_human"], data["duplicates_suppressed"]),
            "-" * 68,
        ]
        for entry in data["entries"]:
            state = "PAID " if entry["paid"] else ("ASK  " if entry["action"] == "needs_human" else "DENY ")
            lines.append("%s %s  %6d cents  %s" % (
                state, entry["out_trade_no"][:20].ljust(20),
                entry["amount_cents"], entry["resource_id"]))
            for reason in entry["reasons"][:3]:
                lines.append("        - %s" % reason)
        lines.append("-" * 68)
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(self.receipt(), ensure_ascii=False, indent=2, sort_keys=True)
