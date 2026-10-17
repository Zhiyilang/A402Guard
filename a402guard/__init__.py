"""A402Guard -- an A402 paying agent with a deterministic spend firewall.

    request -> 402 + bill -> structural gate -> signature check
            -> SPEND FIREWALL -> pay -> proof -> retry -> receipt

stdlib only.  No model in the spend decision path.
"""

from .agent import A402Error, BuyerAgent
from .bill import BillError
from .guard import ALLOW, DENY, NEEDS_HUMAN, evaluate_bill, screen, screen_pii
from .ledger import Ledger

__all__ = [
    "A402Error", "BuyerAgent", "BillError",
    "ALLOW", "DENY", "NEEDS_HUMAN",
    "evaluate_bill", "screen", "screen_pii", "Ledger",
]

__version__ = "0.1.0"
