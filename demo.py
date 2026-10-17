"""End-to-end demo against the offline mock seller.

    python demo.py

Prints one receipt showing all four outcomes side by side: a clean paid
purchase, an injected bill denied, an unknown payee held for a human, and a
replayed bill suppressed without a second charge.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from a402guard.agent import BuyerAgent  # noqa: E402
from a402guard.ledger import Ledger  # noqa: E402
from mock_seller import CATALOG, SECRET, MockSeller  # noqa: E402


def main() -> int:
    with MockSeller() as seller:
        base = seller.base_url
        ledger = Ledger(1000, session_id="demo-session")  # 10.00 CNY ceiling
        agent = BuyerAgent(ledger, SECRET, known_payees={"seller_trusted"})

        print("A402Guard demo  (session budget 1000 cents = CNY 10.00)")
        print("=" * 68)

        result = agent.buy(base + "/r/good")
        print("[1] clean bill          -> %s  (%s)"
              % (result.get("status"), result.get("body", "")[:46]))

        result = agent.buy(base + "/r/inject")
        print("[2] injected bill       -> %s  reasons=%s"
              % (result.get("status"), result.get("reasons")))

        result = agent.buy(base + "/r/expensive")
        print("[3] over budget         -> %s  reasons=%s"
              % (result.get("status"), result.get("reasons")))

        result = agent.buy(base + "/r/unknown")
        print("[4] unknown payee       -> %s  reasons=%s"
              % (result.get("status"), result.get("reasons")))

        CATALOG["/r/second"]["out_trade_no"] = "T-DEMO-DUP"
        agent.buy(base + "/r/second")
        result = agent.buy(base + "/r/second")
        print("[5] replayed bill       -> %s  charged=%s"
              % (result.get("status"), result.get("charged")))

        print("=" * 68)
        print(ledger.receipt_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
