# A402Guard

**The A402 paying agent that may propose, but never decides.**

An agent that can spend money is the sharpest attack surface in agent
engineering: the seller writes the bill text, the resource description and every
redirect in the chain — and the buyer is the one holding the wallet. Prompt
injection aimed at a paying agent is not a content problem, it is a money
problem.

A402Guard implements the A402 (`HTTP 402 Payment Required`) buyer loop with a
**deterministic spend firewall** in front of the money.

```
GET resource ──► 402 + Payment-Needed
                    │
                    ├─ decode + structural gate      (bill.py)
                    ├─ verify seller signature       (bill.py)
                    ├─ SPEND FIREWALL                (guard.py)   ← no model here
                    │     ├─ deny   → receipt, no charge
                    │     ├─ needs_human → held, no charge
                    │     └─ allow  → charge
                    ├─ idempotency gate BEFORE charge (ledger.py)
                    ├─ pay → Payment-Proof
                    └─ retry GET with proof → resource + receipt
```

## Run it

```bash
python eval.py     # 89 assertions, offline, stdlib only
python demo.py     # end-to-end against the bundled mock seller
```

Both run with zero network access, zero API keys and zero third-party packages.

## What is enforced

| Property | Where | How it is proven |
|---|---|---|
| **Bill structure** | `bill.py` | Missing field / bad amount / bad currency / bad date all raise before anything else runs |
| **Seller authenticity** | `bill.py` | HMAC-SHA256 over the canonical bill; a tampered amount fails verification |
| **No injection spend** | `guard.py` | 21 deterministic rules across injection / jailbreak / forged system tags / tool coercion / exfiltration / credentials / payee swap |
| **Hard red lines never downgrade** | `guard.py` | exfiltration, tool coercion, credentials, forged system tags stay `deny` even inside explicitly educational text |
| **False positives stay cheap** | `guard.py` | PII uses real check digits (GB 11643 for 18-digit IDs, Luhn for cards) — a random 18-digit number is not an ID |
| **Budget is arithmetic** | `ledger.py` | integer cents only; an over-budget bill is denied by subtraction, not by policy |
| **Pay once** | `agent.py` | the duplicate check runs *before* the charge; a replayed bill is suppressed and never charged |
| **Unknown payee** | `agent.py` | routed to `needs_human`, costs nothing, stays in the receipt |
| **Every decision receipted** | `ledger.py` | paid / denied / held / suppressed, each with the rule ids that decided it |

## Design contract

* **stdlib only** — no dependencies, so it runs anywhere Python runs
* **no model in the spend path** — an LLM may propose which resource to fetch;
  it never decides whether a bill may be paid
* **deterministic** — the same bill produces the same decision, every time
* **money is integer cents** — floats never touch the budget

## Delta from the official A402 spec

The official seller signature is **RSA2**. Python's stdlib has no RSA, so
`bill.sign_bill` / `bill.verify_bill` use HMAC-SHA256 as a **stand-in with the
identical call shape**. Swapping in RSA2 (via the official Alipay SDK) is a
single function replacement and touches neither the agent, the guard nor the
ledger. Everything else — the `Payment-Needed` / `Payment-Proof` header shapes,
the bill fields, the 402 → pay → retry loop — follows the documented protocol.

## Layout

```
a402guard/bill.py     A402 codec: Base64URL bills, Base64 proofs, signature
a402guard/guard.py    deterministic spend firewall (21 rules + PII check digits)
a402guard/ledger.py   idempotent, budgeted, receipted spend ledger (cents)
a402guard/agent.py    the buyer loop
mock_seller.py        offline A402 seller with one route per adversarial case
eval.py               89 assertions (incl. a real LC_ALL=C subprocess run)
demo.py               printable end-to-end run
```

## License

MIT
