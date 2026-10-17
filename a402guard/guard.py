"""Deterministic spend firewall for A402 buyers -- stdlib only.

An agent that can spend money is the sharpest attack surface in agent
engineering: the seller controls the bill text, the resource description and
every redirect in the chain, and the buyer is the one holding the wallet.
Prompt injection aimed at a paying agent is not a content problem, it is a
money problem.

Design contract (identical discipline to AgentGuard):

  * deterministic -- no model in the decision path, ever
  * every finding carries a rule id and the matched span
  * four categories NEVER downgrade for "educational" or quoted context:
    exfiltration, tool coercion, credentials, forged system tags
  * a bill that fails screening is denied, never "flagged and continued"
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

ALLOW = "allow"
DENY = "deny"
NEEDS_HUMAN = "needs_human"

# Categories that must not be softened just because the text looks educational.
HARD_CATEGORIES = frozenset(
    {"exfiltration", "tool_coercion", "credentials", "forged_system"}
)

# (rule_id, category, severity, pattern)
RULES: List[Tuple[str, str, int, str]] = [
    ("a402.instruction_override", "injection", 3,
     r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules)"),
    ("a402.instruction_override_zh", "injection", 3,
     r"忽略(?:上面|之前|以上|所有)(?:的)?(?:指令|提示|规则)"),
    ("a402.system_override", "injection", 3,
     r"disregard\s+(?:your|the)\s+(?:system|safety|spending)\s+(?:prompt|rules|limits)"),
    ("a402.forged_system_en", "forged_system", 4,
     r"(?:^|\n)\s*(?:system|developer|assistant)\s*[:：]"),
    ("a402.forged_system_tag", "forged_system", 4,
     r"</?(?:system|im_start|im_end)>"),
    ("a402.jailbreak_dan", "jailbreak", 3,
     r"\b(?:dan\s+mode|do\s+anything\s+now|developer\s+mode\s+enabled)\b"),
    ("a402.jailbreak_persona", "jailbreak", 2,
     r"you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|unfiltered|unlimited)\b"),
    ("a402.tool_coercion", "tool_coercion", 4,
     r"(?:call|invoke|run|execute)\s+(?:the\s+)?(?:pay|transfer|purchase|refund|withdraw)\s*(?:tool|api|function)?\s*(?:now|immediately|again)?"),
    ("a402.tool_coercion_zh", "tool_coercion", 4,
     r"(?:立即|马上|立刻)(?:调用|执行)?(?:付款|转账|支付|下单|提现)"),
    ("a402.exfiltration", "exfiltration", 4,
     r"(?:send|post|upload|forward)\s+(?:the\s+)?(?:api\s+)?(?:key|token|secret|password|credential|wallet)"),
    ("a402.exfiltration_url", "exfiltration", 4,
     r"(?:webhook|curl|fetch|POST)\s+(?:to\s+)?https?://"),
    ("a402.exfiltration_zh", "exfiltration", 4,
     r"(?:发送|上传|外发|转发)(?:你的)?(?:密钥|令牌|密码|凭证|钱包|私钥)"),
    ("a402.credentials", "credentials", 4,
     r"(?:read|cat|dump|print|show)\s+(?:/|\.{0,2}/)?(?:~/)?(?:etc/)?"
     r"(?:passwd|shadow|\.env|\.aws/credentials|id_rsa|\.ssh/id_)"
     r"|BEGIN\s+(?:RSA|OPENSSH|PRIVATE)\s+PRIVATE\s+KEY"),
    ("a402.credentials_zh", "credentials", 4,
     r"(?:读取|打印|输出|展示)(?:你的)?(?:私钥|密钥文件|口令文件|\.env)"),
    ("a402.prompt_echo", "prompt_echo", 2,
     r"(?:repeat|print|reveal|show)\s+(?:your\s+)?(?:system\s+prompt|instructions|rules)\s*(?:back)?"),
    ("a402.privilege", "privilege", 2,
     r"\b(?:sudo|rm\s+-rf|chmod\s+777|chown\s+root)\b"),
    ("a402.urgency_pressure", "social_engineering", 2,
     r"(?:act\s+now|immediately|within\s+\d+\s+(?:seconds|minutes)|last\s+chance)"
     r"\s*(?:or\s+(?:you\s+)?(?:lose|forfeit|miss))?"),
    ("a402.amount_bait", "social_engineering", 3,
     r"(?:set|change|raise|override)\s+(?:the\s+)?(?:amount|price|budget|limit)\s+to\b"),
    ("a402.payee_swap", "social_engineering", 4,
     r"(?:pay|send|transfer)\s+(?:to\s+)?(?:this\s+)?(?:new|different|updated)\s+(?:account|address|wallet|recipient)"),
    ("a402.payee_swap_zh", "social_engineering", 4,
     r"(?:付款|转账|支付)到(?:这个)?(?:新的|另一个|更换后的?)(?:账户|地址|钱包)"),
    ("a402.refund_loop", "social_engineering", 3,
     r"(?:pay\s+again|double\s+pay|re-?pay)\s+(?:and\s+)?(?:get\s+)?(?:refund|cashback)"),
]

_COMPILED = [(rid, cat, sev, re.compile(pat, re.IGNORECASE)) for rid, cat, sev, pat in RULES]

# ---- PII with real check digits (a regex alone produces false refusals) ----

_CN_MOBILE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_CN_ID = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")
_CARD = re.compile(r"(?<!\d)\d{16,19}(?!\d)")
# The domain must be label-based, not "2+ chars then a dot": that shape rejects
# every single-letter domain (a@b.com) and matches nonsense like a@..com.
_EMAIL = re.compile(
    r"[A-Za-z0-9._%+\-]{1,200}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,}"
)

_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK = "10X98765432"


def _luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _cn_id_ok(value: str) -> bool:
    """GB 11643 check digit -- the only way to tell an ID from a random number."""
    if len(value) != 18:
        return False
    total = 0
    for index in range(17):
        char = value[index]
        if not char.isdigit():
            return False
        total += (ord(char) - 48) * _ID_WEIGHTS[index]
    expected = _ID_CHECK[total % 11]
    return value[17].upper() == expected


def screen_pii(text: str) -> List[Dict[str, object]]:
    """Return PII findings with real checksum validation, or nothing.

    A 18-digit run that fails GB 11643 is not an ID card number, and refusing to
    pay a bill because it happened to contain a long integer would be a false
    positive that costs real money.
    """
    out: List[Dict[str, object]] = []
    for match in _CN_MOBILE.finditer(text):
        out.append({"rule": "a402.pii.mobile", "category": "pii", "severity": 3,
                    "span": match.group(0)})
    for match in _CN_ID.finditer(text):
        if _cn_id_ok(match.group(0)):
            out.append({"rule": "a402.pii.cn_id", "category": "pii", "severity": 4,
                        "span": match.group(0)})
    if "@" in text:
        for match in _EMAIL.finditer(text):
            out.append({"rule": "a402.pii.email", "category": "pii", "severity": 2,
                        "span": match.group(0)})
    if any(ch.isdigit() for ch in text):
        for match in _CARD.finditer(text):
            digits = match.group(0)
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                out.append({"rule": "a402.pii.card", "category": "pii", "severity": 4,
                            "span": digits})
    return out


def screen(text: str) -> List[Dict[str, object]]:
    """Screen any seller-controlled text.  Deterministic, no model involved."""
    if not isinstance(text, str) or not text:
        return []
    findings: List[Dict[str, object]] = []
    for rule_id, category, severity, pattern in _COMPILED:
        match = pattern.search(text)
        if match:
            findings.append({
                "rule": rule_id,
                "category": category,
                "severity": severity,
                "span": match.group(0)[:120],
            })
    findings.extend(screen_pii(text))
    findings.sort(key=lambda item: (-int(item["severity"]), str(item["rule"])))
    return findings


def _educational(text: str) -> bool:
    return bool(
        re.search(r"(?:for\s+)?(?:educational|training|example|demo|test|sample)\s+"
                  r"(?:purposes?|only|data|input)", text, re.IGNORECASE)
        or re.search(r"(?:教育|培训|示例|测试|演示)(?:用途|用|数据|输入)", text)
    )


class Decision(object):
    """Immutable outcome of one spend evaluation."""

    __slots__ = ("action", "reasons", "findings", "amount_cents", "out_trade_no")

    def __init__(self, action: str, reasons: List[str], findings: List[Dict[str, object]],
                 amount_cents: int = 0, out_trade_no: str = ""):
        self.action = action
        self.reasons = reasons
        self.findings = findings
        self.amount_cents = amount_cents
        self.out_trade_no = out_trade_no

    def as_dict(self) -> Dict[str, object]:
        return {
            "action": self.action,
            "reasons": list(self.reasons),
            "findings": list(self.findings),
            "amount_cents": self.amount_cents,
            "out_trade_no": self.out_trade_no,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return "Decision(%s, %s)" % (self.action, self.reasons)


def evaluate_bill(bill: Dict[str, object], resource_text: str = "",
                  remaining_cents: int = 0, known_payee: bool = True,
                  educational: Optional[bool] = None) -> Decision:
    """Decide whether this specific bill may be paid.

    Order of checks is the security property:

      1. text screening (injection / coercion / exfil / PII)
      2. hard-category refusal -- never downgraded
      3. budget arithmetic
      4. unknown-payee human gate

    A bill that trips (2) is denied even when the budget is fine.  A bill that
    trips (3) is denied even when the text is clean.  There is no path where a
    finding is merely "noted" and the spend continues.
    """
    findings: List[Dict[str, object]] = []
    haystack = " ".join(
        str(bill.get(key, "")) for key in
        ("resource_id", "description", "memo", "note", "title", "seller_note")
    )
    if resource_text:
        haystack = haystack + " " + resource_text
    findings.extend(screen(haystack))

    is_edu = _educational(haystack) if educational is None else educational

    reasons: List[str] = []
    hard_hits = [f for f in findings if str(f["category"]) in HARD_CATEGORIES]
    if hard_hits:
        # Hard categories are never downgraded -- not for education, not for demos.
        for finding in hard_hits:
            reasons.append("hard-redline:%s" % finding["rule"])
        return Decision(DENY, reasons, findings)

    soft_hits = [f for f in findings if str(f["category"]) not in HARD_CATEGORIES]
    if soft_hits:
        if is_edu:
            for finding in soft_hits:
                reasons.append("downgraded(educational):%s" % finding["rule"])
        else:
            for finding in soft_hits:
                reasons.append("refused:%s" % finding["rule"])
            return Decision(DENY, reasons, findings)

    amount = int(round(float(bill.get("amount", 0)) * 100))
    if amount <= 0:
        reasons.append("nonpositive-amount")
        return Decision(DENY, reasons, findings)
    if remaining_cents < amount:
        reasons.append("over-budget:need=%d have=%d" % (amount, remaining_cents))
        return Decision(DENY, reasons, findings)

    if not known_payee:
        reasons.append("unknown-payee:human-confirmation-required")
        return Decision(NEEDS_HUMAN, reasons, findings,
                        amount_cents=amount, out_trade_no=str(bill.get("out_trade_no", "")))

    reasons.append("clean-within-budget")
    return Decision(ALLOW, reasons, findings,
                    amount_cents=amount, out_trade_no=str(bill.get("out_trade_no", "")))
