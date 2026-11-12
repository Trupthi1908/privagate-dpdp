"""Automated Document Error, Inconsistency, and Anomaly Detection Module for PrivaGate."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


def validate_document_anomalies(text: str) -> List[Dict[str, Any]]:
    """Scans document text using regex and business logic for common errors, invalid data formats,
    and missing mandatory fields:
    - Phone numbers that do not match standard 10-digit formats (e.g. 8-digit or incomplete phone numbers).
    - Missing or malformed PIN codes / postal codes (e.g. non-6-digit codes like 4, 5, or 7 digits).
    - Incomplete dates or invalid monetary figures (e.g. truncated dates or malformed currency figures).
    - Missing mandatory clauses (principal amount, interest rate, borrower name, terms).
    """
    anomalies: List[Dict[str, Any]] = []
    if not text or not text.strip():
        return anomalies

    t = text
    t_lower = text.lower()

    # =========================================================================
    # 1. Phone Number Validation (Standard 10-digit formats, catching 8-digit etc.)
    # =========================================================================
    phone_label_pattern = re.compile(
        r"(?:phone(?:\s*number)?|mobile(?:\s*no\.?|\s*number)?|contact(?:\s*no\.?|\s*number)?|cell|tel(?:ephone)?)[\s#:]*([+]?[\d\s-]{5,18})",
        re.IGNORECASE,
    )
    for m in phone_label_pattern.finditer(t):
        raw_val = m.group(1).strip()
        digits = re.sub(r"\D", "", raw_val)
        
        is_valid_len = False
        if len(digits) == 10 and digits[0] in "6789":
            is_valid_len = True
        elif len(digits) == 11 and digits.startswith("0") and digits[1] in "6789":
            is_valid_len = True
        elif len(digits) == 12 and digits.startswith("91") and digits[2] in "6789":
            is_valid_len = True

        if not is_valid_len and len(digits) > 0:
            anomalies.append({
                "type": "INVALID_PHONE_FORMAT",
                "severity": "HIGH",
                "field": "phone_number",
                "raw_value": raw_val,
                "description": (
                    f"Invalid phone number format: '{raw_val}' contains {len(digits)} digits. "
                    f"Standard mobile numbers must be 10 digits (e.g. 9876543210)."
                ),
            })

    # Catch standalone 7-9 digit numbers in phone-like contexts
    standalone_short_phones = re.findall(r"\b(?<!\d)[6-9]\d{6,8}(?!\d)\b", t)
    for sp in standalone_short_phones:
        if not any(sp in a.get("raw_value", "") for a in anomalies if a["type"] == "INVALID_PHONE_FORMAT"):
            idx = t.find(sp)
            ctx_before = t_lower[max(0, idx - 25):idx]
            if not any(k in ctx_before for k in ["rs", "inr", "₹", "amount", "salary", "pincode", "pin", "date", "tenure"]):
                anomalies.append({
                    "type": "INVALID_PHONE_FORMAT",
                    "severity": "HIGH",
                    "field": "phone_number",
                    "raw_value": sp,
                    "description": (
                        f"Incomplete phone number detected: '{sp}' has only {len(sp)} digits instead of standard 10 digits."
                    ),
                })

    # =========================================================================
    # 2. PIN Code / Postal Code Validation (Indian 6-digit standard)
    # =========================================================================
    pin_label_pattern = re.compile(
        r"(?:postal(?:\s*code)?|pin(?:\s*code)?|pincode|zip(?:\s*code)?)[\s:#-]*([0-9]{3,10})",
        re.IGNORECASE,
    )
    found_pin_labels = False
    for m in pin_label_pattern.finditer(t):
        found_pin_labels = True
        raw_val = m.group(1).strip()
        digits = re.sub(r"\D", "", raw_val)
        if len(digits) != 6 or (len(digits) == 6 and digits.startswith("0")):
            anomalies.append({
                "type": "MALFORMED_PIN_CODE",
                "severity": "HIGH",
                "field": "pincode",
                "raw_value": raw_val,
                "description": (
                    f"Malformed postal PIN code: '{raw_val}' has {len(digits)} digits. "
                    f"Standard postal PIN codes must be exactly 6 digits starting with 1-9 (e.g. 560001)."
                ),
            })

    has_address_context = any(
        k in t_lower
        for k in ["address", "residential", "premises", "flat no", "street", "nagar", "road", "bangalore", "mumbai", "delhi", "karnataka", "maharashtra"]
    )
    if has_address_context and not found_pin_labels:
        six_digit_pins = re.findall(r"\b[1-9]\d{5}\b", t)
        if not six_digit_pins:
            anomalies.append({
                "type": "MISSING_PIN_CODE",
                "severity": "MEDIUM",
                "field": "pincode",
                "raw_value": None,
                "description": "Residential/Office address is specified but missing a mandatory 6-digit postal PIN code.",
            })

    # =========================================================================
    # 3. Incomplete Dates & Invalid Monetary Figures
    # =========================================================================
    # Truncated year (e.g. 15/08/202 with 3-digit year or 15/08/2 with 1-digit year)
    truncated_date_pattern = re.compile(
        r"\b\d{1,2}[/-]\d{1,2}[/-]\d{1,3}\b(?!\d)|\b\d{4}[/-]\d{1,2}[/-](?!\d)"
    )
    for m in truncated_date_pattern.finditer(t):
        raw_date = m.group(0).strip()
        anomalies.append({
            "type": "INCOMPLETE_DATE",
            "severity": "HIGH",
            "field": "date",
            "raw_value": raw_date,
            "description": f"Incomplete or truncated date detected: '{raw_date}' lacks standard complete calendar components (DD/MM/YYYY or YYYY-MM-DD).",
        })

    standard_date_pattern = re.compile(r"\b(\d{1,2})[/-](\d{1,2})[/-](\d{4})\b")
    for m in standard_date_pattern.finditer(t):
        d1, d2, yr = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if d1 > 31 or d2 > 31 or (d1 > 12 and d2 > 12):
            anomalies.append({
                "type": "INVALID_DATE_VALUES",
                "severity": "HIGH",
                "field": "date",
                "raw_value": m.group(0),
                "description": f"Calendar date '{m.group(0)}' contains out-of-range day or month values.",
            })

    # Malformed or missing monetary figures
    malformed_curr_pattern = re.compile(
        r"(?:₹|\bINR\b|\bRs\.|\bRs\b(?!\.))\s*(?:([^0-9\s\n,][^\n\r]*)|$)",
        re.IGNORECASE | re.MULTILINE,
    )
    for m in malformed_curr_pattern.finditer(t):
        raw_val = m.group(0).strip()
        anomalies.append({
            "type": "INVALID_MONETARY_FIGURE",
            "severity": "HIGH",
            "field": "monetary_amount",
            "raw_value": raw_val,
            "description": f"Invalid monetary figure detected: '{raw_val}' contains malformed syntax, missing numeric value, or negative quantity.",
        })

    # =========================================================================
    # 4. Mandatory Financial & Contractual Fields Extraction / Check
    # =========================================================================
    is_finance_doc = any(k in t_lower for k in ["loan", "credit", "borrower", "sanction", "lender", "emi", "interest rate", "repayment", "facility"])
    if is_finance_doc:
        has_amt = re.search(
            r"(?:principal(?:\s+loan)?(?:\s+facility)?\s+amount|loan\s+facility\s+requested|credit\s+facility|loan\s+amount|sanction(?:ed)?\s+amount|facility\s+amount|principal\s+amount)[\s:]*([^\n\r]+)",
            t,
            re.IGNORECASE,
        ) or re.search(r"(?:₹|Rs\.?|INR)\s*[\d,]+", t, re.IGNORECASE)
        if not has_amt:
            anomalies.append({
                "type": "MISSING_PRINCIPAL_AMOUNT",
                "severity": "HIGH",
                "field": "principal_amount",
                "raw_value": None,
                "description": "Mandatory Principal Loan Facility Amount could not be located in document text.",
            })

        has_roi = re.search(
            r"(?:rate\s+of\s+interest|interest\s+rate|roi|annualized\s+interest)[\s:]*([^\n\r]+)",
            t,
            re.IGNORECASE,
        ) or re.search(r"\b\d+(?:\.\d+)?\s*%\s*(?:p\.?a\.?|per\s+annum)?\b", t, re.IGNORECASE)
        if not has_roi:
            anomalies.append({
                "type": "MISSING_INTEREST_RATE",
                "severity": "MEDIUM",
                "field": "interest_rate",
                "raw_value": None,
                "description": "Annualized Rate of Interest (ROI) is not declared in the agreement terms.",
            })

        has_borrower = re.search(
            r"(?:borrower(?:\s+full)?\s+name|applicant(?:\s+full)?\s+name|customer(?:\s+full)?\s+name|borrower\s+name|applicant\s+name)[\s:]*([^\n\r]+)",
            t,
            re.IGNORECASE,
        ) or any("PERSON" in tok for tok in re.findall(r"<[A-Z_]+_\d+>", t))
        if not has_borrower:
            anomalies.append({
                "type": "MISSING_BORROWER_NAME",
                "severity": "HIGH",
                "field": "borrower_name",
                "raw_value": None,
                "description": "Designated Borrower or Applicant Name could not be located in document text.",
            })

        has_tenure = re.search(
            r"(?:repayment\s+tenure|loan\s+tenure|tenure|duration|term|months|installments)[\s:]*([^\n\r]+)",
            t,
            re.IGNORECASE,
        ) or re.search(r"\b\d+\s*(?:months|years|installments)\b", t, re.IGNORECASE)
        if not has_tenure:
            anomalies.append({
                "type": "MISSING_REPAYMENT_TERMS",
                "severity": "MEDIUM",
                "field": "tenure",
                "raw_value": None,
                "description": "Loan Repayment Tenure and Terms could not be located in document clauses.",
            })

    return anomalies
