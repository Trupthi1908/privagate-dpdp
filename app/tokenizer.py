"""Consistent Typed Tokenizer and Masking Engine with Purpose Policy and Format Preservation (FPT).

Compliant with DPDP Act 2023 Section 6 (Purpose Limitation) and Format-Preserving Tokenization.
"""

from __future__ import annotations

import hashlib
import random
import re
import string
from typing import Any, Dict, List, Optional, Tuple

# DPDP Section 6 Purpose Policy Matrix: defines prohibited entity types by processing purpose
PURPOSE_BLOCKED_ENTITIES: Dict[str, List[str]] = {
    "marketing": ["AADHAAR", "PAN", "GSTIN", "VOTER_ID", "PASSPORT"],
    "customer_support": ["AADHAAR", "PAN", "PASSPORT"],
    "general": [],
    "kyc_processing": [],
    "loan_underwriting": [],
}

# Cryptographically structured pools for Format-Preserving Tokenization (FPT)
def generate_fpt_dummy(entity_type: str, index: int, seed_key: str) -> str:
    """Generates format-valid synthetic dummy tokens matching Indian identity schemas."""
    # Deterministic pseudo-randomness based on entity index and text hash
    rng = random.Random(int(hashlib.md5(f"{seed_key}_{index}".encode()).hexdigest(), 16))

    if entity_type == "AADHAAR":
        p1 = "".join(str(rng.randint(2, 9)) if i == 0 else str(rng.randint(0, 9)) for i in range(4))
        p2 = "".join(str(rng.randint(0, 9)) for _ in range(4))
        p3 = "".join(str(rng.randint(0, 9)) for _ in range(4))
        return f"{p1} {p2} {p3}"

    elif entity_type == "PAN":
        letters1 = "".join(rng.choice(string.ascii_uppercase) for _ in range(5))
        digits = "".join(str(rng.randint(0, 9)) for _ in range(4))
        letter2 = rng.choice(string.ascii_uppercase)
        return f"{letters1}{digits}{letter2}"

    elif entity_type == "GSTIN":
        state_code = f"{rng.randint(1, 35):02d}"
        pan = "".join(rng.choice(string.ascii_uppercase) for _ in range(5)) + "".join(str(rng.randint(0, 9)) for _ in range(4)) + rng.choice(string.ascii_uppercase)
        return f"{state_code}{pan}1Z{rng.randint(1, 9)}"

    elif entity_type == "VOTER_ID":
        letters = "".join(rng.choice(string.ascii_uppercase) for _ in range(3))
        digits = "".join(str(rng.randint(0, 9)) for _ in range(7))
        return f"{letters}{digits}"

    elif entity_type == "PASSPORT":
        valid_letters = [c for c in string.ascii_uppercase if c not in ("Q", "X", "Z")]
        letter = rng.choice(valid_letters)
        d1 = str(rng.randint(1, 9))
        mid = "".join(str(rng.randint(0, 9)) for _ in range(5))
        d7 = str(rng.randint(1, 9))
        return f"{letter}{d1}{mid}{d7}"

    elif entity_type == "PERSON":
        dummies = [
            "Vikram Malhotra", "Ananya Deshmukh", "Rajesh Iyer", "Pooja Verma",
            "Amitabh Sen", "Sneha Kulkarni", "Rohan Mehta", "Divya Pillai"
        ]
        return dummies[(index - 1) % len(dummies)]

    elif entity_type == "ADDRESS":
        addresses = [
            "Flat No 101, Shanti Enclave, 4th Main Road, Indiranagar, Bengaluru - 560038",
            "Flat No 204, Green Heights, 2nd Cross, Vidyanagar, Davangere - 577004",
            "42 Park Avenue, Connaught Place, New Delhi - 110001",
            "Plot No 12, 1st Cross, Brigade Road, Ashok Nagar, Bengaluru - 560025",
        ]
        return addresses[(index - 1) % len(addresses)]

    return f"DUMMY_{entity_type}_{index}"


class TokenizerResult:
    def __init__(
        self,
        sanitized_text: str,
        placeholder_map: Dict[str, str],
        blocked_entities: List[Dict[str, Any]],
        detected_types: List[str],
        entity_count: int,
        leakage_count: int,
        format_preserving: bool = False,
    ):
        self.sanitized_text = sanitized_text
        self.placeholder_map = placeholder_map  # {placeholder_or_fpt_token: original_value}
        self.reverse_map = {v: k for k, v in placeholder_map.items()}
        self.blocked_entities = blocked_entities
        self.detected_types = detected_types
        self.entity_count = entity_count
        self.leakage_count = leakage_count
        self.format_preserving = format_preserving

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sanitized_text": self.sanitized_text,
            "placeholder_map": self.placeholder_map,
            "blocked_entities": self.blocked_entities,
            "detected_types": self.detected_types,
            "entity_count": self.entity_count,
            "leakage_count": self.leakage_count,
            "format_preserving": self.format_preserving,
        }


class ConsistentTokenizer:
    """Replaces detected PII with consistent typed placeholders (<TYPE_N>) or format-preserving tokens."""

    def __init__(self):
        pass

    def mask(
        self,
        text: str,
        detected_entities: List[Dict[str, Any]],
        purpose: str = "general",
        format_preserving: bool = False,
    ) -> TokenizerResult:
        """Tokenizes text based on detected entities, DPDP purpose policy, and FPT preference."""
        purpose_lower = purpose.lower().strip()
        blocked_types = set(PURPOSE_BLOCKED_ENTITIES.get(purpose_lower, []))

        type_counters: Dict[str, int] = {}
        raw_to_token: Dict[Tuple[str, str], str] = {}
        token_to_original: Dict[str, str] = {}
        blocked_list: List[Dict[str, Any]] = []

        valid_spans = self._filter_valid_spans(text, detected_entities)

        # 1. Establish consistent token mappings
        for item in valid_spans:
            entity_type = item["entity_type"].upper()
            raw_text = item["text"].strip()
            norm_key = (entity_type, raw_text.lower())

            if entity_type in blocked_types:
                blocked_list.append(
                    {
                        "entity_type": entity_type,
                        "raw_text": raw_text,
                        "reason": f"Prohibited under DPDP Section 6 purpose limitation for '{purpose}'",
                    }
                )
                continue

            if norm_key not in raw_to_token:
                idx = type_counters.get(entity_type, 0) + 1
                type_counters[entity_type] = idx

                if format_preserving:
                    token = generate_fpt_dummy(entity_type, idx, raw_text)
                else:
                    token = f"<{entity_type}_{idx}>"

                raw_to_token[norm_key] = token
                token_to_original[token] = raw_text

        # 2. Replace spans from right to left (descending start offset)
        sorted_spans = sorted(valid_spans, key=lambda x: x["start"], reverse=True)
        sanitized_chars = list(text)

        for item in sorted_spans:
            start = item["start"]
            end = item["end"]
            entity_type = item["entity_type"].upper()
            raw_text = item["text"].strip()
            norm_key = (entity_type, raw_text.lower())

            if entity_type in blocked_types:
                replacement = "[BLOCKED_BY_DPDP_POLICY]"
            else:
                replacement = raw_to_token.get(norm_key, f"<{entity_type}>")

            sanitized_chars[start:end] = list(replacement)

        sanitized_text = "".join(sanitized_chars)

        # 3. Secondary sweep for identical recurring values
        for norm_key, token in raw_to_token.items():
            _, original_val = norm_key
            if len(original_val) >= 3 and original_val.lower() in sanitized_text.lower():
                pattern = re.compile(re.escape(original_val), re.IGNORECASE)
                sanitized_text = pattern.sub(token, sanitized_text)

        # 4. Secondary sweep for blocked values
        for item in blocked_list:
            raw_val = item["raw_text"]
            if len(raw_val) >= 3 and raw_val.lower() in sanitized_text.lower():
                sanitized_text = re.sub(
                    re.escape(raw_val),
                    "[BLOCKED_BY_DPDP_POLICY]",
                    sanitized_text,
                    flags=re.IGNORECASE,
                )

        # 5. Outbound zero-leakage verification scan
        all_pii = list(token_to_original.values()) + [b["raw_text"] for b in blocked_list]
        leakage_count = self.verify_leakage(sanitized_text, all_pii)

        detected_types_list = sorted(list(set(item["entity_type"] for item in valid_spans)))

        return TokenizerResult(
            sanitized_text=sanitized_text,
            placeholder_map=token_to_original,
            blocked_entities=blocked_list,
            detected_types=detected_types_list,
            entity_count=len(valid_spans),
            leakage_count=leakage_count,
            format_preserving=format_preserving,
        )

    def verify_leakage(self, text: str, original_pii_values: List[str]) -> int:
        """Counts how many raw sensitive values leak into the sanitized text."""
        leakage = 0
        text_lower = text.lower()
        for val in original_pii_values:
            val_clean = val.strip()
            if len(val_clean) < 4:
                continue
            if val_clean.lower() in text_lower:
                leakage += 1
        return leakage

    def _filter_valid_spans(
        self, text: str, entities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        valid = []
        for ent in entities:
            start = ent.get("start", 0)
            end = ent.get("end", 0)
            if 0 <= start < end <= len(text):
                ent_copy = dict(ent)
                if "text" not in ent_copy:
                    ent_copy["text"] = text[start:end]
                valid.append(ent_copy)
        return valid
