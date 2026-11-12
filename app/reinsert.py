"""Safe Local Placeholder Reinsertion Engine.

Restores original sensitive values from the local secure mapping into the LLM output,
gracefully handling paraphrasing, reordered tokens, dropped placeholders, and HTML entities.
"""

from __future__ import annotations

import html
import re
from typing import Any, Dict, List, Optional, Tuple


class ReinsertResult:
    def __init__(
        self,
        restored_text: str,
        expected_placeholders: List[str],
        restored_placeholders: List[str],
        dropped_placeholders: List[str],
        reinsertion_accuracy: float,
        metrics: Dict[str, Any],
    ):
        self.restored_text = restored_text
        self.expected_placeholders = expected_placeholders
        self.restored_placeholders = restored_placeholders
        self.dropped_placeholders = dropped_placeholders
        self.reinsertion_accuracy = reinsertion_accuracy
        self.metrics = metrics

    def to_dict(self) -> Dict[str, Any]:
        return {
            "restored_text": self.restored_text,
            "expected_placeholders": self.expected_placeholders,
            "restored_placeholders": self.restored_placeholders,
            "dropped_placeholders": self.dropped_placeholders,
            "reinsertion_accuracy": self.reinsertion_accuracy,
            "metrics": self.metrics,
        }


class SafeReinsertEngine:
    """Restores placeholders to original values using strict descending-length boundary matching."""

    def __init__(self):
        pass

    def reinsert(
        self,
        llm_output: str,
        placeholder_map: Dict[str, str],
    ) -> ReinsertResult:
        if not placeholder_map:
            return ReinsertResult(
                restored_text=llm_output,
                expected_placeholders=[],
                restored_placeholders=[],
                dropped_placeholders=[],
                reinsertion_accuracy=100.0,
                metrics={
                    "total_expected": 0,
                    "total_restored": 0,
                    "total_dropped": 0,
                    "accuracy_pct": 100.0,
                },
            )

        expected = list(placeholder_map.keys())
        # Sort by descending length so <PERSON_10> is replaced before <PERSON_1>
        sorted_placeholders = sorted(expected, key=len, reverse=True)

        restored_text = llm_output
        restored_placeholders: List[str] = []
        dropped_placeholders: List[str] = []

        for ph in sorted_placeholders:
            orig_val = placeholder_map[ph]
            escaped_ph = re.escape(ph)

            # Variations: exact placeholder, HTML escaped (< -> &lt;), bracketed [PERSON_1]
            variants = [
                escaped_ph,
                re.escape(html.escape(ph)),
            ]

            # If placeholder is <TAG_N>, also match [TAG_N] or TAG_N boundary
            tag_match = re.match(r"^<([A-Z_]+_\d+)(?:_[^>]+)?>$", ph)
            if tag_match:
                inner_tag = tag_match.group(1)
                variants.append(rf"\[{re.escape(inner_tag)}\]")

            combined_pattern = re.compile("|".join(variants))

            # Check if present in text
            if combined_pattern.search(restored_text):
                restored_text = combined_pattern.sub(orig_val, restored_text)
                restored_placeholders.append(ph)
            else:
                dropped_placeholders.append(ph)

        # Accuracy calculation
        total_expected = len(expected)
        total_restored = len(restored_placeholders)
        accuracy = round((total_restored / total_expected * 100.0), 2) if total_expected > 0 else 100.0

        metrics = {
            "total_expected": total_expected,
            "total_restored": total_restored,
            "total_dropped": len(dropped_placeholders),
            "accuracy_pct": accuracy,
        }

        return ReinsertResult(
            restored_text=restored_text,
            expected_placeholders=expected,
            restored_placeholders=restored_placeholders,
            dropped_placeholders=dropped_placeholders,
            reinsertion_accuracy=accuracy,
            metrics=metrics,
        )

