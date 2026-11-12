"""Comprehensive DPDP Gateway Evaluation Suite.

Evaluates 50 synthetic Indian enterprise documents across:
1. Outbound Raw PII Leakage (Target: 0)
2. Entity Detection Precision, Recall, and F1 per type (AADHAAR, PAN, GSTIN, VOTER_ID, PASSPORT, PERSON, ADDRESS)
3. Placeholder Reinsertion Accuracy (handles normal, reordered, paraphrased, and dropped scenarios)
4. Gateway Latency Benchmark (ms)

Saves results to eval/latest_report.json.
"""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

# Add root directory to sys.path so app modules import cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.detector import PIIDetectionEngine
from app.reinsert import SafeReinsertEngine
from app.tokenizer import ConsistentTokenizer

DATASET_FILE = ROOT_DIR / "data" / "synthetic_50.json"
REPORT_FILE = ROOT_DIR / "eval" / "latest_report.json"

TARGET_ENTITIES = [
    "AADHAAR",
    "PAN",
    "GSTIN",
    "VOTER_ID",
    "PASSPORT",
    "PERSON",
    "ADDRESS",
]


def normalize_id(text: str) -> str:
    """Removes spaces, hyphens, and standardizes casing for ID comparison."""
    return re.sub(r"[\s-]", "", text).upper()


def match_entities(
    gt_entities: List[Dict[str, Any]], detected_entities: List[Dict[str, Any]]
) -> Tuple[Dict[str, int], Dict[str, int], Dict[str, int]]:
    """Matches detected entities against ground truth, returning TP, FP, FN counts per entity type."""
    tp: Dict[str, int] = {e: 0 for e in TARGET_ENTITIES}
    fp: Dict[str, int] = {e: 0 for e in TARGET_ENTITIES}
    fn: Dict[str, int] = {e: 0 for e in TARGET_ENTITIES}

    # Group by entity type
    for etype in TARGET_ENTITIES:
        gt_list = [g for g in gt_entities if g["entity_type"].upper() == etype]
        det_list = [d for d in detected_entities if d["entity_type"].upper() == etype]

        matched_gt_indices: Set[int] = set()
        matched_det_indices: Set[int] = set()

        for d_idx, d_ent in enumerate(det_list):
            d_text_norm = normalize_id(d_ent["text"])
            d_start, d_end = d_ent["start"], d_ent["end"]

            best_match_idx = -1
            for g_idx, g_ent in enumerate(gt_list):
                if g_idx in matched_gt_indices:
                    continue

                g_text_norm = normalize_id(g_ent["text"])
                g_start, g_end = g_ent["start"], g_ent["end"]

                # 1. Exact or normalized text match
                if d_text_norm == g_text_norm or g_ent["text"].lower() == d_ent["text"].lower():
                    best_match_idx = g_idx
                    break

                # 2. Substantial span overlap
                overlap = max(0, min(d_end, g_end) - max(d_start, g_start))
                span_len = max(1, g_end - g_start)
                if overlap / span_len >= 0.65 or overlap / max(1, d_end - d_start) >= 0.65:
                    best_match_idx = g_idx
                    break

                # 3. For addresses: substring locality/pincode match
                if etype == "ADDRESS" and (d_ent["text"] in g_ent["text"] or g_ent["text"] in d_ent["text"]):
                    best_match_idx = g_idx
                    break

            if best_match_idx != -1:
                matched_gt_indices.add(best_match_idx)
                matched_det_indices.add(d_idx)
                tp[etype] += 1
            else:
                fp[etype] += 1

        fn[etype] += len(gt_list) - len(matched_gt_indices)

    return tp, fp, fn


def run_full_evaluation() -> Dict[str, Any]:
    if not DATASET_FILE.exists():
        from data.generate_dataset import main as gen_dataset
        gen_dataset()

    with open(DATASET_FILE, "r", encoding="utf-8") as f:
        documents: List[Dict[str, Any]] = json.load(f)

    detector = PIIDetectionEngine()
    tokenizer = ConsistentTokenizer()
    reinsert_engine = SafeReinsertEngine()

    total_tp: Dict[str, int] = {e: 0 for e in TARGET_ENTITIES}
    total_fp: Dict[str, int] = {e: 0 for e in TARGET_ENTITIES}
    total_fn: Dict[str, int] = {e: 0 for e in TARGET_ENTITIES}

    total_raw_leakage_count = 0
    total_reinsertion_accuracy = 0.0
    latencies_ms: List[float] = []

    doc_eval_results = []

    # Stress test scenarios for reinsertion engine: normal, reordered, paraphrased, dropped
    test_scenarios = ["standard", "reordered", "paraphrased", "standard", "dropped"]

    for idx, doc in enumerate(documents):
        t0 = time.perf_counter()
        raw_text = doc["text"]
        gt_ents = doc["entities"]

        # Stage 1: Detect
        detected = detector.detect(raw_text)

        # Stage 2: Mask (test general purpose to evaluate full entity mapping)
        purpose = "general"
        masked = tokenizer.mask(raw_text, detected, purpose=purpose)

        # Measure leakage: verify if any ground truth raw PII leaked into sanitized text
        gt_values = [g["text"] for g in gt_ents]
        doc_leakage = tokenizer.verify_leakage(masked.sanitized_text, gt_values)
        total_raw_leakage_count += doc_leakage

        # Update detection accuracy metrics
        tp_doc, fp_doc, fn_doc = match_entities(gt_ents, detected)
        for e in TARGET_ENTITIES:
            total_tp[e] += tp_doc[e]
            total_fp[e] += fp_doc[e]
            total_fn[e] += fn_doc[e]

        # Stage 4: Test Safe Reinsertion under simulated LLM variations
        scenario = test_scenarios[idx % len(test_scenarios)]
        ph_keys = list(masked.placeholder_map.keys())

        if scenario == "reordered" and ph_keys:
            # Reorder all placeholders to test inverted boundary matching
            reversed_phs = list(reversed(ph_keys))
            simulated_llm_out = f"Summary report: Key subjects and identifiers: {', '.join(reversed_phs)}. Verification completed."
        elif scenario == "paraphrased" and ph_keys:
            # Paraphrased context wrapping all placeholders
            simulated_llm_out = f"Executive briefing note. Relevant identifiers: {' & '.join(ph_keys)}. Status: Verified."
        elif scenario == "dropped" and len(ph_keys) >= 2:
            # LLM omitted only one non-essential placeholder; tests that the remaining are cleanly restored
            simulated_llm_out = f"Condensed summary mentions {', '.join(ph_keys[:-1])}."
        else:
            simulated_llm_out = masked.sanitized_text

        reinsert_res = reinsert_engine.reinsert(simulated_llm_out, masked.placeholder_map)
        # Measure restoration integrity: placeholders present in LLM text successfully restored
        expected_in_sim = [ph for ph in ph_keys if ph in simulated_llm_out]
        if expected_in_sim:
            doc_reinsert_acc = (
                len([ph for ph in expected_in_sim if ph in reinsert_res.restored_placeholders])
                / len(expected_in_sim)
                * 100.0
            )
        else:
            doc_reinsert_acc = 100.0

        total_reinsertion_accuracy += doc_reinsert_acc

        t_elapsed = (time.perf_counter() - t0) * 1000.0
        latencies_ms.append(t_elapsed)

        doc_eval_results.append({
            "doc_id": doc["id"],
            "category": doc["category"],
            "detected_count": len(detected),
            "ground_truth_count": len(gt_ents),
            "leakage": doc_leakage,
            "reinsertion_accuracy": round(doc_reinsert_acc, 2),
            "latency_ms": round(t_elapsed, 2),
        })

    # Calculate overall and per-entity metrics
    per_entity_metrics = {}
    sum_tp = sum(total_tp.values())
    sum_fp = sum(total_fp.values())
    sum_fn = sum(total_fn.values())

    for e in TARGET_ENTITIES:
        tp = total_tp[e]
        fp = total_fp[e]
        fn = total_fn[e]
        p = round(tp / (tp + fp) * 100.0, 2) if (tp + fp) > 0 else 100.0
        r = round(tp / (tp + fn) * 100.0, 2) if (tp + fn) > 0 else 100.0
        f1 = round(2 * p * r / (p + r), 2) if (p + r) > 0 else 100.0
        per_entity_metrics[e] = {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": p,
            "recall": r,
            "f1_score": f1,
        }

    overall_precision = round(sum_tp / (sum_tp + sum_fp) * 100.0, 2) if (sum_tp + sum_fp) > 0 else 100.0
    overall_recall = round(sum_tp / (sum_tp + sum_fn) * 100.0, 2) if (sum_tp + sum_fn) > 0 else 100.0
    overall_f1 = round(
        2 * overall_precision * overall_recall / (overall_precision + overall_recall), 2
    ) if (overall_precision + overall_recall) > 0 else 100.0

    avg_reinsertion_acc = round(total_reinsertion_accuracy / len(documents), 2)
    avg_latency = round(sum(latencies_ms) / len(latencies_ms), 2)

    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_documents_evaluated": len(documents),
        "outbound_raw_pii_leakage": total_raw_leakage_count,
        "leakage_zero_verified": total_raw_leakage_count == 0,
        "overall_precision": overall_precision,
        "overall_recall": overall_recall,
        "overall_f1_score": overall_f1,
        "average_reinsertion_accuracy": avg_reinsertion_acc,
        "average_gateway_latency_ms": avg_latency,
        "per_entity_metrics": per_entity_metrics,
        "sample_document_results": doc_eval_results[:10],
    }

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"=== PRIVAGATE BENCHMARK RESULTS ({len(documents)} DOCUMENTS) ===")
    print(f"• Outbound Raw PII Leakage: {total_raw_leakage_count} (Verified Zero Leakage: {total_raw_leakage_count == 0})")
    print(f"• Overall Precision: {overall_precision}%")
    print(f"• Overall Recall: {overall_recall}%")
    print(f"• Overall F1-Score: {overall_f1}%")
    print(f"• Placeholder Reinsertion Accuracy: {avg_reinsertion_acc}%")
    print(f"• Average Gateway Latency: {avg_latency} ms")
    print("===============================================================")
    return report


if __name__ == "__main__":
    run_full_evaluation()
