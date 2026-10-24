import os
import sys
import json
import time
from pathlib import Path

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Dict, Any, List
from app.security.analyzer import analyze


def run_evaluation(dataset_path: str = "evaluation/dataset.jsonl") -> Dict[str, Any]:
    dataset_file = Path(dataset_path)
    if not dataset_file.exists():
        raise FileNotFoundError(f"Evaluation dataset not found at {dataset_path}")

    records: List[Dict[str, Any]] = []
    with open(dataset_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    latencies: List[float] = []
    category_breakdown: Dict[str, Dict[str, int]] = {}
    detailed_results: List[Dict[str, Any]] = []

    print(f"Starting PromptGuard evaluation on {len(records)} test examples...\n" + "=" * 65)

    for record in records:
        test_id = record["id"]
        prompt = record["prompt"]
        context = record.get("context", "")
        expected_label = record["expected_label"]
        category = record.get("category", "unknown")

        if category not in category_breakdown:
            category_breakdown[category] = {"total": 0, "flagged": 0, "passed": 0}
        category_breakdown[category]["total"] += 1

        t0 = time.perf_counter()
        decision = analyze(prompt, context)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(latency_ms)

        # In policy: 'block' and 'review' are flagged (not silently permitted)
        flagged = decision.action in ("block", "review")
        is_malicious = expected_label == "malicious"

        if flagged:
            category_breakdown[category]["flagged"] += 1
        else:
            category_breakdown[category]["passed"] += 1

        if is_malicious and flagged:
            true_positives += 1
            verdict = "CORRECT_BLOCK"
        elif is_malicious and not flagged:
            false_negatives += 1
            verdict = "MISSED_ATTACK (FN)"
        elif not is_malicious and flagged:
            false_positives += 1
            verdict = "FALSE_POSITIVE (FP)"
        else:
            true_negatives += 1
            verdict = "CORRECT_ALLOW"

        detailed_results.append({
            "id": test_id,
            "category": category,
            "expected": expected_label,
            "action": decision.action,
            "risk_score": decision.risk_score,
            "verdict": verdict,
            "latency_ms": round(latency_ms, 2),
            "reasons": decision.reasons,
        })

        print(f"[{test_id}] Category: {category:<20} | Decision: {decision.action.upper():<6} | Score: {decision.risk_score:>3} | Verdict: {verdict}")

    total_malicious = true_positives + false_negatives
    total_benign = true_negatives + false_positives

    recall = round((true_positives / total_malicious) * 100, 2) if total_malicious else 0.0
    precision = round((true_positives / (true_positives + false_positives)) * 100, 2) if (true_positives + false_positives) else 0.0
    fpr = round((false_positives / total_benign) * 100, 2) if total_benign else 0.0

    # Attack success rate: with firewall = FN / total_malicious; without firewall = 100%
    asr_with_firewall = round((false_negatives / total_malicious) * 100, 2) if total_malicious else 0.0
    asr_without_firewall = 100.0

    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

    metrics = {
        "dataset_size": len(records),
        "total_malicious": total_malicious,
        "total_benign": total_benign,
        "recall_pct": recall,
        "precision_pct": precision,
        "false_positive_rate_pct": fpr,
        "attack_success_rate_with_firewall_pct": asr_with_firewall,
        "attack_success_rate_without_firewall_pct": asr_without_firewall,
        "avg_latency_ms": avg_latency,
        "min_latency_ms": round(min(latencies), 2) if latencies else 0.0,
        "max_latency_ms": round(max(latencies), 2) if latencies else 0.0,
        "category_breakdown": category_breakdown,
        "detailed_results": detailed_results,
    }

    print("\n" + "=" * 65)
    print("PROMPTGUARD EVALUATION SUMMARY")
    print(f"- Dataset size:                 {metrics['dataset_size']}")
    print(f"- Recall (Detection Rate):      {metrics['recall_pct']}%")
    print(f"- Precision:                    {metrics['precision_pct']}%")
    print(f"- False Positive Rate:          {metrics['false_positive_rate_pct']}%")
    print(f"- Attack Success (with firewall):   {metrics['attack_success_rate_with_firewall_pct']}%")
    print(f"- Attack Success (no firewall): {metrics['attack_success_rate_without_firewall_pct']}%")
    print(f"- Average Latency:              {metrics['avg_latency_ms']} ms")
    print("=" * 65)

    # Save to JSON
    output_file = Path("evaluation/evaluation_results.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics saved to {output_file.resolve()}")

    return metrics


if __name__ == "__main__":
    run_evaluation()
