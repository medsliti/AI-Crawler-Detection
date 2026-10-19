import os
import json
import datetime
import numpy as np
import pandas as pd

from crawlers_config import AI_CRAWLERS, SEARCH_ENGINES
from features import build_feature_table, FEATURE_COLUMNS
from block_evasion import (
    detect_operator_clusters,
    attach_linking_features,
    evaluate_linking,
    summarize_clusters,
    LINKING_FEATURE_COLUMNS,
)
from rules import run_rules, CATEGORIES
from ml_model import build_ml_table, train_and_evaluate, build_shap_explainer, explain_instance, ML_FEATURE_COLUMNS
from anomaly import run_anomaly_detection, evaluate_anomaly
from analyst_notes import generate_notes_for_top_clients

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
OUTPUT_DIR = os.path.join(HERE, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

LOG_PATH = os.path.join(DATA_DIR, "access.log")
GT_PATH = os.path.join(DATA_DIR, "ground_truth.csv")

TRICKY_SUBSTRINGS = ("tricky:", "imperson")

def combine_hybrid_verdict(row):
    reasons = []
    if row["linked_to_blocked_client"]:
        score = max(90, round(70 + 30 * row["path_jaccard_with_blocked"]))
        reasons.append("Linked to a recently blocked declared crawler identity (treated as decisive)")
        return "Block evader", min(score, 100), reasons

    rules_label, ml_label = row["rules_label"], row["ml_pred"]
    ml_conf = row["ml_confidence"]

    if rules_label == ml_label:
        verdict = rules_label
        reasons.append("Rules and the ML model agree")
        base_score = max(row["rules_score"], round(ml_conf * 100))
    elif ml_conf >= 0.5:
        verdict = ml_label
        reasons.append(f"Rules said \"{rules_label}\", but the ML model disagreed with {ml_conf:.0%} confidence and was trusted")
        base_score = round(ml_conf * 100)
    else:
        verdict = rules_label
        reasons.append(f"ML disagreed (\"{ml_label}\") but with low confidence ({ml_conf:.0%}); kept the rules verdict")
        base_score = row["rules_score"]

    clean_labels = {"Human", "Verified AI crawler", "Search engine"}
    if verdict in clean_labels and row["anomaly_risk"] >= 65:
        reasons.append(
            f"Anomaly detection flagged this client as a behavioral outlier (risk {row['anomaly_risk']:.0f}/100) "
            f"despite otherwise looking like {verdict} -- surfaced for extra review without changing the label"
        )
        base_score = max(base_score, row["anomaly_risk"] * 0.6)

    return verdict, min(round(base_score), 100), reasons

def _jsonable(obj):
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, (np.bool_,)):
        return bool(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, (pd.Timestamp, datetime.datetime)):
        return obj.isoformat()
    if isinstance(obj, (frozenset, set)):
        return sorted(obj)
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, float) and (np.isnan(obj) or np.isinf(obj)):
        return None
    return obj

def main():
    print("=" * 70)
    print("AI-Powered Crawler Detection -- running full pipeline")
    print("=" * 70)

    print("\n[1/7] Parsing access log and extracting per-client features...")
    feats = build_feature_table(LOG_PATH)
    gt = pd.read_csv(GT_PATH)
    print(f"  {len(feats)} clients, {feats['n_requests'].sum()} requests")

    print("\n[2/7] Detecting block-evasion operator clusters...")
    links = detect_operator_clusters(feats)
    feats = attach_linking_features(feats, links)
    linking_eval = evaluate_linking(feats, gt)
    clusters = summarize_clusters(feats)
    print(f"  {len(links)} candidate links found; linking recall={linking_eval['linking_recall']}, "
          f"precision={linking_eval['linking_precision']}")

    print("\n[3/7] Running rule-based detector...")
    feats = run_rules(feats)

    print("\n[4/7] Training supervised ML model (5-fold CV)...")
    ml_table = build_ml_table(feats, gt).reset_index(drop=True)
    ml_result = train_and_evaluate(ml_table)
    feats = feats.reset_index(drop=True)
    feats["ml_pred"] = ml_result["oof_pred"]
    feats["ml_confidence"] = [ml_result["oof_proba"].loc[i].max() for i in feats.index]
    print(f"  Model: {ml_result['model_name']}; overall accuracy: {ml_result['report']['accuracy']:.3f}")

    shap_explainer = build_shap_explainer(ml_result["model"], ml_result["model_name"], ml_table[ML_FEATURE_COLUMNS])
    print(f"  SHAP explainer available: {shap_explainer is not None}")

    print("\n[5/7] Running Isolation Forest anomaly detection...")
    feats, anomaly_model = run_anomaly_detection(feats, ML_FEATURE_COLUMNS)
    anomaly_eval = evaluate_anomaly(feats, gt)
    print(f"  ROC-AUC (any-bot vs human): {anomaly_eval['roc_auc']}")

    print("\n[6/7] Combining into hybrid verdict...")
    hybrid_results = feats.apply(combine_hybrid_verdict, axis=1)
    feats["hybrid_label"] = [r[0] for r in hybrid_results]
    feats["hybrid_score"] = [r[1] for r in hybrid_results]
    feats["hybrid_reasons"] = [r[2] for r in hybrid_results]

    merged = feats.merge(
        gt[["ip", "user_agent", "category", "subtype", "operator_id"]], on=["ip", "user_agent"], how="left"
    )
    from sklearn.metrics import classification_report, confusion_matrix

    hybrid_report = classification_report(merged["category"], merged["hybrid_label"], labels=CATEGORIES, output_dict=True, zero_division=0)
    hybrid_cm = confusion_matrix(merged["category"], merged["hybrid_label"], labels=CATEGORIES)
    rules_report = classification_report(merged["category"], merged["rules_label"], labels=CATEGORIES, output_dict=True, zero_division=0)
    rules_cm = confusion_matrix(merged["category"], merged["rules_label"], labels=CATEGORIES)
    print(f"  Hybrid accuracy: {hybrid_report['accuracy']:.3f} | Rules accuracy: {rules_report['accuracy']:.3f} "
          f"| ML (OOF) accuracy: {ml_result['report']['accuracy']:.3f}")

    print("\n[7/7] Generating analyst notes and writing dashboard bundle...")
    merged["client_key_str"] = merged["client_key"].apply(lambda k: "||".join(k))
    notes = generate_notes_for_top_clients(merged.assign(client_key=merged["client_key_str"]), top_n=10, score_col="hybrid_score")

    is_tricky = merged["subtype"].str.contains("|".join(TRICKY_SUBSTRINGS))
    tricky = merged[is_tricky][
        ["client_key_str", "subtype", "category", "rules_label", "ml_pred", "hybrid_label", "anomaly_flag", "anomaly_risk"]
    ]

    total_requests = int(feats["n_requests"].sum())
    ai_crawler_names = set(AI_CRAWLERS.keys())
    claims_ai = merged[merged["claimed_identity"].isin(ai_crawler_names)]
    pct_ai_crawler_traffic = round(100 * claims_ai["n_requests"].sum() / total_requests, 2) if total_requests else 0.0
    verified_ai = claims_ai[claims_ai["category"] == "Verified AI crawler"]
    spoofed_ai = claims_ai[claims_ai["category"] == "Spoofed crawler"]
    pct_claims_spoofed = (
        round(100 * len(spoofed_ai) / (len(verified_ai) + len(spoofed_ai)), 1) if (len(verified_ai) + len(spoofed_ai)) else 0.0
    )
    bot_categories = {"Verified AI crawler", "Spoofed crawler", "Undeclared bot", "Block evader"}
    bot_bandwidth = int(merged[merged["category"].isin(bot_categories)]["total_bytes"].sum())
    total_bandwidth = int(merged["total_bytes"].sum())

    headline_stats = {
        "total_clients": int(len(merged)),
        "total_requests": total_requests,
        "pct_ai_crawler_traffic": pct_ai_crawler_traffic,
        "pct_ai_crawler_claims_spoofed": pct_claims_spoofed,
        "bot_bandwidth_bytes": bot_bandwidth,
        "bot_bandwidth_pct": round(100 * bot_bandwidth / total_bandwidth, 1) if total_bandwidth else 0.0,
    }

    traffic_share_by_category = (
        merged.groupby("category")["n_requests"].sum().sort_values(ascending=False).to_dict()
    )

    top_identities = []
    for name in list(AI_CRAWLERS.keys()) + list(SEARCH_ENGINES.keys()):
        sub = merged[merged["claimed_identity"] == name]
        if len(sub) == 0:
            continue
        top_identities.append(
            {
                "identity": name,
                "is_ai_crawler": name in ai_crawler_names,
                "verified_count": int((sub["category"].isin(["Verified AI crawler", "Search engine"])).sum()),
                "spoofed_count": int((sub["category"] == "Spoofed crawler").sum()),
                "total_requests": int(sub["n_requests"].sum()),
            }
        )

    robots_violations = (
        merged[merged["disallowed_hits"] > 0][["client_key_str", "category", "claimed_identity", "disallowed_hits"]]
        .sort_values("disallowed_hits", ascending=False)
        .to_dict(orient="records")
    )

    client_rows = []
    for _, row in merged.iterrows():
        client_rows.append(
            {
                "client_key": row["client_key_str"],
                "ip": row["ip"],
                "asn": row["asn"],
                "user_agent": row["user_agent"],
                "claimed_identity": row["claimed_identity"] if pd.notna(row["claimed_identity"]) else None,
                "true_category": row["category"],
                "subtype": row["subtype"],
                "operator_id": row["operator_id"] if row["operator_id"] != "-" else None,
                "n_requests": int(row["n_requests"]),
                "total_bytes": int(row["total_bytes"]),
                "request_rate_per_min": round(float(row["request_rate_per_min"]), 2),
                "timing_cv": round(float(row["timing_cv"]), 2),
                "asset_ratio": round(float(row["asset_ratio"]), 3),
                "sequential_score": round(float(row["sequential_score"]), 3),
                "disallowed_hits": int(row["disallowed_hits"]),
                "robots_txt_fetched": bool(row["robots_txt_fetched"]),
                "rules_score": round(float(row["rules_score"]), 1),
                "rules_label": row["rules_label"],
                "rules_reasons": row["rules_reasons"],
                "ml_pred": row["ml_pred"],
                "ml_confidence": round(float(row["ml_confidence"]), 3),
                "anomaly_risk": round(float(row["anomaly_risk"]), 1),
                "anomaly_flag": bool(row["anomaly_flag"]),
                "hybrid_label": row["hybrid_label"],
                "hybrid_score": round(float(row["hybrid_score"]), 1),
                "hybrid_reasons": row["hybrid_reasons"],
                "linked_to_blocked_client": bool(row["linked_to_blocked_client"]),
                "suspected_operator_cluster": row["suspected_operator_cluster"],
                "analyst_note": notes.get(row["client_key_str"]),
            }
        )

    bundle = {
        "meta": {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "model_name": ml_result["model_name"],
            "disclaimer": (
                "All data on this dashboard is SYNTHETIC, generated for a demo. No real traffic, companies, or "
                "crawlers are represented -- all crawler/operator names are fictional. A high risk score is a "
                "reason to investigate, never proof of bad intent."
            ),
        },
        "headline_stats": headline_stats,
        "traffic_share_by_category": _jsonable(traffic_share_by_category),
        "top_claimed_identities": top_identities,
        "robots_violations": robots_violations,
        "categories": CATEGORIES,
        "method_comparison": {
            "rules": {"report": rules_report, "confusion_matrix": rules_cm.tolist()},
            "ml": {"report": ml_result["report"], "confusion_matrix": ml_result["confusion_matrix"].tolist(), "model_name": ml_result["model_name"]},
            "anomaly": {
                "roc_auc": anomaly_eval["roc_auc"],
                "binary_report": anomaly_eval["binary_report"],
                "binary_confusion_matrix": anomaly_eval["binary_confusion_matrix"],
                "flag_rate_by_category": anomaly_eval["flag_rate_by_category"],
                "mean_risk_by_category": anomaly_eval["mean_risk_by_category"],
            },
            "hybrid": {"report": hybrid_report, "confusion_matrix": hybrid_cm.tolist()},
        },
        "feature_importance": ml_result["feature_importance"],
        "block_evasion": {
            "linking_eval": linking_eval,
            "clusters": clusters.assign(
                blocked_client_key=clusters["blocked_client_key"].apply(lambda k: "||".join(k) if isinstance(k, tuple) else k),
                disguised_client_keys=clusters["disguised_client_keys"].apply(lambda ks: ["||".join(k) for k in ks]),
            ).to_dict(orient="records")
            if len(clusters)
            else [],
        },
        "tricky_cases": tricky.to_dict(orient="records"),
        "clients": client_rows,
    }

    out_path = os.path.join(OUTPUT_DIR, "results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(_jsonable(bundle), f, indent=2, default=str)
    print(f"\nWrote dashboard bundle to {out_path}")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Clients: {len(merged)} | Requests: {total_requests}")
    print(f"Rules accuracy:  {rules_report['accuracy']:.3f}")
    print(f"ML accuracy:     {ml_result['report']['accuracy']:.3f} (5-fold out-of-fold)")
    print(f"Hybrid accuracy: {hybrid_report['accuracy']:.3f}")
    print(f"Anomaly ROC-AUC: {anomaly_eval['roc_auc']}")
    print(f"Block-evasion linking: recall={linking_eval['linking_recall']}, precision={linking_eval['linking_precision']}")
    print("\nTricky-case results (true category vs each method):")
    print(tricky.to_string(index=False))

    return bundle

if __name__ == "__main__":
    main()
