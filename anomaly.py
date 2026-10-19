import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, classification_report, confusion_matrix

FLAG_RISK_THRESHOLD = 50.0

def run_anomaly_detection(feature_df, feature_cols, random_state=42, n_estimators=300):
    X = feature_df[feature_cols].fillna(0.5).to_numpy()
    model = IsolationForest(n_estimators=n_estimators, contamination="auto", random_state=random_state)
    model.fit(X)

    raw_scores = model.score_samples(X)
    pct_rank = pd.Series(raw_scores).rank(pct=True)
    risk = ((1 - pct_rank) * 100).round(1)

    out = feature_df.copy()
    out["anomaly_raw_score"] = raw_scores
    out["anomaly_risk"] = risk
    out["anomaly_flag"] = out["anomaly_risk"] >= FLAG_RISK_THRESHOLD
    return out, model

def evaluate_anomaly(feature_df_with_scores, ground_truth_df):
    merged = feature_df_with_scores.merge(
        ground_truth_df[["ip", "user_agent", "category"]], on=["ip", "user_agent"], how="left"
    )
    y_true_binary = (merged["category"] != "Human").astype(int)
    y_flag = merged["anomaly_flag"].astype(int)

    auc = roc_auc_score(y_true_binary, merged["anomaly_risk"])
    report = classification_report(
        y_true_binary, y_flag, target_names=["Human", "Any bot/crawler"], output_dict=True, zero_division=0
    )
    cm = confusion_matrix(y_true_binary, y_flag)

    flag_rate_by_category = merged.groupby("category")["anomaly_flag"].mean().round(3).to_dict()
    mean_risk_by_category = merged.groupby("category")["anomaly_risk"].mean().round(1).to_dict()

    return {
        "roc_auc": round(auc, 3),
        "binary_report": report,
        "binary_confusion_matrix": cm.tolist(),
        "flag_rate_by_category": flag_rate_by_category,
        "mean_risk_by_category": mean_risk_by_category,
    }
