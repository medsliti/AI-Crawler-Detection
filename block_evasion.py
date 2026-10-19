import pandas as pd

def jaccard(set_a, set_b):
    if not set_a and not set_b:
        return 0.0
    union = set_a | set_b
    if not union:
        return 0.0
    return len(set_a & set_b) / len(union)

def find_blocked_clients(feat_df, min_block_rate=0.5, min_requests=2):
    return feat_df[
        feat_df["claimed_identity"].notna()
        & (feat_df["block_rate"] >= min_block_rate)
        & (feat_df["n_requests"] >= min_requests)
    ]

def find_candidate_evaders(feat_df):
    return feat_df[
        feat_df["claimed_identity"].isna()
        & feat_df["claimed_browser"].notna()
        & (~feat_df["robots_txt_fetched"])
    ]

def detect_operator_clusters(feat_df, window_minutes=90, min_jaccard=0.25):
    blocked = find_blocked_clients(feat_df)
    candidates = find_candidate_evaders(feat_df)

    links = []
    for _, b in blocked.iterrows():
        for _, c in candidates.iterrows():
            gap_minutes = (c["first_timestamp"] - b["last_timestamp"]).total_seconds() / 60.0
            if gap_minutes < 0 or gap_minutes > window_minutes:
                continue
            jac = jaccard(b["path_set"], c["path_set"])
            if jac < min_jaccard:
                continue
            timing_score = max(0.0, 1 - gap_minutes / window_minutes)
            confidence = round(0.65 * jac + 0.35 * timing_score, 4)
            links.append(
                {
                    "blocked_client_key": b["client_key"],
                    "blocked_claimed_identity": b["claimed_identity"],
                    "candidate_client_key": c["client_key"],
                    "gap_minutes": round(gap_minutes, 2),
                    "path_jaccard": round(jac, 3),
                    "link_confidence": confidence,
                }
            )
    links_df = pd.DataFrame(
        links,
        columns=["blocked_client_key", "blocked_claimed_identity", "candidate_client_key", "gap_minutes", "path_jaccard", "link_confidence"],
    )
    if len(links_df):
        links_df = links_df.sort_values("link_confidence", ascending=False).drop_duplicates("candidate_client_key")
    return links_df.reset_index(drop=True)

def attach_linking_features(feat_df, links_df):
    out = feat_df.copy()
    out["linked_to_blocked_client"] = False
    out["path_jaccard_with_blocked"] = 0.0
    out["minutes_since_related_block"] = -1.0
    out["suspected_operator_cluster"] = None

    link_map = {row["candidate_client_key"]: row for _, row in links_df.iterrows()} if len(links_df) else {}
    for i, row in out.iterrows():
        link = link_map.get(row["client_key"])
        if link is not None:
            out.at[i, "linked_to_blocked_client"] = True
            out.at[i, "path_jaccard_with_blocked"] = link["path_jaccard"]
            out.at[i, "minutes_since_related_block"] = link["gap_minutes"]
            out.at[i, "suspected_operator_cluster"] = link["blocked_client_key"]

    out["linked_to_blocked_client_num"] = out["linked_to_blocked_client"].astype(int)
    return out

LINKING_FEATURE_COLUMNS = [
    "linked_to_blocked_client_num",
    "path_jaccard_with_blocked",
]

def summarize_clusters(feat_df_with_links):
    linked = feat_df_with_links[feat_df_with_links["linked_to_blocked_client"]]
    rows = []
    for cluster_key, members in linked.groupby("suspected_operator_cluster"):
        asns = set(members["asn"])
        rows.append(
            {
                "blocked_client_key": cluster_key,
                "n_disguised_clients": len(members),
                "disguised_client_keys": list(members["client_key"]),
                "distinct_asns": len(asns),
                "avg_link_confidence": round(
                    (0.65 * members["path_jaccard_with_blocked"] + 0.35 * 1).mean(), 3
                ),
            }
        )
    return pd.DataFrame(rows)

def evaluate_linking(feat_df_with_links, ground_truth_df):
    merged = feat_df_with_links.merge(
        ground_truth_df[["ip", "user_agent", "operator_id", "subtype"]], on=["ip", "user_agent"], how="left"
    )
    true_evaders = merged[merged["subtype"] == "block_evader"]
    pre_evasion = merged[merged["subtype"] == "pre_evasion"].set_index("operator_id")["client_key"].to_dict()

    total = len(true_evaders)
    flagged = int(true_evaders["linked_to_blocked_client"].sum())
    correct = 0
    for _, row in true_evaders.iterrows():
        if not row["linked_to_blocked_client"]:
            continue
        true_blocked_key = pre_evasion.get(row["operator_id"])
        if row["suspected_operator_cluster"] == true_blocked_key:
            correct += 1

    false_positive_links = int(
        merged[(merged["subtype"] != "block_evader") & (merged["linked_to_blocked_client"])].shape[0]
    )

    return {
        "total_true_block_evaders": total,
        "flagged_as_linked": flagged,
        "correctly_linked_to_origin": correct,
        "linking_recall": round(correct / total, 3) if total else 0.0,
        "linking_precision": round(correct / flagged, 3) if flagged else 0.0,
        "false_positive_links": false_positive_links,
    }
