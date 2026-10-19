from crawlers_config import AI_CRAWLERS, ROBOTS_FULLY_BLOCKED

CATEGORIES = ["Verified AI crawler", "Spoofed crawler", "Block evader", "Undeclared bot", "Search engine", "Human"]

def score_client(row):
    reasons = []
    score = 0
    claimed = row["claimed_identity"]

    if row.get("linked_to_blocked_client"):
        score = max(90, round(70 + 30 * row.get("path_jaccard_with_blocked", 0)))
        reasons.append(
            f"Appeared {row.get('minutes_since_related_block', 0):.0f} minutes after a declared crawler was "
            f"blocked, requesting {row.get('path_jaccard_with_blocked', 0):.0%} of the same pages from a new "
            f"IP/ASN under a generic browser identity -- consistent with block evasion"
        )
        return min(score, 100), "Block evader", reasons

    if isinstance(claimed, str):

        is_ai = claimed in AI_CRAWLERS
        ip_ok = row["ip_matches_declared_range"]
        asn_ok = row["asn_matches_declared_asn"]
        ja4_ok = row["ja4_matches_expected_bot"]

        if ip_ok is False:
            score += 38
            reasons.append(f"Claims to be {claimed} but its IP address falls outside {claimed}'s declared ranges")
        if asn_ok is False:
            score += 18
            reasons.append(f"Claims to be {claimed} but its network (ASN) doesn't match {claimed}'s declared infrastructure")
        if ja4_ok is False:
            score += 24
            reasons.append(f"Claims to be {claimed} but its TLS (JA4) fingerprint doesn't match {claimed}'s expected client")

        if row["disallowed_hits"] > 0 and claimed not in ROBOTS_FULLY_BLOCKED:
            pts = min(16, row["disallowed_hits"] * 3)
            score += pts
            reasons.append(f"Requested {row['disallowed_hits']} robots.txt-disallowed path(s) despite claiming to be {claimed}")

        if row["header_anomaly_count"] > 0:
            reasons.extend(row["header_reasons"])

        score = min(round(score), 100)
        if score >= 45:
            label = "Spoofed crawler"
        else:
            label = "Verified AI crawler" if is_ai else "Search engine"
            if claimed in ROBOTS_FULLY_BLOCKED and row["block_rate"] > 0.5:
                reasons.append(
                    f"{claimed} is fully disallowed by robots.txt/WAF and was blocked (403) on most requests; "
                    "no disguised follow-up traffic was linked to it"
                )
            elif score > 0:
                reasons.append("Minor inconsistencies found, but identity signals are mostly consistent")
        if not reasons:
            reasons.append(f"IP, ASN and TLS fingerprint are all consistent with {claimed}'s published infrastructure")
        return score, label, reasons

    claimed_browser = row["claimed_browser"]

    if claimed_browser is not None and row["looks_like_script_ja4"]:
        pts = 40 * row.get("ja4_consistency", 1.0)
        score += pts
        reasons.append(
            f"Claims to be {claimed_browser} but its dominant TLS fingerprint matches a scripting "
            f"library (python-requests/curl/Go), not a real browser"
        )

    if row["timing_cv"] < 0.35 and row["request_rate_per_min"] > 2:
        score += 16
        reasons.append("Request timing is unusually regular (low variance) -- typical of a script, not a person")

    if row["sequential_score"] > 0.7:
        score += 14
        reasons.append("Pages were requested in near-perfect site order -- typical of systematic crawling")

    if claimed_browser is not None and row["asset_ratio"] < 0.05:
        score += 12
        reasons.append("Never loaded any CSS/JS/image sub-resources despite claiming to be a browser")

    if row["header_anomaly_count"] > 0:
        score += 6 * row["header_anomaly_count"]
        reasons.extend(row["header_reasons"])

    if row["disallowed_hits"] > 0:
        pts = min(14, row["disallowed_hits"] * 2)
        score += pts
        reasons.append(f"Requested {row['disallowed_hits']} robots.txt-disallowed path(s)")

    if row["error_rate"] > 0.08:
        score += 6
        reasons.append("Elevated 4xx/429 error rate, consistent with blind URL guessing")

    score = min(round(score), 100)
    if score >= 45:
        label = "Undeclared bot"
    else:
        label = "Human"
        if not reasons:
            reasons.append("Irregular timing, normal asset loading, and non-sequential browsing look human")
        else:
            reasons.append("Signals present but not strong enough to outweigh human-like browsing overall")
    return score, label, reasons

def run_rules(feature_df):
    scores, labels, reasons_list = [], [], []
    for _, row in feature_df.iterrows():
        s, lab, r = score_client(row)
        scores.append(s)
        labels.append(lab)
        reasons_list.append(r)
    out = feature_df.copy()
    out["rules_score"] = scores
    out["rules_label"] = labels
    out["rules_reasons"] = reasons_list
    return out
