def build_context(row, hybrid_label, hybrid_score, rules_reasons, ml_label, ml_confidence, anomaly_risk, linked):
    return {
        "client_id": row.get("client_id", row.get("client_key")),
        "ip": row["ip"],
        "asn": row.get("asn"),
        "claimed_identity": row.get("claimed_identity"),
        "claimed_browser": row.get("claimed_browser"),
        "hybrid_label": hybrid_label,
        "hybrid_score": hybrid_score,
        "rules_reasons": rules_reasons,
        "ml_label": ml_label,
        "ml_confidence": ml_confidence,
        "anomaly_risk": anomaly_risk,
        "linked_to_blocked_client": linked,
        "n_requests": row.get("n_requests"),
        "request_rate_per_min": row.get("request_rate_per_min"),
        "timing_cv": row.get("timing_cv"),
        "asset_ratio": row.get("asset_ratio"),
        "sequential_score": row.get("sequential_score"),
        "disallowed_hits": row.get("disallowed_hits"),
    }

def generate_note(context):
    c = context
    parts = []

    ident = c["claimed_identity"] if c["claimed_identity"] not in (None, "-") else None
    if ident:
        parts.append(f"This client claims to be {ident}")
    elif c["claimed_browser"]:
        parts.append(f"This client presents itself as a {c['claimed_browser']} browser")
    else:
        parts.append("This client has no identifiable claimed identity")

    parts.append(
        f"from {c['ip']} (ASN {c['asn']}), sending {c['n_requests']} requests at "
        f"~{c['request_rate_per_min']:.1f} req/min."
    )

    if c["linked_to_blocked_client"]:
        parts.append(
            "It appeared shortly after a declared crawler identity was blocked on this site, requesting a "
            "similar set of pages from a new network -- a pattern consistent with block evasion, and it "
            "warrants review alongside the originating blocked client."
        )
    elif c["rules_reasons"]:
        top_reasons = c["rules_reasons"][:2]
        parts.append("The rule-based check flagged: " + "; ".join(top_reasons) + ".")

    if c["ml_label"] and c["ml_confidence"] is not None:
        parts.append(
            f"The machine-learning model independently predicted \"{c['ml_label']}\" "
            f"({c['ml_confidence']:.0%} confidence)."
        )

    if c["anomaly_risk"] is not None:
        if c["anomaly_risk"] >= 65:
            parts.append(
                f"It also scored as a behavioral outlier relative to the rest of the traffic "
                f"(anomaly risk {c['anomaly_risk']:.0f}/100), even considering its overall profile."
            )
        else:
            parts.append(f"Its behavioral-outlier score was moderate ({c['anomaly_risk']:.0f}/100).")

    parts.append(
        f"Overall hybrid risk score: {c['hybrid_score']}/100 (\"{c['hybrid_label']}\"). "
        "This combination of signals warrants review -- it is not, on its own, proof of malicious intent."
    )
    return " ".join(parts)

def generate_notes_for_top_clients(enriched_df, top_n=10, score_col="hybrid_score"):
    top = enriched_df.sort_values(score_col, ascending=False).head(top_n)
    notes = {}
    for _, row in top.iterrows():
        context = build_context(
            row,
            hybrid_label=row["hybrid_label"],
            hybrid_score=row["hybrid_score"],
            rules_reasons=row.get("rules_reasons", []),
            ml_label=row.get("ml_pred"),
            ml_confidence=row.get("ml_confidence"),
            anomaly_risk=row.get("anomaly_risk"),
            linked=row.get("linked_to_blocked_client", False),
        )
        notes[row["client_key"]] = generate_note(context)
    return notes
