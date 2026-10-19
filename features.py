import re
import ipaddress
import datetime

import pandas as pd

from crawlers_config import ALL_KNOWN_BOTS, BROWSER_JA4_PREFIXES, SCRIPT_JA4_PREFIXES
from site_structure import is_asset, is_disallowed, CONTENT_PATH_INDEX, ROBOTS_TXT_PATH

_Q = r'((?:[^"\\]|\\.)*)'
LOG_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d+) (?P<bytes>\d+) '
    r'"(?P<referer>' + _Q + r')" "(?P<ua>' + _Q + r')" "(?P<ja4>' + _Q + r')" "(?P<asn>' + _Q + r')" '
    r'"(?P<accept_lang>' + _Q + r')" "(?P<sec_ch_ua>' + _Q + r')"$'
)
NGINX_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

KNOWN_BROWSER_UA_HINTS = {
    "chrome": re.compile(r"Chrome/(?!.*Edg/)", re.IGNORECASE),
    "edge": re.compile(r"Edg/", re.IGNORECASE),
    "firefox": re.compile(r"Firefox/", re.IGNORECASE),
    "safari": re.compile(r"Safari/(?!.*Chrome)", re.IGNORECASE),
}

def _unescape(s):
    return s.replace('\\"', '"') if s else s

def parse_log(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = LOG_LINE_RE.match(line.strip())
            if not m:
                continue
            d = m.groupdict()
            rows.append(
                {
                    "ip": d["ip"],
                    "timestamp": datetime.datetime.strptime(d["time"], NGINX_TIME_FMT),
                    "method": d["method"],
                    "path": d["path"],
                    "status": int(d["status"]),
                    "bytes": int(d["bytes"]),
                    "referer": _unescape(d["referer"]),
                    "user_agent": _unescape(d["ua"]),
                    "ja4": _unescape(d["ja4"]),
                    "asn": _unescape(d["asn"]),
                    "accept_language": _unescape(d["accept_lang"]),
                    "sec_ch_ua": _unescape(d["sec_ch_ua"]),
                }
            )
    df = pd.DataFrame(rows)

    df["client_key"] = list(zip(df["ip"], df["user_agent"]))
    return df

def claimed_identity(user_agent):
    for name, cfg in ALL_KNOWN_BOTS.items():
        if re.search(cfg["ua_pattern"], user_agent):
            return name
    return None

def ip_in_declared_ranges(ip, bot_name):
    cfg = ALL_KNOWN_BOTS[bot_name]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(r) for r in cfg["ip_ranges"])

def asn_matches_declared(asn, bot_name):
    return asn == ALL_KNOWN_BOTS[bot_name]["asn"]

def ja4_family(ja4):
    return ja4.split("_")[0] if ja4 and ja4 != "-" else None

def detect_claimed_browser(user_agent):
    for name, pattern in KNOWN_BROWSER_UA_HINTS.items():
        if pattern.search(user_agent):
            return name
    return None

def coefficient_of_variation(values):
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    if mean == 0:
        return 0.0
    var = sum((v - mean) ** 2 for v in values) / n
    return (var ** 0.5) / mean

def sequential_score(paths):
    idxs = [CONTENT_PATH_INDEX[p] for p in paths if p in CONTENT_PATH_INDEX]
    if len(idxs) < 2:
        return 0.0
    steps = 0
    for a, b in zip(idxs, idxs[1:]):
        if abs(b - a) <= 1:
            steps += 1
    return steps / (len(idxs) - 1)

def extract_features(df):
    records = []
    for client_key, g in df.groupby("client_key"):
        ip, ua = client_key
        g = g.sort_values("timestamp")
        timestamps = g["timestamp"].tolist()
        paths = g["path"].tolist()
        n_requests = len(g)

        first_ts, last_ts = timestamps[0], timestamps[-1]
        duration_s = max((last_ts - first_ts).total_seconds(), 1.0)
        request_rate_per_min = n_requests / (duration_s / 60.0)

        intervals = [
            (b - a).total_seconds() for a, b in zip(timestamps, timestamps[1:]) if (b - a).total_seconds() > 0
        ]
        timing_cv = coefficient_of_variation(intervals)

        non_robots = g[g["path"] != ROBOTS_TXT_PATH]
        asset_mask = non_robots["path"].apply(is_asset)
        asset_ratio = asset_mask.mean() if len(non_robots) else 0.0

        content_paths = [p for p in non_robots["path"].tolist() if not is_asset(p)]
        seq_score = sequential_score(content_paths)
        path_set = frozenset(content_paths)

        unique_paths = non_robots["path"].nunique()
        total_bytes = int(g["bytes"].sum())

        error_rate = (g["status"].isin([404, 429, 403, 500])).mean()
        block_rate = (g["status"] == 403).mean()
        robots_txt_fetched = bool((g["path"] == ROBOTS_TXT_PATH).any())

        disallowed_hits = int(non_robots["path"].apply(is_disallowed).sum())

        ja4_families_seen = g["ja4"].apply(ja4_family)
        family_counts = ja4_families_seen.value_counts()
        dominant_family = family_counts.index[0] if len(family_counts) else None
        ja4_consistency = (family_counts.iloc[0] / len(g)) if len(family_counts) else 0.0
        example_ja4 = g.loc[ja4_families_seen == dominant_family, "ja4"].iloc[0] if dominant_family else "-"

        asn = g["asn"].mode().iloc[0] if len(g) else "-"

        claimed = claimed_identity(ua)
        accept_lang_present = (g["accept_language"] != "-").mean()
        sec_ch_ua_present = (g["sec_ch_ua"] != "-").mean()
        claimed_browser = detect_claimed_browser(ua)

        ip_matches_declared_range = None
        asn_matches_declared_asn = None
        ja4_matches_expected_bot = None
        if claimed is not None:
            ip_matches_declared_range = ip_in_declared_ranges(ip, claimed)
            asn_matches_declared_asn = asn_matches_declared(asn, claimed)
            expected_prefixes = ALL_KNOWN_BOTS[claimed]["ja4_prefixes"]
            ja4_matches_expected_bot = dominant_family in expected_prefixes

        header_anomaly_count = 0
        reasons = []
        if claimed_browser is not None and accept_lang_present < 0.5:
            header_anomaly_count += 1
            reasons.append("missing Accept-Language despite claiming a browser")
        if claimed_browser in ("chrome", "edge") and sec_ch_ua_present < 0.5:
            header_anomaly_count += 1
            reasons.append(f"missing Sec-CH-UA despite claiming {claimed_browser}")

        ja4_browser_mismatch = False
        if claimed_browser is not None and dominant_family in SCRIPT_JA4_PREFIXES.values():
            ja4_browser_mismatch = True
            header_anomaly_count += 1
            reasons.append(
                f"claims {claimed_browser} but {ja4_consistency:.0%} of requests fingerprint as a scripting "
                f"library, not a browser"
            )

        records.append(
            {
                "client_key": client_key,
                "ip": ip,
                "user_agent": ua,
                "asn": asn,
                "ja4": example_ja4,
                "ja4_family": dominant_family,
                "ja4_consistency": ja4_consistency,
                "claimed_identity": claimed,
                "claimed_browser": claimed_browser,
                "n_requests": n_requests,
                "first_timestamp": first_ts,
                "last_timestamp": last_ts,
                "duration_s": duration_s,
                "request_rate_per_min": request_rate_per_min,
                "timing_cv": timing_cv,
                "asset_ratio": asset_ratio,
                "sequential_score": seq_score,
                "unique_paths": unique_paths,
                "path_set": path_set,
                "total_bytes": total_bytes,
                "error_rate": error_rate,
                "block_rate": block_rate,
                "robots_txt_fetched": robots_txt_fetched,
                "disallowed_hits": disallowed_hits,
                "accept_lang_present": accept_lang_present,
                "sec_ch_ua_present": sec_ch_ua_present,
                "header_anomaly_count": header_anomaly_count,
                "ip_matches_declared_range": ip_matches_declared_range,
                "asn_matches_declared_asn": asn_matches_declared_asn,
                "ja4_matches_expected_bot": ja4_matches_expected_bot,
                "ja4_browser_mismatch": ja4_browser_mismatch,
                "looks_like_browser_ja4": dominant_family in BROWSER_JA4_PREFIXES.values(),
                "looks_like_script_ja4": dominant_family in SCRIPT_JA4_PREFIXES.values(),
                "header_reasons": reasons,
            }
        )
    out = pd.DataFrame(records)

    out["claims_known_identity"] = out["claimed_identity"].notna().astype(int)
    out["ip_matches_declared_range_num"] = out["ip_matches_declared_range"].map({True: 1.0, False: 0.0}).fillna(0.5)
    out["asn_matches_declared_asn_num"] = out["asn_matches_declared_asn"].map({True: 1.0, False: 0.0}).fillna(0.5)
    out["ja4_matches_expected_bot_num"] = out["ja4_matches_expected_bot"].map({True: 1.0, False: 0.0}).fillna(0.5)
    out["looks_like_script_ja4_num"] = out["looks_like_script_ja4"].astype(int)
    out["looks_like_browser_ja4_num"] = out["looks_like_browser_ja4"].astype(int)
    out["ja4_browser_mismatch_num"] = out["ja4_browser_mismatch"].astype(int)
    out["robots_txt_fetched_num"] = out["robots_txt_fetched"].astype(int)
    out["block_rate_num"] = out["block_rate"].astype(float)
    return out

FEATURE_COLUMNS = [
    "n_requests",
    "request_rate_per_min",
    "timing_cv",
    "asset_ratio",
    "sequential_score",
    "unique_paths",
    "total_bytes",
    "error_rate",
    "block_rate_num",
    "disallowed_hits",
    "accept_lang_present",
    "sec_ch_ua_present",
    "header_anomaly_count",
    "robots_txt_fetched_num",
    "ja4_consistency",
    "claims_known_identity",
    "ip_matches_declared_range_num",
    "asn_matches_declared_asn_num",
    "ja4_matches_expected_bot_num",
    "looks_like_script_ja4_num",
    "looks_like_browser_ja4_num",
    "ja4_browser_mismatch_num",
]

def build_feature_table(log_path):
    df = parse_log(log_path)
    feats = extract_features(df)
    return feats
