import random
import ipaddress
import datetime
import os
import csv
from collections import Counter

from crawlers_config import (
    AI_CRAWLERS,
    SEARCH_ENGINES,
    ALL_KNOWN_BOTS,
    BROWSER_JA4_PREFIXES,
    SCRIPT_JA4_PREFIXES,
    ROBOTS_DISALLOW_ALL,
    ROBOTS_FULLY_BLOCKED,
)
from site_structure import (
    CONTENT_PATHS,
    ASSET_PATHS,
    DISALLOWED_PATHS,
    NONEXISTENT_PATHS,
    ROBOTS_TXT_PATH,
    BLOCK_EVASION_TARGET_PATHS,
)

RNG_SEED = 42
random.seed(RNG_SEED)

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
os.makedirs(DATA_DIR, exist_ok=True)

SIM_START = datetime.datetime(2026, 3, 2, 0, 0, 0)

BYTES_BY_KIND = {
    "html": (12000, 48000),
    "css": (6000, 11000),
    "js": (15000, 42000),
    "image": (90000, 420000),
    "font": (20000, 60000),
    "api": (400, 3200),
    "robots": (250, 700),
}

def kind_of(path):
    if path == ROBOTS_TXT_PATH:
        return "robots"
    if path.endswith(".css"):
        return "css"
    if path.endswith(".js"):
        return "js"
    if path.endswith((".png", ".jpg", ".svg")):
        return "image"
    if path.endswith(".woff2"):
        return "font"
    if path.startswith("/api/"):
        return "api"
    return "html"

def bytes_for(path):
    lo, hi = BYTES_BY_KIND[kind_of(path)]
    return random.randint(lo, hi)

BROWSER_UAS = {
    "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "mobile_safari": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "mobile_chrome": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",

    "chrome_macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
}
SEC_CH_UA = {
    "chrome": '"Chromium";v="129", "Not(A:Brand";v="99", "Google Chrome";v="129"',
    "edge": '"Chromium";v="129", "Not(A:Brand";v="99", "Microsoft Edge";v="129"',
    "mobile_chrome": '"Chromium";v="129", "Not(A:Brand";v="99", "Google Chrome";v="129"',
    "chrome_macos": '"Chromium";v="129", "Not(A:Brand";v="99", "Google Chrome";v="129"',
}
BOT_UAS = {
    "AlphaBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; AlphaBot/1.1; +https://alphaailabs.example/alphabot",
    "NovaCrawler": "Mozilla/5.0 (compatible; NovaCrawler/1.0; +https://novaresearch.example/novacrawler)",
    "QueryWeaver": "Mozilla/5.0 (compatible; QueryWeaver/1.0; +https://queryweaver.example/bot)",
    "ByteHarvest": "ByteHarvest/2.0 (+https://byteharvestdata.example/faq)",
    "DeepIndexer": "Mozilla/5.0 (compatible; DeepIndexer; +https://deepindexerlabs.example/bot.html)",
    "SeekerBot": "Mozilla/5.0 (compatible; SeekerBot/2.1; +https://seekersearch.example/bot.html)",
    "FinderCrawl": "Mozilla/5.0 (compatible; FinderCrawl/2.0; +https://finderwebservices.example/bot.htm)",
}

ACCEPT_LANGUAGES = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "fr-FR,fr;q=0.9,en;q=0.8", "de-DE,de;q=0.9,en;q=0.8"]

ALL_BOT_NETWORKS = [ipaddress.ip_network(r) for bot in ALL_KNOWN_BOTS.values() for r in bot["ip_ranges"]]

def random_ip_in(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    base = int(net.network_address)
    span = net.num_addresses
    offset = random.randint(1, span - 2) if span > 2 else random.randint(0, span - 1)
    return str(ipaddress.IPv4Address(base + offset))

def random_outside_ip():
    while True:
        ip = ipaddress.IPv4Address(random.randint(0x0C000000, 0xDF000000))
        if ip.is_private or ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local:
            continue
        if any(ip in n for n in ALL_BOT_NETWORKS):
            continue
        return str(ip)

_used_asns = {cfg["asn"] for cfg in ALL_KNOWN_BOTS.values()}

def random_fake_asn():
    while True:
        asn = f"AS{random.randint(64600, 65300)}"
        if asn not in _used_asns:
            _used_asns.add(asn)
            return asn

def random_fake_asn_shared_pool():
    return f"AS{random.randint(64600, 65300)}"

def ja4_of(family):
    return family + "_" + f"{random.randint(0,0xffffff):06x}" + "_" + f"{random.randint(0,0xffffff):06x}"

clients = []
_client_seq = 0

def new_client_id():
    global _client_seq
    _client_seq += 1
    return f"client_{_client_seq:04d}"

def add_client(**kwargs):
    kwargs.setdefault("client_id", new_client_id())
    kwargs.setdefault("accept_language", random.choice(ACCEPT_LANGUAGES))
    kwargs.setdefault("sec_ch_ua", None)
    kwargs.setdefault("fetch_robots", False)
    kwargs.setdefault("operator_id", "-")
    kwargs.setdefault("custom_events", None)
    clients.append(kwargs)
    return kwargs

HUMAN_BROWSER_CHOICES = ["chrome", "chrome", "chrome", "firefox", "safari", "edge", "mobile_safari", "mobile_chrome"]

def browser_family(browser_key):
    if browser_key.startswith("mobile_"):
        browser_key = browser_key[len("mobile_"):]
    return browser_key

for _ in range(31):
    browser = random.choice(HUMAN_BROWSER_CHOICES)
    add_client(
        category="Human",
        subtype="regular",
        claimed_identity="-",
        ip=random_outside_ip(),
        asn=random_fake_asn_shared_pool(),
        user_agent=BROWSER_UAS[browser],
        ja4=ja4_of(BROWSER_JA4_PREFIXES[browser_family(browser)]),
        sec_ch_ua=SEC_CH_UA.get(browser),
        n_sessions=random.randint(1, 3),
        pages_per_session=(3, 18),
        interval_mean=random.uniform(8, 35),
        timing_regular=False,
        asset_ratio=random.uniform(0.55, 0.75),
        sequential=0.1,
        violation_prob=0.0,
        missing_accept_language=False,
        active_hours=(6, 24),
    )

browser = "firefox"
add_client(
    category="Human",
    subtype="tricky:privacy_browser",
    claimed_identity="-",
    ip=random_outside_ip(),
    asn=random_fake_asn_shared_pool(),
    user_agent=BROWSER_UAS[browser],
    ja4=ja4_of(BROWSER_JA4_PREFIXES[browser]),
    sec_ch_ua=None,
    n_sessions=2,
    pages_per_session=(4, 12),
    interval_mean=18,
    timing_regular=False,
    asset_ratio=0.45,
    sequential=0.1,
    violation_prob=0.0,
    missing_accept_language=True,
    active_hours=(6, 24),
)

browser = "chrome"
add_client(
    category="Human",
    subtype="tricky:office_nat",
    claimed_identity="-",
    ip=random_outside_ip(),
    asn=random_fake_asn_shared_pool(),
    user_agent=BROWSER_UAS[browser],
    ja4=ja4_of(BROWSER_JA4_PREFIXES[browser]),
    sec_ch_ua=SEC_CH_UA[browser],
    n_sessions=5,
    pages_per_session=(15, 35),
    interval_mean=4,
    timing_regular=False,
    asset_ratio=0.6,
    sequential=0.1,
    violation_prob=0.0,
    missing_accept_language=False,
    active_hours=(8, 19),
)

browser = "safari"
add_client(
    category="Human",
    subtype="tricky:screen_reader",
    claimed_identity="-",
    ip=random_outside_ip(),
    asn=random_fake_asn_shared_pool(),
    user_agent=BROWSER_UAS[browser],
    ja4=ja4_of(BROWSER_JA4_PREFIXES[browser]),
    sec_ch_ua=None,
    n_sessions=1,
    pages_per_session=(10, 16),
    interval_mean=45,
    timing_regular=False,
    asset_ratio=0.5,
    sequential=0.65,
    violation_prob=0.0,
    missing_accept_language=False,
    active_hours=(6, 24),
)

VERIFIED_COUNTS = {"AlphaBot": 3, "NovaCrawler": 2, "QueryWeaver": 2}
for bot_name, count in VERIFIED_COUNTS.items():
    bot_cfg = AI_CRAWLERS[bot_name]
    for _ in range(count):
        add_client(
            category="Verified AI crawler",
            subtype="verified",
            claimed_identity=bot_name,
            ip=random_ip_in(random.choice(bot_cfg["ip_ranges"])),
            asn=bot_cfg["asn"],
            user_agent=BOT_UAS[bot_name],
            ja4=ja4_of(bot_cfg["ja4_prefixes"][0]),
            sec_ch_ua=None,
            accept_language="-",
            n_sessions=1,
            pages_per_session=(60, 140),
            interval_mean=random.uniform(3, 9),
            timing_regular=True,
            asset_ratio=0.0,
            sequential=0.9,
            violation_prob=0.02,
            missing_accept_language=True,
            active_hours=(0, 24),
            fetch_robots=True,
        )

blocked_name = random.choice(ROBOTS_FULLY_BLOCKED)
bot_cfg = AI_CRAWLERS[blocked_name]
add_client(
    category="Verified AI crawler",
    subtype="verified_blocked_non_evading",
    claimed_identity=blocked_name,
    ip=random_ip_in(random.choice(bot_cfg["ip_ranges"])),
    asn=bot_cfg["asn"],
    user_agent=BOT_UAS[blocked_name],
    ja4=ja4_of(bot_cfg["ja4_prefixes"][0]),
    sec_ch_ua=None,
    accept_language="-",
    fetch_robots=True,
    missing_accept_language=True,
    custom_events={"kind": "blocked_short_session", "n_tries": random.randint(2, 4)},
)

SPOOFABLE = ["AlphaBot", "NovaCrawler", "QueryWeaver"]
SPOOF_COUNTS = {"AlphaBot": 3, "NovaCrawler": 3, "QueryWeaver": 2}
for bot_name, count in SPOOF_COUNTS.items():
    bot_cfg = AI_CRAWLERS[bot_name]
    for _ in range(count):
        ja4_mismatch = random.random() < 0.7
        family = random.choice(list(SCRIPT_JA4_PREFIXES.values())) if ja4_mismatch else bot_cfg["ja4_prefixes"][0]
        add_client(
            category="Spoofed crawler",
            subtype="spoofed",
            claimed_identity=bot_name,
            ip=random_outside_ip(),
            asn=random_fake_asn_shared_pool(),
            user_agent=BOT_UAS[bot_name],
            ja4=ja4_of(family),
            sec_ch_ua=None,
            accept_language="-",
            n_sessions=1,
            pages_per_session=(40, 110),
            interval_mean=random.uniform(2, 7),
            timing_regular=True,
            asset_ratio=0.0,
            sequential=0.6,
            violation_prob=0.25,
            missing_accept_language=True,
            active_hours=(0, 24),
            fetch_robots=(random.random() < 0.5),
        )

for i in range(9):
    browser = random.choice(["chrome", "firefox", "edge"])
    sophisticated = i == 0
    if sophisticated:
        family = BROWSER_JA4_PREFIXES[browser]
    else:
        script = random.choice(list(SCRIPT_JA4_PREFIXES.keys()))
        family = SCRIPT_JA4_PREFIXES[script]
    add_client(
        category="Undeclared bot",
        subtype="undeclared_scraper_impersonated" if sophisticated else "undeclared_scraper",
        claimed_identity="-",
        ip=random_outside_ip(),
        asn=random_fake_asn_shared_pool(),
        user_agent=BROWSER_UAS[browser],
        ja4=ja4_of(family),
        sec_ch_ua=(SEC_CH_UA.get(browser) if sophisticated else None),
        accept_language=random.choice(ACCEPT_LANGUAGES) if sophisticated else "-",
        n_sessions=1,
        pages_per_session=(80, 220),
        interval_mean=random.uniform(0.8, 2.5),
        timing_regular=True,
        asset_ratio=0.03 if sophisticated else 0.0,
        sequential=0.95,
        violation_prob=0.08 if sophisticated else 0.35,
        missing_accept_language=False if sophisticated else True,
        active_hours=(0, 24),
        fetch_robots=False,
    )

browser = random.choice(["chrome", "firefox"])
add_client(
    category="Undeclared bot",
    subtype="tricky:stealthy_scraper",
    claimed_identity="-",
    ip=random_outside_ip(),
    asn=random_fake_asn_shared_pool(),
    user_agent=BROWSER_UAS[browser],
    ja4=ja4_of(BROWSER_JA4_PREFIXES[browser]),
    sec_ch_ua=SEC_CH_UA.get(browser),
    n_sessions=3,
    pages_per_session=(15, 40),
    interval_mean=random.uniform(6, 14),
    timing_regular=False,
    asset_ratio=0.2,
    sequential=0.5,
    violation_prob=0.01,
    missing_accept_language=False,
    active_hours=(0, 24),
    fetch_robots=False,
)

SEARCH_COUNTS = {"SeekerBot": 5, "FinderCrawl": 3}
for bot_name, count in SEARCH_COUNTS.items():
    bot_cfg = SEARCH_ENGINES[bot_name]
    for _ in range(count):
        add_client(
            category="Search engine",
            subtype="search_engine",
            claimed_identity=bot_name,
            ip=random_ip_in(random.choice(bot_cfg["ip_ranges"])),
            asn=bot_cfg["asn"],
            user_agent=BOT_UAS[bot_name],
            ja4=ja4_of(bot_cfg["ja4_prefixes"][0]),
            sec_ch_ua=None,
            accept_language="-",
            n_sessions=1,
            pages_per_session=(50, 130),
            interval_mean=random.uniform(3, 8),
            timing_regular=True,
            asset_ratio=random.uniform(0.05, 0.15),
            sequential=0.75,
            violation_prob=0.01,
            missing_accept_language=True,
            active_hours=(0, 24),
            fetch_robots=True,
        )

N_EPISODES = 4
episode_clients = []
for ep in range(N_EPISODES):
    operator_id = f"operator_{ep + 1:02d}"
    blocked_name = random.choice(ROBOTS_FULLY_BLOCKED)
    bot_cfg = AI_CRAWLERS[blocked_name]
    n_targets = random.randint(2, len(BLOCK_EVASION_TARGET_PATHS))
    targets = random.sample(BLOCK_EVASION_TARGET_PATHS, n_targets)

    pre = add_client(
        category="Verified AI crawler",
        subtype="pre_evasion",
        claimed_identity=blocked_name,
        ip=random_ip_in(random.choice(bot_cfg["ip_ranges"])),
        asn=bot_cfg["asn"],
        user_agent=BOT_UAS[blocked_name],
        ja4=ja4_of(bot_cfg["ja4_prefixes"][0]),
        sec_ch_ua=None,
        accept_language="-",
        fetch_robots=True,
        missing_accept_language=True,
        operator_id=operator_id,
        custom_events={"kind": "pre_evasion", "targets": targets},
    )
    episode_clients.append((operator_id, pre, targets))

    n_disguised = 2
    for d in range(n_disguised):
        add_client(
            category="Block evader",
            subtype="block_evader",
            claimed_identity="-",
            ip=random_outside_ip(),
            asn=random_fake_asn(),
            user_agent=BROWSER_UAS["chrome_macos"],
            ja4=ja4_of(BROWSER_JA4_PREFIXES["chrome"]),
            sec_ch_ua=SEC_CH_UA["chrome_macos"],
            accept_language=random.choice(ACCEPT_LANGUAGES),
            fetch_robots=False,
            missing_accept_language=False,
            operator_id=operator_id,
            custom_events={
                "kind": "block_evader",
                "targets": targets,
                "gap_minutes": random.uniform(3, 12) + d * random.uniform(2, 9),
                "n_requests": random.randint(10, 26),
            },
        )

random.shuffle(clients)

NGINX_TIME_FMT = "%d/%b/%Y:%H:%M:%S +0000"

JA4_NOISE_POOL = sorted(set(BROWSER_JA4_PREFIXES.values()) | set(SCRIPT_JA4_PREFIXES.values()))
JA4_NOISE_PROB = 0.08
NOISY_CATEGORIES = {"Human", "Undeclared bot", "Spoofed crawler"}

def maybe_noisy_ja4(client):
    if client["category"] in NOISY_CATEGORIES and random.random() < JA4_NOISE_PROB:
        return ja4_of(random.choice(JA4_NOISE_POOL))
    return client["ja4"]

def waf_status(client, path):
    if client["claimed_identity"] in ROBOTS_FULLY_BLOCKED and path != ROBOTS_TXT_PATH:
        return 403
    if path in NONEXISTENT_PATHS:
        return 404
    if client["category"] == "Undeclared bot" and random.random() < 0.03:
        return 429
    return 200

def weighted_hour_offset(active_hours):
    lo, hi = active_hours
    h = random.triangular(lo, hi, (lo + hi) / 2 + 2)
    return h * 3600 + random.uniform(0, 3599)

def gen_intervals(n, mean_sec, regular):
    if n <= 0:
        return []
    shape = random.uniform(14, 28) if regular else random.uniform(0.5, 1.3)
    scale = mean_sec / shape
    return [max(0.05, random.gammavariate(shape, scale)) for _ in range(n)]

def pick_path_sequence(count, sequential_prob, violation_prob):
    sorted_content = sorted(CONTENT_PATHS)
    cursor = random.randrange(len(sorted_content))
    last = None
    paths = []
    for _ in range(count):
        roll = random.random()
        if roll < violation_prob:
            p = random.choice(DISALLOWED_PATHS)
        elif roll < violation_prob + 0.02:
            p = random.choice(NONEXISTENT_PATHS)
        elif random.random() < sequential_prob:
            p = sorted_content[cursor % len(sorted_content)]
            cursor += 1
        else:
            if last is not None and random.random() < 0.4:
                idx = CONTENT_PATHS.index(last) if last in CONTENT_PATHS else 0
                jitter = random.choice([-2, -1, 1, 2])
                p = CONTENT_PATHS[(idx + jitter) % len(CONTENT_PATHS)]
            else:
                p = random.choice(CONTENT_PATHS)
        paths.append(p)
        last = p
    return paths

events = []

def emit(t, client, path, referer, status_override=None):
    status = status_override if status_override is not None else waf_status(client, path)
    events.append([t, client, "GET", path, status, bytes_for(path), referer, maybe_noisy_ja4(client)])
    return status

for client in clients:
    custom = client["custom_events"]

    if custom and custom["kind"] == "blocked_short_session":
        session_start = SIM_START + datetime.timedelta(seconds=weighted_hour_offset((0, 24)))
        t = session_start
        emit(t, client, ROBOTS_TXT_PATH, "-")
        targets = random.sample(BLOCK_EVASION_TARGET_PATHS, min(custom["n_tries"], len(BLOCK_EVASION_TARGET_PATHS)))
        for p in targets:
            t = t + datetime.timedelta(seconds=random.uniform(8, 30))
            emit(t, client, p, "-")
        client["_last_event_time"] = t
        continue

    if custom and custom["kind"] == "pre_evasion":
        session_start = SIM_START + datetime.timedelta(seconds=weighted_hour_offset((0, 24)))
        t = session_start
        emit(t, client, ROBOTS_TXT_PATH, "-")
        for p in custom["targets"]:
            t = t + datetime.timedelta(seconds=random.uniform(8, 30))
            emit(t, client, p, "-")
        client["_last_event_time"] = t
        continue

    if custom and custom["kind"] == "block_evader":
        continue

    lo_pages, hi_pages = client["pages_per_session"]
    for _ in range(client["n_sessions"]):
        n_pages = random.randint(lo_pages, hi_pages)
        session_start = SIM_START + datetime.timedelta(seconds=weighted_hour_offset(client["active_hours"]))
        intervals = gen_intervals(n_pages, client["interval_mean"], client["timing_regular"])
        path_seq = pick_path_sequence(n_pages, client["sequential"], client["violation_prob"])

        t = session_start
        referer = "-"
        if client["fetch_robots"]:
            emit(t, client, ROBOTS_TXT_PATH, "-")

        for i, path in enumerate(path_seq):
            if i > 0:
                t = t + datetime.timedelta(seconds=intervals[i - 1])
            emit(t, client, path, referer)
            referer = f"https://example-news-site.test{path}"

            if random.random() < client["asset_ratio"]:
                n_assets = random.randint(1, 4) if client["category"] == "Human" else 1
                for _ in range(n_assets):
                    asset_t = t + datetime.timedelta(seconds=random.uniform(0.05, 0.6))
                    asset_path = random.choice(ASSET_PATHS)
                    emit(asset_t, client, asset_path, referer)

pre_evasion_by_operator = {
    c["operator_id"]: c
    for c in clients
    if c.get("custom_events") and c["custom_events"].get("kind") == "pre_evasion"
}
for client in clients:
    custom = client["custom_events"]
    if not (custom and custom["kind"] == "block_evader"):
        continue

    pre_client = pre_evasion_by_operator[client["operator_id"]]
    anchor = pre_client["_last_event_time"]
    t = anchor + datetime.timedelta(minutes=custom["gap_minutes"])
    n = custom["n_requests"]
    intervals = gen_intervals(n, random.uniform(5, 11), regular=False)
    referer = "-"
    for i in range(n):
        if i > 0:
            t = t + datetime.timedelta(seconds=intervals[i - 1])
        if random.random() < 0.12:
            p = random.choice(CONTENT_PATHS)
        else:
            p = random.choice(custom["targets"])
        emit(t, client, p, referer, status_override=200)
        referer = f"https://example-news-site.test{p}"
        if random.random() < 0.15:
            asset_t = t + datetime.timedelta(seconds=random.uniform(0.05, 0.5))
            asset_path = random.choice(ASSET_PATHS)
            emit(asset_t, client, asset_path, referer, status_override=200)

events.sort(key=lambda e: e[0])

TARGET_TOTAL = 6000
if len(events) > TARGET_TOTAL:
    keep_prob = TARGET_TOTAL / len(events)
    events = [e for e in events if random.random() < keep_prob]
    events.sort(key=lambda e: e[0])

log_path = os.path.join(DATA_DIR, "access.log")
with open(log_path, "w", encoding="utf-8") as f:
    for t, client, method, path, status, nbytes, referer, ja4 in events:
        time_str = t.strftime(NGINX_TIME_FMT)
        ua = client["user_agent"]
        asn = client["asn"]
        accept_lang = "-" if client["missing_accept_language"] else client["accept_language"]
        sec_ch_ua_raw = client["sec_ch_ua"] if client["sec_ch_ua"] else "-"
        sec_ch_ua = sec_ch_ua_raw.replace('"', '\\"')
        line = (
            f'{client["ip"]} - - [{time_str}] "{method} {path} HTTP/1.1" {status} {nbytes} '
            f'"{referer}" "{ua}" "{ja4}" "{asn}" "{accept_lang}" "{sec_ch_ua}"'
        )
        f.write(line + "\n")

print(f"Wrote {len(events)} log lines to {log_path}")

gt_path = os.path.join(DATA_DIR, "ground_truth.csv")
with open(gt_path, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["client_id", "ip", "user_agent", "category", "claimed_identity", "subtype", "operator_id"])
    for client in clients:
        w.writerow(
            [
                client["client_id"],
                client["ip"],
                client["user_agent"],
                client["category"],
                client["claimed_identity"],
                client["subtype"],
                client["operator_id"],
            ]
        )
print(f"Wrote ground truth for {len(clients)} clients to {gt_path}")

robots_path = os.path.join(DATA_DIR, "robots.txt")
with open(robots_path, "w", encoding="utf-8") as f:
    f.write("User-agent: *\n")
    for p in ROBOTS_DISALLOW_ALL:
        f.write(f"Disallow: {p}\n")
    f.write("\n")
    for bot in ROBOTS_FULLY_BLOCKED:
        f.write(f"User-agent: {bot}\n")
        f.write("Disallow: /\n\n")
print(f"Wrote {robots_path}")

cat_counts = Counter(c["category"] for c in clients)
print("Client category breakdown:", dict(cat_counts))
print("Total clients:", len(clients))
print("Episodes:", [(op, pre["claimed_identity"], targets) for op, pre, targets in episode_clients])
