AI_CRAWLERS = {
    "AlphaBot": {
        "operator": "(fictional) Alpha AI Labs",
        "category": "ai_crawler",
        "ua_pattern": r"AlphaBot",
        "robots_token": "AlphaBot",
        "ip_ranges": ["20.15.240.0/24", "20.15.241.0/24"],
        "asn": "AS64501",
        "ja4_prefixes": ["t13d1517h2"],
        "fully_blocked": False,
    },
    "NovaCrawler": {
        "operator": "(fictional) Nova Research",
        "category": "ai_crawler",
        "ua_pattern": r"NovaCrawler",
        "robots_token": "NovaCrawler",
        "ip_ranges": ["34.102.136.0/24", "34.102.137.0/24"],
        "asn": "AS64502",
        "ja4_prefixes": ["t13d1516h2"],
        "fully_blocked": False,
    },
    "QueryWeaver": {
        "operator": "(fictional) QueryWeaver Inc.",
        "category": "ai_crawler",
        "ua_pattern": r"QueryWeaver",
        "robots_token": "QueryWeaver",
        "ip_ranges": ["44.221.0.0/24"],
        "asn": "AS64503",
        "ja4_prefixes": ["t13d1514h2"],
        "fully_blocked": False,
    },

    "ByteHarvest": {
        "operator": "(fictional) ByteHarvest Data",
        "category": "ai_crawler",
        "ua_pattern": r"ByteHarvest",
        "robots_token": "ByteHarvest",
        "ip_ranges": ["18.97.0.0/24"],
        "asn": "AS64504",
        "ja4_prefixes": ["t13d1508h2"],
        "fully_blocked": True,
    },
    "DeepIndexer": {
        "operator": "(fictional) DeepIndexer Labs",
        "category": "ai_crawler",
        "ua_pattern": r"DeepIndexer",
        "robots_token": "DeepIndexer",
        "ip_ranges": ["66.249.72.0/24"],
        "asn": "AS64505",
        "ja4_prefixes": ["t13d1518h2"],
        "fully_blocked": True,
    },
}

SEARCH_ENGINES = {
    "SeekerBot": {
        "operator": "(fictional) Seeker Search",
        "category": "search_engine",
        "ua_pattern": r"SeekerBot",
        "robots_token": "SeekerBot",
        "ip_ranges": ["66.249.66.0/24", "66.249.68.0/24"],
        "asn": "AS64510",
        "ja4_prefixes": ["t13d1519h2"],
        "fully_blocked": False,
    },
    "FinderCrawl": {
        "operator": "(fictional) Finder Web Services",
        "category": "search_engine",
        "ua_pattern": r"FinderCrawl",
        "robots_token": "FinderCrawl",
        "ip_ranges": ["157.55.39.0/24"],
        "asn": "AS64511",
        "ja4_prefixes": ["t13d1520h2"],
        "fully_blocked": False,
    },
}

ALL_KNOWN_BOTS = {**AI_CRAWLERS, **SEARCH_ENGINES}

ROBOTS_FULLY_BLOCKED = [name for name, cfg in AI_CRAWLERS.items() if cfg["fully_blocked"]]

BROWSER_JA4_PREFIXES = {
    "chrome": "t13d1516h2",
    "edge": "t13d1516h2",
    "firefox": "t13d1715h2",
    "safari": "t13d1312h2",
}

SCRIPT_JA4_PREFIXES = {
    "python-requests": "t13i0908h0",
    "curl": "t13i0505h0",
    "go-http-client": "t13i1309h0",
}

ROBOTS_DISALLOW_ALL = ["/admin/", "/private/", "/api/"]
