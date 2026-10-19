CONTENT_PATHS = (
    ["/", "/about", "/contact", "/pricing", "/blog", "/products"]
    + [f"/blog/post-{i}" for i in range(1, 41)]
    + [f"/products/item-{i}" for i in range(1, 26)]
)

ASSET_PATHS = [
    "/static/style.css",
    "/static/app.js",
    "/static/logo.png",
    "/static/hero.jpg",
    "/static/font.woff2",
    "/static/analytics.js",
    "/static/icons.svg",
]

DISALLOWED_PATHS = [
    "/admin/",
    "/admin/login",
    "/admin/dashboard",
    "/private/",
    "/private/reports",
    "/api/",
    "/api/v1/users",
    "/api/v1/orders",
]

NONEXISTENT_PATHS = ["/old-promo", "/2019/sale", "/blog/post-999", "/favicon.ico"]

ROBOTS_TXT_PATH = "/robots.txt"

BLOCK_EVASION_TARGET_PATHS = [
    "/private/reports",
    "/blog/post-1",
    "/blog/post-2",
    "/products/item-1",
]

ASSET_EXTENSIONS = (".css", ".js", ".png", ".jpg", ".svg", ".woff2")

SORTED_CONTENT_PATHS = sorted(CONTENT_PATHS)
CONTENT_PATH_INDEX = {p: i for i, p in enumerate(SORTED_CONTENT_PATHS)}

def is_asset(path):
    return path.endswith(ASSET_EXTENSIONS)

def is_disallowed(path):
    return any(path == d or path.startswith(d) for d in DISALLOWED_PATHS)
