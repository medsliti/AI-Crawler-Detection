import os

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_PATH = os.path.join(HERE, "dashboard_template.html")
APP_JS_PATH = os.path.join(HERE, "dashboard_app.js")
RESULTS_PATH = os.path.join(HERE, "output", "results.json")
OUT_PATH = os.path.join(HERE, "dashboard.html")

def main():
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        template = f.read()
    with open(RESULTS_PATH, "r", encoding="utf-8") as f:
        data_raw = f.read()
    with open(APP_JS_PATH, "r", encoding="utf-8") as f:
        app_js = f.read()

    data_safe = data_raw.replace("</", "<\\/")

    html = template.replace("__DATA_JSON__", data_safe).replace("__APP_JS__", app_js)

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Wrote {OUT_PATH} ({len(html)} bytes)")

if __name__ == "__main__":
    main()
