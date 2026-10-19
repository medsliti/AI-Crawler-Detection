# AI-Powered Crawler Detection

A demonstration project that analyzes web server access logs to identify AI
crawlers, verify their claimed identity, and detect spoofed, undeclared, or
**block-evading** bots. It compares three detection methods side by side —
hand-written rules, a supervised ML classifier, and unsupervised anomaly
detection — and combines them into a hybrid verdict.

**This runs entirely on synthetic, seeded data. It is a demonstration, not a
production system.** Every crawler/operator name used (AlphaBot, NovaCrawler,
QueryWeaver, ByteHarvest, DeepIndexer, SeekerBot, FinderCrawl) is fictional —
none of them represent, impersonate, or make claims about any real company.
The block-evasion storyline is a generic, illustrative scenario loosely
inspired by public reporting that an AI company's crawler allegedly evaded a
block (a claim that company disputed) — it is not a recreation or accusation
regarding that or any other specific real-world incident.

## What's in here

| File | Purpose |
|---|---|
| `crawlers_config.py` | Registry of fictional crawlers: UA patterns, IP ranges, ASNs, JA4 prefixes. Replace with real published data before using real logs (see below). |
| `site_structure.py` | The synthetic demo site's page/asset/disallowed-path layout, shared by the generator and the feature extractor. |
| `generate_logs.py` | Generates ~6,000 synthetic log lines from ~80 clients over 24h, plus `robots.txt` and `ground_truth.csv`. |
| `features.py` | Parses the log and computes one feature row per `(ip, user_agent)` client. |
| `block_evasion.py` | Cross-client identity-switch linking: connects a blocked declared crawler to the disguised clients that show up afterward chasing the same content. |
| `rules.py` | Hand-written, weighted 0-100 risk scorer with plain-language reasons. |
| `ml_model.py` | Random Forest (or XGBoost if installed) classifier, evaluated with 5-fold out-of-fold cross-validation; SHAP (or feature-importance fallback) explanations. |
| `anomaly.py` | Isolation Forest, trained with no labels at all. |
| `analyst_notes.py` | Template-based plain-language investigation notes for the highest-risk clients. |
| `analyze.py` | Runs the full pipeline and writes `output/results.json` for the dashboard. |
| `make_gif.py` | Renders the animated GIF (plus a static PNG, and an MP4 if `ffmpeg` is on PATH) telling the block-evasion story. |
| `dashboard_template.html` / `dashboard_app.js` | Editable dashboard sources (markup/CSS and JS). |
| `build_dashboard.py` | Inlines `output/results.json` into the template to produce the single-file `dashboard.html`. |
| `dashboard.html` | The built, self-contained dashboard — open directly in a browser. |

## How to run it

```bash
python -m venv venv
venv\Scripts\activate          # on Windows; `source venv/bin/activate` on macOS/Linux
pip install pandas scikit-learn matplotlib pillow
# optional, used if present: pip install shap xgboost

python generate_logs.py        # writes data/access.log, data/ground_truth.csv, data/robots.txt
python analyze.py              # writes output/results.json, prints a summary + tricky-case breakdown
python make_gif.py             # writes output/block_evasion_story.{gif,png[,mp4]}
python build_dashboard.py      # inlines results.json + dashboard_app.js into dashboard.html
```

Open `dashboard.html` directly in a browser — it's fully self-contained, no
server needed.

## The synthetic dataset

~80 clients, ~6,000 requests over a simulated 24-hour window, fixed random
seed (`RNG_SEED = 42` in `generate_logs.py`) for full reproducibility. Mix:

- **Humans (~42%)**: real browser UAs with matching JA4 fingerprints,
  irregular timing, asset loading, non-sequential browsing. Three are
  deliberately unusual-but-legitimate ("tricky") cases: a privacy browser
  that strips headers, a shared office NAT with an elevated request rate,
  and a screen-reader user with methodical navigation.
- **Verified AI crawlers (15%)**: declared identities, correct IP/ASN/JA4,
  fetch `robots.txt` first, mostly respect it. Includes one crawler that's
  fully blocked by `robots.txt`/WAF and simply stops (a contrast case against
  the block evaders below — being blocked is not, by itself, evasion).
- **Spoofed crawlers (10%)**: crawler UA strings from IPs/ASNs outside the
  declared ranges, often with mismatched TLS fingerprints.
- **Undeclared bots (12.5%)**: browser UAs with script-library JA4
  (python-requests/curl/Go), regular timing, no asset loading, sequential
  URLs. Two are deliberately harder: they use TLS impersonation (a
  browser-matching JA4, as a headless browser or `curl-impersonate`-style
  tool would produce) so they can't be caught on fingerprint mismatch alone.
- **Search engines (10%)**: declared, verified, from their own IP/ASN
  ranges.
- **Block evaders (10%)**: the key scenario. Each episode starts with a
  declared crawler identity (one of two fictional crawlers that are fully
  blocked by `robots.txt` plus a hard WAF rule) getting a 403 on every
  request from its real, declared IP/ASN. Minutes later, two new "Chrome on
  macOS" clients appear from different IPs and different ASNs, request the
  same pages the blocked identity was after, and never fetch `robots.txt`.
  A hidden `operator_id` in `ground_truth.csv` links each episode's blocked
  client to its disguised follow-ups, so the linking logic in
  `block_evasion.py` can be scored directly.

### Why the data isn't "too easy"

An earlier version of this dataset let every method hit 100% accuracy — a
sign the synthetic data was leaking its own answer (for example, "has a
script-library JA4" perfectly defining "is an undeclared bot" by
construction), not a sign of a good detector. To keep the evaluation honest:

- JA4 fingerprints carry 8% random noise per request for humans, spoofers,
  and naive scrapers (simulating TLS-inspecting proxies, VPNs, library
  updates), so "dominant fingerprint family" is a strong signal but not a
  perfect one.
- Two undeclared bots and the block-evasion disguised clients use TLS
  impersonation, matching a real browser's JA4 family, so they can only be
  caught — if at all — through behavioral signals.
- The ML evaluation uses 5-fold out-of-fold cross-validation over all 80
  clients rather than a single train/test split, since with this few labeled
  examples a single split can get lucky and hide exactly the cases that
  matter most.

## Results

Exact numbers are in the console output of `analyze.py` and in the
dashboard's method-comparison panel; the general shape is:

- **Rules**: strong precision, perfect on block evasion (via the
  deterministic linking signal) and on spoofing (via IP/ASN/JA4 checks), but
  it misses both TLS-impersonating undeclared bots, scoring them as human —
  it only knows the signals that were hand-encoded.
- **ML (Random Forest, out-of-fold)**: catches one of the two hard
  impersonators by combining several weak secondary signals (asset ratio,
  request rate, sequentiality) that no single rule threshold captures, but
  still misses the stealthiest one, which was deliberately built to
  randomize timing and load some assets specifically to blend in.
- **Anomaly detection (Isolation Forest, unsupervised)**: catches the
  stealthy bot that both rules and ML missed, but at a real cost — it also
  flags 2 of the 3 unusual-but-legitimate humans (the office-NAT and
  privacy-browser cases) as outliers. This is the classic unsupervised
  trade-off, so the dashboard reports it with ROC-AUC (threshold-free)
  rather than treating a single cutoff as correct, since roughly half this
  traffic is bot traffic — a setting where Isolation Forest's usual
  "anomalies are rare" assumption doesn't really hold.
- **Hybrid**: trusts rules/ML agreement when present, defers to ML when it
  disagrees with reasonable confidence, treats a block-evasion link as
  near-decisive, and uses the anomaly score only to flag a client for review
  — never to silently relabel it — when the agreed verdict looks clean but
  scores as a behavioral outlier. It doesn't surpass ML's accuracy by magic;
  it stays honest about which cases remain hard.

Block-evasion linking hits perfect recall and precision on this run, which
is expected rather than suspicious: it's a narrow, well-defined pattern
(same small set of target pages, requested again within a bounded time
window, from a client that never fetches `robots.txt`) that the linking
heuristic was specifically built to catch, unlike the open-ended six-way
classification problem above.

## Using this with real logs

1. **Replace the placeholders in `crawlers_config.py`** with each operator's
   actual, currently-published crawler info — IP ranges, ASN, and
   User-Agent pattern. These feeds change over time, so fetch and cache them
   periodically rather than hard-coding a snapshot. A few public starting
   points: OpenAI publishes `gptbot.json` and `chatgpt-user.json`; Google
   publishes a crawler IP JSON feed covering Googlebot and Google-Extended;
   Microsoft publishes `bingbot.json`; most other operators document their
   crawler's IP ranges or verification method in their own developer docs.
2. **Point `features.py` at your real access log.** It expects an
   nginx-combined-format log extended with JA4, ASN, and two header fields
   (see `LOG_LINE_RE` in `features.py` for the exact format, or adapt the
   regex to whatever your access-log format or JA4-capturing proxy
   produces).
3. **Replace `site_structure.py`** with your actual sitemap, or derive
   `CONTENT_PATHS` from the paths seen in your own logs.
4. **Re-fit the ML model and Isolation Forest on your own labeled or
   unlabeled traffic** — the model in this repo is fit on synthetic data and
   will not generalize to real traffic patterns.
5. **Tune `block_evasion.py`'s thresholds** (`window_minutes`,
   `min_jaccard`) to your site's real traffic volume and page structure; the
   defaults here were chosen for this synthetic dataset's scale.
6. **Treat every score as a prioritization signal, not a verdict.** This
   applies in production even more than here — see the disclaimer in the
   dashboard and in every analyst note.

## A note on the analyst notes

`analyst_notes.py` generates its notes from templates over the
already-computed features (`build_context()` / `generate_note()`) — no
external API call is made. The function boundary is deliberate: swap the
body of `generate_note()` for a call to an LLM API that takes the same
`context` dict as its prompt payload, and nothing else in the pipeline needs
to change. House style is enforced either way: describe what was observed
and say it "warrants review" — never assert that a client definitely is a
bot or is malicious.
