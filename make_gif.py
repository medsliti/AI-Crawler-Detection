import os
import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import matplotlib.patheffects as pe
from PIL import Image

from features import parse_log

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
OUTPUT_DIR = os.path.join(HERE, "output")
LOG_PATH = os.path.join(DATA_DIR, "access.log")
RESULTS_PATH = os.path.join(OUTPUT_DIR, "results.json")

BG = "#0d1117"
PANEL = "#161b22"
GRID = "#30363d"
FG = "#e6edf3"
MUTED = "#8b949e"
GREEN = "#3fb950"
RED = "#f85149"
AMBER = "#d29922"
BLUE = "#58a6ff"
PURPLE = "#bc8cff"

FIGSIZE = (12, 6.75)
DPI = 100
FPS = 8
DURATION_S = 17
N_FRAMES = FPS * DURATION_S

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "text.color": FG,
        "axes.edgecolor": GRID,
        "axes.labelcolor": FG,
        "xtick.color": MUTED,
        "ytick.color": FG,
        "figure.facecolor": BG,
        "axes.facecolor": PANEL,
    }
)

def load_story():
    with open(RESULTS_PATH, "r", encoding="utf-8") as f:
        results = json.load(f)
    cluster = results["block_evasion"]["clusters"][0]
    blocked_key = cluster["blocked_client_key"]
    disguised_keys = cluster["disguised_client_keys"]

    df = parse_log(LOG_PATH)
    df["client_key_str"] = df["client_key"].apply(lambda k: "||".join(k))

    blocked_df = df[df["client_key_str"] == blocked_key].sort_values("timestamp")
    disguised_dfs = [df[df["client_key_str"] == k].sort_values("timestamp") for k in disguised_keys]

    client_lookup = {c["client_key"]: c for c in results["clients"]}
    blocked_info = client_lookup[blocked_key]
    disguised_infos = [client_lookup[k] for k in disguised_keys]
    return results, blocked_df, blocked_info, disguised_dfs, disguised_infos

def to_rel_minutes(series, t0):
    return (series - t0).dt.total_seconds() / 60.0

def build_timeline_data(blocked_df, disguised_dfs):
    t0 = blocked_df["timestamp"].min()
    blocked_t = to_rel_minutes(blocked_df["timestamp"], t0).tolist()
    disguised_t = [to_rel_minutes(d["timestamp"], t0).tolist() for d in disguised_dfs]
    all_t = blocked_t + [t for lst in disguised_t for t in lst]
    t_min, t_max = min(all_t), max(all_t)
    pad = max(0.6, (t_max - t_min) * 0.08)
    return blocked_t, disguised_t, t_min - pad, t_max + pad

def draw_swimlane_frame(ax, lanes, blocked_t, disguised_t, playhead, caption, threshold_line=None, risk_values=None):
    ax.clear()
    ax.set_facecolor(PANEL)
    n_lanes = len(lanes)
    ax.set_ylim(-0.7, n_lanes - 0.3)
    ax.set_yticks(range(n_lanes))
    ax.set_yticklabels(lanes, fontsize=13, fontweight="bold")
    ax.set_xlabel("Minutes since the declared crawler's first request", fontsize=11, color=MUTED)
    ax.grid(axis="x", color=GRID, linewidth=0.6, alpha=0.6)
    for spine in ax.spines.values():
        spine.set_color(GRID)

    visible_blocked = [t for t in blocked_t if t <= playhead]
    if visible_blocked:
        ax.scatter(visible_blocked, [0] * len(visible_blocked), marker="x", s=130, linewidths=3, color=RED, zorder=3)

    for i, times in enumerate(disguised_t):
        lane_y = i + 1
        visible = [t for t in times if t <= playhead]
        if visible:
            ax.scatter(visible, [lane_y] * len(visible), marker="o", s=90, color=GREEN, alpha=0.9, zorder=3)
        if risk_values is not None:
            score = risk_values[i]
            ax.text(
                playhead + 0.15, lane_y, f"risk {score:.0f}", color=AMBER, fontsize=12, fontweight="bold",
                va="center", path_effects=[pe.withStroke(linewidth=2, foreground=BG)],
            )

    if threshold_line is not None:
        ax.axhline(y=0, color=GRID, linewidth=0.5)

    ax.axvline(x=playhead, color=BLUE, linewidth=1.5, alpha=0.8, zorder=2)

    if caption:
        ax.text(
            0.5, 1.10, caption, transform=ax.transAxes, ha="center", va="bottom",
            fontsize=17, fontweight="bold", color=FG, wrap=True,
        )

def draw_link_frame(ax, lanes, blocked_t, disguised_t, t_min, t_max, progress, risk_targets):
    ax.clear()
    ax.set_facecolor(PANEL)
    n_lanes = len(lanes)

    right_pad = (t_max - t_min) * 0.22
    ax.set_xlim(t_min, t_max + right_pad)
    ax.set_ylim(-0.7, n_lanes - 0.3)
    ax.set_yticks(range(n_lanes))
    ax.set_yticklabels(lanes, fontsize=13, fontweight="bold")
    ax.set_xlabel("Minutes since the declared crawler's first request", fontsize=11, color=MUTED)
    ax.grid(axis="x", color=GRID, linewidth=0.6, alpha=0.6)
    for spine in ax.spines.values():
        spine.set_color(GRID)

    ax.scatter(blocked_t, [0] * len(blocked_t), marker="x", s=130, linewidths=3, color=RED, zorder=3)
    anchor_x = blocked_t[-1]

    for i, times in enumerate(disguised_t):
        lane_y = i + 1
        ax.scatter(times, [lane_y] * len(times), marker="o", s=90, color=GREEN, alpha=0.9, zorder=3)
        link_alpha = min(1.0, progress * 1.4)
        ax.plot(
            [anchor_x, times[0]], [0, lane_y], linestyle="--", linewidth=2, color=PURPLE, alpha=link_alpha, zorder=2
        )
        score = 20 + (risk_targets[i] - 20) * min(1.0, progress * 1.3)
        color = AMBER if score < 65 else RED
        ax.text(
            times[-1] + (t_max - t_min) * 0.015, lane_y, f"risk {score:.0f}/100", color=color, fontsize=13,
            fontweight="bold", va="center", path_effects=[pe.withStroke(linewidth=2.5, foreground=BG)],
        )

    thresh_x0, thresh_x1 = t_min, t_max
    ax.plot([thresh_x0, thresh_x1], [-0.55, -0.55], color=MUTED, linewidth=0, alpha=0)
    ax.text(
        0.5, 1.12, "The detector links the disguised clients back to the blocked identity", transform=ax.transAxes,
        ha="center", va="bottom", fontsize=16, fontweight="bold", color=FG,
    )
    ax.text(
        0.5, 1.01,
        f"Review threshold: 65/100" if progress > 0.3 else "",
        transform=ax.transAxes, ha="center", va="bottom", fontsize=11, color=MUTED,
    )

def draw_end_card(fig, ax, results):
    ax.clear()
    ax.set_facecolor(BG)
    ax.axis("off")

    mc = results["method_comparison"]
    methods = ["Rules", "ML", "Anomaly (AUC)", "Hybrid"]
    values = [
        mc["rules"]["report"]["weighted avg"]["f1-score"],
        mc["ml"]["report"]["weighted avg"]["f1-score"],
        mc["anomaly"]["roc_auc"],
        mc["hybrid"]["report"]["weighted avg"]["f1-score"],
    ]
    colors = [BLUE, PURPLE, AMBER, GREEN]

    ax.text(0.5, 0.93, "Detection results", transform=ax.transAxes, ha="center", fontsize=26, fontweight="bold", color=FG)
    ax.text(
        0.5, 0.85, "Rules vs ML vs Anomaly vs Hybrid (weighted F1 / ROC-AUC)", transform=ax.transAxes, ha="center",
        fontsize=13, color=MUTED,
    )

    bar_ax = fig.add_axes([0.12, 0.30, 0.76, 0.42])
    bar_ax.set_facecolor(BG)
    bars = bar_ax.bar(methods, values, color=colors, width=0.55)
    bar_ax.set_ylim(0, 1.08)
    bar_ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    bar_ax.tick_params(colors=MUTED, labelsize=12)
    for spine in ["top", "right", "left"]:
        bar_ax.spines[spine].set_visible(False)
    bar_ax.spines["bottom"].set_color(GRID)
    bar_ax.grid(axis="y", color=GRID, linewidth=0.6, alpha=0.5)
    for b, v in zip(bars, values):
        bar_ax.text(b.get_x() + b.get_width() / 2, v + 0.03, f"{v:.2f}", ha="center", fontsize=13, fontweight="bold", color=FG)

    ax.text(
        0.5, 0.14, "Synthetic data. A high score means: investigate, not proof.", transform=ax.transAxes, ha="center",
        fontsize=15, fontweight="bold", color=AMBER,
    )
    ax.text(
        0.5, 0.06, "All crawler/operator names in this demo are fictional.", transform=ax.transAxes, ha="center",
        fontsize=11, color=MUTED,
    )
    return bar_ax

def fig_to_pil(fig):
    fig.canvas.draw()
    w, h = fig.canvas.get_width_height()
    buf = fig.canvas.buffer_rgba()
    img = Image.frombuffer("RGBA", (w, h), buf, "raw", "RGBA", 0, 1).convert("RGB")
    return img.copy()

def main():
    results, blocked_df, blocked_info, disguised_dfs, disguised_infos = load_story()
    blocked_t, disguised_t, t_min, t_max = build_timeline_data(blocked_df, disguised_dfs)
    lanes = [f"Declared: {blocked_info['claimed_identity']} (blocked)"] + [
        f"Disguised client {i+1} (new IP/ASN)" for i in range(len(disguised_infos))
    ]
    risk_targets = [info["hybrid_score"] for info in disguised_infos]

    fig = plt.figure(figsize=FIGSIZE, dpi=DPI, facecolor=BG)

    frame_ms = round(1000 / FPS)
    n_sweep = int(N_FRAMES * 0.45)
    n_link = int(N_FRAMES * 0.27)
    PAUSE1_MS = 1200
    END_CARD_MS = 3600

    def caption_for(frac):
        if frac < 0.15:
            return f"A declared crawler ({blocked_info['claimed_identity']}) starts crawling the site"
        if frac < 0.55:
            return "The site blocks it -- 403s on every request"
        return "Minutes later, new \"Chrome on macOS\" clients appear from new IPs/ASNs"

    frames = []

    for frame_idx in range(n_sweep):
        fig.clf()
        ax = fig.add_axes([0.30, 0.16, 0.66, 0.64])
        frac = frame_idx / n_sweep
        playhead = t_min + frac * (t_max - t_min)
        draw_swimlane_frame(ax, lanes, blocked_t, disguised_t, playhead, caption_for(frac))
        frames.append((fig_to_pil(fig), frame_ms))

    fig.clf()
    ax = fig.add_axes([0.30, 0.16, 0.66, 0.64])
    draw_swimlane_frame(ax, lanes, blocked_t, disguised_t, t_max, "All requests observed in this episode")
    frames.append((fig_to_pil(fig), PAUSE1_MS))

    for local_i in range(n_link):
        fig.clf()
        ax = fig.add_axes([0.30, 0.18, 0.66, 0.62])
        progress = local_i / max(1, n_link - 1)
        draw_link_frame(ax, lanes, blocked_t, disguised_t, t_min, t_max, progress, risk_targets)
        frames.append((fig_to_pil(fig), frame_ms))

    fig.clf()
    ax = fig.add_axes([0, 0, 1, 1])
    draw_end_card(fig, ax, results)
    frames.append((fig_to_pil(fig), END_CARD_MS))

    gif_path = os.path.join(OUTPUT_DIR, "block_evasion_story.gif")
    first_img, _ = frames[0]
    first_img.save(
        gif_path,
        save_all=True,
        append_images=[im for im, _ in frames[1:]],
        duration=[d for _, d in frames],
        loop=0,
    )
    total_s = sum(d for _, d in frames) / 1000
    print(f"Wrote {gif_path} ({os.path.getsize(gif_path) / 1e6:.2f} MB, {len(frames)} frames, ~{total_s:.1f}s)")

    png_path = os.path.join(OUTPUT_DIR, "block_evasion_story.png")
    frames[-1][0].save(png_path)
    print(f"Wrote {png_path}")

    try:
        import shutil

        if shutil.which("ffmpeg") is None:
            raise FileNotFoundError("ffmpeg not found on PATH")
        import numpy as np

        mp4_path = os.path.join(OUTPUT_DIR, "block_evasion_story.mp4")
        fig_v = plt.figure(figsize=FIGSIZE, dpi=DPI, facecolor=BG)
        ax_v = fig_v.add_axes([0, 0, 1, 1])
        ax_v.axis("off")
        im_artist = ax_v.imshow(np.asarray(frames[0][0]))

        def update_v(i):
            im_artist.set_data(np.asarray(frames[i][0]))
            return [im_artist]

        expanded = []
        for i, (_, dur_ms) in enumerate(frames):
            expanded += [i] * max(1, round(dur_ms / frame_ms))

        anim_v = animation.FuncAnimation(fig_v, lambda k: update_v(expanded[k]), frames=len(expanded), blit=True)
        anim_v.save(mp4_path, writer=animation.FFMpegWriter(fps=FPS, bitrate=1800))
        print(f"Wrote {mp4_path}")
        plt.close(fig_v)
    except (FileNotFoundError, RuntimeError) as e:
        print(f"Skipped MP4 export (ffmpeg not available): {e}")

    plt.close(fig)

if __name__ == "__main__":
    main()
