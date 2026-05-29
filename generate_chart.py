# ============================================
# ThreatWatch AI - Chart Generator
# ============================================
# Creates a professional bar chart comparing
# all 3 AI models across 5 metrics.
# Saves the chart as an image in reports/
# ============================================

import matplotlib
matplotlib.use('Agg')  # No popup window, just saves to file
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import json
import os

def generate_comparison_chart():

    # Load results from model_comparison.json
    with open("reports/model_comparison.json", "r") as f:
        data = json.load(f)

    # Extract model names and scores
    models  = ["Random Forest", "SVM", "Neural Network"]
    metrics = ["accuracy", "precision", "recall", "f1_score", "cv_mean"]
    labels  = ["Accuracy", "Precision", "Recall", "F1 Score", "CV Score"]

    # Build score matrix
    scores = []
    for model in models:
        row = [data[model][m] for m in metrics]
        scores.append(row)

    scores = np.array(scores)

    # -----------------------------------------------
    # CHART SETTINGS - dark theme to match dashboard
    # -----------------------------------------------
    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(12, 7))
    fig.patch.set_facecolor("#0a0e1a")
    ax.set_facecolor("#0d1b2a")

    # Bar positions
    x         = np.arange(len(labels))
    bar_width  = 0.25
    colors     = ["#00aaff", "#00ff88", "#ff8800"]

    # Draw bars for each model
    for i, (model, color) in enumerate(zip(models, colors)):
        bars = ax.bar(
            x + i * bar_width,
            scores[i],
            bar_width,
            label    = model,
            color    = color,
            alpha    = 0.85,
            edgecolor= color
        )
        # Add value labels on top of each bar
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                height + 0.5,
                f"{height:.1f}%",
                ha        = "center",
                va        = "bottom",
                fontsize  = 8,
                color     = color,
                fontweight= "bold"
            )

    # -----------------------------------------------
    # LABELS AND STYLING
    # -----------------------------------------------
    ax.set_title(
        "ThreatWatch AI — Model Comparison\nRandom Forest vs SVM vs Neural Network",
        fontsize  = 15,
        color     = "#ffffff",
        fontweight= "bold",
        pad       = 20
    )
    ax.set_ylabel("Score (%)", fontsize=12, color="#aaaaaa")
    ax.set_xlabel("Metric",    fontsize=12, color="#aaaaaa")
    ax.set_xticks(x + bar_width)
    ax.set_xticklabels(labels, fontsize=11, color="#cccccc")
    ax.set_ylim(0, 115)
    ax.set_yticks(range(0, 110, 10))
    ax.tick_params(colors="#aaaaaa")

    # Grid lines
    ax.yaxis.grid(True, color="#1a3a5c", linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)

    # Legend
    ax.legend(
        fontsize    = 11,
        facecolor   = "#0d1b2a",
        edgecolor   = "#1a3a5c",
        labelcolor  = "white",
        loc         = "upper left"
    )

    # Border
    for spine in ax.spines.values():
        spine.set_edgecolor("#1a3a5c")

    # Best model annotation
    best = data.get("best_model", "SVM")
    ax.annotate(
        f"🏆 Best CV Score: {best}",
        xy        = (0.98, 0.95),
        xycoords  = "axes fraction",
        fontsize  = 10,
        color     = "#00ff88",
        ha        = "right",
        va        = "top",
        bbox      = dict(boxstyle="round,pad=0.4",
                         facecolor="#002d1a",
                         edgecolor="#00ff88",
                         alpha=0.8)
    )

    # Save chart
    os.makedirs("reports", exist_ok=True)
    chart_path = "reports/model_comparison_chart.png"
    plt.tight_layout()
    plt.savefig(chart_path, dpi=150, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close()

    print(f"✅ Chart saved to {chart_path}")
    return chart_path


if __name__ == "__main__":
    print("="*50)
    print("  ThreatWatch AI - Generating Chart...")
    print("="*50 + "\n")

    # Make sure model_comparison.json exists
    if not os.path.exists("reports/model_comparison.json"):
        print("❌ Error: Run model_comparison.py first!")
    else:
        path = generate_comparison_chart()
        print(f"\n  Open this file to see your chart:")
        print(f"  {path}")
        print("\n  You can also include this image in your report!")