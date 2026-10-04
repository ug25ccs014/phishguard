from __future__ import annotations

from pathlib import Path

from ucimlrepo import fetch_ucirepo

OUT = Path(__file__).resolve().parents[1] / "data" / "phiusiil_urls.csv"


def main() -> None:
    dataset = fetch_ucirepo(id=967)
    X = dataset.data.features.copy()
    y = dataset.data.targets.copy()
    url_col = next((c for c in X.columns if c.lower() == "url"), None)
    if url_col is None:
        raise RuntimeError("PhiUSIIL URL column not found.")
    target_col = y.columns[0]
    # Official PhiUSIIL definition: 1=legitimate, 0=phishing. Invert for our model's convention.
    out = X[[url_col]].rename(columns={url_col: "url"})
    out["label"] = (y[target_col].astype(int) == 0).astype(int).to_numpy()
    out["source"] = "uci-phiusiil-967"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(OUT, index=False)
    print(f"Saved {len(out):,} rows to {OUT}")


if __name__ == "__main__":
    main()
