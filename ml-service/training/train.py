from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

APP_ROOT = Path(__file__).resolve().parents[1]
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from ml_core.features import FEATURE_NAMES, FEATURE_VERSION, canonicalize_url, extract_features  # noqa: E402

DATA_DIR = APP_ROOT / "data"
MODEL_DIR = APP_ROOT / "models"
REPORT_DIR = APP_ROOT / "reports"
MODEL_VERSION = "url-lexical-0.2.0"
SEED = 20261002


def load_csv(path: Path, source_name: str) -> tuple[pd.DataFrame, str, dict[str, Any]]:
    frame = pd.read_csv(path)
    url_col = next((c for c in ["url", "URL", "Url"] if c in frame.columns), None)
    label_col = next((c for c in ["label", "Label", "CLASS", "class", "Result"] if c in frame.columns), None)
    if not url_col or not label_col:
        raise ValueError(f"Dataset {path} must contain a URL and label column.")

    urls = frame[url_col].astype(str).str.strip()
    raw = frame[label_col]
    labels = pd.to_numeric(raw, errors="coerce")
    if labels.isna().any():
        labels = raw.astype(str).str.strip().str.lower().map({
            "legitimate": 0,
            "phishing": 1,
            "phishy": 1,
            "suspicious": 1,
            "benign": 0,
            "malicious": 1,
            "1": 1,
            "0": 0,
        })
    labels = labels.astype("Int64")
    valid = urls.ne("") & labels.notna()
    clean = pd.DataFrame({"url": urls[valid].values, "label": labels[valid].astype(int).values})

    clean["canonical_url"] = clean["url"].map(canonicalize_url)
    invalid = clean["canonical_url"].eq("")
    if invalid.any():
        clean = clean.loc[~invalid].copy()

    before = int(len(clean))
    conflict_groups = (
        clean.groupby("canonical_url")["label"].nunique()
        .loc[lambda s: s > 1]
        .index.tolist()
    )
    if conflict_groups:
        raise ValueError(
            f"Dataset contains {len(conflict_groups)} canonical URLs with conflicting labels. "
            "Resolve labeling conflicts before training."
        )

    duplicate_groups = clean[clean.duplicated("canonical_url", keep=False)]["canonical_url"].nunique()
    duplicate_rows_removed = int(clean.duplicated("canonical_url", keep="first").sum())
    clean = clean.drop_duplicates("canonical_url", keep="first").reset_index(drop=True)

    clean["group"] = clean["url"].map(_hostname_group)
    audit = {
        "raw_valid_rows": before,
        "canonical_duplicate_groups": int(duplicate_groups),
        "duplicate_rows_removed": duplicate_rows_removed,
        "rows_after_deduplication": int(len(clean)),
        "conflicting_canonical_urls": int(len(conflict_groups)),
        "unique_groups": int(clean["group"].nunique()),
    }
    if clean["label"].nunique() != 2:
        raise ValueError("Training dataset must contain both legitimate (0) and phishing (1) labels.")
    return clean, source_name, audit


def _hostname_group(url: str) -> str:
    from urllib.parse import urlsplit

    hostname = urlsplit(url).hostname
    if not hostname:
        raise ValueError(f"URL has no hostname: {url}")
    return hostname.lower().rstrip(".")


def build_features(urls: pd.Series) -> np.ndarray:
    rows: list[list[float]] = []
    for url in urls:
        features = extract_features(url).to_dict()
        rows.append([float(features[name]) for name in FEATURE_NAMES])
    return np.asarray(rows, dtype=float)


def evaluate(name: str, model: Any, X: np.ndarray, y: np.ndarray) -> dict[str, Any]:
    pred_start = time.perf_counter()
    pred = model.predict(X)
    pred_seconds = time.perf_counter() - pred_start
    proba = model.predict_proba(X)[:, 1] if hasattr(model, "predict_proba") else None
    cm = confusion_matrix(y, pred, labels=[0, 1]).tolist()
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    return {
        "model": name,
        "accuracy": round(float(accuracy_score(y, pred)), 6),
        "precision": round(float(precision_score(y, pred, zero_division=0)), 6),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 6),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 6),
        "roc_auc": round(float(roc_auc_score(y, proba)) if proba is not None and len(np.unique(y)) == 2 else 0.0, 6),
        "confusion_matrix": cm,
        "false_positive_rate": round(float(fp / max(fp + tn, 1)), 6),
        "false_negative_rate": round(float(fn / max(fn + tp, 1)), 6),
        "predict_seconds_for_test_batch": round(pred_seconds, 6),
        "classification_report": classification_report(y, pred, output_dict=True, zero_division=0),
    }


def grouped_split(frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, Any]]:
    """Create disjoint domain groups across train/validation/test.

    A five-fold stratified-group split is used. One fold becomes test, one validation,
    and the remaining three become training. This prevents the same hostname from
    appearing across evaluation partitions.
    """
    groups = frame["group"].to_numpy()
    y = frame["label"].to_numpy(dtype=int)
    indices = np.arange(len(frame))
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    folds = list(splitter.split(indices, y, groups))
    if len(folds) != 5:
        raise RuntimeError("Expected five stratified group folds.")

    test_idx = folds[0][1]
    val_idx = folds[1][1]
    train_idx = np.concatenate([folds[i][1] for i in (2, 3, 4)])

    train_groups = set(groups[train_idx])
    val_groups = set(groups[val_idx])
    test_groups = set(groups[test_idx])
    if train_groups & val_groups or train_groups & test_groups or val_groups & test_groups:
        raise RuntimeError("Group leakage detected across train/validation/test partitions.")

    split_info = {
        "method": "StratifiedGroupKFold",
        "n_splits": 5,
        "train_rows": int(len(train_idx)),
        "validation_rows": int(len(val_idx)),
        "test_rows": int(len(test_idx)),
        "train_groups": int(len(train_groups)),
        "validation_groups": int(len(val_groups)),
        "test_groups": int(len(test_groups)),
        "group_overlap": {
            "train_validation": int(len(train_groups & val_groups)),
            "train_test": int(len(train_groups & test_groups)),
            "validation_test": int(len(val_groups & test_groups)),
        },
        "class_counts": {
            "train": {str(k): int(v) for k, v in pd.Series(y[train_idx]).value_counts().sort_index().items()},
            "validation": {str(k): int(v) for k, v in pd.Series(y[val_idx]).value_counts().sort_index().items()},
            "test": {str(k): int(v) for k, v in pd.Series(y[test_idx]).value_counts().sort_index().items()},
        },
    }
    return train_idx, val_idx, test_idx, split_info


def dataset_path_from_args(args: argparse.Namespace) -> tuple[Path, str, bool]:
    if args.dataset:
        return Path(args.dataset), "user-supplied", False
    bootstrap = DATA_DIR / "bootstrap_urls.csv"
    if not bootstrap.exists():
        import importlib.util

        module_path = APP_ROOT / "training" / "bootstrap_dataset.py"
        spec = importlib.util.spec_from_file_location("bootstrap_dataset", module_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("Unable to load bootstrap dataset generator.")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.main()
    return bootstrap, "bootstrap-template", True


def _feature_importance(estimator: Any) -> list[dict[str, Any]]:
    if hasattr(estimator, "feature_importances_"):
        vals = np.asarray(estimator.feature_importances_, dtype=float)
    elif hasattr(estimator, "coef_"):
        vals = np.abs(np.asarray(estimator.coef_[0], dtype=float))
    else:
        return []
    total = float(np.sum(vals))
    if total > 0:
        vals = vals / total
    return [
        {"feature": feature, "importance": round(float(value), 6)}
        for feature, value in sorted(zip(FEATURE_NAMES, vals), key=lambda item: item[1], reverse=True)
    ]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset",
        default="",
        help="CSV path with URL and label columns; labels must be 0=legitimate, 1=phishing.",
    )
    args = parser.parse_args()

    path, source_name, bootstrap = dataset_path_from_args(args)
    frame, _, data_audit = load_csv(path, source_name)
    if len(frame) < 100:
        raise ValueError("At least 100 labeled URLs are required for training.")

    X = build_features(frame["url"])
    y = frame["label"].to_numpy(dtype=int)
    train_idx, val_idx, test_idx, split_info = grouped_split(frame)
    X_train, y_train = X[train_idx], y[train_idx]
    X_val, y_val = X[val_idx], y[val_idx]
    X_test, y_test = X[test_idx], y[test_idx]

    models: dict[str, Any] = {
        "logistic-regression": Pipeline([
            ("scale", StandardScaler()),
            ("model", LogisticRegression(max_iter=3000, class_weight="balanced", random_state=SEED)),
        ]),
        "random-forest": RandomForestClassifier(
            n_estimators=400,
            max_depth=18,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=SEED,
            n_jobs=-1,
        ),
        "xgboost": XGBClassifier(
            n_estimators=350,
            max_depth=7,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            reg_lambda=1.0,
            objective="binary:logistic",
            eval_metric="logloss",
            random_state=SEED,
            n_jobs=4,
        ),
    }

    comparisons = []
    validation_runtime = {}
    for name, model in models.items():
        model.fit(X_train, y_train)
        evaluation = evaluate(name, model, X_val, y_val)
        validation_runtime[name] = evaluation.pop("predict_seconds_for_test_batch", None)
        comparisons.append(evaluation)

    comparisons.sort(key=lambda row: (row["f1"], row["roc_auc"], row["recall"], row["accuracy"]), reverse=True)
    selected_name = comparisons[0]["model"]
    selected = models[selected_name]

    X_train_final = np.concatenate([X_train, X_val], axis=0)
    y_train_final = np.concatenate([y_train, y_val], axis=0)
    train_start = time.perf_counter()
    selected.fit(X_train_final, y_train_final)
    train_seconds = time.perf_counter() - train_start
    test_metrics = evaluate(selected_name, selected, X_test, y_test)
    test_predict_seconds = test_metrics.pop("predict_seconds_for_test_batch")
    runtime_metrics = {
        "validation_predict_seconds_by_model": validation_runtime,
        "test_predict_seconds_for_batch": test_predict_seconds,
        "train_seconds_on_train_plus_validation": round(train_seconds, 4),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODEL_DIR / "phishing_model.joblib"
    joblib.dump(selected, model_path)

    estimator = selected.named_steps["model"] if isinstance(selected, Pipeline) else selected
    importance = _feature_importance(estimator)

    source_note = (
        "Bootstrap template corpus generated locally because this build environment has no outbound network. "
        "These metrics validate the runnable pipeline only; they are not a production benchmark."
        if bootstrap
        else
        "User-supplied dataset. Verify provenance, license, leakage, temporal generalization and operational drift before production use."
    )

    try:
        dataset_path_display = str(path.resolve().relative_to(APP_ROOT.parent.resolve()))
    except ValueError:
        dataset_path_display = str(path.resolve())

    metadata = {
        "model_version": MODEL_VERSION,
        "feature_version": FEATURE_VERSION,
        "selected_model": selected_name,
        "label_definition": {"0": "LEGITIMATE", "1": "PHISHING"},
        "dataset": {
            "path": dataset_path_display,
            "source": source_name,
            "rows": int(len(frame)),
            "class_counts": {str(k): int(v) for k, v in frame["label"].value_counts().sort_index().items()},
            "bootstrap": bootstrap,
            "audit": data_audit,
        },
        "evaluation_protocol": {
            "strategy": "stratified_group_holdout",
            "group_key": "hostname",
            "duplicate_policy": "canonical_url_deduplicate_and_reject_label_conflicts",
            "random_seed": SEED,
            "split": split_info,
        },
        "validation_model_comparison": comparisons,
        "test_metrics": test_metrics,
        "feature_names": FEATURE_NAMES,
        "feature_importance": importance,
        "probability_calibrated": False,
        "source_note": source_note,
        "random_seed": SEED,
    }
    (MODEL_DIR / "metrics.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (REPORT_DIR / "model_comparison.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (REPORT_DIR / "feature_schema.json").write_text(
        json.dumps({"version": FEATURE_VERSION, "features": FEATURE_NAMES}, indent=2), encoding="utf-8"
    )
    (REPORT_DIR / "leakage_audit.json").write_text(
        json.dumps({"dataset_audit": data_audit, "evaluation_protocol": split_info}, indent=2), encoding="utf-8"
    )
    (REPORT_DIR / "training_runtime.json").write_text(
        json.dumps(runtime_metrics, indent=2), encoding="utf-8"
    )
    model_manifest = {
        "model_version": MODEL_VERSION,
        "feature_version": FEATURE_VERSION,
        "model_sha256": sha256_file(model_path),
        "metrics_sha256": sha256_file(MODEL_DIR / "metrics.json"),
        "feature_schema_sha256": sha256_file(REPORT_DIR / "feature_schema.json"),
        "training_script_sha256": sha256_file(Path(__file__)),
        "feature_code_sha256": sha256_file(APP_ROOT / "ml_core" / "features.py"),
    }
    (MODEL_DIR / "model_manifest.json").write_text(json.dumps(model_manifest, indent=2), encoding="utf-8")
    print(json.dumps({
        "selected_model": selected_name,
        "model_version": MODEL_VERSION,
        "test_metrics": {k: v for k, v in test_metrics.items() if k != "classification_report"},
        "runtime_metrics": runtime_metrics,
        "rows_after_deduplication": len(frame),
        "bootstrap": bootstrap,
        "model_path": str(model_path),
        "group_overlap": split_info["group_overlap"],
    }, indent=2))


if __name__ == "__main__":
    main()
