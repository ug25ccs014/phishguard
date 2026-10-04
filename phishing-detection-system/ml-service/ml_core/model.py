from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from .features import FEATURE_NAMES, FEATURE_VERSION, extract_features

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
MODEL_PATH = MODEL_DIR / "phishing_model.joblib"
METRICS_PATH = MODEL_DIR / "metrics.json"
MANIFEST_PATH = MODEL_DIR / "model_manifest.json"


def _validate_artifact(model: Any, metadata: dict[str, Any]) -> None:
    expected_features = metadata.get("feature_names") or FEATURE_NAMES
    if expected_features != FEATURE_NAMES:
        raise RuntimeError("Model metadata feature schema does not match runtime feature schema.")
    if metadata.get("feature_version") != FEATURE_VERSION:
        raise RuntimeError("Model metadata feature version does not match runtime feature version.")
    if getattr(model, "n_features_in_", None) != len(FEATURE_NAMES):
        raise RuntimeError("Model artifact feature count does not match runtime feature count.")
    classes = list(getattr(model, "classes_", []))
    if classes != [0, 1]:
        raise RuntimeError("Model artifact must expose binary classes [0, 1].")
    if not hasattr(model, "predict") or not hasattr(model, "predict_proba"):
        raise RuntimeError("Model artifact does not provide the required inference interface.")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_artifacts() -> tuple[Any | None, dict[str, Any]]:
    if not MODEL_PATH.exists():
        return None, {"status": "not_loaded", "reason": "model artifact missing"}
    try:
        metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8")) if METRICS_PATH.exists() else {}
        if not MANIFEST_PATH.exists():
            raise RuntimeError("model manifest missing")
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        actual_hash = _sha256_file(MODEL_PATH)
        expected_hash = os.getenv("PHISHGUARD_MODEL_SHA256", "").strip().lower()
        pinned_hash = expected_hash or str(manifest.get("model_sha256", "")).lower()
        if len(pinned_hash) != 64 or actual_hash != pinned_hash:
            raise RuntimeError("model artifact SHA-256 does not match the pinned/manifest hash")
        if manifest.get("model_version") != metrics.get("model_version"):
            raise RuntimeError("model manifest version does not match metrics metadata")
        if manifest.get("feature_version") != metrics.get("feature_version"):
            raise RuntimeError("model manifest feature version does not match metrics metadata")
        model = joblib.load(MODEL_PATH)
        _validate_artifact(model, metrics)
        return model, metrics
    except Exception as exc:
        return None, {"status": "not_loaded", "reason": f"invalid model artifact: {type(exc).__name__}: {exc}"}


MODEL, METADATA = _load_artifacts()


def reload_artifacts() -> dict[str, Any]:
    global MODEL, METADATA
    MODEL, METADATA = _load_artifacts()
    return METADATA


def predict_url(url: str) -> dict[str, Any]:
    features = extract_features(url)
    vector = np.array([[features.to_dict()[name] for name in FEATURE_NAMES]], dtype=float)

    if MODEL is None:
        raise RuntimeError("ML model is not installed or failed artifact validation. Run training first.")

    prediction = int(MODEL.predict(vector)[0])
    probabilities = MODEL.predict_proba(vector)[0]
    classes = list(getattr(MODEL, "classes_", []))
    if classes != [0, 1] or len(probabilities) != 2:
        raise RuntimeError("Loaded model probability contract is invalid.")
    phishing_probability = float(probabilities[1])
    legitimate_probability = float(probabilities[0])

    return {
        "prediction": prediction,
        "label": "PHISHING" if prediction == 1 else "LEGITIMATE",
        "phishingProbability": round(phishing_probability, 6),
        "legitimateProbability": round(legitimate_probability, 6),
        "featureVersion": FEATURE_VERSION,
        "modelVersion": METADATA.get("model_version", "unknown"),
        "modelName": METADATA.get("selected_model", "unknown"),
        "features": features.to_dict(),
        "topModelFeatures": METADATA.get("feature_importance", [])[:8],
        "probabilityCalibrated": bool(METADATA.get("probability_calibrated", False)),
    }
