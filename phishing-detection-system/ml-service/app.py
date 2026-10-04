from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, HttpUrl, field_validator

from ml_core.model import METADATA, MODEL, predict_url

PRODUCTION = os.getenv("ML_ENV", "development").lower() == "production"

app = FastAPI(
    title="PhishGuard ML Service",
    version="0.5.0",
    description="Versioned URL feature extraction and phishing classification service.",
    docs_url=None if PRODUCTION else "/docs",
    redoc_url=None if PRODUCTION else "/redoc",
    openapi_url=None if PRODUCTION else "/openapi.json",
)

MAX_REQUEST_BYTES = 64 * 1024


@app.middleware("http")
async def request_size_limit(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length."})
        if declared_length > MAX_REQUEST_BYTES:
            return JSONResponse(status_code=413, content={"detail": "Request body is too large."})
    return await call_next(request)



class PredictRequest(BaseModel):
    url: HttpUrl = Field(max_length=4096)

    @field_validator("url")
    @classmethod
    def reject_credentials(cls, value: HttpUrl) -> HttpUrl:
        parsed = urlsplit(str(value))
        if parsed.username or parsed.password:
            raise ValueError("Credential-bearing URLs are not accepted.")
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only HTTP/HTTPS URLs are accepted.")
        return value


class PredictResponse(BaseModel):
    prediction: int
    label: str
    phishingProbability: float = Field(ge=0, le=1)
    legitimateProbability: float = Field(ge=0, le=1)
    featureVersion: str
    modelVersion: str
    modelName: str
    features: dict[str, int | float]
    topModelFeatures: list[dict[str, Any]]
    probabilityCalibrated: bool = False


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "phishguard-ml",
        "stage": "final-release",
        "modelLoaded": MODEL is not None,
        "modelVersion": METADATA.get("model_version"),
        "featureVersion": METADATA.get("feature_version"),
    }


@app.get("/ready")
def ready() -> JSONResponse:
    if MODEL is None:
        return JSONResponse(status_code=503, content={"status": "not_ready", "service": "phishguard-ml"})
    return JSONResponse(status_code=200, content={"status": "ready", "service": "phishguard-ml", "modelVersion": METADATA.get("model_version"), "featureVersion": METADATA.get("feature_version")})


@app.get("/model-info")
def model_info() -> dict[str, Any]:
    return METADATA


@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest) -> PredictResponse:
    try:
        return PredictResponse(**predict_url(str(request.url)))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
