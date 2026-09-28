"""Local HTTP API for XSS decision backends."""
from __future__ import annotations

import argparse
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from xss_decision.backend import HeuristicBackend
from xss_decision.schema import DecisionRequest, DecisionResponse

app = FastAPI(title="XSS Decision Model", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1", "http://localhost"],
                   allow_methods=["GET", "POST"], allow_headers=["content-type"])
app.state.backend = HeuristicBackend()


@app.middleware("http")
async def request_id(request, call_next):
    response = await call_next(request)
    response.headers["x-request-id"] = request.headers.get("x-request-id") or uuid.uuid4().hex
    return response


@app.post("/v1/systemone", response_model=DecisionResponse)
def systemone(request: DecisionRequest):
    try:
        return app.state.backend.answer(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/v1/models")
def models():
    if hasattr(app.state.backend, "details"):
        return {"models": [app.state.backend.details]}
    return {"models": [{"name": app.state.backend.model_name,
                        "description": "Non-learned API reference backend; not the XSS SLM release."}]}


def main() -> None:
    ap = argparse.ArgumentParser(prog="xss-decision-serve")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8009)
    ap.add_argument("--run", help="Local checkpoint or pinned Kev Hub ID; omitted = explicitly non-learned reference backend")
    ap.add_argument("--device", choices=["cpu", "mps", "cuda"], default="mps")
    ap.add_argument("--backend", choices=["auto", "torch", "mlx"], default="auto")
    ap.add_argument("--calibration", help="Calibration-only temperature.json for this exact checkpoint")
    args = ap.parse_args()
    if args.run:
        from xss_decision.learned import LearnedBackend
        app.state.backend = LearnedBackend(args.run, device=args.device, backend=args.backend, calibration=args.calibration)
    elif args.calibration:
        ap.error("--calibration requires --run")
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
