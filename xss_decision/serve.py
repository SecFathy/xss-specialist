"""Local HTTP API for XSS decision backends."""
from __future__ import annotations

import argparse
import uuid

from fastapi import FastAPI
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
    return app.state.backend.answer(request)


@app.get("/v1/models")
def models():
    return {"models": [{"name": app.state.backend.model_name,
                        "description": "Non-learned API reference backend; not the XSS SLM release."}]}


def main() -> None:
    ap = argparse.ArgumentParser(prog="xss-decision-serve")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8009)
    args = ap.parse_args()
    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

