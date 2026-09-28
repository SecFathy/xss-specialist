"""Ask the learned API about supplied code; does not crawl or execute a target."""
import argparse
import json
from pathlib import Path
from urllib.request import Request, urlopen

from xss_decision.questions import XSS_QUESTIONS_V2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--code-file", required=True)
    ap.add_argument("--language", default="javascript")
    ap.add_argument("--url", default="http://127.0.0.1:8009")
    args = ap.parse_args()
    payload = {"state": {"language": args.language, "code": Path(args.code_file).read_text()},
               "questions": XSS_QUESTIONS_V2}
    request = Request(args.url.rstrip("/") + "/v1/systemone", data=json.dumps(payload).encode(),
                      headers={"content-type": "application/json"}, method="POST")
    with urlopen(request, timeout=120) as response:
        result = json.load(response)
    if result["model"] == "xss-decision-mock":
        raise SystemExit("Refused: the server is using a heuristic. Start it with --run for model-only decisions.")
    print(json.dumps(result, indent=2))


if __name__ == "__main__": main()
