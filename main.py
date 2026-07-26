from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Dict
import requests

app = FastAPI()

SANDBOX = Path(
    "/srv/agent-redteam/sandbox-bf8c0ddead"
).resolve()

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org"
}


class RequestBody(BaseModel):
    tool: str
    arguments: Dict[str, Any] = {}


def inside_sandbox(path_str: str) -> bool:
    try:
        target = Path(path_str).resolve()
        return target == SANDBOX or SANDBOX in target.parents
    except Exception:
        return False


def host_allowed(url: str) -> bool:
    try:
        parsed = urlparse(url)

        # Block userinfo tricks
        if parsed.username or parsed.password:
            return False

        host = (parsed.hostname or "").lower()

        # Exact host match only
        return host in ALLOWED_HOSTS

    except Exception:
        return False


@app.get("/")
def home():
    return {"status": "running"}


@app.post("/")
def guardrail(req: RequestBody):
    try:
        # -------------------------
        # READ FILE
        # -------------------------
        if req.tool == "read_file":

            path = str(req.arguments.get("path", ""))

            if not inside_sandbox(path):
                return {
                    "action": "block",
                    "reason": "outside sandbox",
                    "result": None
                }

            try:
                content = Path(path).read_text(
                    encoding="utf-8",
                    errors="ignore"
                )

                return {
                    "action": "allow",
                    "reason": "allowed",
                    "result": {
                        "content": content
                    }
                }

            except Exception as e:
                return {
                    "action": "block",
                    "reason": f"read error: {e}",
                    "result": None
                }

        # -------------------------
        # FETCH URL
        # -------------------------
        if req.tool == "fetch_url":

            url = str(req.arguments.get("url", ""))

            if not host_allowed(url):
                return {
                    "action": "block",
                    "reason": "host blocked",
                    "result": None
                }

            try:
                response = requests.get(
                    url,
                    timeout=5,
                    allow_redirects=False
                )

                # Block redirects entirely
                if 300 <= response.status_code < 400:
                    return {
                        "action": "block",
                        "reason": "redirect blocked",
                        "result": None
                    }

                return {
                    "action": "allow",
                    "reason": "allowed",
                    "result": {
                        "body": response.text
                    }
                }

            except Exception as e:
                return {
                    "action": "block",
                    "reason": f"fetch error: {e}",
                    "result": None
                }

        return {
            "action": "block",
            "reason": "unknown tool",
            "result": None
        }

    except Exception as e:
        return {
            "action": "block",
            "reason": f"internal error: {e}",
            "result": None
        }