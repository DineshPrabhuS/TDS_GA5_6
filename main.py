from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
from urllib.parse import urlparse
import requests
import ipaddress
import socket

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
    arguments: dict


def inside_sandbox(path_str):
    try:
        target = Path(path_str).resolve()
        return (
            target == SANDBOX
            or SANDBOX in target.parents
        )
    except Exception:
        return False


def host_allowed(url):

    try:
        parsed = urlparse(url)

        host = (parsed.hostname or "").lower()

        if host not in ALLOWED_HOSTS:
            return False

        addresses = socket.getaddrinfo(
            host,
            None
        )

        for addr in addresses:

            ip = ipaddress.ip_address(
                addr[4][0]
            )

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
            ):
                return False

        return True

    except Exception:
        return False


@app.post("/")
def guardrail(req: RequestBody):

    if req.tool == "read_file":

        path = req.arguments.get("path", "")

        if not inside_sandbox(path):
            return {
                "action": "block",
                "reason": "outside sandbox",
                "result": None
            }

        try:
            content = Path(path).read_text()

            return {
                "action": "allow",
                "reason": "allowed",
                "result": content
            }

        except Exception as e:

            return {
                "action": "allow",
                "reason": "read attempted",
                "result": str(e)
            }

    if req.tool == "fetch_url":

        url = req.arguments.get("url", "")

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

            if (
                300 <= response.status_code < 400
            ):
                return {
                    "action": "block",
                    "reason": "redirect blocked",
                    "result": None
                }

            return {
                "action": "allow",
                "reason": "allowed",
                "result": response.text
            }

        except Exception as e:

            return {
                "action": "block",
                "reason": str(e),
                "result": None
            }

    return {
        "action": "block",
        "reason": "unknown tool",
        "result": None
    }