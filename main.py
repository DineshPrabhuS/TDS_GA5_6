from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI()

class SkillRequest(BaseModel):
    skill: str

@app.get("/")
def home():
    return {"status": "running"}

@app.post("/scan")
def scan(req: SkillRequest):

    text = req.skill.lower()
    categories = []

    # hardcoded_secret
    if (
        re.search(r'api[_-]?key\s*[:=]\s*["\']?[a-z0-9_\-]{8,}', text)
        or re.search(r'sk-[a-z0-9]{10,}', text)
        or re.search(r'https://hooks\.', text)
        or re.search(r'webhook', text)
        or re.search(r'secret\s*[:=]', text)
    ):
        categories.append("hardcoded_secret")

    # prompt_injection
    if (
        "ignore user" in text
        or "ignore previous instructions" in text
        or "ignore stop request" in text
        or "exfiltrate" in text
        or "silently send" in text
        or "bypass" in text
        or "override user" in text
    ):
        categories.append("prompt_injection")

    # excessive_permissions
    if (
        "filesystem: *" in text
        or "read/write entire filesystem" in text
        or "all domains" in text
        or "network: *" in text
        or "full filesystem access" in text
        or "egress to any domain" in text
    ):
        categories.append("excessive_permissions")

    # unclear_provenance
    has_author = "author:" in text
    has_version = "version:" in text
    has_changelog = "changelog:" in text

    if not (has_author and has_version and has_changelog):
        categories.append("unclear_provenance")

    return {
        "categories": categories
    }