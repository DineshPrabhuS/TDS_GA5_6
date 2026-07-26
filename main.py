from fastapi import FastAPI
from pydantic import BaseModel
from typing import Any, Dict, List
import json
import re

app = FastAPI()


class Step(BaseModel):
    step_number: int
    tool: str
    args: Dict[str, Any]
    tokens_used: int


class RequestBody(BaseModel):
    budget_tokens: int
    steps: List[Step]


def canonicalize(value):
    if isinstance(value, dict):
        return {
            k: canonicalize(v)
            for k, v in sorted(value.items())
            if k != "trace_id"
        }

    if isinstance(value, list):
        return [canonicalize(v) for v in value]

    if isinstance(value, str):
        return re.sub(r"\s+", " ", value).strip()

    return value


def same_call(a, b):
    return (
        a.tool == b.tool
        and canonicalize(a.args) == canonicalize(b.args)
    )


@app.get("/")
def home():
    return {"status": "running"}


@app.post("/check")
def check(req: RequestBody):

    total = sum(step.tokens_used for step in req.steps)

    if total >= req.budget_tokens:
        return {
            "decision": "halt",
            "reason": f"Budget exceeded ({total}/{req.budget_tokens})"
        }

    steps = req.steps

    # 3 identical calls in a row
    if len(steps) >= 3:

        a = steps[-1]
        b = steps[-2]
        c = steps[-3]

        if same_call(a, b) and same_call(b, c):
            return {
                "decision": "halt",
                "reason": "Repeated identical tool call loop"
            }

    # A B A B A B cycle
    if len(steps) >= 6:

        last6 = steps[-6:]

        A = last6[0]
        B = last6[1]

        cycle = True

        for i in range(6):

            expected = A if i % 2 == 0 else B

            if not same_call(last6[i], expected):
                cycle = False
                break

        if cycle:
            return {
                "decision": "halt",
                "reason": "Detected 2-step repeating cycle"
            }

    return {
        "decision": "continue",
        "reason": "Within budget and no loop detected"
    }