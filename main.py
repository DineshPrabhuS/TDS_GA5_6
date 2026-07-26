from fastapi import FastAPI

app = FastAPI()

@app.get("/.well-known/agent-card.json")
def card():
    return {
        "name": "Invoice Agent",
        "version": "1.0",
        "skills": [
            {
                "name": "invoice_action_agent",
                "description": "Invoice processing",
                "tags": ["invoice"]
            }
        ]
    }