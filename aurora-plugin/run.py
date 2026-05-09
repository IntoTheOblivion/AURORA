"""Entry point v5 — carica .env e avvia uvicorn."""
from dotenv import load_dotenv
load_dotenv()

import uvicorn, os

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("app.main:app",
                host="0.0.0.0", port=port,
                reload=True, log_level="warning")
