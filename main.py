"""PrivaGate FastAPI entrypoint wrapper for Render and root execution environments."""
from app.main import app

__all__ = ["app"]

if __name__ == "__main__":
    import os
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
