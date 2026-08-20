"""Compatibility entry point: ``uvicorn main:app``."""

from app.application import app as app

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
