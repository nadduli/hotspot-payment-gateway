from fastapi import FastAPI

app = FastAPI(title="Hotspot Payment Gateway")


@app.get("/api/v1/health")
async def health() -> dict[str, bool]:
    return {"ok": True}
