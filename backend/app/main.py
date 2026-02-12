from fastapi import FastAPI
from app.api.ingest import router as ingest_router
from app.api.events import router as events_router
from fastapi.middleware.cors import CORSMiddleware



app = FastAPI(title="LogSense Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(ingest_router, prefix="/api")
app.include_router(events_router, prefix="/api")


@app.get("/")
def root():
    return {"status": "LogSense backend running"}
