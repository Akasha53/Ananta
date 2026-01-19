from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pathlib import Path
import asyncio
import logging
import traceback

# Imports de nos modules divisés
from database import init_db
import backend_logic as logic
from web_routes import router as api_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- LIFESPAN ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialisation DB
    init_db()

    # Lancement tâche de fond (purge)
    asyncio.create_task(logic.purge_old_osint_results_task())

    yield

# ✅ UNE SEULE APP
app = FastAPI(lifespan=lifespan, debug=True)

# --- GLOBAL EXCEPTION HANDLER (DEV) ---
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    logger.error("❌ UNHANDLED EXCEPTION on %s %s\n%s", request.method, request.url.path, tb)
    return JSONResponse(
        status_code=500,
        content={
            "detail": str(exc),
            "path": str(request.url.path),
            "traceback": tb,  # DEV ONLY
        },
    )

# --- CONFIG APP ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Montage du routeur API
app.include_router(api_router)

# --- SERVING UI STATIQUE ---
BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"

if WEB_DIR.exists():
    app.mount("/web", StaticFiles(directory=str(WEB_DIR)), name="web")

@app.get("/ui", include_in_schema=False)
def serve_ui():
    index_path = WEB_DIR / "html" / "index.html"
    return FileResponse(str(index_path))

@app.get("/")
def read_root():
    return {"message": "API OSINT & Cyber Ready", "ui": "/ui"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8010, reload=True, log_level="debug")
