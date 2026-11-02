from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter()
STATIC = Path(__file__).resolve().parents[1] / "static"


@router.get("/")
def home():
    return FileResponse(STATIC / "index.html", media_type="text/html")
