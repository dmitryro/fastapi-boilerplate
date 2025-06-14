from fastapi import APIRouter, Query, HTTPException
from app.api.routes import predictor

router = APIRouter()


@router.get("/health", tags=["Health Check"])
async def health_check():
    return {"status": "ok"}

@router.get("/ask", tags=["Ask Question"])
async def ask_get(
    question: str = Query(..., min_length=3, description="The question text")
):
    try:
        pass
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"status": "asked", "question": question }

router.include_router(predictor.router, prefix="/predict", tags=["Prediction"])
