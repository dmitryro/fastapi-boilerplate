from fastapi import APIRouter, Query, HTTPException

router = APIRouter()

@router.get("/health", tags=["Health Check"])
async def health_check():
    return {"status": "ok"}

@router.get("/ask", tags=["Ask Question"])
async def ask_get(
    question: str = Query(..., min_length=3, description="The question text"),
    raise_error: bool = Query(False, description="Trigger an error for testing")
):
    try:
        if raise_error:
            raise ValueError("Test error")
        pass
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"status": "asked", "question": question}
