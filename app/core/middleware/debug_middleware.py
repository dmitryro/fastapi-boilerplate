from loguru import logger

async def debug_middleware(request, call_next):
    logger.debug(f"Request URL: {request.url}, Query params: {request.query_params}")
    response = await call_next(request)
    logger.debug(f"Response status: {response.status_code}")
    return response
