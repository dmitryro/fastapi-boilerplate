from typing import Callable

import joblib
from fastapi import FastAPI


def preload_model():
    """
    In order to load model on memory to each worker
    """
    pass

def create_start_app_handler(app: FastAPI) -> Callable:
    def start_app() -> None:
        preload_model()

    return start_app
