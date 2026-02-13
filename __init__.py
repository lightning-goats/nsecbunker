from fastapi import APIRouter

from .crud import db
from .views import nsecbunker_generic_router
from .views_api import nsecbunker_api_router

nsecbunker_static_files = [
    {
        "path": "/nsecbunker/static",
        "name": "nsecbunker_static",
    }
]
nsecbunker_ext: APIRouter = APIRouter(prefix="/nsecbunker", tags=["nsecbunker"])
nsecbunker_ext.include_router(nsecbunker_generic_router)
nsecbunker_ext.include_router(nsecbunker_api_router)


def nsecbunker_stop():
    pass


def nsecbunker_start():
    pass


__all__ = [
    "db",
    "nsecbunker_ext",
    "nsecbunker_static_files",
    "nsecbunker_start",
    "nsecbunker_stop",
]
