import logging
import os

import pymongo
from pymongo.collection import Collection

logger = logging.getLogger(__name__)

"""
This module provides functionality to interact with a MongoDB database.
Classes:
    MongoDB: A class to handle MongoDB connections and operations.
"""

_client = None
_db = None


def _get_shared_client():
    """Return (and lazily create) a single MongoClient for the process."""
    global _client, _db

    if _client is not None:
        return _client, _db

    mongo_uri = os.environ.get("MONGO_URI")
    mongo_db_name = os.environ.get("MONGO_DB")

    if not mongo_uri or not mongo_db_name:
        raise RuntimeError(
            "MONGO_URI and MONGO_DB environment variables must be set."
        )

    _client = pymongo.MongoClient(
        mongo_uri,
        serverSelectionTimeoutMS=60000,
        connectTimeoutMS=30000,
        socketTimeoutMS=300000,
        maxPoolSize=50,
        retryWrites=True,
        retryReads=True,
    )
    _client.admin.command('ping')
    _db = _client[mongo_db_name]
    return _client, _db


class MongoDB:
    def __init__(self) -> None:
        try:
            self.client, self.db = _get_shared_client()
            self.collection = None
        except Exception as e:
            logger.critical("Could not connect to MongoDB: %s", e)
            raise

    def set_collection(self, collection) -> Collection:
        self.collection = self.db[collection]
        return self.collection
