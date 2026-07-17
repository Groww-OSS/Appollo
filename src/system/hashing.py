import hashlib
import json
import threading
from datetime import datetime
from rich import print
import pandas as pd
from system.db import MongoDB

_hash_lock = threading.Lock()
_hash_collection = None


def _get_hash_collection():
    """Return (and lazily create) a shared MongoDB collection for hash dedup."""
    global _hash_collection
    if _hash_collection is None:
        mongo = MongoDB()
        _hash_collection = mongo.set_collection("Prod Hash Dedup")
        _hash_collection.create_index("hash", unique=True)
    return _hash_collection


def calculate_hash(data) -> str:
    """Compute a deterministic SHA-256 hex digest for dict, list, str, or DataFrame."""
    if isinstance(data, pd.DataFrame):
        json_data = data.to_json(orient='records', default_handler=str)
    elif isinstance(data, (dict, list)):
        json_data = json.dumps(data, default=str, sort_keys=True)
    elif isinstance(data, str):
        json_data = data
    else:
        raise ValueError(f"Unsupported data type for hashing: {type(data)}")

    return hashlib.sha256(json_data.encode()).hexdigest()


def check_if_hash_exists(hash_value: str) -> bool:
    """Thread-safe check whether a dedup hash already exists in MongoDB."""
    with _hash_lock:
        col = _get_hash_collection()
        return col.find_one({"hash": hash_value}) is not None


def add_hash_to_db(hash_value: str) -> None:
    """Thread-safe, idempotent insert of a dedup hash into MongoDB.

    Uses a unique index on ``hash`` so concurrent inserts of the same
    value are silently deduplicated instead of creating duplicates.
    """
    with _hash_lock:
        col = _get_hash_collection()
        try:
            col.update_one(
                {"hash": hash_value},
                {"$setOnInsert": {"hash": hash_value, "created_at": datetime.utcnow()}},
                upsert=True,
            )
        except Exception as e:
            print(f"[bold yellow]Warning: hash insert failed: {e}[/bold yellow]")


def clear_hash_database() -> bool:
    """Clear all hashes from the database."""
    try:
        col = _get_hash_collection()
        col.delete_many({})
        return True
    except Exception as e:
        print(f"[bold red]Error clearing hash database: {e}[/bold red]")
        return False


def get_hash_database_info() -> str:
    """Get information about the hash database."""
    try:
        col = _get_hash_collection()
        hash_count = col.count_documents({})
        return f"Total hashes: {hash_count}"
    except Exception as e:
        return f"Error getting database info: {e}"
