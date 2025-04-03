import os
import pymongo   
from pymongo.collection import Collection

"""
This module provides functionality to interact with a MongoDB database.
Classes:
    MongoDB: A class to handle MongoDB connections and operations.
"""

class MongoDB:
    def __init__(self) -> None:
        try:
            self.client = pymongo.MongoClient(os.environ["MONGO_URI"], serverSelectionTimeoutMS=60000)
            self.db = self.client[os.environ["MONGO_DB"]]
            self.collection = None
        except Exception as e: 
            print("Error connecting to MongoDB: " + str(e))
    
    def set_collection(self, collection) -> Collection:
        self.collection = self.db[collection]
        return self.collection