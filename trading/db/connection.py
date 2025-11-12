# pylint: disable=R0903
"""
This module initializes the database
"""


import os
from mongomock import MongoClient
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.collection import Collection
from dotenv import load_dotenv


load_dotenv()

MONGO_URL = os.getenv("MONGO_URL")

client = AsyncIOMotorClient(MONGO_URL)
database_trading = client["trading"]


def get_trading_logs_collection() -> Collection:
    """
    Get the trading logs collection
    """
    return database_trading["trading_logs"]


def get_trading_performance_collection() -> Collection:
    """
    Get the trading performance collection
    """
    return database_trading["trading_performance"]


class MongoDBClient:
    """
    Singleton class to manage MongoDB client connection.
    Ensures that only one instance of MongoDBClient is created.
    """
    _instance = None

    def __new__(cls):
        """
        Create a new instance of MongoDBClient if one does not exist.
        Reuse the existing instance if it already exists.
        """
        if cls._instance is None:
            cls._instance = super(MongoDBClient, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        """
        Initialize MongoDB client connection.
        """
        if not hasattr(self, 'client'):
            try:
                self.client = MongoClient(os.getenv("MONGO_URL"))
            except Exception as e:
                print(f"Error connecting to MongoDB: {str(e)}")
                raise
