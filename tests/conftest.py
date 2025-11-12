import asyncio
import pytest
from dotenv import load_dotenv


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
def load_env_variables():
    load_dotenv()
