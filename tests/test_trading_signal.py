"""
Unit tests for Trading Signal Processing using real HTTP connection
"""

import sys
import asyncio

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import pytest
import httpx
from datetime import datetime

BASE_URL = "http://localhost:8001"


@pytest.mark.asyncio
async def test_post_signal():
    """
    Test posting a trading signal
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as ac:
        response = await ac.post("/signal", json={
            "datetime": datetime.now().isoformat(),
            "close": 100000.0,
            "signal": 1
        })
    assert response.status_code == 200
    assert "message" in response.json()


@pytest.mark.asyncio
async def test_get_performance():
    """
    Test retrieving the current portfolio performance
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as ac:
        response = await ac.get("/performance")
    assert response.status_code == 200
    assert "cumulative_return" in response.json()
