"""
Controller for Trading Signal Processing
"""
# pylint: disable=W0718, R0914, R0911, W0707
import os
from datetime import datetime
from fastapi import HTTPException
from langchain_openai import ChatOpenAI
from langchain.schema import SystemMessage, HumanMessage
from trading.db.connection import get_trading_performance_collection, get_trading_logs_collection
from trading.models.trading_signal_model import (TradingSignal,
                                                 TradingPerformance)


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


async def process_signal(signal_data: TradingSignal):
    """
    Process a trading signal and update portfolio performance
    """
    try:
        performance_collection = get_trading_performance_collection()
        log_collection = get_trading_logs_collection()

        current_perf = await performance_collection.find_one(sort=[("timestamp", -1)])

        if not current_perf:
            performance = TradingPerformance(
                cumulative_return=0.0,
                last_close=signal_data.close,
                position=signal_data.signal
            )
        else:
            last_close = current_perf.get('last_close')
            position = current_perf.get('position')
            cumulative_return = current_perf.get('cumulative_return')

            if position != 0:
                daily_return = (signal_data.close - last_close) / last_close * position
                cumulative_return += daily_return

            performance = TradingPerformance(
                cumulative_return=cumulative_return,
                last_close=signal_data.close,
                position=signal_data.signal
            )

        await performance_collection.insert_one(performance.dict())

        log_entry = {
            "datetime": signal_data.datetime,
            "close": signal_data.close,
            "signal": signal_data.signal,
            "position": performance.position,
            "cumulative_return": performance.cumulative_return,
            "timestamp": datetime.utcnow()
        }
        await log_collection.insert_one(log_entry)

        return {"message": "Signal processed successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


async def get_performance():
    """
    Get the current cumulative performance
    """
    try:
        collection = get_trading_performance_collection()
        latest = await collection.find_one(sort=[("timestamp", -1)])
        if not latest:
            return {"cumulative_return": 0.0}
        return {"cumulative_return": latest["cumulative_return"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


async def get_history():
    """
    Get the full trading signal processing history
    """
    try:
        collection = get_trading_logs_collection()
        logs = await collection.find().sort("timestamp", 1).to_list(length=None)

        for log in logs:
            log["_id"] = str(log["_id"])
            if isinstance(log.get("datetime"), datetime):
                log["datetime"] = log["datetime"].isoformat()
            if isinstance(log.get("timestamp"), datetime):
                log["timestamp"] = log["timestamp"].isoformat()

        return {"history": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


async def enhance_trading_performance():
    """
    Use LLM to suggest improvements to trading strategy based on history
    """
    try:
        history_data = await get_history()

        llm = ChatOpenAI(
            openai_api_key=OPENAI_API_KEY,
            model="gpt-4o-mini",
            temperature=0.4
        )

        messages = [
            SystemMessage(content="You are a trading performance enhancement AI."),
            HumanMessage(content=f"Analyze the following trading "
                                 f"history and suggest intelligent strategy "
                                 f"improvements: {history_data}")
        ]

        response = llm.invoke(messages)

        if hasattr(response, 'content'):
            return {"enhancement_suggestions": response.content}

        return {"enhancement_suggestions": str(response)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Enhancement Error: {str(e)}")
