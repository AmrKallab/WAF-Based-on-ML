# import asyncio
# import pandas as pd
# from app.detection.ml.model import load_model
# from app.core.config import settings


# async def predict(request_data: dict) -> dict:
#     model = load_model()

#     df = pd.DataFrame([{
#         "Method":          request_data.get("method", ""),
#         "User-Agent":      request_data.get("user-agent", ""),
#         "Pragma":          request_data.get("pragma", ""),
#         "Cache-Control":   request_data.get("cache-control", ""),
#         "Accept":          request_data.get("accept", ""),
#         "Accept-encoding": request_data.get("accept-encoding", ""),
#         "Accept-charset":  request_data.get("accept-charset", ""),
#         "language":        request_data.get("accept-language", ""),
#         "host":            request_data.get("host", ""),
#         "cookie":          request_data.get("cookie", ""),
#         "content-type":    request_data.get("content_type", ""),
#         "connection":      request_data.get("connection", ""),
#         "content_length":  request_data.get("content_length", 0),
#         "content":         request_data.get("body", ""),
#         "URL":             request_data.get("url", ""),
#     }])

#     loop = asyncio.get_event_loop()

#     ml_score = await loop.run_in_executor(
#         None,
#         lambda: model.predict_proba(df)[0][1]
#     )

#     is_malicious = ml_score >= settings.ML_THRESHOLD

#     return {
#         "ml_score": round(float(ml_score), 4),
#         "is_malicious": is_malicious
#     }


# import asyncio
# import pandas as pd
# from urllib.parse import urlparse
# from app.detection.ml.model import load_model
# from app.core.config import settings


# def normalize_url(url: str) -> str:
#     try:
#         parsed = urlparse(url)
#         normalized = parsed._replace(netloc="localhost:8080").geturl()
#         return normalized
#     except:
#         return url


# async def predict(request_data: dict) -> dict:
#     model = load_model()

#     df = pd.DataFrame([{
#         "URL":     request_data.get("url", ""),
#         "Method":  request_data.get("method", "GET"),
#         "content": request_data.get("body", ""),
#     }])

#     loop = asyncio.get_event_loop()

#     ml_score = await loop.run_in_executor(
#         None,
#         lambda: model.predict_proba(df)[0][1]
#     )

#     is_malicious = ml_score >= settings.ML_THRESHOLD

#     return {
#         "ml_score": round(float(ml_score), 4),
#         "is_malicious": is_malicious
#     }

import asyncio
import pandas as pd
from urllib.parse import urlparse
from app.detection.ml.model import load_model
from app.core.config import settings


def strip_host(url: str) -> str:
    try:
        parsed = urlparse(url)
        # نرجع بس الـ path + query بدون host
        result = parsed.path
        if parsed.query:
            result += f"?{parsed.query}"
        return result
    except:
        return url


async def predict(request_data: dict) -> dict:
    model = load_model()

    url = strip_host(request_data.get("url", ""))

    df = pd.DataFrame([{
        "URL":     url,
        "Method":  request_data.get("method", "GET"),
        "content": request_data.get("body", ""),
    }])

    loop = asyncio.get_event_loop()

    ml_score = await loop.run_in_executor(
        None,
        lambda: model.predict_proba(df)[0][1]
    )

    is_malicious = ml_score >= settings.ML_THRESHOLD

    return {
        "ml_score": round(float(ml_score), 4),
        "is_malicious": is_malicious
    }