import time
from collections import defaultdict
from app.detection.rules.base import BaseRule
from app.core.config import settings


# in-memory storage للـ requests
_request_counts: dict = defaultdict(list)


class RateLimitRule(BaseRule):

    name = "rate_limit"
    attack_type = "Rate Limit / DDoS"

    def detect(self, request_data: dict) -> dict:
        ip = request_data.get("ip_address", "")
        now = time.time()
        window = settings.RATE_LIMIT_WINDOW
        max_requests = settings.RATE_LIMIT_REQUESTS

        # نحذف الـ timestamps القديمة خارج الـ window
        _request_counts[ip] = [
            t for t in _request_counts[ip]
            if now - t < window
        ]

        # نضيف الـ timestamp الحالي
        _request_counts[ip].append(now)

        count = len(_request_counts[ip])

        if count > max_requests:
            return self._result(
                detected=True,
                details=f"Rate limit exceeded: {count} requests in {window}s"
            )

        return self._result(detected=False)