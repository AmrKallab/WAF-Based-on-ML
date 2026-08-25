from abc import ABC, abstractmethod
from urllib.parse import unquote, unquote_plus


class BaseRule(ABC):
    
    name: str = "base"
    attack_type: str = "unknown"

    @abstractmethod
    def detect(self, request_data: dict) -> dict:
        pass

    def _result(self, detected: bool, details: str = "") -> dict:
        return {
            "detected": detected,
            "attack_type": self.attack_type if detected else None,
            "details": details
        }

    def _normalize(self, text: str) -> str:
        try:
            # unquote_plus بيحول + لـ space كمان
            decoded = unquote_plus(unquote_plus(text))
            return decoded
        except:
            return text