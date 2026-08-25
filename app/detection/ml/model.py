import sys
import os
from functools import lru_cache
import joblib

# نضيف مسار ml_models لـ sys.path
sys.path.insert(0, os.path.abspath("ml_models"))

from app.core.config import settings


@lru_cache(maxsize=1)
def load_model():
    import Features  # نستورده صراحة — الاسم بحرف كبير
    model = joblib.load(settings.ML_MODEL_PATH)
    return model


