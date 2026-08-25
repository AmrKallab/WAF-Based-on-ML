import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse


def safe_str(value):
    if pd.isna(value):
        return ""
    return str(value)

def count_dot(text):
    return safe_str(text).count(".")

def count_dir(text):
    return urlparse(safe_str(text)).path.count("/")

def count_embed(text):
    return urlparse(safe_str(text)).path.count("//")

def count_http(text):
    return safe_str(text).lower().count("http")

def count_percent(text):
    return safe_str(text).count("%")

def count_question(text):
    return safe_str(text).count("?")

def count_hyphen(text):
    return safe_str(text).count("-")

def count_equal(text):
    return safe_str(text).count("=")

def text_length(text):
    return len(safe_str(text))

def hostname_length(text):
    return len(urlparse(safe_str(text)).netloc)

def digit_count(text):
    return sum(ch.isdigit() for ch in safe_str(text))

def letter_count(text):
    return sum(ch.isalpha() for ch in safe_str(text))

def special_char_count(text):
    text = safe_str(text)
    return len(re.sub(r"[a-zA-Z0-9\s]", "", text))

def number_of_parameters(text):
    query = urlparse(safe_str(text)).query
    if query == "":
        return 0
    return len(query.split("&"))

def is_encoded(text):
    return int("%" in safe_str(text))

def unusual_character_ratio(text):
    text = safe_str(text)
    if len(text) == 0:
        return 0
    unusual = re.sub(r"[a-zA-Z0-9\s\-._]", "", text)
    return len(unusual) / len(text)

def shortening_service(text):
    text = safe_str(text).lower()
    shorteners = [
        "bit.ly", "goo.gl", "tinyurl", "t.co", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "bit.do", "cutt.us", "rebrand.ly",
        "tiny.cc", "shorturl.at", "lnkd.in"
    ]
    return int(any(service in text for service in shorteners))

from urllib.parse import urlparse, unquote

def parse_url_parts(url):
    url = safe_str(url)
    url = unquote(url)  # يفك الترميز مرة واحدة
    parsed = urlparse(url)

    path = parsed.path
    query = parsed.query

    return path, query



from collections import Counter
import math

def shannon_entropy(text):
    text = safe_str(text)
    if not text:
        return 0

    freq = Counter(text)
    probs = [v / len(text) for v in freq.values()]

    return -sum(p * math.log2(p) for p in probs)

# =========================
# 5. Feature Extraction — بدون TF-IDF
# يعتمد على السلوك فقط لا على القيم الحرفية
# =========================
def get_url_text(data):
    data = pd.DataFrame(data)
    return data["URL"].fillna("").astype(str)


def get_content_text(data):
    data = pd.DataFrame(data)
    return data["content"].fillna("").astype(str)

def extract_manual_features(data):
    data = pd.DataFrame(data).copy()
    features = pd.DataFrame(index=data.index)

    # --- URL Features ---
    if "URL" in data.columns:
        url_col = data["URL"].apply(safe_str)
    else:
        url_col = pd.Series([""] * len(data), index=data.index)

    # الـ features الأصلية
    # features["url_entropy"] = url_col.apply(shannon_entropy)
    # features["content_entropy"] = content_col.apply(shannon_entropy)
    
    features["url_length"]          = url_col.apply(text_length)
    features["url_count_dot"]       = url_col.apply(count_dot)
    features["url_count_dir"]       = url_col.apply(count_dir)
    features["url_count_embed"]     = url_col.apply(count_embed)
    features["url_count_http"]      = url_col.apply(count_http)
    features["url_count_percent"]   = url_col.apply(count_percent)
    features["url_count_question"]  = url_col.apply(count_question)
    features["url_count_hyphen"]    = url_col.apply(count_hyphen)
    features["url_count_equal"]     = url_col.apply(count_equal)
    features["url_digit_count"]     = url_col.apply(digit_count)
    features["url_letter_count"]    = url_col.apply(letter_count)
    features["url_special_count"]   = url_col.apply(special_char_count)
    features["url_is_encoded"]      = url_col.apply(is_encoded)
    features["url_unusual_ratio"]   = url_col.apply(unusual_character_ratio)
    # features["url_suspicious_score"]= url_col.apply(suspicious_score)
    features["url_hostname_length"] = url_col.apply(hostname_length)
    features["url_num_parameters"]  = url_col.apply(number_of_parameters)
    features["url_shortener"]       = url_col.apply(shortening_service)

    # الـ features الجديدة
    features["url_path_depth"]   = url_col.apply(
        lambda x: urlparse(safe_str(x)).path.count("/")
    )
    features["url_path_length"]  = url_col.apply(
        lambda x: len(urlparse(safe_str(x)).path)
    )
    features["url_query_length"] = url_col.apply(
        lambda x: len(urlparse(safe_str(x)).query)
    )
    features["url_has_extension"] = url_col.apply(
        lambda x: int("." in urlparse(safe_str(x)).path.split("/")[-1])
    )

    if "content" in data.columns:
        content_col = data["content"].apply(safe_str)
    else:
        content_col = pd.Series([""] * len(data), index=data.index)

    # الـ features الأصلية
    features["content_length"]          = content_col.apply(text_length)
    features["content_count_dot"]       = content_col.apply(count_dot)
    features["content_count_dir"]       = content_col.apply(count_dir)
    features["content_count_embed"]     = content_col.apply(count_embed)
    features["content_count_http"]      = content_col.apply(count_http)
    features["content_count_percent"]   = content_col.apply(count_percent)
    features["content_count_question"]  = content_col.apply(count_question)
    features["content_count_hyphen"]    = content_col.apply(count_hyphen)
    features["content_count_equal"]     = content_col.apply(count_equal)
    features["content_digit_count"]     = content_col.apply(digit_count)
    features["content_letter_count"]    = content_col.apply(letter_count)
    features["content_special_count"]   = content_col.apply(special_char_count)
    features["content_is_encoded"]      = content_col.apply(is_encoded)
    features["content_unusual_ratio"]   = content_col.apply(unusual_character_ratio)

    if "content_length_header" in data.columns:
        cl = data["content_length_header"].astype(str).str.extract(r"(\d+)")[0]
        features["content_length_header"] = pd.to_numeric(cl, errors="coerce").fillna(0)
    else:
        features["content_length_header"] = 0

    features = features.replace([np.inf, -np.inf], np.nan).fillna(0)
    return features.astype(np.float64)