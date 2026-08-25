import numpy as np
import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.svm import LinearSVC


from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

import sys
import os
sys.path.insert(0, os.path.abspath("ml_models"))
from Features import (
    safe_str, extract_manual_features, get_url_text, get_content_text,
    count_dot, count_dir, count_embed, count_http, count_percent,
    count_question, count_hyphen, count_equal, text_length,
    hostname_length, digit_count, letter_count, special_char_count,
    number_of_parameters, is_encoded, unusual_character_ratio,
    # shortening_service, suspicious_score
)


# =========================
# 1. Load dataset
# =========================


df = pd.read_csv("csic_database.csv")
print("Dataset loaded")
print("Shape:", df.shape)

df = df.rename(columns={"lenght": "content_length_header"})

if "Unnamed: 0" in df.columns:
    df = df.drop(columns=["Unnamed: 0"])


cols_to_drop = [
    "User-Agent",       # 1 unique  → لا معلومة
    "Pragma",           # 1 unique  → لا معلومة
    "Cache-Control",    # 1 unique  → لا معلومة
    "Accept",           # 1 unique  → لا معلومة
    "Accept-encoding",  # 1 unique  → لا معلومة
    "Accept-charset",   # 1 unique  → لا معلومة
    "language",         # 1 unique  → لا معلومة
    "host",             # 2 unique  → localhost فقط
    "cookie",           # 61065 unique → session IDs = noise خطير
    "content-type",     # 1 unique  → لا معلومة
    "connection",       # 2 unique  → لا معلومة
]

df = df.drop(columns=[c for c in cols_to_drop if c in df.columns])

print("\nالأعمدة المتبقية بعد الحذف:")
print(df.columns.tolist())
# =========================
# 2. Target
# =========================

target_col = "classification"
y = df[target_col]

if y.dtype == "object":
    y = y.astype("category").cat.codes

X = df.drop(columns=[target_col])

print("\nTarget distribution:")
print(pd.Series(y).value_counts())

# =========================
# 3. Helper functions
# =========================

# def safe_str(value):
#     if pd.isna(value):
#         return ""
#     return str(value)


# def count_dot(text):
#     return safe_str(text).count(".")


# def count_dir(text):
#     return urlparse(safe_str(text)).path.count("/")


# def count_embed(text):
#     return urlparse(safe_str(text)).path.count("//")


# def count_http(text):
#     return safe_str(text).lower().count("http")


# def count_percent(text):
#     return safe_str(text).count("%")


# def count_question(text):
#     return safe_str(text).count("?")


# def count_hyphen(text):
#     return safe_str(text).count("-")


# def count_equal(text):
#     return safe_str(text).count("=")


# def text_length(text):
#     return len(safe_str(text))


# def hostname_length(text):
#     return len(urlparse(safe_str(text)).netloc)


# def digit_count(text):
#     return sum(ch.isdigit() for ch in safe_str(text))


# def letter_count(text):
#     return sum(ch.isalpha() for ch in safe_str(text))


# def special_char_count(text):
#     text = safe_str(text)
#     return len(re.sub(r"[a-zA-Z0-9\s]", "", text))


# def number_of_parameters(text):
#     query = urlparse(safe_str(text)).query
#     if query == "":
#         return 0
#     return len(query.split("&"))


# def is_encoded(text):
#     return int("%" in safe_str(text))


# def unusual_character_ratio(text):
#     text = safe_str(text)
#     if len(text) == 0:
#         return 0

#     unusual = re.sub(r"[a-zA-Z0-9\s\-._]", "", text)
#     return len(unusual) / len(text)


# def shortening_service(text):
#     text = safe_str(text).lower()

#     shorteners = [
#         "bit.ly", "goo.gl", "tinyurl", "t.co", "ow.ly", "is.gd",
#         "buff.ly", "adf.ly", "bit.do", "cutt.us", "rebrand.ly",
#         "tiny.cc", "shorturl.at", "lnkd.in"
#     ]

#     return int(any(service in text for service in shorteners))


# def suspicious_score(text):
#     text = safe_str(text).lower()

#     score_map = {
#         "select": 50,
#         "union": 45,
#         "from": 35,
#         "where": 35,
#         "drop": 50,
#         "delete": 50,
#         "insert": 40,
#         "update": 40,
#         "table": 35,
#         "database": 35,
#         "or 1=1": 60,
#         "' or": 50,
#         "--": 40,
#         "#": 20,
#         "sleep": 45,
#         "benchmark": 45,

#         "script": 40,
#         "<script": 60,
#         "javascript": 45,
#         "alert": 35,
#         "onerror": 45,
#         "onload": 40,
#         "iframe": 35,
#         "document.cookie": 60,
#         "document.": 25,
#         "window.": 25,
#         "eval": 40,
#         "src=": 30,

#         "../": 50,
#         "..%2f": 50,
#         "/etc/passwd": 60,
#         "cmd": 45,
#         "shell": 45,
#         "exec": 45,
#         "root": 30,
#         "admin": 20,

#         "password": 25,
#         "passwd": 25,
#         "pwd": 20,
#         "login": 20,
#         "credential": 30,
#         "cookie": 25,

#         "malware": 45,
#         "ransomware": 45,
#         "trojan": 45,
#         "backdoor": 45,
#         "exploit": 45,
#     }

#     total = 0

#     for word, score in score_map.items():
#         total += text.count(word) * score

#     return total


# # =========================
# # 4. Feature extraction functions for Pipeline
# # =========================

# def extract_manual_features(data):
#     data = pd.DataFrame(data).copy()

#     features = pd.DataFrame(index=data.index)

#     # URL
#     if "URL" in data.columns:
#         url_col = data["URL"].apply(safe_str)
#     else:
#         url_col = pd.Series([""] * len(data), index=data.index)

#     features["url_length"] = url_col.apply(text_length)
#     features["url_count_dot"] = url_col.apply(count_dot)
#     features["url_count_dir"] = url_col.apply(count_dir)
#     features["url_count_embed"] = url_col.apply(count_embed)
#     features["url_count_http"] = url_col.apply(count_http)
#     features["url_count_percent"] = url_col.apply(count_percent)
#     features["url_count_question"] = url_col.apply(count_question)
#     features["url_count_hyphen"] = url_col.apply(count_hyphen)
#     features["url_count_equal"] = url_col.apply(count_equal)
#     features["url_digit_count"] = url_col.apply(digit_count)
#     features["url_letter_count"] = url_col.apply(letter_count)
#     features["url_special_count"] = url_col.apply(special_char_count)
#     features["url_is_encoded"] = url_col.apply(is_encoded)
#     features["url_unusual_ratio"] = url_col.apply(unusual_character_ratio)
#     features["url_suspicious_score"] = url_col.apply(suspicious_score)
#     features["url_hostname_length"] = url_col.apply(hostname_length)
#     features["url_num_parameters"] = url_col.apply(number_of_parameters)
#     features["url_shortener"] = url_col.apply(shortening_service)

#     # Content
#     if "content" in data.columns:
#         content_col = data["content"].apply(safe_str)
#     else:
#         content_col = pd.Series([""] * len(data), index=data.index)

#     features["content_length"] = content_col.apply(text_length)
#     features["content_count_dot"] = content_col.apply(count_dot)
#     features["content_count_dir"] = content_col.apply(count_dir)
#     features["content_count_embed"] = content_col.apply(count_embed)
#     features["content_count_http"] = content_col.apply(count_http)
#     features["content_count_percent"] = content_col.apply(count_percent)
#     features["content_count_question"] = content_col.apply(count_question)
#     features["content_count_hyphen"] = content_col.apply(count_hyphen)
#     features["content_count_equal"] = content_col.apply(count_equal)
#     features["content_digit_count"] = content_col.apply(digit_count)
#     features["content_letter_count"] = content_col.apply(letter_count)
#     features["content_special_count"] = content_col.apply(special_char_count)
#     features["content_is_encoded"] = content_col.apply(is_encoded)
#     features["content_unusual_ratio"] = content_col.apply(unusual_character_ratio)
#     features["content_suspicious_score"] = content_col.apply(suspicious_score)

#     # content_length header
#     if "content_length" in data.columns:
#         content_length_header = data["content_length"].astype(str).str.extract(r"(\d+)")[0]
#         features["content_length_header"] = pd.to_numeric(
#             content_length_header,
#             errors="coerce"
#         ).fillna(0)
#     else:
#         features["content_length_header"] = 0

#     features = features.replace([np.inf, -np.inf], np.nan).fillna(0)
#     return features.astype(np.float64)


# def get_url_text(data):
#     data = pd.DataFrame(data)
#     return data["URL"].fillna("").astype(str)


# def get_content_text(data):
#     data = pd.DataFrame(data)
#     return data["content"].fillna("").astype(str)


# =========================
# 5. Columns
# =========================

categorical_cols = []

for col in ["Method", "host", "Accept", "content-type"]:
    if col in X.columns:
        categorical_cols.append(col)


# =========================
# 6. Preprocessor Pipeline
# =========================
categorical_cols = ["Method"] if "Method" in X.columns else []

preprocessor = ColumnTransformer(
    transformers=[
        (
            "manual_features",
            FunctionTransformer(extract_manual_features, validate=False),
            ["URL", "Method", "content"]
        ),
        (
            "categorical",
            OneHotEncoder(handle_unknown="ignore", sparse_output=True),
            categorical_cols
        )
    ],
    remainder="drop"
)


# =========================
# 7. Full Model Pipeline
# =========================

# model = {
#     # "Random Forest": RandomForestClassifier(
#     #     n_estimators=300,
#     #     max_depth=20,           # حد لمنع الـ overfitting
#     #     min_samples_leaf=5,     # يمنع حفظ البيانات
#     #     max_features="sqrt",
#     #     random_state=42,
#     #     n_jobs=-1,
#     #     class_weight="balanced"
#     # ),
    
#     "Logistic Regression": LogisticRegression(
#         max_iter=3000,      # ✅ زد من 3000 إلى 5000
#         solver="saga",
#         C=0.1,              # ✅ أضف regularization
#         class_weight="balanced",
#         random_state=42
#     ),

#     # "Linear SVM": LinearSVC(
#     #     class_weight="balanced",
#     #     random_state=42
#     # ),
#     # "SGD Classifier": SGDClassifier(
#     #     loss="log_loss",
#     #     class_weight="balanced",
#     #     max_iter=2000,
#     #     tol=1e-3,
#     #     random_state=42,
#     #     n_jobs=-1
#     # )
# }


# =========================
# 8. Train-test split
# =========================

x_train, x_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.30,
    random_state=42,
    stratify=y
)

print("Train shape:", x_train.shape)
print("Test shape:", x_test.shape)


# =========================
# 9. Train
# =========================
model = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", LogisticRegression(
        max_iter=3000,      # ✅ زد من 3000 إلى 5000
        solver="saga",
        C=0.1,              # ✅ أضف regularization
        class_weight="balanced",
        random_state=42
    ))
    ])
model.fit(x_train, y_train)


# =========================
# 10. Evaluation
# =========================

y_pred = model.predict(x_test)

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("Precision:", precision_score(y_test, y_pred, average="weighted"))
print("Recall:", recall_score(y_test, y_pred, average="weighted"))
print("F1:", f1_score(y_test, y_pred, average="weighted"))

classifier = model.named_steps["classifier"]

if hasattr(classifier, "predict_proba"):
    y_prob = model.predict_proba(x_test)

    if y_prob.shape[1] == 2:
        auc = roc_auc_score(y_test, y_prob[:, 1])
    else:
        auc = roc_auc_score(y_test, y_prob, multi_class="ovr")

    print("ROC AUC:", auc)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(y_test, y_pred))


import joblib
joblib.dump(model, "./sqli_model.pkl")
print("Model saved to ml_models/sqli_model.pkl")