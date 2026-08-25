# import sys
# sys.path.insert(0, "ml_models")
# import pandas as pd
# import joblib

# model = joblib.load("ml_models/sqli_model.pkl")

# # نجرب URL مشابهة للـ dataset
# samples = [
#     {
#         "name": "Normal - مشابه للـ dataset",
#         "data": {
#             "Method": "GET",
#             "User-Agent": "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
#             "Pragma": "no-cache",
#             "Cache-Control": "no-cache",
#             "Accept": "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
#             "Accept-encoding": "x-gzip, x-deflate, gzip, deflate",
#             "Accept-charset": "utf-8, utf-8;q=0.5, *;q=0.5",
#             "language": "en",
#             "host": "localhost:8080",
#             "cookie": "",
#             "content-type": "",
#             "connection": "close",
#             "content_length": 0,
#             "content": "",
#             "URL": "http://localhost:8080/products?id=5",
#         }
#     },
#     {
#         "name": "Normal - بعد normalize",
#         "data": {
#             "Method": "GET",
#             "User-Agent": "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
#             "Pragma": "no-cache",
#             "Cache-Control": "no-cache",
#             "Accept": "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
#             "Accept-encoding": "x-gzip, x-deflate, gzip, deflate",
#             "Accept-charset": "utf-8, utf-8;q=0.5, *;q=0.5",
#             "language": "en",
#             "host": "localhost:8080",
#             "cookie": "",
#             "content-type": "",
#             "connection": "close",
#             "content_length": 0,
#             "content": "",
#             "URL": "http://localhost:8080/tienda1/index.jsp",
#         }
#     },
#     {
#         "name": "Malicious - SQLi",
#         "data": {
#             "Method": "GET",
#             "User-Agent": "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
#             "Pragma": "no-cache",
#             "Cache-Control": "no-cache",
#             "Accept": "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
#             "Accept-encoding": "x-gzip, x-deflate, gzip, deflate",
#             "Accept-charset": "utf-8, utf-8;q=0.5, *;q=0.5",
#             "language": "en",
#             "host": "localhost:8080",
#             "cookie": "",
#             "content-type": "",
#             "connection": "close",
#             "content_length": 0,
#             "content": "",
#             "URL": "http://localhost:8080/products?id=1 OR 1=1",
#         }
#     },
# ]

# for sample in samples:
#     df = pd.DataFrame([sample["data"]])
#     proba = model.predict_proba(df)
#     score = proba[0][1]
#     label = "MALICIOUS ❌" if score >= 0.5 else "SAFE ✅"
#     print(f"{sample['name']}: Score={score:.4f} → {label}")

# import sys
# sys.path.insert(0, "ml_models")
# import pandas as pd
# import joblib

# model = joblib.load("ml_models/sqli_model.pkl")
# df = pd.read_csv("ml_models/csic_database.csv")
# df = df.rename(columns={"lenght": "content_length"})
# if "Unnamed: 0" in df.columns:
#     df = df.drop(columns=["Unnamed: 0"])

# # نملأ الـ NaN بقيم فاضية
# df = df.fillna("")

# normal = df[df["classification"] == 0].drop(columns=["classification"]).head(450)

# for i, row in normal.iterrows():
#     sample = pd.DataFrame([row])
#     proba = model.predict_proba(sample)
#     score = proba[0][1]
#     label = "MALICIOUS ❌" if score >= 0.5 else "SAFE ✅"
#     print(f"Row {i}: ML Score={score:.4f} → {label}")


# import sys
# sys.path.insert(0, "ml_models")
# import pandas as pd
# import joblib

# model = joblib.load("ml_models/sqli_model.pkl")
# df = pd.read_csv("ml_models/csic_database.csv")
# df = df.rename(columns={"lenght": "content_length"})
# if "Unnamed: 0" in df.columns:
#     df = df.drop(columns=["Unnamed: 0"])

# categorical_cols = ["Method", "host", "Accept", "content-type"]
# df[categorical_cols] = df[categorical_cols].fillna("")

# # ناخد 10 عشوائية مع تسميتهم
# sample_df = df.sample(10, random_state=42)

# for i, row in sample_df.iterrows():
#     actual = "MALICIOUS" if row["classification"] == 1 else "SAFE"
#     sample = pd.DataFrame([row.drop("classification")])
#     proba = model.predict_proba(sample)
#     score = proba[0][1]
#     predicted = "MALICIOUS ❌" if score >= 0.5 else "SAFE ✅"
#     match = "✅" if (actual == "MALICIOUS") == (score >= 0.5) else "❌ WRONG"
#     print(f"Actual: {actual:10} | Predicted: {predicted:15} | Score: {score:.4f} | {match}")

import sys
sys.path.insert(0, "ml_models")
import pandas as pd
import joblib

model = joblib.load("ml_models/sqli_model.pkl")

samples = [
    {"URL": "/products?id=15",                    "Method": "GET",  "content": "", "label": "NORMAL"},
    {"URL": "/search?q=laptop",                   "Method": "GET",  "content": "", "label": "NORMAL"},
    {"URL": "/blog/javascript-tutorial",          "Method": "GET",  "content": "", "label": "NORMAL"},
    {"URL": "/api/products?page=2&category=phones","Method": "GET",  "content": "", "label": "NORMAL"},
    {"URL": "/user/profile/edit",                 "Method": "POST", "content": "username=ahmed&bio=hello", "label": "NORMAL"},
    {"URL": "/docs/admin-guide",                  "Method": "GET",  "content": "", "label": "NORMAL"},
    {"URL": "/shop/drop-shipping-products",       "Method": "GET",  "content": "", "label": "NORMAL"},
    {"URL": "/download/manual.pdf",               "Method": "GET",  "content": "", "label": "NORMAL"},
    {"URL": "/news?title=best+select+products",   "Method": "GET",  "content": "", "label": "NORMAL"},
]
samples = [
    {"URL": "/comment?text=<script>alert(1)</script>", "Method": "GET",  "content": "",                      "label": "XSS"},
    {"URL": "/search",                                 "Method": "POST", "content": "q=<img onerror=alert(1)>", "label": "XSS"},
    {"URL": "/profile",                                "Method": "POST", "content": "bio=<iframe src=evil.com>", "label": "XSS"},
    {"URL": "/post",                                   "Method": "POST", "content": "body=javascript:alert(1)", "label": "XSS"},
    {"URL": "/update",                                 "Method": "POST", "content": "name=<svg onload=alert(1)>","label": "XSS"},
]
print(f"{'Label':<10} {'Score':>8} {'Result':<15} URL")
print("-" * 80)
for s in samples:
    df = pd.DataFrame([{
        "URL":     s["URL"],
        "Method":  s["Method"],
        "content": s["content"],
    }])
    score = model.predict_proba(df)[0][1]
    label = "MALICIOUS ❌" if score >= 0.5 else "SAFE ✅"
    print(f"{s['label']:<10} {score:>8.4f} {label:<15} {s['URL']}")
    