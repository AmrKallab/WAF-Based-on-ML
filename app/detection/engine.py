# from app.detection.ml.predictor import predict
# from app.detection.rules.sqli import SQLiRule
# from app.detection.rules.xss import XSSRule
# from app.detection.rules.path_traversal import PathTraversalRule
# from app.detection.rules.command_injection import CommandInjectionRule
# from app.detection.rules.rate_limit import RateLimitRule


# # نعمل instance لكل rule مرة وحدة
# rules = [
#     RateLimitRule(),
#     SQLiRule(),
#     XSSRule(),
#     PathTraversalRule(),
#     CommandInjectionRule(),
# ]


# async def analyze(request_data: dict) -> dict:

#     # 1. نفحص الـ Rate Limit أولاً — لأنه أسرع وما يحتاج ML
#     rate_limit_result = rules[0].detect(request_data)
#     if rate_limit_result["detected"]:
#         return {
#             "is_malicious": True,
#             "attack_type": rate_limit_result["attack_type"],
#             "ml_score": None,
#             "blocked": True,
#             "details": rate_limit_result["details"]
#         }

#     # 2. نفحص الـ Rules
#     for rule in rules[1:]:
#         result = rule.detect(request_data)
#         if result["detected"]:
#             # 3. لو rule كشف هجوم → نأكد بالـ ML
#             ml_result = await predict(request_data)
#             return {
#                 "is_malicious": True,
#                 "attack_type": result["attack_type"],
#                 "ml_score": ml_result["ml_score"],
#                 "blocked": True,
#                 "details": result["details"]
#             }

#     # 4. لو ما في rule كشف شي → نسأل الـ ML
#     ml_result = await predict(request_data)
#     is_malicious = ml_result["is_malicious"]

#     return {
#         "is_malicious": is_malicious,
#         "attack_type": "Unknown" if is_malicious else None,
#         "ml_score": ml_result["ml_score"],
#         "blocked": is_malicious,
#         "details": "ML detection only" if is_malicious else ""
#     }

from app.detection.ml.predictor import predict
from app.detection.rules.sqli import SQLiRule
from app.detection.rules.xss import XSSRule
from app.detection.rules.path_traversal import PathTraversalRule
from app.detection.rules.command_injection import CommandInjectionRule
from app.detection.rules.rate_limit import RateLimitRule


rules = [
    RateLimitRule(),
    SQLiRule(),
    XSSRule(),
    PathTraversalRule(),
    CommandInjectionRule(),
]


async def analyze(request_data: dict) -> dict:

    # 1. Rate Limit أولاً
    rate_limit_result = rules[0].detect(request_data)
    if rate_limit_result["detected"]:
        return {
            "is_malicious": True,
            "attack_type": rate_limit_result["attack_type"],
            "ml_score": None,
            "blocked": True,
            "details": rate_limit_result["details"]
        }

    # 2. Rules
    for rule in rules[1:]:
        result = rule.detect(request_data)
        if result["detected"]:
            # ML يأكد فقط
            ml_result = await predict(request_data)
            return {
                "is_malicious": True,
                "attack_type": result["attack_type"],
                "ml_score": ml_result["ml_score"],
                "blocked": True,
                "details": result["details"]
            }

    # 3. ML بـ threshold عالي
    ml_result = await predict(request_data)
    is_malicious = ml_result["ml_score"] >= 0.5

    return {
        "is_malicious": is_malicious,
        "attack_type": "Unknown" if is_malicious else None,
        "ml_score": ml_result["ml_score"],
        "blocked": is_malicious,
        "details": "ML detection only" if is_malicious else ""
    }