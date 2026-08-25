model = {
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
