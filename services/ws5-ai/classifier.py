"""WS-5 layer-2 light classifier (CPU, fast).

Production: TF-IDF + logistic regression (scikit-learn) trained on labelled logs.
This skeleton ships a deterministic rule-of-thumb classifier with the SAME interface
(`predict(event) -> {category, priority, confidence}`) so the pipeline and tests run
with zero ML dependencies. Swap `LightClassifier` for the sklearn model later without
touching the worker.
"""
from __future__ import annotations

# OCSF class_uid -> coarse category label
_CATEGORY = {
    3002: "authentication",
    3003: "account_change",
    4001: "network",
    4002: "web_dns",
    6003: "api",
    6005: "datastore",
    1001: "file",
    1002: "process",
}


class LightClassifier:
    def predict(self, event: dict) -> dict:
        cls = event.get("class_uid")
        category = _CATEGORY.get(cls, "other") if isinstance(cls, int) else "other"
        sev = event.get("severity_id", 0)
        score = event.get("siem", {}).get("score", 0)
        if score >= 60 or sev >= 5:
            priority = "high"
        elif score >= 40 or sev == 4:
            priority = "medium"
        else:
            priority = "low"
        # crude confidence: stronger when severity and score agree
        confidence = round(min(1.0, 0.5 + (sev / 12) + (score / 200)), 2)
        return {"category": category, "priority": priority, "confidence": confidence}
