"""Versioned experimental presets; recognition never changes supplied weights."""
from .domain import FEATURES

PROFILES = {
    "cvss-only-v1": {"label": "CVSS 3.1 solo", "weights": dict(zip(FEATURES, (1, 0, 0, 0, 0)))},
    "equal-weights-v1": {"label": "Cinco pesos iguales", "weights": dict.fromkeys(FEATURES, 0.2)},
    "roc-autores-v1": {"label": "ROC experimental", "weights": dict(zip(FEATURES, (0.04, 0.26, 0.46, 0.15, 0.09)))},
}


def identify_profile(weights):
    for identifier, profile in PROFILES.items():
        if weights == profile["weights"]:
            return identifier
    return "custom"


def profile_label(weights):
    return PROFILES.get(identify_profile(weights), {"label": "Pesos personalizados"})["label"]
