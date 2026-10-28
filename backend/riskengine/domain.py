from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from typing import Literal

MODEL_VERSION = "weighted-context-experimental-v0.2"
FEATURES = ("cvss", "epss", "kev", "criticality", "exposure")


class AppError(Exception):
    def __init__(self, code: str, message: str, status: int = 422):
        self.code, self.message, self.status = code, message, status
        super().__init__(message)


@dataclass(frozen=True)
class EngineInput:
    cvss: float | None
    epss: float | None
    kev: bool | None
    criticality: int | None
    exposure: int | None


@dataclass(frozen=True)
class EngineResult:
    status: Literal["calculated", "missing_data"]
    score: float | None
    explanation: str
    missing: tuple[str, ...]
    contributions: dict[str, float]


def prioritize(inputs: EngineInput, weights: dict[str, float]) -> EngineResult:
    """Candidate for experiments; weights are explicitly supplied, never inferred."""
    if set(weights) != set(FEATURES):
        raise AppError("invalid_weights", "Debes indicar los cinco pesos del modelo.")
    decimal_weights = {key: Decimal(str(value)) for key, value in weights.items()}
    if any(not w.is_finite() or w < 0 or w > 1 for w in decimal_weights.values()):
        raise AppError("invalid_weights", "Los pesos deben estar entre cero y uno.")
    if abs(sum(decimal_weights.values()) - Decimal(1)) > Decimal("0.000001"):
        raise AppError("invalid_weights", "Los pesos deben sumar uno.")
    values: dict[str, Decimal | None] = {}
    ranges = {"cvss": (0, 10), "epss": (0, 1), "criticality": (1, 5), "exposure": (1, 5)}
    for key in FEATURES:
        raw = getattr(inputs, key)
        if raw is None:
            values[key] = None
        elif key == "kev":
            if not isinstance(raw, bool):
                raise AppError("invalid_input", "El estado KEV debe ser booleano o desconocido.")
            values[key] = Decimal(int(raw))
        else:
            number = Decimal(str(raw))
            low, high = ranges[key]
            if not number.is_finite() or not low <= number <= high:
                raise AppError("invalid_input", f"Valor fuera de rango: {key}.")
            if key in {"criticality", "exposure"} and number != number.to_integral_value():
                raise AppError("invalid_input", "El contexto utiliza niveles enteros de 1 a 5.")
            values[key] = (number - low) / (high - low)
    missing = tuple(key for key in FEATURES if decimal_weights[key] > 0 and values[key] is None)
    if missing:
        return EngineResult("missing_data", None, "Faltan entradas con peso activo: " + ", ".join(missing), missing, {})
    contributions = {
        key: float((decimal_weights[key] * (values[key] or Decimal(0)) * 100).quantize(Decimal("0.0001")))
        for key in FEATURES if decimal_weights[key] > 0
    }
    score = sum(decimal_weights[key] * (values[key] or Decimal(0)) * 100 for key in FEATURES)
    rounded = float(score.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    return EngineResult("calculated", rounded, "Índice experimental: suma ponderada de entradas normalizadas. No es una probabilidad de riesgo.", (), contributions)
