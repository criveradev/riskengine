import math
from uuid import UUID
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .domain import FEATURES


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, allow_inf_nan=False)


class AuditCreate(Contract):
    name: str = Field(min_length=1, max_length=160)
    scope: str = Field(min_length=1, max_length=3000)


class ContextUpdate(Contract):
    criticality: int | None = Field(default=None, ge=1, le=5, strict=True)
    exposure: int | None = Field(default=None, ge=1, le=5, strict=True)


class RunCreate(Contract):
    import_id: UUID
    weights: dict[str, float]
    acknowledge_experimental: Literal[True]
    max_evidence_age_days: int = Field(ge=0, le=365)

    @model_validator(mode="after")
    def validate_weights(self):
        if set(self.weights) != set(FEATURES) or any(not math.isfinite(w) or w < 0 or w > 1 for w in self.weights.values()):
            raise ValueError("Indica los cinco pesos entre cero y uno.")
        if abs(sum(self.weights.values()) - 1) > 0.000001:
            raise ValueError("Los pesos deben sumar uno.")
        return self


class FindingUpdate(Contract):
    status: Literal["open", "reviewing", "resolved"]


class CVEReviewCreate(Contract):
    status: Literal["pending", "applicable", "not_applicable"]
    reviewer: str = Field(min_length=1, max_length=160)
    rationale: str = Field(min_length=1, max_length=3000)
