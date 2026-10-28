import pytest
from riskengine.domain import AppError, EngineInput, prioritize


def weights(**changes):
    return {"cvss": 0, "epss": 0, "kev": 0, "criticality": 0, "exposure": 0, **changes}


def test_missing_active_inputs_are_not_zero():
    result = prioritize(EngineInput(9.8, None, None, None, None), weights(cvss=.5, epss=.5))
    assert result.score is None and result.missing == ("epss",)


def test_known_zero_and_false_are_valid():
    result = prioritize(EngineInput(None, 0, False, None, None), weights(epss=.5, kev=.5))
    assert result.score == 0 and result.status == "calculated"


def test_explicitly_disabled_unknown_input_is_not_required():
    assert prioritize(EngineInput(9.8, None, None, None, None), weights(cvss=1)).score == 98


def test_context_changes_score_and_engine_is_repeatable():
    low = EngineInput(9.8, None, None, 1, 1)
    high = EngineInput(9.8, None, None, 5, 5)
    config = weights(cvss=.5, criticality=.25, exposure=.25)
    assert prioritize(low, config).score == 49
    assert prioritize(high, config).score == 99
    assert prioritize(high, config) == prioritize(high, config)


@pytest.mark.parametrize("bad", [weights(cvss=.5), weights(cvss=float('nan')), weights(cvss=-1, epss=2), {"cvss": 1}])
def test_invalid_weights_rejected(bad):
    with pytest.raises(AppError):
        prioritize(EngineInput(9.8, None, None, None, None), bad)


@pytest.mark.parametrize("inputs", [EngineInput(float('inf'), None, None, None, None), EngineInput(None, None, None, 6, None), EngineInput(None, None, 1, None, None)])
def test_invalid_domain_values_rejected(inputs):
    with pytest.raises(AppError):
        prioritize(inputs, weights(cvss=1))
