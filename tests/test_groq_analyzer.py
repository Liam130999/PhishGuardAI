"""Unit tests for the Groq analyzer used by the web UI (phish_guard.groq_analyzer)."""

from types import SimpleNamespace

import pytest
from groq import GroqError

from phish_guard.groq_analyzer import (
    GroqAnalysisError,
    SYSTEM_PROMPT,
    analyze_email,
    parse_verdict,
)


class FakeGroqClient:
    """Mimics the groq client's chat.completions.create surface."""

    def __init__(self, content="{\"Risk_Score\": 80, \"XAI_Explanation\": \"test\"}", error=None):
        self._content = content
        self._error = error
        self.calls = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        message = SimpleNamespace(content=self._content)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


# --- parse_verdict -----------------------------------------------------------
def test_parse_plain_json():
    out = parse_verdict('{"Risk_Score": 90, "XAI_Explanation": "BEC fraud"}')
    assert out == {"Risk_Score": 90, "XAI_Explanation": "BEC fraud"}


def test_parse_json_with_surrounding_prose():
    raw = 'Here is the verdict: {"Risk_Score": 12, "XAI_Explanation": "benign"} done.'
    assert parse_verdict(raw)["Risk_Score"] == 12


def test_parse_numeric_string_score():
    assert parse_verdict('{"Risk_Score": "77", "XAI_Explanation": "x"}')["Risk_Score"] == 77


def test_parse_score_is_clamped():
    assert parse_verdict('{"Risk_Score": 300, "XAI_Explanation": "x"}')["Risk_Score"] == 100
    assert parse_verdict('{"Risk_Score": -4, "XAI_Explanation": "x"}')["Risk_Score"] == 1


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not json",
        '{"XAI_Explanation": "no score"}',
        '{"Risk_Score": 50}',
        '{"Risk_Score": null, "XAI_Explanation": "x"}',
        '{"Risk_Score": [1,2], "XAI_Explanation": "x"}',
    ],
)
def test_parse_invalid_raises(raw):
    with pytest.raises(GroqAnalysisError):
        parse_verdict(raw)


# --- analyze_email -----------------------------------------------------------
def test_analyze_email_returns_contract():
    client = FakeGroqClient('{"Risk_Score": 88, "XAI_Explanation": "impersonation"}')
    out = analyze_email("key", "llama-3.1-8b-instant", "Urgent", "Wire money", client=client)
    assert out == {"Risk_Score": 88, "XAI_Explanation": "impersonation"}


def test_analyze_email_sends_system_prompt_and_json_mode():
    client = FakeGroqClient()
    analyze_email("key", "llama-3.1-8b-instant", "Sub", "Body", client=client)
    call = client.calls[0]
    assert call["model"] == "llama-3.1-8b-instant"
    assert call["response_format"] == {"type": "json_object"}
    assert call["messages"][0]["content"] == SYSTEM_PROMPT
    assert "Sub" in call["messages"][1]["content"]
    assert "Body" in call["messages"][1]["content"]


def test_analyze_email_wraps_api_error():
    err = GroqError("boom")
    client = FakeGroqClient(error=err)
    with pytest.raises(GroqAnalysisError):
        analyze_email("key", "m", "s", "b", client=client)


def test_analyze_email_wraps_bad_json():
    client = FakeGroqClient("the model refused")
    with pytest.raises(GroqAnalysisError):
        analyze_email("key", "m", "s", "b", client=client)
