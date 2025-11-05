# tests/test_analysis.py
from app.analysis import analyze_url
import json

def test_google():
    res = analyze_url("https://www.google.com")
    assert isinstance(res, dict)
    assert res["domain"].endswith("google.com")
    assert res["score"] >= 0

def test_example_http():
    res = analyze_url("http://example.com")
    assert "example.com" in res["domain"]

if __name__ == "__main__":
    print("Running basic tests...")
    print(json.dumps(analyze_url("https://www.google.com"), indent=2))
    print("Done.")
