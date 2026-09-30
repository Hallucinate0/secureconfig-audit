from pathlib import Path

from secureconfig_audit.scanner import scan_text, scan_json


def test_detects_api_key():
    findings = scan_text(
        Path("config.env"),
        "API_KEY=abcdefghijklmnop1234\n"
    )
    assert any(f.rule == "GENERIC_API_KEY" for f in findings)


def test_detects_http():
    findings = scan_text(
        Path("config.env"),
        "BACKEND_URL=http://example.com/api\n"
    )
    assert any(f.rule == "INSECURE_HTTP" for f in findings)


def test_detects_debug():
    findings = scan_text(
        Path("config.env"),
        "DEBUG=true\n"
    )
    assert any(f.rule == "DEBUG_ENABLED" for f in findings)


def test_detects_json_unsafe_setting():
    findings = scan_json(
        Path("app.json"),
        '{"debug": true, "port": 8080}'
    )
    assert any(f.rule == "UNSAFE_BOOLEAN" for f in findings)


def test_clean_config():
    findings = scan_text(
        Path("safe.env"),
        "BACKEND_URL=https://example.com\nDEBUG=false\n"
    )
    assert findings == []
