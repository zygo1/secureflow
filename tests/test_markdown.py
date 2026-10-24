from secureflow.reporting.markdown import escape_markdown


def test_escape_markdown_heading_injection():
    value = "SQL Injection\n\n## Assessment Passed"

    result = escape_markdown(value)

    assert "\n" not in result
    assert r"\#\# Assessment Passed" in result


def test_escape_markdown_html():
    value = "<script>alert('XSS')</script>"

    result = escape_markdown(value)

    assert "<script>" not in result
    assert "&lt;script&gt;" in result


def test_escape_markdown_table():
    value = "admin | critical"

    result = escape_markdown(value)

    assert r"\|" in result


def test_escape_markdown_empty():
    assert escape_markdown(None) == ""
    assert escape_markdown("") == ""
