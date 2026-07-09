import pytest
from soc_analyzer.preprocessing.comment_stripper import strip_comments

def test_inline_comment_with_keyword():
    source = "assign a = b; // contains secret key!"
    result = strip_comments(source)
    assert "secret key" in result
    assert "// contains secret key!" in result

def test_block_comment_no_keyword():
    source = "module A;\n/*\n  plain text here\n*/\nendmodule"
    result = strip_comments(source)
    assert "plain text" not in result
    # Line count must be preserved (5 lines)
    assert len(result.splitlines()) == 5
    # Verify it has spaces inside the comment block
    assert "  " in result

def test_string_literal_not_stripped():
    source = 'initial begin $display("This is a string literal containing // and /* which must not be stripped"); end'
    result = strip_comments(source)
    assert result == source

def test_comment_immediately_followed_by_code():
    source = "assign x = y; // secret path keyword\nassign a = b;"
    result = strip_comments(source)
    assert "secret path" in result
    assert "assign a = b;" in result

def test_nested_looking_comments():
    source = "module block;\n/* first /* second */ code */\nendmodule"
    result = strip_comments(source)
    # The first */ closes the comment. The text ' code */' will be treated as normal code.
    # Since 'first /* second' does not contain any keyword, it gets stripped.
    # The outer comment was /* first /* second */.
    # Verify line count is preserved.
    assert len(result.splitlines()) == 3
    assert "code" in result
