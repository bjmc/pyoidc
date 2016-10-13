import pytest

from oic.utils.sanitize import sanitize

@pytest.mark.parametrize("raw,expected", [

    ('code=%5B999%5D&bing=baz&password=foo&param1=bar',
     'code=<REDACTED>&bing=baz&password=<REDACTED>&param1=bar'),

    ({'Password': 'foo', 'param1': 'bar', 'CODE': [999], 'bing': 'baz'},
     {'bing': 'baz', 'code': '<REDACTED>', 'param1': 'bar', 'password': '<REDACTED>'}),

    ("{'code': [999], 'bing': 'baz', 'password': 'foo', 'param1': 'bar'}",
     "{'code': [<REDACTED>], 'bing': 'baz', 'password': '<REDACTED>', 'param1': 'bar'}"),

     ([('code', [999]), ('bing', 'baz'), ('password', 'foo'), ('param1', 'bar')],
      "[('code', [<REDACTED>]), ('bing', 'baz'), ('password', '<REDACTED>'), ('param1', 'bar')]")
])

def test_sanitize(raw, expected):
    assert sanitize(raw) == expected

def test_sanitize_preserves_original():
    old = {'passwd': 'secret'}
    new = sanitize(old)
    assert old['passwd'] == 'secret'
    assert new['passwd'] == '<REDACTED>'
