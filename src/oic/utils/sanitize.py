from collections import Mapping
from textwrap import dedent
import re


SENSITIVE_THINGS = ('password', 'passwd', 'client_secret', 'code',
                    'authorization', 'authorization_code', 'access_token',
                    'refresh_token')


REPLACEMENT = '<REDACTED>'


SANITIZE_PATTERN = r'''( # Start of capturing group--we'll keep this bit.
                            (?: # non-capturing group
                                {} # Template-in things we want to sanitize
                            ) #
                           ['\"]? # Might have a quote after them?
                           \s* # Maybe some whitespace
                           [=:,] # Probably a : , or = in tuple, dict or qs format
                           \s* # Maybe more whitespace
                           [([]? # Could be inside a list/tuple, parse_qs?
                           [ub]? # Python 2/3
                           [\"']? # Might be a quote here.
                       ) # End of capturing group
                       (?:[%\w]+) # This is the bit we replace with '<REDACTED>'
                    '''
SANITIZE_PATTERN = dedent(SANITIZE_PATTERN.format('|'.join(SENSITIVE_THINGS)))
SANITIZE_REGEX = re.compile(SANITIZE_PATTERN, re.VERBOSE|re.IGNORECASE)

def sanitize(potentially_sensitive):
    if isinstance(potentially_sensitive, Mapping):
        # Copy the dict so we don't modify the original
        # Also case-insensitive--possibly important for HTTP headers.
        potentially_sensitive = {k.lower(): v for k, v in potentially_sensitive.items()}
        for sensitive in SENSITIVE_THINGS:
            if sensitive in potentially_sensitive:
                potentially_sensitive[sensitive] = REPLACEMENT
        return potentially_sensitive
    else:
        potentially_sensitive = str(potentially_sensitive)
        return SANITIZE_REGEX.sub(r'\1{}'.format(REPLACEMENT),
                                  potentially_sensitive)
