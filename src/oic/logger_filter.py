import logging
import re

SANITIZE_PATTERN = r'''(['\"]?(?:password|passwd|client_secret|access_token|refresh_token)['\"]?\s*[=:]\s*[\"']?)(?:\w+)'''

class SanitizingFilter(logging.Filter):

    def __init__(self, pattern):
        self.pattern = re.compile(pattern)

    def filter(self, record):
        record.msg = self.pattern.sub(r'\1<SANITIZED>', record.msg)
        return True

sanitizing_filter = SanitizingFilter(SANITIZE_PATTERN)
