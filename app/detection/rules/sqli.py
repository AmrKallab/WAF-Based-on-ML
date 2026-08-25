import re
from app.detection.rules.base import BaseRule


class SQLiRule(BaseRule):

    name = "sqli"
    attack_type = "SQLi"

    PATTERNS = [
        # Basic SQL keywords
        r"(\bselect\b.+\bfrom\b)",
        r"(\bunion\b.+\bselect\b)",
        r"(\binsert\b.+\binto\b)",
        r"(\bupdate\b.+\bset\b)",
        r"(\bdelete\b.+\bfrom\b)",
        r"(\bdrop\b.+\btable\b)",
        r"(\bdrop\b.+\bdatabase\b)",
        r"(\bcreate\b.+\btable\b)",
        r"(\balter\b.+\btable\b)",
        r"(\btruncate\b.+\btable\b)",

        # Authentication bypass
        r"('\s*or\s*'?\d+'\s*=\s*'?\d+)",
        r"('\s*or\s*'1'\s*=\s*'1)",
        r"(\bor\b\s+1\s*=\s*1)",
        r"(\bor\b\s+\d+\s*=\s*\d+)",
        r"('\s*or\s*'[^']+'\s*=\s*'[^']+)",
        r"(admin'\s*--)",
        r"(admin'\s*#)",
        r"('\s*;\s*--)",

        # Comment injection
        r"(--\s*$)",
        r"(;--)",
        r"(/\*.*\*/)",
        r"(#\s*$)",

        # Time-based blind
        r"(\bsleep\s*\(\s*\d+\s*\))",
        r"(\bbenchmark\s*\()",
        r"(\bwaitfor\s+delay\b)",
        r"(\bpg_sleep\s*\()",

        # Error-based
        r"(\bextractvalue\s*\()",
        r"(\bupdatexml\s*\()",
        r"(\bgroup_concat\s*\()",
        r"(\bconvert\s*\(.+\busing\b)",

        # Stacked queries
        r"(;\s*\binsert\b)",
        r"(;\s*\bupdate\b)",
        r"(;\s*\bdrop\b)",
        r"(;\s*\bdelete\b)",
        r"(;\s*\bexec\b)",

        # Information gathering
        r"(\binformation_schema\b)",
        r"(\bsys\.tables\b)",
        r"(\bsysobjects\b)",
        r"(\bsyscolumns\b)",
        r"(\bload_file\s*\()",
        r"(\binto\s+outfile\b)",
        r"(\binto\s+dumpfile\b)",

        # Encoding evasion
        r"(%27\s*(or|and))",         # URL encoded '
        r"(%3d%3d)",                  # URL encoded ==
        r"(0x[0-9a-f]+)",            # Hex encoding
        r"(\bchar\s*\(\s*\d+)",      # CHAR() function
        r"(\bconcat\s*\()",          # CONCAT()
        r"(\bcast\s*\()",            # CAST()

        # NoSQL injection
        r"(\$where\s*:)",
        r"(\$gt\s*:)",
        r"(\$ne\s*:)",
        r"(\$or\s*:\s*\[)",
    ]

    def detect(self, request_data: dict) -> dict:
        targets = [
            request_data.get("url", ""),
            request_data.get("body", ""),
    ]

        for target in targets:
            if not target:
                continue
    
            # نفك الـ encoding قبل الفحص
            text = self._normalize(target).lower()
    
            for pattern in self.PATTERNS:
                match = re.search(pattern, text)
                if match:
                    return self._result(
                        detected=True,
                        details=f"SQLi pattern found: {match.group()}"
                    )

        return self._result(detected=False)