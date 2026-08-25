import re
from app.detection.rules.base import BaseRule


class PathTraversalRule(BaseRule):

    name = "path_traversal"
    attack_type = "Path Traversal"

    PATTERNS = [
        # Basic traversal
        r"(\.\./){2,}",
        r"(\.\.\\){2,}",
        r"(\.\./.*\.\./)",

        # URL encoded
        r"(%2e%2e%2f){1,}",
        r"(%2e%2e/){1,}",
        r"(\.\.%2f){1,}",
        r"(%2e%2e%5c){1,}",

        # Double encoded
        r"(%252e%252e%252f){1,}",
        r"(%252e%252e/){1,}",
        r"(\.\.%252f){1,}",

        # Nested sequences (bypass filters)
        r"(\.\.\.\.//){1,}",
        r"(\.\.\.\.\\\\){1,}",
        r"(\.\./\.\./)",

        # Null byte injection
        r"(\.\./.*%00)",
        r"(\.\.\\.*%00)",

        # Unicode/overlong encoding
        r"(%c0%ae%c0%ae/)",
        r"(%c0%2e%c0%2e/)",
        r"(\.\.%c0%af)",
        r"(\.\.%ef%bc%8f)",

        # Mixed encoding
        r"(\.\.%2f\.\.%2f)",
        r"(%2e\./%2e\./)",

        # Sensitive Linux files
        r"(/etc/passwd)",
        r"(/etc/shadow)",
        r"(/etc/hosts)",
        r"(/etc/hostname)",
        r"(/etc/group)",
        r"(/etc/issue)",
        r"(/proc/self/environ)",
        r"(/proc/self/cmdline)",
        r"(/proc/version)",
        r"(/var/log/)",
        r"(/var/www/)",
        r"(/root/\.ssh/)",
        r"(/home/.*\.ssh/)",

        # Sensitive Windows files
        r"(c:\\windows\\system32)",
        r"(c:\\windows\\win\.ini)",
        r"(c:\\boot\.ini)",
        r"(c:\\inetpub\\)",
        r"(\\windows\\system32\\)",
        r"(boot\.ini)",
        r"(win\.ini)",
        r"(system\.ini)",

        # Web config files
        r"(\.htaccess)",
        r"(\.htpasswd)",
        r"(web\.config)",
        r"(wp-config\.php)",
        r"(config\.php)",
        r"(database\.yml)",
        r"(\.env)",
        r"(application\.properties)",

        # Script file traversal
        r"(\.\./.*\.(php|asp|aspx|jsp|cgi|py|rb|sh))",
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