import re
from app.detection.rules.base import BaseRule


class CommandInjectionRule(BaseRule):

    name = "command_injection"
    attack_type = "Command Injection"

    PATTERNS = [
        # Semicolon injection
        r"(;\s*\bwhoami\b)",
        r"(;\s*\bls\b(\s+-\w+)*)",
        r"(;\s*\bcat\b\s+\S+)",
        r"(;\s*\bpwd\b)",
        r"(;\s*\bid\b)",
        r"(;\s*\buname\b)",
        r"(;\s*\bifconfig\b)",
        r"(;\s*\bnetstat\b)",
        r"(;\s*\bps\b(\s+-\w+)*)",
        r"(;\s*\bkill\b)",
        r"(;\s*\bchmod\b)",
        r"(;\s*\bchown\b)",

        # Pipe injection
        r"(\|\s*\bwhoami\b)",
        r"(\|\s*\bcat\b)",
        r"(\|\s*\bls\b)",
        r"(\|\s*\bid\b)",
        r"(\|\s*\bsh\b)",
        r"(\|\s*\bbash\b)",
        r"(\|\s*\bpython\b)",
        r"(\|\s*\bperl\b)",
        r"(\|\s*\bruby\b)",

        # AND/OR injection
        r"(&&\s*\b(cat|ls|whoami|id|uname)\b)",
        r"(\|\|\s*\b(cat|ls|whoami|id)\b)",

        # Backtick execution
        r"(`[^`]+`)",

        # $() execution
        r"(\$\([^)]+\))",
        r"(\$\{[^}]+\})",

        # Reverse shells
        r"(\bnc\b.+-e\b)",
        r"(\bnetcat\b.+-e\b)",
        r"(\bbash\s+-i\b)",
        r"(\bsh\s+-i\b)",
        r"(/dev/tcp/)",
        r"(/dev/udp/)",

        # Download & execute
        r"(\bcurl\b.+\|\s*\bbash\b)",
        r"(\bcurl\b.+\|\s*\bsh\b)",
        r"(\bwget\b.+\|\s*\bbash\b)",
        r"(\bwget\b.+\|\s*\bsh\b)",
        r"(\bcurl\b.+-o\b.+\bchmod\b)",

        # File operations
        r"(\brm\b\s+-rf\b)",
        r"(\bmkdir\b.+\bchmod\b)",
        r"(\bchmod\b\s+[0-7]{3,4})",
        r"(\bchown\b\s+root)",

        # Network commands
        r"(\bping\b\s+-[cn]\s*\d+)",
        r"(\bnslookup\b\s+\S+)",
        r"(\bdig\b\s+\S+)",
        r"(\btraceroute\b)",

        # Python/Perl/Ruby execution
        r"(python\s+-c\s+['\"]import)",
        r"(perl\s+-e\s+['\"])",
        r"(ruby\s+-e\s+['\"])",
        r"(php\s+-r\s+['\"])",

        # Windows commands
        r"(\bcmd\s*/c\b)",
        r"(\bcmd\.exe\b)",
        r"(\bpowershell\b.+-exec\b)",
        r"(\bpowershell\b.+-enc\b)",
        r"(\bpowershell\b.+-command\b)",
        r"(\bwscript\b)",
        r"(\bcscript\b)",
        r"(\bregsvr32\b)",
        r"(\bmshta\b)",
        r"(\bnet\s+user\b)",
        r"(\bnet\s+localgroup\b)",

        # Environment variables
        r"(\$path\b)",
        r"(\$home\b)",
        r"(\$shell\b)",
        r"(%systemroot%)",
        r"(%windir%)",
        r"(%comspec%)",
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