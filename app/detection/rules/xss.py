import re
from app.detection.rules.base import BaseRule


class XSSRule(BaseRule):

    name = "xss"
    attack_type = "XSS"

    PATTERNS = [
        # Script tags
        r"(<script[\s\S]*?>[\s\S]*?<\/script>)",
        r"(<script[\s\S]*?>)",
        r"(<\/script>)",

        # Javascript protocol
        r"(javascript\s*:)",
        r"(vbscript\s*:)",
        r"(data\s*:\s*text/html)",
        r"(data\s*:\s*application/javascript)",

        # Event handlers
        r"(on\w+\s*=\s*[\"']?[^\"'>\s]+)",
        r"(onerror\s*=)",
        r"(onload\s*=)",
        r"(onclick\s*=)",
        r"(onmouseover\s*=)",
        r"(onfocus\s*=)",
        r"(onblur\s*=)",
        r"(onsubmit\s*=)",
        r"(onkeypress\s*=)",
        r"(onkeydown\s*=)",
        r"(onkeyup\s*=)",

        # HTML tags
        r"(<iframe[\s\S]*?>)",
        r"(<frame[\s\S]*?>)",
        r"(<object[\s\S]*?>)",
        r"(<embed[\s\S]*?>)",
        r"(<applet[\s\S]*?>)",
        r"(<meta[\s\S]*?>)",
        r"(<link[\s\S]*?>)",
        r"(<base[\s\S]*?>)",
        r"(<form[\s\S]*?>)",
        r"(<input[\s\S]*?>)",
        r"(<button[\s\S]*?>)",
        r"(<svg[\s\S]*?>)",
        r"(<math[\s\S]*?>)",
        r"(<img[^>]+src\s*=\s*[\"']?\s*javascript:)",
        r"(<img[^>]+onerror\s*=)",

        # DOM manipulation
        r"(document\.cookie)",
        r"(document\.write\s*\()",
        r"(document\.writeln\s*\()",
        r"(document\.location)",
        r"(document\.referrer)",
        r"(document\.body)",
        r"(document\.createElement)",
        r"(document\.getElementById)",
        r"(document\.querySelector)",
        r"(window\.location)",
        r"(window\.open\s*\()",
        r"(window\.history)",
        r"(window\.navigate)",
        r"(history\.pushstate)",

        # JS functions
        r"(eval\s*\()",
        r"(alert\s*\()",
        r"(confirm\s*\()",
        r"(prompt\s*\()",
        r"(setTimeout\s*\()",
        r"(setInterval\s*\()",
        r"(fetch\s*\()",
        r"(XMLHttpRequest)",
        r"(innerHTML\s*=)",
        r"(outerHTML\s*=)",
        r"(insertAdjacentHTML)",

        # Encoding tricks
        r"(%3cscript)",           # URL encoded <script
        r"(%3c%2fscript)",        # URL encoded </script
        r"(&#x3c;script)",        # HTML encoded <script
        r"(&#60;script)",         # HTML decimal encoded
        r"(\\u003cscript)",       # Unicode encoded
        r"(\x3cscript)",          # Hex encoded

        # Other
        r"(expression\s*\()",     # CSS expression
        r"(livescript\s*:)",
        r"(mocha\s*:)",
        r"(charset\s*=\s*[\"']?\s*javascript)",
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