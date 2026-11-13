import re

ALLOWED_DOMAINS = {"support.novapay.example"}
SECRET_PATTERNS = [
    r"\bTIGER-42\b",
    r"\bTIGER-\d+\b",
    r"\bACCT-\d{6}\b",
    r"INTERNAL_OVERRIDE_KEY",
]


def spotlight_chunks(chunks: list[dict]) -> str:
    """Layer 1: Wrap retrieved chunks in strict XML tags and neutralize tag breakouts."""
    blocks = []
    for idx, chunk in enumerate(chunks):
        sanitized = chunk["text"].replace("</retrieved_context>", "[BLOCKED_TAG]")
        blocks.append(
            f'<retrieved_context doc_id="{chunk["id"]}" index="{idx}">\n{sanitized}\n</retrieved_context>'
        )
    return "\n\n".join(blocks)


def scan_chunk_malicious(text: str) -> tuple[bool, str]:
    """Layer 2: Pre-LLM chunk scanner detecting prompt injection signatures."""
    rules = [
        (r"ignore\s+(all\s+)?previous\s+instructions", "Direct override directive"),
        (r"<!--.*?-->", "Hidden HTML comment injection"),
        (r"(^|\n)\s*system\s*:", "Fake system role delimiter"),
        (r"you\s+are\s+now\s+\w+bot", "Persona/jailbreak switch"),
        (r"pichle\s+saare\s+nirdesh", "Multilingual Hinglish override"),
        (r"!\[.*?\]\(https?://", "Markdown image exfiltration"),
        (r"i\s*n\s*t\s*e\s*r\s*n\s*a\s*l\s*_\s*o\s*v\s*e\s*r\s*r\s*i\s*d\s*e", "Spaced token obfuscation"),
        (r"rbi\s+audit\s+compliance.*tiger-42", "Fake compliance pretext"),
        (r"acct-\d{6}", "Cross-tenant account leak payload"),
    ]
    for pattern, reason in rules:
        if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            return True, reason
    return False, "clean"


def output_firewall(reply: str) -> tuple[bool, str]:
    """Layer 3: Post-LLM deterministic regex & domain allowlist filter."""
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, reply, flags=re.IGNORECASE):
            return False, "[BLOCKED BY OUTPUT FIREWALL: Sensitive secret or account pattern detected.]"

    urls = re.findall(r"https?://([^/\s\)]+)", reply)
    for domain in urls:
        if domain.lower() not in ALLOWED_DOMAINS:
            return False, f"[BLOCKED BY OUTPUT FIREWALL: Unauthorized external domain '{domain}'.]"

    return True, reply