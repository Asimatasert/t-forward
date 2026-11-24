"""Built-in code source; configuration arrives only on stdin, code on stdout."""
import email.policy
import email.parser
import imaplib
import json
import re
import ssl
import sys
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path


class Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


KEYWORD = re.compile(
    r"(?<![a-z])(?:code|otp|passcode|pin|token|verification|kod|kodu)(?![a-z])",
    re.I)
CANDIDATE = re.compile(r"(?<![0-9])[0-9]{4,8}(?![0-9])")
# Characters that join digit groups into dates, times, phone numbers, amounts.
JOINERS = "-./:,"


def standalone(text, match):
    """True when the digit run is not part of a date, phone number or amount."""
    start, end = match.span()
    before = text[start - 1] if start else ""
    after = text[end] if end < len(text) else ""
    if before in "+$#\u20ac\u00a3" and before:
        return False
    if before and before in JOINERS and start > 1 and text[start - 2].isdigit():
        return False
    if after and after in JOINERS and end + 1 < len(text) and text[end + 1].isdigit():
        return False
    return True


def rank(text, match):
    """0: code keyword just before the number, 1: just after it, 2: none.

    Only the text up to the neighbouring digit run counts, so a keyword that
    belongs to another number does not promote this one.
    """
    start, end = match.span()
    prev = re.search(r"[0-9]", text[max(0, start - 40):start][::-1])
    before = text[max(0, start - 40):start]
    if prev:
        before = before[len(before) - prev.start():]
    if KEYWORD.search(before):
        return 0
    after = text[end:end + 25]
    nxt = re.search(r"[0-9]", after)
    if nxt:
        after = after[:nxt.start()]
    if KEYWORD.search(after):
        return 1
    return 2


def extract_code(raw, length=None):
    """Best code in the mail: keyword-adjacent standalone numbers first, then
    the first standalone number; `length` demands that exact digit count."""
    best = None
    msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(raw)
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        body = part.get_content()
        if part.get_content_type() == "text/html":
            parser = Text()
            parser.feed(body)
            body = " ".join(parser.parts)
        for match in CANDIDATE.finditer(body):
            if length and len(match.group()) != length:
                continue
            if not standalone(body, match):
                continue
            tier = rank(body, match)
            if best is None or tier < best[0]:
                best = (tier, match.group())
            if tier == 0:
                return best[1]
    return best[1] if best else ""


def quoted(value):
    if any(c in value for c in "\r\n\x00"):
        raise ValueError("invalid IMAP string")
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def fetch_code(client, config, since):
    # SINCE is day-granularity; INTERNALDATE below enforces the exact cutoff.
    day = datetime.fromtimestamp(since, timezone.utc)
    months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
    date = f"{day.day:02d}-{months[day.month - 1]}-{day.year}"
    criteria = ["UNSEEN", "SINCE", date]
    if config.get("from_filter"):
        criteria += ["FROM", quoted(config["from_filter"])]
    status, data = client.uid("search", None, *criteria)
    if status != "OK":
        raise RuntimeError("search failed")
    # Descending UIDs: newest arrivals first, bounded to avoid a huge backlog.
    for uid in sorted(data[0].split(), key=int, reverse=True)[:50]:
        status, result = client.uid("fetch", uid, "(INTERNALDATE BODY.PEEK[])")
        if status != "OK":
            continue
        for item in result:
            if not isinstance(item, tuple):
                continue
            stamp = re.search(rb'INTERNALDATE "([^"]+)"', item[0])
            if not stamp:
                continue
            # imaplib handles IMAP's English month names independently of locale.
            received = imaplib.Internaldate2tuple(item[0])
            if received is None or time.mktime(received) < since:
                continue
            code = extract_code(item[1], config.get("code_length"))
            if code:
                return code
    return ""


def main():
    config = json.load(sys.stdin)
    if not config.get("host") or not config.get("user") or not config.get("password"):
        raise ValueError("missing configuration")
    tls = config.get("tls", True)
    if not isinstance(tls, bool):
        raise ValueError("invalid TLS setting")
    length = config.get("code_length")
    if length is not None and (isinstance(length, bool) or not isinstance(length, int)
                               or not 4 <= length <= 8):
        raise ValueError("invalid code length")
    marker = Path(sys.argv[1])
    original = marker.stat()
    # Allow delivery just before the gateway announces its prompt, but no old mail.
    since = max(time.time() - 120, original.st_mtime - 30)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        current = marker.stat()
        if (current.st_ino, current.st_mtime_ns) != (original.st_ino, original.st_mtime_ns):
            return
        if (marker.parent / "code").exists() or (marker.parent / "ready").exists():
            return
        try:
            factory = imaplib.IMAP4_SSL if tls else imaplib.IMAP4
            kwargs = {"timeout": 10}
            if tls:
                kwargs["ssl_context"] = ssl.create_default_context()
            with factory(config["host"], config.get("port") or (993 if tls else 143), **kwargs) as client:
                # tls:false selects STARTTLS, never plaintext password delivery.
                if not tls:
                    client.starttls(ssl_context=ssl.create_default_context())
                client.login(config["user"], config["password"])
                status, _ = client.select(quoted(config.get("mailbox") or "INBOX"), readonly=True)
                if status != "OK":
                    raise RuntimeError("mailbox unavailable")
                code = fetch_code(client, config, since)
                if code:
                    print(code, flush=True)
                    return
        except (OSError, imaplib.IMAP4.abort):
            pass  # Transient network failures are retried within the deadline.
        time.sleep(3)
    raise TimeoutError("no code")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never expose server responses, credentials, or message contents.
        sys.exit(1)
