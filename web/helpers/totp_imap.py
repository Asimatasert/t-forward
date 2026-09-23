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


def extract_code(raw):
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
        match = re.search(r"(?<![0-9])[0-9]{4,8}(?![0-9])", body)
        if match:
            return match.group()
    return ""


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
            code = extract_code(item[1])
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
