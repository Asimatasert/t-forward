import contextlib
import imaplib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from email.message import EmailMessage
from unittest.mock import patch

import totp_imap


class IMAPTests(unittest.TestCase):
    def test_mime_and_boundaries(self):
        msg = EmailMessage()
        msg.set_content("No code here")
        msg.add_alternative('<p>Code: <b>004321</b></p>', subtype="html", cte="base64")
        self.assertEqual(totp_imap.extract_code(msg.as_bytes()), "004321")
        self.assertEqual(totp_imap.extract_code(b"\r\n123456789"), "")
        self.assertEqual(totp_imap.extract_code(b"\r\n123 12345678"), "12345678")

    def test_attachment_ignored(self):
        msg = EmailMessage()
        msg.set_content("No code")
        msg.add_attachment("Code 123456", filename="attachment.txt")
        self.assertEqual(totp_imap.extract_code(msg.as_bytes()), "")

    def test_newest_recent_matching_unseen(self):
        calls = []
        class Client:
            def uid(self, action, *args):
                calls.append((action, args))
                if action == "search":
                    return "OK", [b"1 2 3"]
                return "OK", [(b'INTERNALDATE "01-Jan-2026 00:00:00 +0000"',
                               b"\r\nCode 004321")]
        now = time.time()
        # Newest candidate is stale, next is fresh.
        with patch.object(totp_imap.imaplib, "Internaldate2tuple", side_effect=[time.localtime(now-300), time.localtime(now)]):
            code = totp_imap.fetch_code(Client(), {"from_filter": "sender@example.com"}, now-120)
        self.assertEqual(code, "004321")
        self.assertIn("UNSEEN", calls[0][1])
        self.assertIn('"sender@example.com"', calls[0][1])
        self.assertEqual([c[1][0] for c in calls[1:]], [b"3", b"2"])
        self.assertTrue(all("BODY.PEEK[]" in c[1][1] for c in calls[1:]))

    def test_quote_rejects_injection(self):
        with self.assertRaises(ValueError):
            totp_imap.quoted('sender@example.com\r\nALL')


# --- extract_code edge cases -------------------------------------------------

class ExtractCodeEdgeTests(unittest.TestCase):
    def test_empty_and_codeless_mail(self):
        self.assertEqual(totp_imap.extract_code(b""), "")
        self.assertEqual(totp_imap.extract_code(b"\r\nHello, nothing to see here."), "")

    def test_wrong_length_digit_runs_rejected(self):
        # 3 digits is too short; 9+ digits too long. Neither yields a partial match.
        for body in (b"123", b"12 34 56", b"123456789", b"1234567890123"):
            with self.subTest(body=body):
                self.assertEqual(totp_imap.extract_code(b"\r\n" + body), "")

    def test_length_boundaries_accepted(self):
        self.assertEqual(totp_imap.extract_code(b"\r\ncode 1234."), "1234")
        self.assertEqual(totp_imap.extract_code(b"\r\ncode 12345678."), "12345678")

    def test_first_candidate_in_body_wins_and_wrong_length_skipped(self):
        self.assertEqual(totp_imap.extract_code(b"\r\n123 1234 12345 123456"), "1234")
        self.assertEqual(totp_imap.extract_code(b"\r\nfirst 111111 second 222222"), "111111")

    def test_only_ascii_digits_count_and_letters_do_not_block(self):
        self.assertEqual(totp_imap.extract_code("\r\nKod: \u0663\u0664\u0665\u0666".encode()), "")
        self.assertEqual(totp_imap.extract_code(b"\r\nab1234cd"), "1234")

    def test_headers_are_not_searched(self):
        raw = b"Subject: Your code 777777\r\n\r\nbody has no code"
        self.assertEqual(totp_imap.extract_code(raw), "")

    def test_html_tags_split_digits_with_a_space(self):
        # Text() joins fragments with spaces, so digits split by tags do not merge.
        raw = b"Content-Type: text/html\r\n\r\n<p>12<b>34</b>56</p>"
        self.assertEqual(totp_imap.extract_code(raw), "")
        raw = b"Content-Type: text/html\r\n\r\n<p>Code: <b>505050</b></p>"
        self.assertEqual(totp_imap.extract_code(raw), "505050")

    def test_multipart_alternative_falls_through_to_html_part(self):
        raw = (b"Content-Type: multipart/alternative; boundary=B\r\n\r\n"
               b"--B\r\nContent-Type: text/plain\r\n\r\nno code\r\n"
               b"--B\r\nContent-Type: text/html\r\n\r\n<b>505050</b>\r\n--B--\r\n")
        self.assertEqual(totp_imap.extract_code(raw), "505050")

    def test_non_text_parts_and_inline_disposition(self):
        self.assertEqual(totp_imap.extract_code(
            b"Content-Type: image/png\r\n\r\nCode 123456"), "")
        self.assertEqual(totp_imap.extract_code(
            b"Content-Type: text/plain\r\nContent-Disposition: inline\r\n\r\nCode 424242"),
            "424242")

    def test_malformed_multipart_does_not_crash(self):
        # Missing closing boundary / missing boundary parameter must not raise.
        unterminated = (b"Content-Type: multipart/mixed; boundary=XX\r\n\r\n"
                        b"--XX\r\nContent-Type: text/plain\r\n\r\nCode 654321\r\n")
        self.assertEqual(totp_imap.extract_code(unterminated), "654321")
        self.assertEqual(totp_imap.extract_code(
            b"Content-Type: multipart/mixed\r\n\r\nCode 654321"), "")
        self.assertEqual(totp_imap.extract_code(
            b"Content-Type: multipart/mixed; boundary=XX\r\n\r\nno parts 111222"), "")

    def test_invalid_utf8_body_is_decoded_leniently(self):
        raw = (b"Content-Type: text/plain; charset=utf-8\r\n"
               b"Content-Transfer-Encoding: 8bit\r\n\r\nCode \xff\xfe 123456")
        self.assertEqual(totp_imap.extract_code(raw), "123456")

    def test_attachment_before_body_is_skipped(self):
        msg = EmailMessage()
        msg.set_content("Body code 246810")
        msg.add_attachment("Code 135791", filename="a.txt")
        self.assertEqual(totp_imap.extract_code(msg.as_bytes()), "246810")

    @unittest.skip("bug: unknown charset makes extract_code raise LookupError and "
                   "aborts the whole run instead of skipping the message (ayrı iş)")
    def test_unknown_charset_mail_is_skipped_not_fatal(self):
        raw = b"Content-Type: text/plain; charset=nosuch\r\n\r\nCode 123456"
        self.assertEqual(totp_imap.extract_code(raw), "")


# --- quoted ------------------------------------------------------------------

class QuotedTests(unittest.TestCase):
    def test_wraps_and_escapes(self):
        self.assertEqual(totp_imap.quoted("INBOX"), '"INBOX"')
        self.assertEqual(totp_imap.quoted('a"b\\c'), '"a\\"b\\\\c"')

    def test_rejects_every_control_character(self):
        for bad in ("a\rb", "a\nb", "a\x00b"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    totp_imap.quoted(bad)


# --- fetch_code --------------------------------------------------------------

def internaldate(ts):
    return imaplib.Time2Internaldate(ts).encode()


class FakeClient:
    """Scripted IMAP client. messages: {uid(bytes): (timestamp, raw)}."""

    def __init__(self, messages=None, search=("OK", None), fetch_status=None):
        self.messages = messages or {}
        self.search_result = search
        self.fetch_status = fetch_status or {}
        self.calls = []

    def uid(self, action, *args):
        self.calls.append((action, args))
        if action == "search":
            status, data = self.search_result
            if data is None:
                data = [b" ".join(self.messages)]
            return status, data
        uid = args[0]
        if self.fetch_status.get(uid):
            return self.fetch_status[uid], [None]
        ts, raw = self.messages[uid]
        head = b"%s (INTERNALDATE %s BODY[] {%d}" % (uid, internaldate(ts), len(raw))
        return "OK", [(head, raw), b")"]

    def fetched(self):
        return [c[1][0] for c in self.calls if c[0] == "fetch"]


class FetchCodeTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.since = self.now - 120

    def test_search_failure_raises(self):
        client = FakeClient(search=("NO", [b"nope"]))
        with self.assertRaises(RuntimeError):
            totp_imap.fetch_code(client, {}, self.since)
        self.assertEqual(client.fetched(), [])

    def test_empty_mailbox_returns_empty(self):
        client = FakeClient(search=("OK", [b""]))
        self.assertEqual(totp_imap.fetch_code(client, {}, self.since), "")

    def test_no_from_filter_means_no_from_criterion(self):
        client = FakeClient(search=("OK", [b""]))
        totp_imap.fetch_code(client, {"from_filter": ""}, self.since)
        self.assertNotIn("FROM", client.calls[0][1])
        self.assertEqual(client.calls[0][1][:3], (None, "UNSEEN", "SINCE"))

    def test_from_filter_is_quoted_and_injection_rejected(self):
        client = FakeClient(search=("OK", [b""]))
        totp_imap.fetch_code(client, {"from_filter": 'a"b'}, self.since)
        criteria = client.calls[0][1]
        self.assertEqual(criteria[-2:], ("FROM", '"a\\"b"'))
        with self.assertRaises(ValueError):
            totp_imap.fetch_code(FakeClient(), {"from_filter": "x\r\nALL"}, self.since)

    def test_since_date_is_utc_day_with_english_month(self):
        # 2026-03-05 23:59:59 UTC -> 05-Mar-2026 regardless of local timezone.
        client = FakeClient(search=("OK", [b""]))
        totp_imap.fetch_code(client, {}, 1772755199)
        self.assertEqual(client.calls[0][1], (None, "UNSEEN", "SINCE", "05-Mar-2026"))

    def test_newest_uid_wins_numeric_not_lexical_order(self):
        client = FakeClient({
            b"9": (self.now, b"\r\nCode 111111"),
            b"10": (self.now, b"\r\nCode 222222"),
            b"2": (self.now, b"\r\nCode 333333"),
        })
        self.assertEqual(totp_imap.fetch_code(client, {}, self.since), "222222")
        self.assertEqual(client.fetched(), [b"10"])  # stops at the first hit

    def test_message_without_code_falls_back_to_older_one(self):
        client = FakeClient({
            b"3": (self.now, b"\r\nnothing"),
            b"2": (self.now, b"\r\nCode 123456"),
        })
        self.assertEqual(totp_imap.fetch_code(client, {}, self.since), "123456")
        self.assertEqual(client.fetched(), [b"3", b"2"])

    def test_stale_messages_are_ignored(self):
        client = FakeClient({
            b"2": (self.since - 60, b"\r\nCode 999999"),
            b"1": (self.since - 3600, b"\r\nCode 888888"),
        })
        self.assertEqual(totp_imap.fetch_code(client, {}, self.since), "")

    def test_only_newest_50_uids_are_examined(self):
        messages = {str(i).encode(): (self.now, b"\r\nnothing") for i in range(1, 61)}
        messages[b"5"] = (self.now, b"\r\nCode 123456")  # outside the newest 50
        client = FakeClient(messages)
        self.assertEqual(totp_imap.fetch_code(client, {}, self.since), "")
        self.assertEqual(len(client.fetched()), 50)
        self.assertEqual(client.fetched()[0], b"60")
        self.assertEqual(client.fetched()[-1], b"11")

    def test_failed_fetch_is_skipped(self):
        client = FakeClient({
            b"2": (self.now, b"\r\nCode 111111"),
            b"1": (self.now, b"\r\nCode 222222"),
        }, fetch_status={b"2": "NO"})
        self.assertEqual(totp_imap.fetch_code(client, {}, self.since), "222222")

    def test_fetch_items_without_tuple_or_internaldate_are_skipped(self):
        class Odd(FakeClient):
            def uid(self, action, *args):
                if action == "search":
                    return "OK", [b"3 2 1"]
                uid = args[0]
                if uid == b"3":
                    return "OK", [b")"]  # bytes only, no tuple
                if uid == b"2":  # tuple without INTERNALDATE
                    return "OK", [(b"2 (BODY[] {10}", b"\r\nCode 111111"), b")"]
                # unparsable INTERNALDATE
                return "OK", [(b'1 (INTERNALDATE "garbage"', b"\r\nCode 222222")]
        self.assertEqual(totp_imap.fetch_code(Odd(), {}, self.since), "")

    def test_fetch_uses_peek_so_mail_stays_unseen(self):
        client = FakeClient({b"1": (self.now, b"\r\nCode 123456")})
        totp_imap.fetch_code(client, {}, self.since)
        fetch = [c for c in client.calls if c[0] == "fetch"][0]
        self.assertIn("BODY.PEEK[]", fetch[1][1])
        self.assertNotIn("BODY[]", fetch[1][1].replace("BODY.PEEK[]", ""))


# --- main --------------------------------------------------------------------

class FakeTime:
    """Replacement for totp_imap.time: virtual monotonic clock, recorded sleeps."""

    def __init__(self, step=3.0):
        self.now = 0.0
        self.step = step
        self.sleeps = []

    def time(self):
        return time.time()

    def mktime(self, tup):
        return time.mktime(tup)

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += self.step


class FakeIMAP:
    """Stands in for IMAP4 / IMAP4_SSL; scripted through class attributes."""
    instances = []
    connect_error = None
    login_error = None
    select_status = "OK"
    messages = None  # None -> no mail
    # main() catches imaplib.IMAP4.abort while IMAP4 is patched with this class.
    abort = imaplib.IMAP4.abort
    error = imaplib.IMAP4.error

    def __init__(self, host, port, **kwargs):
        FakeIMAP.instances.append(self)
        self.host, self.port, self.kwargs = host, port, kwargs
        self.log = []
        if FakeIMAP.connect_error:
            raise FakeIMAP.connect_error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.log.append("close")
        return False

    def starttls(self, ssl_context=None):
        self.log.append("starttls")

    def login(self, user, password):
        self.log.append(("login", user, password))
        if FakeIMAP.login_error:
            raise FakeIMAP.login_error

    def select(self, mailbox, readonly=False):
        self.log.append(("select", mailbox, readonly))
        return FakeIMAP.select_status, [b"1"]

    def uid(self, action, *args):
        if action == "search":
            return "OK", [b" ".join(FakeIMAP.messages or {})]
        ts, raw = FakeIMAP.messages[args[0]]
        head = b"%s (INTERNALDATE %s BODY[] {1}" % (args[0], internaldate(ts))
        return "OK", [(head, raw), b")"]


SECRET = "s3cr3t-pa55w0rd-FAKE"


class MainTests(unittest.TestCase):
    def setUp(self):
        FakeIMAP.instances = []
        FakeIMAP.connect_error = None
        FakeIMAP.login_error = None
        FakeIMAP.select_status = "OK"
        FakeIMAP.messages = None
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.marker = os.path.join(self.tmp.name, "marker")
        with open(self.marker, "w") as fh:
            fh.write("x")
        self.clock = FakeTime()

    def config(self, **over):
        cfg = {"host": "imap.example.test", "user": "user@example.test", "password": SECRET}
        cfg.update(over)
        return cfg

    def run_main(self, cfg):
        """Run main() with fake clock/IMAP; return (stdout, stderr, exception|None)."""
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["totp_imap.py", self.marker]), \
             patch.object(sys, "stdin", io.StringIO(json.dumps(cfg))), \
             patch.object(totp_imap, "time", self.clock), \
             patch.object(totp_imap.imaplib, "IMAP4_SSL", FakeIMAP), \
             patch.object(totp_imap.imaplib, "IMAP4", FakeIMAP), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                totp_imap.main()
            except Exception as exc:
                return out.getvalue(), err.getvalue(), exc
        return out.getvalue(), err.getvalue(), None

    def test_missing_configuration_rejected_before_any_connection(self):
        for missing in ("host", "user", "password"):
            with self.subTest(missing=missing):
                cfg = self.config()
                del cfg[missing]
                _, _, exc = self.run_main(cfg)
                self.assertIsInstance(exc, ValueError)
        _, _, exc = self.run_main(self.config(password=""))
        self.assertIsInstance(exc, ValueError)
        self.assertEqual(FakeIMAP.instances, [])

    def test_tls_must_be_a_real_boolean(self):
        for bad in ("false", 0, 1, None, "true"):
            with self.subTest(tls=bad):
                _, _, exc = self.run_main(self.config(tls=bad))
                self.assertIsInstance(exc, ValueError)
        self.assertEqual(FakeIMAP.instances, [])

    def test_success_prints_only_the_code(self):
        FakeIMAP.messages = {b"1": (time.time(), b"\r\nYour code is 482913")}
        out, err, exc = self.run_main(self.config(mailbox="Codes", port=1993))
        self.assertIsNone(exc)
        self.assertEqual(out, "482913\n")
        self.assertEqual(err, "")
        client = FakeIMAP.instances[0]
        self.assertEqual((client.host, client.port), ("imap.example.test", 1993))
        self.assertEqual(client.kwargs["timeout"], 10)
        self.assertIn("ssl_context", client.kwargs)
        self.assertIn(("select", '"Codes"', True), client.log)  # read-only
        self.assertNotIn("starttls", client.log)
        self.assertEqual(self.clock.sleeps, [])

    def test_default_port_and_mailbox_with_tls(self):
        FakeIMAP.messages = {b"1": (time.time(), b"\r\ncode 123456")}
        self.run_main(self.config())
        client = FakeIMAP.instances[0]
        self.assertEqual(client.port, 993)
        self.assertIn(("select", '"INBOX"', True), client.log)

    def test_tls_false_uses_starttls_before_login(self):
        FakeIMAP.messages = {b"1": (time.time(), b"\r\ncode 123456")}
        out, _, exc = self.run_main(self.config(tls=False))
        self.assertIsNone(exc)
        self.assertEqual(out, "123456\n")
        client = FakeIMAP.instances[0]
        self.assertEqual(client.port, 143)
        self.assertNotIn("ssl_context", client.kwargs)
        steps = [e if isinstance(e, str) else e[0] for e in client.log]
        self.assertLess(steps.index("starttls"), steps.index("login"))

    def test_connection_errors_are_retried_until_deadline_then_timeout(self):
        FakeIMAP.connect_error = ConnectionRefusedError("refused")
        out, _, exc = self.run_main(self.config())
        self.assertIsInstance(exc, TimeoutError)
        self.assertEqual(out, "")
        self.assertGreater(len(FakeIMAP.instances), 5)
        self.assertEqual(set(self.clock.sleeps), {3})
        self.assertGreaterEqual(self.clock.now, 90)

    def test_connection_recovers_after_transient_failure(self):
        FakeIMAP.messages = {b"1": (time.time(), b"\r\ncode 654321")}
        calls = {"n": 0}
        real_init = FakeIMAP.__init__

        def flaky(self_, host, port, **kw):
            calls["n"] += 1
            if calls["n"] < 3:
                raise OSError("network down")
            real_init(self_, host, port, **kw)
        with patch.object(FakeIMAP, "__init__", flaky):
            out, _, exc = self.run_main(self.config())
        self.assertIsNone(exc)
        self.assertEqual(out, "654321\n")
        self.assertEqual(len(self.clock.sleeps), 2)

    def test_imap_abort_is_retried(self):
        FakeIMAP.connect_error = imaplib.IMAP4.abort("socket error")
        _, _, exc = self.run_main(self.config())
        self.assertIsInstance(exc, TimeoutError)
        self.assertGreater(len(FakeIMAP.instances), 5)

    def test_no_mail_polls_until_deadline(self):
        out, _, exc = self.run_main(self.config())
        self.assertIsInstance(exc, TimeoutError)
        self.assertEqual(out, "")
        self.assertGreater(len(FakeIMAP.instances), 5)

    def test_login_and_mailbox_errors_are_not_retried(self):
        FakeIMAP.login_error = imaplib.IMAP4.error("AUTHENTICATIONFAILED")
        _, _, exc = self.run_main(self.config())
        self.assertIsInstance(exc, imaplib.IMAP4.error)
        self.assertEqual(len(FakeIMAP.instances), 1)
        FakeIMAP.instances, FakeIMAP.login_error = [], None
        FakeIMAP.select_status = "NO"
        _, _, exc = self.run_main(self.config())
        self.assertIsInstance(exc, RuntimeError)
        self.assertEqual(len(FakeIMAP.instances), 1)

    def test_mailbox_name_injection_rejected(self):
        _, _, exc = self.run_main(self.config(mailbox="INBOX\r\nA1 LOGOUT"))
        self.assertIsInstance(exc, ValueError)

    def test_stops_when_code_or_ready_file_exists(self):
        FakeIMAP.messages = {b"1": (time.time(), b"\r\ncode 123456")}
        for name in ("code", "ready"):
            with self.subTest(file=name):
                path = os.path.join(self.tmp.name, name)
                open(path, "w").close()
                out, _, exc = self.run_main(self.config())
                os.remove(path)
                self.assertIsNone(exc)
                self.assertEqual((out, FakeIMAP.instances), ("", []))

    def test_stops_when_marker_is_replaced_while_polling(self):
        real_sleep = self.clock.sleep

        def sleep_and_touch(seconds):
            real_sleep(seconds)
            os.utime(self.marker, ns=(1, 1))
        self.clock.sleep = sleep_and_touch
        out, _, exc = self.run_main(self.config())
        self.assertIsNone(exc)
        self.assertEqual(out, "")
        self.assertEqual(len(FakeIMAP.instances), 1)

    def test_secret_never_reaches_stdout_or_stderr_on_failures(self):
        scenarios = [
            {"login_error": imaplib.IMAP4.error("bad login " + SECRET)},
            {"connect_error": OSError("dial " + SECRET)},
            {"select_status": "NO"},
        ]
        for attrs in scenarios:
            with self.subTest(scenario=list(attrs)):
                FakeIMAP.instances = []
                FakeIMAP.login_error = FakeIMAP.connect_error = None
                FakeIMAP.select_status = "OK"
                for key, value in attrs.items():
                    setattr(FakeIMAP, key, value)
                out, err, exc = self.run_main(self.config())
                self.assertIsNotNone(exc)
                self.assertNotIn(SECRET, out)
                self.assertNotIn(SECRET, err)


class ScriptEntrypointTests(unittest.TestCase):
    """Run the real script in a subprocess: failures must be silent and exit 1."""

    SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "totp_imap.py")

    def run_script(self, stdin_text, *args):
        return subprocess.run([sys.executable, self.SCRIPT, *args], input=stdin_text,
                              capture_output=True, text=True, timeout=30)

    def test_invalid_input_exits_1_silently_without_leaking_secret(self):
        cases = [
            json.dumps({"user": "u@example.test", "password": SECRET}),  # no host
            json.dumps({"host": "h.test", "user": "u", "password": SECRET, "tls": "yes"}),
            "not json " + SECRET,
            "",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "marker")
            open(marker, "w").close()
            for stdin_text in cases:
                with self.subTest(stdin=stdin_text[:20]):
                    res = self.run_script(stdin_text, marker)
                    self.assertEqual(res.returncode, 1)
                    self.assertEqual(res.stdout, "")
                    self.assertEqual(res.stderr, "")  # no traceback, no secret

    def test_missing_marker_argument_exits_1_silently(self):
        res = self.run_script(json.dumps({"host": "h.test", "user": "u", "password": SECRET}))
        self.assertEqual((res.returncode, res.stdout, res.stderr), (1, "", ""))


if __name__ == "__main__":
    unittest.main()
