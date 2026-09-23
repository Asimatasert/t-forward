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


if __name__ == "__main__":
    unittest.main()
