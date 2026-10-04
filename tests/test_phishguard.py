import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["PHISHGUARD_NO_AI"] = "1"

import phishguard as pg


class ScoreUrlTests(unittest.TestCase):
    def test_raw_ip_link_is_phishing(self):
        score, verdict, _ = pg.score_url("http://192.168.0.1/bank-login-verify?otp=update")
        self.assertGreaterEqual(score, 60)
        self.assertEqual(verdict, "PHISHING")

    def test_trusted_github_is_safe(self):
        score, verdict, _ = pg.score_url("https://github.com/shri7-lab/Htb-Notes")
        self.assertEqual(verdict, "SAFE")
        self.assertLess(score, 30)

    def test_shortener_is_suspicious(self):
        score, verdict, findings = pg.score_url("https://bit.ly/free-jio-recharge")
        self.assertEqual(verdict, "SUSPICIOUS")
        self.assertTrue(any("shortener" in d for _, d in findings))

    def test_brand_spoof_domain_flagged(self):
        score, verdict, findings = pg.score_url("https://paypal-secure.tk/login")
        self.assertIn(verdict, ("SUSPICIOUS", "PHISHING"))
        self.assertTrue(any("paypal" in d for _, d in findings))

    def test_homoglyph_digits_brand_flagged(self):
        score, verdict, findings = pg.score_url("http://g00gle-login.com/verify")
        self.assertGreaterEqual(score, 30)
        self.assertTrue(any("branding" in d for _, d in findings))

    def test_unicode_cyrillic_flagged(self):
        _, _, findings = pg.score_url("http://gооgle-support.com/verify")
        self.assertTrue(any("look-alike" in d for _, d in findings))


class MessageScanTests(unittest.TestCase):
    def test_base64_hidden_url_detected(self):
        hidden = base64.b64encode(b"http://evil.test/login").decode()
        result = pg.analyze("please open " + hidden + " thanks")
        self.assertTrue(result["message_findings"])
        self.assertGreaterEqual(result["score"], 30)

    def test_email_spoof_detected(self):
        result = pg.analyze("PayPal Security <secure@paypa1-support.xyz>")
        details = " ".join(f["detail"] for f in result["message_findings"])
        link_details = " ".join(
            f["detail"] for link in result["links"] for f in link["findings"]
        )
        self.assertTrue("paypal" in details or "paypal" in link_details)
        self.assertIn(result["verdict"], ("SUSPICIOUS", "PHISHING"))

    def test_clean_text_is_safe(self):
        result = pg.analyze("hey bro, call me when you reach the mess")
        self.assertEqual(result["verdict"], "SAFE")
        self.assertTrue(result["note"])

    def test_multi_link_extraction_unique(self):
        links = pg.extract_links("see github.com/a and https://bit.ly/x and github.com/a")
        self.assertEqual(len(links), 2)

    def test_result_has_stable_json_keys(self):
        result = pg.analyze("http://192.168.0.1/login")
        for key in ("input", "verdict", "score", "links", "message_findings", "ai", "note"):
            self.assertIn(key, result)

    def test_web_render_escapes_hostile_payloads(self):
        hidden = base64.b64encode(b"<img src=x onerror=alert(1)> http://x").decode()
        rendered = pg.render_html(pg.analyze("check " + hidden))
        self.assertNotIn("<img src=x onerror", rendered)
        self.assertIn("&lt;img", rendered)


if __name__ == "__main__":
    unittest.main()
