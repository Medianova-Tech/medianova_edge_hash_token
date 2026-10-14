import hashlib
import hmac
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from medianova_token import TokenError, TokenGenerator  # noqa: E402

KEY = "0123456789abcdef" * 4          # public test key
VECTORS = json.loads((Path(__file__).parent / "akamai_edgeauth_vectors.json").read_text())["vectors"]


class AkamaiCompatibilityTest(unittest.TestCase):
    """Tokens must be byte-identical to Akamai's EdgeAuth library for the same inputs."""

    def test_reference_vectors(self):
        for case in VECTORS:
            with self.subTest(case["name"]):
                generator = TokenGenerator(case["key"], algorithm=case["algorithm"],
                                           escape_early=case.get("escape_early", False))
                options = dict(start_time=case.get("start_time"), end_time=case["end_time"], ip=case.get("ip"),
                               session_id=case.get("session_id"), payload=case.get("payload"))
                if case["mode"] == "acl":
                    token = generator.generate_acl_token(case["path"], **options)
                else:
                    token = generator.generate_url_token(case["path"], **options)
                self.assertEqual(case["expected"], token)


class TokenFormatTest(unittest.TestCase):
    def setUp(self):
        self.generator = TokenGenerator(KEY)

    def test_acl_token_signs_its_prefix(self):
        token = self.generator.generate_acl_token("/live/a/*", end_time=1790000300)
        prefix, digest = token.split("~hmac=")
        self.assertEqual("exp=1790000300~acl=/live/a/*", prefix)
        expected = hmac.new(bytes.fromhex(KEY), prefix.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(expected, digest)

    def test_url_token_does_not_send_the_path(self):
        token = self.generator.generate_url_token("/files/a.mp4", end_time=1790000300)
        self.assertNotIn("url=", token)
        self.assertNotIn("acl=", token)
        expected = hmac.new(bytes.fromhex(KEY), b"exp=1790000300~url=/files/a.mp4", hashlib.sha256).hexdigest()
        self.assertEqual("exp=1790000300~hmac=" + expected, token)

    def test_acl_list_is_joined_with_exclamation_mark(self):
        token = self.generator.generate_acl_token(["/a/*", "/b/*"], end_time=1790000300)
        self.assertIn("acl=/a/*!/b/*", token)

    def test_window_is_counted_from_now(self):
        with mock.patch("medianova_token.time.time", return_value=1790000000):
            token = self.generator.generate_acl_token("/a/*", window_seconds=300)
        self.assertTrue(token.startswith("exp=1790000300~acl=/a/*~hmac="))

    def test_start_now_adds_st(self):
        with mock.patch("medianova_token.time.time", return_value=1790000000):
            token = self.generator.generate_acl_token("/a/*", window_seconds=60, start_time="now")
        self.assertTrue(token.startswith("st=1790000000~exp=1790000060~"))

    def test_sign_url_encodes_the_token(self):
        token = self.generator.generate_acl_token("/a/*", end_time=1790000300)
        url = self.generator.sign_url("https://cdn.example.com/a/master.m3u8", token)
        self.assertTrue(url.startswith("https://cdn.example.com/a/master.m3u8?hdnts=exp%3D1790000300~acl%3D%2Fa%2F%2A~hmac%3D"))
        self.assertIn("&hdnts=", self.generator.sign_url("https://cdn.example.com/a.m3u8?lang=tr", token))

    def test_custom_token_name(self):
        generator = TokenGenerator(KEY, token_name="__token__")
        self.assertIn("?__token__=", generator.sign_url("https://x/a", "t"))


class ValidationTest(unittest.TestCase):
    def test_key_rules(self):
        for key in ["", "xyz", "abc", "00" * 31, "00" * 65]:
            with self.subTest(key=key), self.assertRaises(TokenError):
                TokenGenerator(key)
        TokenGenerator("00" * 32)
        TokenGenerator("00" * 16, algorithm="sha1")
        with self.assertRaises(TokenError):
            TokenGenerator("00" * 16)                        # sha256 needs 32 bytes

    def test_unknown_algorithm(self):
        with self.assertRaises(TokenError):
            TokenGenerator(KEY, algorithm="sha512")

    def test_fields_cannot_break_the_format(self):
        generator = TokenGenerator(KEY)
        with self.assertRaises(TokenError):
            generator.generate_acl_token("/a/*", end_time=1790000300, session_id="a~b")
        with self.assertRaises(TokenError):
            generator.generate_acl_token("/a/*\n", end_time=1790000300)
        # escape_early encodes other characters ("a b/c" -> "a+b%2fc") but never '~'
        with self.assertRaises(TokenError):
            TokenGenerator(KEY, escape_early=True).generate_acl_token("/a/*", end_time=1790000300, session_id="a~b")
        token = TokenGenerator(KEY, escape_early=True).generate_acl_token("/a/*", end_time=1790000300, session_id="a b/c")
        self.assertIn("~id=a+b%2fc~", token)

    def test_times(self):
        generator = TokenGenerator(KEY)
        with self.assertRaises(TokenError):
            generator.generate_acl_token("/a/*")
        with self.assertRaises(TokenError):
            generator.generate_acl_token("/a/*", window_seconds=0)
        with self.assertRaises(TokenError):
            generator.generate_acl_token("/a/*", start_time=1790000300, end_time=1790000000)

    def test_url_path_rules(self):
        generator = TokenGenerator(KEY)
        for path in ["files/a.mp4", "/a.mp4?x=1", ""]:
            with self.subTest(path=path), self.assertRaises(TokenError):
                generator.generate_url_token(path, end_time=1790000300)


class CommandLineTest(unittest.TestCase):
    def run_cli(self, *args, key=KEY):
        env = dict(os.environ, MEDIANOVA_TOKEN_KEY=key)
        return subprocess.run([sys.executable, str(ROOT / "medianova_token.py"), *args],
                              env=env, capture_output=True, text=True)

    def test_prints_a_signed_url(self):
        result = self.run_cli("--acl", "/live/a/*", "--window", "60", "--url", "https://cdn.example.com/live/a/master.m3u8")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(result.stdout.startswith("https://cdn.example.com/live/a/master.m3u8?hdnts=exp%3D"))

    def test_url_mode(self):
        result = self.run_cli("--url-path", "/files/a.mp4", "--window", "60")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertRegex(result.stdout.strip(), r"^exp=\d+~hmac=[0-9a-f]{64}$")

    def test_missing_key(self):
        result = self.run_cli("--acl", "/a/*", key="")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("MEDIANOVA_TOKEN_KEY", result.stderr)


if __name__ == "__main__":
    unittest.main()
