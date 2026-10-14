#!/usr/bin/env python3
"""Medianova Secure Token generator.

Generates access tokens for Medianova CDN resources protected with the Hash Protected Token
feature. The token format is compatible with Akamai EdgeAuth (Token Authentication 2.0), so
tokens produced by Akamai's EdgeAuth libraries validate unchanged, and vice versa.

Only the Python standard library is used. Python 3.8 or newer.

Library use:

    from medianova_token import TokenGenerator

    generator = TokenGenerator(key=os.environ["MEDIANOVA_TOKEN_KEY"])
    token = generator.generate_acl_token("/live/channel1/*", window_seconds=300)
    url = generator.sign_url("https://cdn.example.com/live/channel1/master.m3u8", token)

Command line use:

    export MEDIANOVA_TOKEN_KEY=<your token key>
    python3 medianova_token.py --acl '/live/channel1/*' --window 300 \\
        --url 'https://cdn.example.com/live/channel1/master.m3u8'
"""

import argparse
import binascii
import hashlib
import hmac
import os
import re
import sys
import time
from urllib.parse import quote, quote_plus

__version__ = "1.0.0"

__all__ = ["TokenGenerator", "TokenError", "ALGORITHMS"]

# Minimum key length in hex characters per algorithm (sha256 keys must be at least 32 bytes).
ALGORITHMS = {"sha256": 64, "sha1": 32, "md5": 32}
MAX_KEY_HEX_LENGTH = 128
DEFAULT_TOKEN_NAME = "hdnts"
FIELD_DELIMITER = "~"
ACL_DELIMITER = "!"


class TokenError(ValueError):
    """Raised for an invalid key, setting or token field."""


class TokenGenerator:
    """Creates signed access tokens.

    :param key: the token key from the Medianova panel, as a hex string.
    :param algorithm: "sha256" (default), "sha1" or "md5". Must match the resource setting.
    :param token_name: query string parameter name; must match the resource setting.
    :param escape_early: URL-encode ip, id, data and the URL path before signing. Must match the
        resource's "escape_early" setting. Only affects URL tokens and those fields.
    """

    def __init__(self, key, algorithm="sha256", token_name=DEFAULT_TOKEN_NAME, escape_early=False):
        algorithm = str(algorithm).lower()
        if algorithm not in ALGORITHMS:
            raise TokenError("algorithm must be one of: " + ", ".join(sorted(ALGORITHMS)))
        if not isinstance(key, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", key):
            raise TokenError("key must be an even-length hexadecimal string")
        if not ALGORITHMS[algorithm] <= len(key) <= MAX_KEY_HEX_LENGTH:
            raise TokenError(
                "key must be %d to %d hex characters for %s" % (ALGORITHMS[algorithm], MAX_KEY_HEX_LENGTH, algorithm)
            )
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", token_name or ""):
            raise TokenError("token_name may contain only letters, digits, '_' and '-' (max 64)")

        self._key = binascii.unhexlify(key)
        self.algorithm = algorithm
        self.token_name = token_name
        self.escape_early = bool(escape_early)

    def generate_acl_token(self, acl, window_seconds=None, start_time=None, end_time=None,
                           ip=None, session_id=None, payload=None):
        """Token for every path that matches the ACL. Use it for HLS/DASH streams.

        :param acl: path pattern; '*' matches any characters (including '/'), '?' one character.
            Several patterns can be given as a list or joined with '!'.
        """
        if isinstance(acl, (list, tuple)):
            acl = ACL_DELIMITER.join(acl)
        if not acl or not isinstance(acl, str):
            raise TokenError("acl is required")
        self._check_value("acl", acl)
        return self._generate(acl=acl, url=None, window_seconds=window_seconds, start_time=start_time,
                              end_time=end_time, ip=ip, session_id=session_id, payload=payload)

    def generate_url_token(self, path, window_seconds=None, start_time=None, end_time=None,
                           ip=None, session_id=None, payload=None):
        """Token for exactly one path (single files, progressive download).

        The path is signed but not sent in the token: pass the URL path only, without the
        host and query string, decoded (for example "/files/my video.mp4").
        """
        if not path or not isinstance(path, str) or not path.startswith("/"):
            raise TokenError("path must start with '/'")
        if "?" in path:
            raise TokenError("path must not contain a query string")
        return self._generate(acl=None, url=path, window_seconds=window_seconds, start_time=start_time,
                              end_time=end_time, ip=ip, session_id=session_id, payload=payload)

    def sign_url(self, url, token):
        """Appends the token to a URL as a query string parameter."""
        separator = "&" if "?" in url else "?"
        return url + separator + self.token_name + "=" + quote(token, safe="")

    # Internals --------------------------------------------------------------------------------

    def _generate(self, acl, url, window_seconds, start_time, end_time, ip, session_id, payload):
        start, end = self._times(window_seconds, start_time, end_time)

        fields = []
        if ip:
            fields.append("ip=" + self._field("ip", ip))
        if start is not None:
            fields.append("st=%d" % start)
        fields.append("exp=%d" % end)
        if acl is not None:
            fields.append("acl=" + acl)                      # never escaped (EdgeAuth behaviour)
        if session_id:
            fields.append("id=" + self._field("id", session_id))
        if payload:
            fields.append("data=" + self._field("data", payload))

        signed = list(fields)
        if url is not None:
            signed.append("url=" + self._escape(url))        # signed only, not sent
        digest = hmac.new(self._key, FIELD_DELIMITER.join(signed).encode("utf-8"),
                          getattr(hashlib, self.algorithm)).hexdigest()
        return FIELD_DELIMITER.join(fields + ["hmac=" + digest])

    @staticmethod
    def _times(window_seconds, start_time, end_time):
        if start_time == "now":
            start_time = int(time.time())
        if start_time is not None:
            start_time = int(start_time)
        if end_time is not None:
            end = int(end_time)
        elif window_seconds is not None:
            if int(window_seconds) <= 0:
                raise TokenError("window_seconds must be positive")
            end = (start_time if start_time is not None else int(time.time())) + int(window_seconds)
        else:
            raise TokenError("window_seconds or end_time is required")
        if start_time is not None and end <= start_time:
            raise TokenError("end time must be after the start time")
        return start_time, end

    def _escape(self, value):
        if not self.escape_early:
            return value
        # quote_plus with lowercase percent-encoding, as Akamai EdgeAuth does.
        return re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), quote_plus(value))

    def _field(self, name, value):
        value = self._escape(str(value))
        self._check_value(name, value)
        return value

    @staticmethod
    def _check_value(name, value):
        # '~' separates fields (escape_early does not encode it either); control characters are
        # rejected by the CDN.
        if FIELD_DELIMITER in value:
            raise TokenError("%s must not contain '~'" % name)
        if re.search(r"[\x00-\x1f\x7f]", value):
            raise TokenError("%s must not contain control characters" % name)


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Generate a Medianova Secure Token (Akamai EdgeAuth compatible).",
        epilog="The key is read from the MEDIANOVA_TOKEN_KEY environment variable or --key-file, "
               "never from the command line, so it does not end up in shell history.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--acl", help="ACL token: path pattern, e.g. '/live/channel1/*' (join several with '!')")
    mode.add_argument("--url-path", help="URL token: the exact path, e.g. '/files/video.mp4'")
    parser.add_argument("--window", type=int, default=300, help="lifetime in seconds (default 300)")
    parser.add_argument("--start", help="start time (unix seconds or 'now'); omitted by default")
    parser.add_argument("--algorithm", default="sha256", choices=sorted(ALGORITHMS))
    parser.add_argument("--name", default=DEFAULT_TOKEN_NAME, help="token name (default %s)" % DEFAULT_TOKEN_NAME)
    parser.add_argument("--ip", help="bind the token to this client IP")
    parser.add_argument("--id", dest="session_id", help="session or user identifier")
    parser.add_argument("--data", help="opaque payload")
    parser.add_argument("--escape-early", action="store_true", help="URL-encode values before signing")
    parser.add_argument("--key-file", help="read the hex key from this file instead of the environment")
    parser.add_argument("--url", help="print a signed URL instead of the bare token")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv)
    if args.key_file:
        with open(args.key_file, encoding="utf-8") as handle:
            key = handle.read().strip()
    else:
        key = os.environ.get("MEDIANOVA_TOKEN_KEY", "").strip()
    if not key:
        sys.exit("error: set MEDIANOVA_TOKEN_KEY or use --key-file")

    try:
        generator = TokenGenerator(key, algorithm=args.algorithm, token_name=args.name, escape_early=args.escape_early)
        options = dict(window_seconds=args.window, start_time=args.start, ip=args.ip,
                       session_id=args.session_id, payload=args.data)
        token = (generator.generate_acl_token(args.acl, **options) if args.acl
                 else generator.generate_url_token(args.url_path, **options))
    except TokenError as error:
        sys.exit("error: %s" % error)

    print(generator.sign_url(args.url, token) if args.url else token)


if __name__ == "__main__":
    main()
