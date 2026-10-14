"""Signed URLs for a live stream (HLS and DASH) and a single file.

Run from the project root:
    export MEDIANOVA_TOKEN_KEY=<your token key>
    python3 examples/basic_usage.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from medianova_token import TokenGenerator  # noqa: E402

CDN = "https://cdn.example.com"

generator = TokenGenerator(
    key=os.environ["MEDIANOVA_TOKEN_KEY"],
    algorithm="sha256",
    token_name="hdnts",
)


def stream_urls(channel, viewer_id=None):
    """One ACL token covers the manifest and, through the CDN session, every segment."""
    token = generator.generate_acl_token("/live/%s/*" % channel, window_seconds=300, session_id=viewer_id)
    return {
        "hls": generator.sign_url("%s/live/%s/master.m3u8" % (CDN, channel), token),
        "dash": generator.sign_url("%s/live/%s/manifest.mpd" % (CDN, channel), token),
    }


def file_url(path):
    """A URL token is valid for this exact path only."""
    token = generator.generate_url_token(path, window_seconds=600)
    return generator.sign_url(CDN + path, token)


if __name__ == "__main__":
    for kind, url in stream_urls("channel1", viewer_id="user-42").items():
        print(kind, url)
    print("file", file_url("/downloads/report.pdf"))
