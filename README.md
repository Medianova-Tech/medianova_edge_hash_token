# Medianova Secure Token: Python generator

Create signed, time-limited URLs for Medianova CDN resources protected with **Hash Protected Token**.

The token format is compatible with Akamai Token Authentication 2.0 (EdgeAuth). If you already
generate tokens with Akamai's EdgeAuth libraries, they keep working unchanged: use the same key,
token name and settings on the Medianova resource.

- One file, Python standard library only, Python 3.8 or newer.
- Use it as a library in your backend or as a command line tool.
- A PHP version with the same output is in [`php/`](php/README.md). It keeps the method names of
  Akamai's EdgeAuth PHP class.

## How it works

1. Your backend creates a token with the **token key** configured on your Medianova resource.
2. The token is added to the video or file URL as a query string parameter, for example `?hdnts=…`.
3. The CDN checks the signature, the expiry time and the path on every request, and returns
   `403 Forbidden` when the token is missing, expired, signed for another path or tampered with.

The key never leaves your backend. Players and browsers only see signed URLs.

## Before you start

Your Medianova resource has these settings. The values you use here must match them.

| Setting | What it means for you | Default |
|---|---|---|
| Token key | Hex key used to sign tokens. Keep it secret. | — |
| Token name | Query string parameter that carries the token | `__token__` (Akamai migrations usually use `hdnts`) |
| Algorithm | `sha256`, `sha1` or `md5` | `sha256` |
| Token modes | ACL tokens, URL tokens, or both | both |
| Escape early | Whether values are URL-encoded before signing | off |
| Require IP | Tokens must contain the viewer's IP | off |
| Clock skew | Tolerated clock difference between your servers and the CDN | 0 seconds (max 5) |
| Max lifetime | Longest allowed token validity | not set |
| Session tokens | Streaming sessions after the first manifest (see below) | on, 6 hours |

A key is a hex string: at least 64 characters (32 bytes) for `sha256`, at least 32 characters for
`sha1`/`md5`. To create one:

```bash
openssl rand -hex 32
```

## Quick start (command line)

```bash
read -s MEDIANOVA_TOKEN_KEY && export MEDIANOVA_TOKEN_KEY   # paste the key, it is not echoed

python3 medianova_token.py --name hdnts --acl '/live/channel1/*' --window 300 \
    --url 'https://cdn.example.com/live/channel1/master.m3u8'
```

Output:

```
https://cdn.example.com/live/channel1/master.m3u8?hdnts=exp%3D1790000300~acl%3D%2Flive%2Fchannel1%2F%2A~hmac%3D…
```

The key is read from the `MEDIANOVA_TOKEN_KEY` environment variable or from `--key-file`, never from
the command line. Run `python3 medianova_token.py --help` for every option.

## Library use

```python
import os
from medianova_token import TokenGenerator

generator = TokenGenerator(
    key=os.environ["MEDIANOVA_TOKEN_KEY"],
    algorithm="sha256",      # must match the resource
    token_name="hdnts",      # must match the resource
    escape_early=False,      # must match the resource
)

# A live or VOD stream: one token for every file under the directory
token = generator.generate_acl_token("/live/channel1/*", window_seconds=300)
url = generator.sign_url("https://cdn.example.com/live/channel1/master.m3u8", token)

# A single file
token = generator.generate_url_token("/downloads/report.pdf", window_seconds=600)
url = generator.sign_url("https://cdn.example.com/downloads/report.pdf", token)
```

Create a new token for each viewer when they start playback, in your backend. See
[`examples/basic_usage.py`](examples/basic_usage.py) for a runnable example.

### Token types

| | ACL token | URL token |
|---|---|---|
| Method | `generate_acl_token(acl, …)` | `generate_url_token(path, …)` |
| Valid for | Every path that matches the pattern | Exactly one path |
| Use for | HLS and DASH streams, directories | Single files, progressive MP4, downloads |
| Streaming sessions | Yes | No |

ACL patterns:

- `*` matches any characters, including `/`: `/live/channel1/*` covers everything under that directory.
- `?` matches exactly one character.
- Several patterns: pass a list, `["/live/a/*", "/live/b/*"]`, or join them with `!`.
- The query string is never part of the match.

For a URL token, pass the path only (no host, no query string), as the viewer requests it, decoded:
`/files/my video.mp4`, not `/files/my%20video.mp4`.

### Options

All token methods accept these keyword arguments:

| Argument | Meaning |
|---|---|
| `window_seconds` | Lifetime from now (or from `start_time`). Required unless `end_time` is given. |
| `end_time` | Absolute expiry time, Unix seconds. |
| `start_time` | Token is not valid before this time: Unix seconds or `"now"`. Usually not needed. |
| `ip` | Bind the token to the viewer's IP address. Required when "Require IP" is on. |
| `session_id` | Opaque viewer or session identifier (`id` field). |
| `payload` | Opaque data (`data` field). |

Values must not contain `~` or control characters. With "Escape early" on, the generator encodes
`ip`, `session_id`, `payload` and the URL token path for you.

Choose `window_seconds` long enough for the player to load the first manifest, and within the
resource's max lifetime. A few minutes is typical; the streaming session continues after that (see below).
Keep your servers' clocks synchronized (NTP): the CDN tolerates only the resource's clock skew setting (0–5 seconds, default 0).

## Streaming (HLS and DASH)

Put the token **only on the entry manifest**: the HLS master playlist (for example `master.m3u8`) or
the DASH MPD. You do not need to sign variant playlists or segments.

When the CDN accepts the token on an entry manifest, it starts a **session** for that viewer:

- **HLS:** the CDN rewrites the master playlist so that every variant URI carries a session token in
  its path (`…/hdntl=<session>/720p/index.m3u8`). Segments inherit it automatically. Use relative
  URIs in your playlists; absolute URIs to another host are left unchanged.
- **DASH:** the MPD is not changed. The CDN sets a session cookie (`hdntl`, `Secure`, `HttpOnly`,
  `SameSite=None`) and the browser sends it with every segment request.

The session is bound to the player. It stops working when:

- the session time is over (6 hours by default, set on the resource),
- the request goes outside the ACL of the original token, or
- the `User-Agent`, `X-Playback-Session-Id` or `Origin` request headers change.

When that happens the player receives `403`. Handle it by requesting a new signed URL from your
backend and reloading the source.

### DASH in a browser on another domain

If your player page and the CDN hostname are on different sites:

- Configure your player origins on the resource ("CORS allowed origins"), for example
  `https://player.example.com`. A subdomain wildcard such as `https://*.example.com` covers every
  subdomain (not `example.com` itself); scheme and port must match.
- Configure the player to send requests with credentials (see below). Players do not do this by
  default, so the browser does not send the session cookie and segment requests fail.
- Browsers that block third-party cookies may drop the session cookie. A CDN hostname under your own
  domain (for example `cdn.example.com` for `www.example.com`) avoids this.

Configure credentials **before** you load the source.

dash.js (v4 and v5):

```js
const player = dashjs.MediaPlayer().create();
player.initialize(videoElement, null, true);
['MPD', 'MediaSegment', 'InitializationSegment', 'IndexSegment']
  .forEach((type) => player.setXHRWithCredentialsForType(type, true));
player.attachSource(signedMpdUrl);
```

Shaka Player:

```js
const player = new shaka.Player();
await player.attach(videoElement);
player.getNetworkingEngine().registerRequestFilter((type, request) => {
  request.allowCrossSiteCredentials = true;
});
await player.load(signedMpdUrl);
```

If credentials are missing, the browser console shows a CORS error for the segments, for example
`No 'Access-Control-Allow-Origin' header is present on the requested resource`. The real cause is a
`403` response: the segment request arrived without the session cookie.

### Without sessions

If session tokens are turned off on the resource, every request must carry the access token. In that
case add the token to each request in the player (for example hls.js `xhrSetup` or Shaka request
filters) and choose a `window_seconds` that covers the whole playback.

## Changing the key

1. Enter the new key on the resource and keep a grace period (for example one hour). During the grace
   period the CDN accepts tokens signed with the old **and** the new key.
2. Wait a few minutes for the change to reach all CDN servers, then switch your backend to the new key.
3. When the grace period ends, the old key is removed.

If a key is leaked, replace it with a grace period of `0`. Tokens signed with the old key stop working
immediately, including running playbacks; they recover once players request new URLs.

## Troubleshooting `403 Forbidden`

The CDN does not tell the client why a token was rejected. Check these first:

| Symptom | Likely cause |
|---|---|
| Every request fails | Wrong key, algorithm, token name or escape-early setting |
| Works, then fails after a while | Token or session expired; clock difference on your server |
| Manifest works, segments fail (HLS) | Player changes `User-Agent` / session headers, or playlists use absolute URIs on another host |
| Manifest works, segments fail (DASH) | Cookie not sent: player credentials not enabled, origin not allowed, third-party cookies blocked |
| Browser reports a CORS error on DASH segments | Same as above: the segment got `403` because the cookie was not sent |
| Manifest and segments return `200`, live stream does not start | No new segments at the live edge: check that the encoder is still publishing |
| URL token fails | Path differs from the requested one (encoding, trailing slash, host or query string included) |
| ACL token fails on some files | Path outside the ACL pattern |
| IP-bound token fails | Viewer IP differs (mobile networks, proxies, IPv4/IPv6) |

If you contact Medianova support, include the request time, the URL **without** the token and the
resource name. Never share the token key.

## Security notes

- Generate tokens only in your backend. Never put the key in a browser, mobile app or repository.
- Keep tokens short-lived; streaming sessions continue playback after the token expires.
- Store the key in your secret manager or an environment variable, and rotate it periodically.

## Running the tests

```bash
python3 -m unittest discover -s tests
```

The tests include reference tokens produced by Akamai's EdgeAuth library, to confirm compatibility.
