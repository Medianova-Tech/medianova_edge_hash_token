# Medianova Secure Token: PHP generator

Create signed, time-limited URLs for Medianova CDN resources protected with **Hash Protected Token**,
from PHP.

- One file, no dependencies, PHP 7.4 or newer.
- Tokens are identical to the [Python generator](../README.md) and compatible with Akamai Token
  Authentication 2.0 (EdgeAuth).
- Same configuration keys and method names as Akamai's EdgeAuth PHP class, so an existing
  integration moves over with a few line changes (see [Moving from Akamai EdgeAuth](#moving-from-akamai-edgeauth)).

Read the main [README](../README.md) first for the resource settings, token types, streaming
sessions, CORS and troubleshooting. This page covers the PHP usage only.

## Install

Copy [`MedianovaToken.php`](MedianovaToken.php) into your project and load it:

```php
require __DIR__ . '/MedianovaToken.php';
```

Or, with Composer, add this directory as a path repository and require `medianova/secure-token`.

## Library use

```php
require __DIR__ . '/MedianovaToken.php';

use Medianova\SecureToken\TokenGenerator;

$generator = new TokenGenerator([
    'key' => getenv('MEDIANOVA_TOKEN_KEY'),  // from the environment or your secret manager
    'algorithm' => 'sha256',                 // must match the resource
    'tokenName' => 'hdnts',                  // must match the resource
    'escapeEarly' => false,                  // must match the resource
    'windowSeconds' => 300,                  // default lifetime of every token
]);

// A live or VOD stream: one token for every file under the directory
$token = $generator->generateACLToken('/live/channel1/*');
$url = $generator->signUrl('https://cdn.example.com/live/channel1/master.m3u8', $token);

// A single file
$token = $generator->generateURLToken('/downloads/report.pdf', ['windowSeconds' => 600]);
$url = $generator->signUrl('https://cdn.example.com/downloads/report.pdf', $token);
```

Create a new token for each viewer when they start playback. See
[`examples/basic_usage.php`](examples/basic_usage.php) and
[`examples/player_page.php`](examples/player_page.php).

Invalid values throw `Medianova\SecureToken\TokenException`.

### Methods

| Method | Use |
|---|---|
| `generateACLToken($acl, array $options = [])` | Token for every path that matches the pattern. HLS and DASH streams. `$acl` is a string or an array of patterns. |
| `generateURLToken($path, array $options = [])` | Token for exactly one path: the URL path only, without host and query string, decoded (`/files/my video.mp4`). |
| `signUrl($url, $token)` | Appends `?<tokenName>=<token>` (or `&…`) to the URL, encoded. |

### Options

Set them in the constructor as defaults for every token, or in `$options` for one token.

| Option | Meaning |
|---|---|
| `windowSeconds` | Lifetime from now (or from `startTime`). Required unless `endTime` is given. |
| `endTime` | Absolute expiry time, Unix seconds. |
| `startTime` | Token is not valid before this time: Unix seconds or `'now'`. Usually not needed. |
| `ip` | Bind the token to the viewer's IP address. Required when "Require IP" is on. |
| `sessionId` | Opaque viewer or session identifier (`id` field). |
| `payload` | Opaque data (`data` field). |

Values must not contain `~` or control characters. Unknown option names throw an exception, so a
typo does not silently produce a token without the intended setting.

## Command line

```bash
read -s MEDIANOVA_TOKEN_KEY && export MEDIANOVA_TOKEN_KEY   # paste the key, it is not echoed

php MedianovaToken.php --acl '/live/channel1/*' --window 300 \
    --url 'https://cdn.example.com/live/channel1/master.m3u8'
```

The options are the same as the Python tool. Run `php MedianovaToken.php --help` for the list.

## Moving from Akamai EdgeAuth

If you use Akamai's EdgeAuth PHP class (`TokenGenerator` with `generateACLToken` /
`generateURLToken`), switch the class and keep the rest:

```php
// Before
$generator = new TokenGenerator(['key' => 'AKAMAI_KEY', 'windowSeconds' => 3]);

// After
require __DIR__ . '/MedianovaToken.php';
use Medianova\SecureToken\TokenGenerator;

$generator = new TokenGenerator(['key' => getenv('MEDIANOVA_TOKEN_KEY'), 'windowSeconds' => 60]);
```

Then:

1. **Key:** use the token key configured on the Medianova resource.
2. **Token name:** the query parameter in your URLs (for example `?hdnts=`) must match the
   resource's token name. `signUrl()` uses `tokenName`, default `hdnts`.
3. **Lifetime:** a very short `windowSeconds` (a few seconds) fails when the player starts late, retries,
   or your server clock differs slightly from the CDN. Use 30–300 seconds. Playback continues after the
   token expires through the streaming session.
4. **Hostname:** point the hostname in your URLs to the Medianova resource.

Differences from Akamai's class:

| Akamai option | Here |
|---|---|
| `fieldDelimiter`, `aclDelimiter` | Only the defaults `~` and `!` are accepted. |
| `salt` | Not supported. |
| `verbose` | Ignored. Akamai's class prints the key when it is on. |
| `startTime` | Without it, the token has no `st` field (same as Akamai). `'now'` is converted to the current time. |
| `escapeEarly` with non-ASCII values | Akamai's PHP class converts values with `utf8_encode()` first, which double-encodes UTF-8 text. This generator encodes UTF-8 as Akamai's Python library does, which is what the CDN expects. ASCII values give the same token. |

## Running the tests

```bash
php php/tests/run_tests.php
```

The tests include the same Akamai EdgeAuth reference tokens as the Python tests.
