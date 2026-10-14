<?php
/**
 * Medianova Secure Token generator (PHP).
 *
 * Generates access tokens for Medianova CDN resources protected with the Hash Protected Token
 * feature. The token format is compatible with Akamai EdgeAuth (Token Authentication 2.0).
 *
 * The class keeps the configuration keys and method names of Akamai's EdgeAuth PHP class
 * (key, windowSeconds, generateACLToken, generateURLToken, ...), so existing integrations only
 * need to load this file and use this class instead.
 *
 * No dependencies. PHP 7.4 or newer.
 *
 * Library use:
 *
 *     require __DIR__ . '/MedianovaToken.php';
 *     use Medianova\SecureToken\TokenGenerator;
 *
 *     $generator = new TokenGenerator(['key' => getenv('MEDIANOVA_TOKEN_KEY'), 'windowSeconds' => 300]);
 *     $token = $generator->generateACLToken('/live/channel1/*');
 *     $url = $generator->signUrl('https://cdn.example.com/live/channel1/master.m3u8', $token);
 *
 * Command line use:
 *
 *     export MEDIANOVA_TOKEN_KEY=<your token key>
 *     php MedianovaToken.php --acl '/live/channel1/*' --window 300 \
 *         --url 'https://cdn.example.com/live/channel1/master.m3u8'
 */

namespace Medianova\SecureToken;

class TokenException extends \InvalidArgumentException
{
}

class TokenGenerator
{
    const VERSION = '1.0.0';

    /** Minimum key length in hex characters per algorithm (sha256 keys must be at least 32 bytes). */
    const ALGORITHMS = ['sha256' => 64, 'sha1' => 32, 'md5' => 32];
    const MAX_KEY_HEX_LENGTH = 128;
    const DEFAULT_TOKEN_NAME = 'hdnts';
    const FIELD_DELIMITER = '~';
    const ACL_DELIMITER = '!';

    /** Per-token values: accepted in the constructor and, per call, in the $options argument. */
    const TOKEN_OPTIONS = ['windowSeconds', 'startTime', 'endTime', 'ip', 'sessionId', 'payload'];

    /**
     * Akamai EdgeAuth keys that are accepted for compatibility and have no effect here.
     * verbose is ignored on purpose: Akamai's class prints the key when it is on.
     */
    const IGNORED_OPTIONS = ['verbose', 'tokenType'];

    private $key;
    private $algorithm;
    private $tokenName;
    private $escapeEarly;
    private $defaults = [];

    /**
     * @param array $config
     *   key           (required) the token key from the Medianova panel, as a hex string
     *   algorithm     "sha256" (default), "sha1" or "md5"; must match the resource
     *   tokenName     query string parameter name used by signUrl() (default "hdnts")
     *   escapeEarly   URL-encode ip, sessionId, payload and the URL path before signing; must match the resource
     *   windowSeconds, startTime, endTime, ip, sessionId, payload: defaults for every token,
     *                 see generateACLToken()
     */
    public function __construct(array $config)
    {
        foreach ($config as $name => $value) {
            if ($name === 'fieldDelimiter' && $value !== self::FIELD_DELIMITER) {
                throw new TokenException("fieldDelimiter must be '" . self::FIELD_DELIMITER . "'");
            }
            if ($name === 'aclDelimiter' && $value !== self::ACL_DELIMITER) {
                throw new TokenException("aclDelimiter must be '" . self::ACL_DELIMITER . "'");
            }
            if ($name === 'salt' && $value !== null && $value !== '') {
                throw new TokenException('salt is not supported');
            }
            $known = ['key', 'algorithm', 'tokenName', 'escapeEarly', 'fieldDelimiter', 'aclDelimiter', 'salt'];
            if (!in_array($name, array_merge($known, self::TOKEN_OPTIONS, self::IGNORED_OPTIONS), true)) {
                throw new TokenException("unknown option: $name");
            }
        }

        $algorithm = strtolower((string)($config['algorithm'] ?? 'sha256'));
        if (!isset(self::ALGORITHMS[$algorithm])) {
            throw new TokenException('algorithm must be one of: md5, sha1, sha256');
        }

        $key = $config['key'] ?? null;
        if (!is_string($key) || !preg_match('/^(?:[0-9a-fA-F]{2})+$/', $key)) {
            throw new TokenException('key must be an even-length hexadecimal string');
        }
        $length = strlen($key);
        if ($length < self::ALGORITHMS[$algorithm] || $length > self::MAX_KEY_HEX_LENGTH) {
            throw new TokenException(sprintf('key must be %d to %d hex characters for %s',
                self::ALGORITHMS[$algorithm], self::MAX_KEY_HEX_LENGTH, $algorithm));
        }

        $tokenName = $config['tokenName'] ?? self::DEFAULT_TOKEN_NAME;
        if (!is_string($tokenName) || !preg_match('/^[A-Za-z0-9_-]{1,64}$/', $tokenName)) {
            throw new TokenException("tokenName may contain only letters, digits, '_' and '-' (max 64)");
        }

        $this->key = hex2bin($key);
        $this->algorithm = $algorithm;
        $this->tokenName = $tokenName;
        $this->escapeEarly = (bool)($config['escapeEarly'] ?? false);
        foreach (self::TOKEN_OPTIONS as $name) {
            if (array_key_exists($name, $config)) {
                $this->defaults[$name] = $config[$name];
            }
        }
    }

    /**
     * Token for every path that matches the ACL. Use it for HLS/DASH streams.
     *
     * @param string|string[] $acl path pattern; '*' matches any characters (including '/'), '?' one
     *                             character. Several patterns can be given as an array or joined with '!'.
     * @param array $options windowSeconds, startTime, endTime, ip, sessionId, payload; override the
     *                       constructor values for this token only
     */
    public function generateACLToken($acl, array $options = []): string
    {
        if (is_array($acl)) {
            $acl = implode(self::ACL_DELIMITER, $acl);
        }
        $acl = is_string($acl) ? trim($acl) : '';
        if ($acl === '') {
            throw new TokenException('acl is required');
        }
        self::checkValue('acl', $acl);
        return $this->generate($acl, null, $options);
    }

    /**
     * Token for exactly one path (single files, progressive download).
     *
     * The path is signed but not sent in the token: pass the URL path only, without the host and
     * query string, decoded (for example "/files/my video.mp4").
     */
    public function generateURLToken($path, array $options = []): string
    {
        if (!is_string($path) || $path === '' || $path[0] !== '/') {
            throw new TokenException("path must start with '/'");
        }
        if (strpos($path, '?') !== false) {
            throw new TokenException('path must not contain a query string');
        }
        return $this->generate(null, $path, $options);
    }

    /** Appends the token to a URL as a query string parameter. */
    public function signUrl(string $url, string $token): string
    {
        $separator = strpos($url, '?') === false ? '?' : '&';
        return $url . $separator . $this->tokenName . '=' . rawurlencode($token);
    }

    public function getTokenName(): string
    {
        return $this->tokenName;
    }

    // Internals --------------------------------------------------------------------------------

    private function generate(?string $acl, ?string $url, array $options): string
    {
        foreach (array_keys($options) as $name) {
            if (!in_array($name, self::TOKEN_OPTIONS, true)) {
                throw new TokenException("unknown option: $name");
            }
        }
        $options = array_merge($this->defaults, $options);
        list($start, $end) = self::times($options);

        $fields = [];
        if (self::hasValue($options, 'ip')) {
            $fields[] = 'ip=' . $this->field('ip', $options['ip']);
        }
        if ($start !== null) {
            $fields[] = 'st=' . $start;
        }
        $fields[] = 'exp=' . $end;
        if ($acl !== null) {
            $fields[] = 'acl=' . $acl;                      // never escaped (EdgeAuth behaviour)
        }
        if (self::hasValue($options, 'sessionId')) {
            $fields[] = 'id=' . $this->field('sessionId', $options['sessionId']);
        }
        if (self::hasValue($options, 'payload')) {
            $fields[] = 'data=' . $this->field('payload', $options['payload']);
        }

        $signed = $fields;
        if ($url !== null) {
            $signed[] = 'url=' . $this->escape($url);       // signed only, not sent
        }
        $digest = hash_hmac($this->algorithm, implode(self::FIELD_DELIMITER, $signed), $this->key);
        $fields[] = 'hmac=' . $digest;
        return implode(self::FIELD_DELIMITER, $fields);
    }

    private static function hasValue(array $options, string $name): bool
    {
        return isset($options[$name]) && $options[$name] !== '';
    }

    private static function times(array $options): array
    {
        $start = $options['startTime'] ?? null;
        if (is_string($start) && strtolower($start) === 'now') {
            $start = time();
        }
        if ($start !== null) {
            $start = self::timestamp('startTime', $start);
        }

        if (isset($options['endTime'])) {
            $end = self::timestamp('endTime', $options['endTime']);
        } elseif (isset($options['windowSeconds'])) {
            $window = self::timestamp('windowSeconds', $options['windowSeconds']);
            $end = ($start ?? time()) + $window;
        } else {
            throw new TokenException('windowSeconds or endTime is required');
        }
        if ($start !== null && $end <= $start) {
            throw new TokenException('end time must be after the start time');
        }
        return [$start, $end];
    }

    private static function timestamp(string $name, $value): int
    {
        if (is_int($value) || (is_string($value) && ctype_digit($value))) {
            $value = (int)$value;
            if ($value > 0) {
                return $value;
            }
        }
        throw new TokenException("$name must be a positive integer");
    }

    /** Python quote_plus with lowercase percent-encoding, as Akamai EdgeAuth and the CDN apply it. */
    private function escape(string $value): string
    {
        if (!$this->escapeEarly) {
            return $value;
        }
        return preg_replace_callback('/[^A-Za-z0-9_.~-]/', static function ($match) {
            return $match[0] === ' ' ? '+' : sprintf('%%%02x', ord($match[0]));
        }, $value);
    }

    private function field(string $name, $value): string
    {
        $value = $this->escape((string)$value);
        self::checkValue($name, $value);
        return $value;
    }

    private static function checkValue(string $name, string $value): void
    {
        // '~' separates fields (escapeEarly does not encode it either); control characters are
        // rejected by the CDN.
        if (strpos($value, self::FIELD_DELIMITER) !== false) {
            throw new TokenException("$name must not contain '~'");
        }
        if (preg_match('/[\x00-\x1f\x7f]/', $value)) {
            throw new TokenException("$name must not contain control characters");
        }
    }
}

// Command line -------------------------------------------------------------------------------------

function main(array $argv): int
{
    $usage = <<<'TXT'
Generate a Medianova Secure Token (Akamai EdgeAuth compatible).

Usage: php MedianovaToken.php (--acl PATTERN | --url-path PATH) [options]

  --acl PATTERN       ACL token: path pattern, e.g. '/live/channel1/*' (join several with '!')
  --url-path PATH     URL token: the exact path, e.g. '/files/video.mp4'
  --window SECONDS    lifetime in seconds (default 300)
  --start TIME        start time (unix seconds or 'now'); omitted by default
  --algorithm NAME    sha256 (default), sha1 or md5
  --name NAME         token name (default hdnts)
  --ip IP             bind the token to this client IP
  --id ID             session or user identifier
  --data DATA         opaque payload
  --escape-early      URL-encode values before signing
  --key-file FILE     read the hex key from this file instead of the environment
  --url URL           print a signed URL instead of the bare token
  --version           print the version
  --help              print this help

The key is read from the MEDIANOVA_TOKEN_KEY environment variable or --key-file, never from the
command line, so it does not end up in shell history.

TXT;
    $longOptions = ['acl:', 'url-path:', 'window:', 'start:', 'algorithm:', 'name:', 'ip:', 'id:', 'data:',
        'escape-early', 'key-file:', 'url:', 'version', 'help'];
    $rest = 0;
    $args = getopt('', $longOptions, $rest);
    if ($args === false || $rest < count($argv)) {
        fwrite(STDERR, $usage);
        return 2;
    }
    if (isset($args['help'])) {
        echo $usage;
        return 0;
    }
    if (isset($args['version'])) {
        echo 'MedianovaToken.php ' . TokenGenerator::VERSION . PHP_EOL;
        return 0;
    }
    foreach ($args as $name => $value) {
        if (is_array($value)) {
            fwrite(STDERR, "error: --$name was given more than once\n");
            return 2;
        }
    }
    if (isset($args['acl']) === isset($args['url-path'])) {
        fwrite(STDERR, "error: use exactly one of --acl or --url-path\n");
        return 2;
    }

    if (isset($args['key-file'])) {
        $key = @file_get_contents($args['key-file']);
        if ($key === false) {
            fwrite(STDERR, "error: cannot read the key file\n");
            return 1;
        }
    } else {
        $key = (string)getenv('MEDIANOVA_TOKEN_KEY');
    }
    $key = trim($key);
    if ($key === '') {
        fwrite(STDERR, "error: set MEDIANOVA_TOKEN_KEY or use --key-file\n");
        return 1;
    }

    try {
        $generator = new TokenGenerator([
            'key' => $key,
            'algorithm' => $args['algorithm'] ?? 'sha256',
            'tokenName' => $args['name'] ?? TokenGenerator::DEFAULT_TOKEN_NAME,
            'escapeEarly' => isset($args['escape-early']),
        ]);
        $options = ['windowSeconds' => $args['window'] ?? '300'];
        foreach (['start' => 'startTime', 'ip' => 'ip', 'id' => 'sessionId', 'data' => 'payload'] as $arg => $option) {
            if (isset($args[$arg])) {
                $options[$option] = $args[$arg];
            }
        }
        $token = isset($args['acl'])
            ? $generator->generateACLToken($args['acl'], $options)
            : $generator->generateURLToken($args['url-path'], $options);
    } catch (TokenException $error) {
        fwrite(STDERR, 'error: ' . $error->getMessage() . PHP_EOL);
        return 1;
    }

    echo (isset($args['url']) ? $generator->signUrl($args['url'], $token) : $token) . PHP_EOL;
    return 0;
}

if (PHP_SAPI === 'cli' && isset($_SERVER['argv'][0]) && realpath($_SERVER['argv'][0]) === __FILE__) {
    exit(main($_SERVER['argv']));
}
