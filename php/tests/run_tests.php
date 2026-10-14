<?php
/**
 * Tests for MedianovaToken.php. No dependencies: php php/tests/run_tests.php
 */

require __DIR__ . '/../MedianovaToken.php';

use Medianova\SecureToken\TokenException;
use Medianova\SecureToken\TokenGenerator;

const KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';   // public test key

$failures = 0;
$count = 0;

function check(string $name, bool $condition, string $detail = ''): void
{
    global $failures, $count;
    $count++;
    if (!$condition) {
        $failures++;
        echo "FAIL $name" . ($detail !== '' ? ": $detail" : '') . PHP_EOL;
    }
}

function throws(string $name, callable $fn, string $message): void
{
    try {
        $fn();
        check($name, false, 'no exception');
    } catch (TokenException $error) {
        check($name, strpos($error->getMessage(), $message) !== false, $error->getMessage());
    }
}

// Tokens must be byte-identical to Akamai's EdgeAuth library for the same inputs.
$vectors = json_decode(file_get_contents(__DIR__ . '/../../tests/akamai_edgeauth_vectors.json'), true)['vectors'];
foreach ($vectors as $case) {
    $generator = new TokenGenerator(['key' => $case['key'], 'algorithm' => $case['algorithm'],
        'escapeEarly' => $case['escape_early'] ?? false]);
    $options = ['endTime' => $case['end_time']];
    foreach (['start_time' => 'startTime', 'ip' => 'ip', 'session_id' => 'sessionId', 'payload' => 'payload'] as $from => $to) {
        if (isset($case[$from])) {
            $options[$to] = $case[$from];
        }
    }
    $token = $case['mode'] === 'acl'
        ? $generator->generateACLToken($case['path'], $options)
        : $generator->generateURLToken($case['path'], $options);
    check('vector ' . $case['name'], $token === $case['expected'], $token);
}

$generator = new TokenGenerator(['key' => KEY]);

// The ACL token signs its own prefix.
$token = $generator->generateACLToken('/live/a/*', ['endTime' => 1790000300]);
list($prefix, $digest) = explode('~hmac=', $token);
check('acl prefix', $prefix === 'exp=1790000300~acl=/live/a/*');
check('acl digest', $digest === hash_hmac('sha256', $prefix, hex2bin(KEY)));

// The URL token signs the path but does not send it.
$token = $generator->generateURLToken('/files/a.mp4', ['endTime' => 1790000300]);
check('url not sent', strpos($token, 'url=') === false && strpos($token, '/files') === false);
check('url signed', $token === 'exp=1790000300~hmac='
    . hash_hmac('sha256', 'exp=1790000300~url=/files/a.mp4', hex2bin(KEY)));

check('acl array', strpos($generator->generateACLToken(['/a/*', '/b/*'], ['endTime' => 1790000300]), 'acl=/a/*!/b/*~') !== false);
check('acl trimmed', strpos($generator->generateACLToken(' /a/* ', ['endTime' => 1790000300]), 'acl=/a/*~') !== false);

// Times.
$before = time();
$token = $generator->generateACLToken('/a/*', ['windowSeconds' => 60]);
preg_match('/^exp=(\d+)~/', $token, $m);
check('window from now', (int)$m[1] >= $before + 60 && (int)$m[1] <= time() + 60, $token);
check('start now adds st', preg_match('/^st=\d+~exp=\d+~/', $generator->generateACLToken('/a/*', ['startTime' => 'now', 'windowSeconds' => 60])) === 1);
check('window from start', strpos($generator->generateACLToken('/a/*', ['startTime' => 1790000000, 'windowSeconds' => 300]), 'st=1790000000~exp=1790000300~') === 0);
check('end time wins', strpos($generator->generateACLToken('/a/*', ['windowSeconds' => 60, 'endTime' => 1790000300]), 'exp=1790000300~') === 0);
throws('no lifetime', function () use ($generator) { $generator->generateACLToken('/a/*'); }, 'windowSeconds or endTime');
throws('zero window', function () use ($generator) { $generator->generateACLToken('/a/*', ['windowSeconds' => 0]); }, 'windowSeconds must be');
throws('negative window', function () use ($generator) { $generator->generateACLToken('/a/*', ['windowSeconds' => -5]); }, 'windowSeconds must be');
throws('end before start', function () use ($generator) {
    $generator->generateACLToken('/a/*', ['startTime' => 1790000300, 'endTime' => 1790000000]);
}, 'after the start');
throws('bad start', function () use ($generator) { $generator->generateACLToken('/a/*', ['startTime' => 'soon', 'windowSeconds' => 5]); }, 'startTime must be');

// Constructor defaults and per-call overrides.
$defaults = new TokenGenerator(['key' => KEY, 'windowSeconds' => 300, 'sessionId' => 'site']);
check('default window', preg_match('/^exp=\d+~acl=\/a\/\*~id=site~hmac=/', $defaults->generateACLToken('/a/*')) === 1);
check('override id', strpos($defaults->generateACLToken('/a/*', ['sessionId' => 'user-1']), '~id=user-1~') !== false);
check('empty id omitted', strpos($defaults->generateACLToken('/a/*', ['sessionId' => '']), 'id=') === false);
check('zero id kept', strpos($generator->generateACLToken('/a/*', ['endTime' => 1790000300, 'sessionId' => '0']), '~id=0~') !== false);
throws('unknown call option', function () use ($generator) { $generator->generateACLToken('/a/*', ['window' => 60]); }, 'unknown option: window');

// Akamai EdgeAuth configuration keys.
$akamai = new TokenGenerator(['key' => KEY, 'windowSeconds' => 3, 'fieldDelimiter' => '~', 'aclDelimiter' => '!',
    'verbose' => true, 'tokenType' => 'acl', 'salt' => null]);
ob_start();
$akamai->generateACLToken('/STREAM/PATH/*');
check('verbose prints nothing', ob_get_clean() === '');
throws('salt', function () { new TokenGenerator(['key' => KEY, 'salt' => 'x']); }, 'salt is not supported');
throws('field delimiter', function () { new TokenGenerator(['key' => KEY, 'fieldDelimiter' => '&']); }, 'fieldDelimiter');
throws('acl delimiter', function () { new TokenGenerator(['key' => KEY, 'aclDelimiter' => ',']); }, 'aclDelimiter');
throws('unknown option', function () { new TokenGenerator(['key' => KEY, 'windowSecond' => 60]); }, 'unknown option: windowSecond');

// signUrl encodes the token.
$token = $generator->generateACLToken('/live/a/*', ['endTime' => 1790000300]);
check('sign url', $generator->signUrl('https://cdn.example.com/live/a/master.m3u8', $token)
    === 'https://cdn.example.com/live/a/master.m3u8?hdnts=' . rawurlencode($token));
check('sign url encoding', strpos($generator->signUrl('https://h/x', $token), 'exp%3D1790000300~acl%3D%2Flive%2Fa%2F%2A~hmac%3D') !== false);
check('sign url with query', strpos($generator->signUrl('https://h/x?a=1', $token), 'https://h/x?a=1&hdnts=') === 0);
$named = new TokenGenerator(['key' => KEY, 'tokenName' => '__token__']);
check('custom name', strpos($named->signUrl('https://h/x', $token), '?__token__=') !== false);

// Key, algorithm and name rules.
throws('missing key', function () { new TokenGenerator([]); }, 'hexadecimal');
throws('odd key', function () { new TokenGenerator(['key' => KEY . 'a']); }, 'even-length');
throws('non-hex key', function () { new TokenGenerator(['key' => str_repeat('zz', 32)]); }, 'hexadecimal');
throws('short sha256 key', function () { new TokenGenerator(['key' => substr(KEY, 0, 62)]); }, '64 to 128');
throws('long key', function () { new TokenGenerator(['key' => str_repeat('ab', 65)]); }, '64 to 128');
check('sha1 short key', (new TokenGenerator(['key' => substr(KEY, 0, 32), 'algorithm' => 'SHA1'])) instanceof TokenGenerator);
check('uppercase key', (new TokenGenerator(['key' => strtoupper(KEY)])) instanceof TokenGenerator);
throws('algorithm', function () { new TokenGenerator(['key' => KEY, 'algorithm' => 'sha512']); }, 'algorithm must be');
throws('token name', function () { new TokenGenerator(['key' => KEY, 'tokenName' => 'a b']); }, 'tokenName');

// Values cannot break the token format.
throws('acl tilde', function () use ($generator) { $generator->generateACLToken('/a~b/*', ['windowSeconds' => 5]); }, "acl must not contain '~'");
throws('id tilde', function () use ($generator) { $generator->generateACLToken('/a/*', ['windowSeconds' => 5, 'sessionId' => 'a~b']); }, "sessionId must not contain '~'");
throws('data control', function () use ($generator) { $generator->generateACLToken('/a/*', ['windowSeconds' => 5, 'payload' => "a\nb"]); }, 'control characters');
throws('empty acl', function () use ($generator) { $generator->generateACLToken('', ['windowSeconds' => 5]); }, 'acl is required');
throws('relative path', function () use ($generator) { $generator->generateURLToken('files/a.mp4', ['windowSeconds' => 5]); }, "start with '/'");
throws('path query', function () use ($generator) { $generator->generateURLToken('/a.mp4?x=1', ['windowSeconds' => 5]); }, 'query string');

// escapeEarly matches Python quote_plus with lowercase escapes; acl is never escaped.
$escaping = new TokenGenerator(['key' => KEY, 'escapeEarly' => true]);
check('escape fields', strpos($escaping->generateACLToken('/a b/*', ['endTime' => 1790000300, 'ip' => '2001:db8::1', 'payload' => 'ü*/x y']),
    'ip=2001%3adb8%3a%3a1~exp=1790000300~acl=/a b/*~data=%c3%bc%2a%2fx+y~') === 0, 'escaped');

// Command line.
function run_cli(array $args, string $key = KEY): array
{
    $command = 'MEDIANOVA_TOKEN_KEY=' . escapeshellarg($key) . ' ' . escapeshellarg(PHP_BINARY) . ' '
        . escapeshellarg(__DIR__ . '/../MedianovaToken.php') . ' ' . implode(' ', array_map('escapeshellarg', $args));
    $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    return [proc_close($process), $out, $err];
}

list($code, $out) = run_cli(['--acl', '/live/a/*', '--window', '60', '--url', 'https://cdn.example.com/live/a/master.m3u8']);
check('cli signed url', $code === 0 && strpos($out, 'https://cdn.example.com/live/a/master.m3u8?hdnts=exp%3D') === 0, $out);
list($code, $out) = run_cli(['--url-path', '/files/a.mp4', '--window', '60']);
check('cli url mode', $code === 0 && preg_match('/^exp=\d+~hmac=[0-9a-f]{64}$/', trim($out)) === 1, $out);
list($code, , $err) = run_cli(['--acl', '/a/*'], '');
check('cli missing key', $code !== 0 && strpos($err, 'MEDIANOVA_TOKEN_KEY') !== false, $err);
list($code, , $err) = run_cli(['--acl', '/a/*', '--url-path', '/a']);
check('cli both modes', $code !== 0 && strpos($err, 'exactly one') !== false, $err);
list($code, , $err) = run_cli(['--acl', '/a/*', '--window', '0']);
check('cli bad window', $code !== 0 && strpos($err, 'windowSeconds') !== false, $err);

echo ($failures === 0 ? 'OK' : 'FAILED') . " ($count checks, $failures failed)" . PHP_EOL;
exit($failures === 0 ? 0 : 1);
