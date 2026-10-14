<?php
/**
 * Signed URLs for a live stream (HLS and DASH) and a single file.
 *
 * Run from the project root:
 *     export MEDIANOVA_TOKEN_KEY=<your token key>
 *     php php/examples/basic_usage.php
 */

require __DIR__ . '/../MedianovaToken.php';

use Medianova\SecureToken\TokenGenerator;

const CDN = 'https://cdn.example.com';

$generator = new TokenGenerator([
    'key' => getenv('MEDIANOVA_TOKEN_KEY'),
    'algorithm' => 'sha256',
    'tokenName' => 'hdnts',
]);

/** One ACL token covers the manifest and, through the CDN session, every segment. */
function streamUrls(TokenGenerator $generator, string $channel, ?string $viewerId = null): array
{
    $options = ['windowSeconds' => 300];
    if ($viewerId !== null) {
        $options['sessionId'] = $viewerId;
    }
    $token = $generator->generateACLToken("/live/$channel/*", $options);
    return [
        'hls' => $generator->signUrl(CDN . "/live/$channel/master.m3u8", $token),
        'dash' => $generator->signUrl(CDN . "/live/$channel/manifest.mpd", $token),
    ];
}

/** A URL token is valid for this exact path only. */
function fileUrl(TokenGenerator $generator, string $path): string
{
    $token = $generator->generateURLToken($path, ['windowSeconds' => 600]);
    return $generator->signUrl(CDN . $path, $token);
}

foreach (streamUrls($generator, 'channel1', 'user-42') as $kind => $url) {
    echo "$kind $url" . PHP_EOL;
}
echo 'file ' . fileUrl($generator, '/downloads/report.pdf') . PHP_EOL;
