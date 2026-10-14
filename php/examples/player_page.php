<?php
/**
 * A player page that receives signed HLS and DASH URLs from the server.
 *
 * The token is created on every page view, in PHP, so the key never reaches the browser.
 * Replace the player part with your own player; only the two URLs come from this file.
 */

require __DIR__ . '/../MedianovaToken.php';

use Medianova\SecureToken\TokenGenerator;

$generator = new TokenGenerator([
    'key' => getenv('MEDIANOVA_TOKEN_KEY'),   // from the server environment, never hard-coded
    'tokenName' => 'hdnts',
    'windowSeconds' => 60,                     // time to load the first manifest; playback continues after it
]);

$token = $generator->generateACLToken('/STREAM/PATH/*');
$sources = [
    ['src' => $generator->signUrl('https://cdn.example.com/STREAM/PATH/playlist.m3u8', $token), 'type' => 'application/x-mpegURL'],
    ['src' => $generator->signUrl('https://cdn.example.com/STREAM/PATH/manifest.mpd', $token), 'type' => 'application/dash+xml'],
];
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Player</title>
</head>
<body>
<div id="player"></div>
<script>
    // Signed URLs from the server. json_encode with these flags is safe inside <script>.
    const sources = <?= json_encode($sources, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES) ?>;

    // Pass `sources` to your player. For DASH in a browser, enable credentials in the player so the
    // session cookie is sent with segment requests (see "DASH in a browser on another domain").
</script>
</body>
</html>
