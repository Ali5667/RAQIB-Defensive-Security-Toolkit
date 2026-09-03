<?php
// Stored settings are base64-encoded at rest; decoded once for display only.
$stored_theme = "eyJjb2xvciI6ICJibHVlIn0=";
$settings = json_decode(base64_decode($stored_theme), true);
echo "<p>Theme color: " . htmlspecialchars($settings['color']) . "</p>";
