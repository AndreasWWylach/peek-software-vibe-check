<?php

// Capped SDK call (hardened).
$result = $client->chat()->create([
    'model' => 'gpt-4',
    'messages' => [['role' => 'user', 'content' => $prompt]],
    'max_tokens' => 1024,
]);

// Capped raw body (hardened).
$body = [
    'model' => 'gpt-4',
    'messages' => [['role' => 'user', 'content' => $prompt]],
    'max_completion_tokens' => 2048,
];
