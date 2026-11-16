<?php

// OpenAI-style SDK call without a token cap (vulnerable).
$result = $client->chat()->create([
    'model' => 'gpt-4',
    'messages' => [['role' => 'user', 'content' => $prompt]],
]);

// Raw request body without a token cap (vulnerable).
$body = [
    'model' => 'gpt-4',
    'messages' => [['role' => 'user', 'content' => $prompt]],
];
