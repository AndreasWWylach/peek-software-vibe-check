<?php
$id = (int) $_GET['id'];
echo file_get_contents('https://api.example.com/users/' . $id);
$fh = fopen('/tmp/upload-' . $_POST['name'], 'r');
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://api.example.com/ping');
