<?php
$url = $_GET['url'];
echo file_get_contents($_GET['url']);
$fh = fopen($_POST['target'], 'r');
echo file_get_contents($_REQUEST['path']);
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $_GET['cb']);
