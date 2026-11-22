<?php
$stored = password_hash($_POST['password'], PASSWORD_DEFAULT);
$checksum = hash('sha256', $fileBytes);
$token = md5($randomToken);
