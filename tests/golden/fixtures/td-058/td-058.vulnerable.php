<?php
$stored = md5($_POST['password']);
$other = sha1($password);
$third = hash('sha256', $pwd);
