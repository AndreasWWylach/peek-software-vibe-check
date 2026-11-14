<?php

// ✅ Control: a non-entitlement field from request data must stay silent.
$user = load_user($_SESSION['user_id']);
$user['display_name'] = $_POST['name'];
save_user($user);
