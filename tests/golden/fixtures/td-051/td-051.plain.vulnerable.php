<?php

// ❌ FLAW (plain PHP): entitlement read from $_POST.
$user = load_user($_SESSION['user_id']);
$user['plan_id'] = $_POST['plan_id'];
save_user($user);
