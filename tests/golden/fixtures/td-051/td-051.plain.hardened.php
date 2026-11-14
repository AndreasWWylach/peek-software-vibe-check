<?php

// ✅ HARDENED (plain PHP): plan derived from the provider-verified subscription.
$user = load_user($_SESSION['user_id']);
$plan = tier_for_plan(verify_subscription($_POST['subscription_id']));
$user['plan_id'] = $plan;
save_user($user);
