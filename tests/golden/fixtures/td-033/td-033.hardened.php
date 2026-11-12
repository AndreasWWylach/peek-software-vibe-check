<?php
// orders.php — the placeholder is what gets escaped.
global $wpdb;

$email = $_GET['email'];
$orders = $wpdb->get_results(
    $wpdb->prepare("SELECT * FROM wp_orders WHERE customer_email = %s", $email)
);
?>
