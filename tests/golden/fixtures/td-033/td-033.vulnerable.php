<?php
// orders.php
global $wpdb;

$email = $_GET['email'];

// "Prepared" — but the input is already concatenated, so prepare() is a no-op.
$sql = "SELECT * FROM wp_orders WHERE customer_email = '" . $email . "'";
$orders = $wpdb->get_results($wpdb->prepare($sql));
?>
