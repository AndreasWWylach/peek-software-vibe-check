<?php
// my-plugin.php
add_action('wp_ajax_nopriv_update_profile', 'handle_profile_update');

function handle_profile_update() {
    global $wpdb;

    $user_id = intval($_POST['user_id']);
    $email = $_POST['email'];

    $wpdb->update($wpdb->users, ['user_email' => $email], ['ID' => $user_id]);

    wp_send_json_success();
}
?>
