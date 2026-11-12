<?php
// my-plugin.php — logged-in users only, nonce + capability + session identity.
add_action('wp_ajax_update_profile', 'handle_profile_update');

function handle_profile_update() {
    check_ajax_referer('update_profile_nonce', 'nonce'); // CSRF nonce

    $user_id = get_current_user_id();
    if (!current_user_can('edit_user', $user_id)) {
        wp_send_json_error('unauthorized', 403);
    }

    $email = sanitize_email($_POST['email']);

    global $wpdb;
    $wpdb->update($wpdb->users, ['user_email' => $email], ['ID' => $user_id]);

    wp_send_json_success();
}
?>
