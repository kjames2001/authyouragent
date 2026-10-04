<?php
/**
 * Plugin Name:       Auth Your Agent
 * Plugin URI:        https://authyouragent.com/for-shops
 * Description:       Let AI assistants sign in as your customer's approved agent and complete orders. The customer approves the sign-in, and each WooCommerce payment, on their phone.
 * Version:           0.1.0
 * Requires at least: 6.4
 * Requires PHP:      7.4
 * Author:            Auth Your Agent
 * Author URI:        https://authyouragent.com
 * License:           MIT
 * License URI:       https://opensource.org/licenses/MIT
 * Text Domain:       authyouragent
 */

defined( 'ABSPATH' ) || exit;

define( 'AYA_VERSION', '0.1.0' );
define( 'AYA_DIR', plugin_dir_path( __FILE__ ) );

require_once AYA_DIR . 'includes/class-aya-jwt.php';
require_once AYA_DIR . 'includes/class-aya-client.php';
require_once AYA_DIR . 'includes/class-aya-login.php';
require_once AYA_DIR . 'includes/class-aya-logout.php';
require_once AYA_DIR . 'includes/class-aya-checkout.php';
require_once AYA_DIR . 'includes/class-aya-settings.php';

/** Plugin settings with defaults. */
function aya_opt( $key ) {
	$o = get_option( 'aya_settings', array() );
	$d = array(
		'issuer'        => 'https://authyouragent.com',
		'client_id'     => '',
		'client_secret' => '',
		'button_label'  => __( 'Sign in with Auth Your Agent', 'authyouragent' ),
		'role'          => '',
		'confirm_orders' => '1',
	);
	return isset( $o[ $key ] ) && '' !== $o[ $key ] ? $o[ $key ] : ( isset( $d[ $key ] ) ? $d[ $key ] : '' );
}

function aya_configured() {
	return aya_opt( 'client_id' ) && aya_opt( 'client_secret' );
}

/** The address the site registers as its redirect URI. */
function aya_redirect_uri() {
	return add_query_arg( 'action', 'authyouragent_callback', wp_login_url() );
}

/** The address the site registers as its back-channel sign-out URI. */
function aya_logout_uri() {
	return rest_url( 'authyouragent/v1/backchannel-logout' );
}

/** Is this WordPress user an agent account created by this plugin? */
function aya_is_agent( $user_id ) {
	return (bool) get_user_meta( $user_id, 'aya_agent_sub', true );
}

AYA_Login::init();
AYA_Logout::init();
AYA_Checkout::init();
AYA_Settings::init();

register_uninstall_hook( __FILE__, 'aya_uninstall' );
function aya_uninstall() {
	delete_option( 'aya_settings' );
	delete_transient( 'aya_discovery' );
	delete_transient( 'aya_jwks' );
}
