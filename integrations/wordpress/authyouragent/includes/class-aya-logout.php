<?php
/**
 * Ending an agent's session when its owner withdraws access:
 *  - OpenID Connect Back-Channel Logout: the provider POSTs a signed
 *    logout_token to /wp-json/authyouragent/v1/backchannel-logout (at once);
 *  - refresh: every page load after the access token expires refreshes it;
 *    a refused refresh signs the agent out (within 10 minutes).
 */
defined( 'ABSPATH' ) || exit;

class AYA_Logout {

	const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'route' ) );
		add_action( 'init', array( __CLASS__, 'refresh' ), 20 );
	}

	public static function route() {
		register_rest_route( 'authyouragent/v1', '/backchannel-logout', array(
			'methods'             => 'POST',
			'callback'            => array( __CLASS__, 'backchannel' ),
			'permission_callback' => '__return_true', // authenticated by the signed logout_token
		) );
	}

	public static function end_for( $uid ) {
		WP_Session_Tokens::get_instance( $uid )->destroy_all();
		delete_user_meta( $uid, 'aya_refresh' );
		delete_user_meta( $uid, 'aya_sid' );
	}

	public static function backchannel( WP_REST_Request $req ) {
		$tok = (string) $req->get_param( 'logout_token' );
		$c   = AYA_JWT::verify( $tok, aya_opt( 'client_id' ), 'logout+jwt' );
		$bad = function ( $why ) {
			return new WP_REST_Response( array( 'error' => 'invalid_request', 'error_description' => $why ), 400 );
		};
		if ( is_wp_error( $c ) ) {
			return $bad( $c->get_error_message() );
		}
		if ( ! isset( $c['events'][ self::EVENT ] ) || isset( $c['nonce'] ) || empty( $c['jti'] ) ) {
			return $bad( 'not a logout token' );
		}
		if ( empty( $c['sid'] ) && empty( $c['sub'] ) ) {
			return $bad( 'no sid or sub' );
		}
		$seen = 'aya_jti_' . hash( 'sha256', $c['jti'] );
		if ( get_transient( $seen ) ) {
			return $bad( 'token already used' );
		}
		set_transient( $seen, 1, 10 * MINUTE_IN_SECONDS );
		$q = ! empty( $c['sid'] ) ? array( 'meta_key' => 'aya_sid', 'meta_value' => $c['sid'] )
			: array( 'meta_key' => 'aya_owner_sub', 'meta_value' => $c['sub'] );
		foreach ( get_users( $q + array( 'fields' => 'ID' ) ) as $uid ) {
			self::end_for( (int) $uid );
		}
		return new WP_REST_Response( null, 200 );
	}

	public static function refresh() {
		if ( ! is_user_logged_in() || ! aya_configured() ) {
			return;
		}
		$uid = get_current_user_id();
		if ( ! aya_is_agent( $uid ) ) {
			return;
		}
		$exp = (int) get_user_meta( $uid, 'aya_at_exp', true );
		if ( $exp > time() ) {
			return;
		}
		$rt = get_user_meta( $uid, 'aya_refresh', true );
		if ( ! $rt ) {
			self::sign_out( $uid );
			return;
		}
		list( $status, $tok ) = AYA_Client::post( 'token_endpoint', array( 'grant_type' => 'refresh_token', 'refresh_token' => $rt ) );
		if ( 200 === $status && ! empty( $tok['access_token'] ) ) {
			update_user_meta( $uid, 'aya_refresh', $tok['refresh_token'] ?? $rt );
			update_user_meta( $uid, 'aya_at_exp', time() + (int) ( $tok['expires_in'] ?? 600 ) );
			return;
		}
		if ( 0 === $status ) {
			return; // provider unreachable: keep the session, try again next page
		}
		self::sign_out( $uid ); // invalid_grant: the owner withdrew access
	}

	private static function sign_out( $uid ) {
		self::end_for( $uid );
		wp_clear_auth_cookie();
		wp_set_current_user( 0 );
	}
}
