<?php
/**
 * "Sign in with Auth Your Agent": OpenID Connect authorization code flow
 * with PKCE, state bound to the browser, and nonce.
 *
 * The browser that signs in belongs to the AGENT. It gets its own WordPress
 * account (never an existing one), named for what it is, for example
 * "Jarvis (agent of James)", keyed by the agent's id for this site (act.sub).
 */
defined( 'ABSPATH' ) || exit;

class AYA_Login {

	const COOKIE = 'aya_login_state';

	public static function init() {
		add_action( 'login_form', array( __CLASS__, 'button' ) );
		add_action( 'woocommerce_login_form_end', array( __CLASS__, 'button' ) );
		add_action( 'login_form_authyouragent_start', array( __CLASS__, 'start' ) );
		add_action( 'login_form_authyouragent_callback', array( __CLASS__, 'callback' ) );
		add_shortcode( 'authyouragent_button', array( __CLASS__, 'shortcode' ) );
		add_filter( 'show_admin_bar', array( __CLASS__, 'no_admin_bar' ) );
	}

	public static function start_url( $redirect_to = '' ) {
		$args = array( 'action' => 'authyouragent_start' );
		if ( $redirect_to ) {
			$args['redirect_to'] = $redirect_to;
		}
		return add_query_arg( $args, wp_login_url() );
	}

	public static function button() {
		if ( ! aya_configured() ) {
			return;
		}
		$to = isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		if ( ! $to && function_exists( 'wc_get_page_permalink' ) && did_action( 'woocommerce_login_form_end' ) ) {
			$to = wc_get_page_permalink( 'myaccount' );
		}
		echo self::markup( $to ); // phpcs:ignore WordPress.Security.EscapeOutput
	}

	public static function shortcode() {
		return aya_configured() && ! is_user_logged_in() ? self::markup( get_permalink() ) : '';
	}

	private static function markup( $to ) {
		return '<p class="aya-signin" style="margin:12px 0"><a class="button aya-button" id="authyouragent-signin" href="'
			. esc_url( self::start_url( $to ) ) . '">' . esc_html( aya_opt( 'button_label' ) ) . '</a></p>'
			. '<p class="aya-note" style="font-size:12px;opacity:.75">' . esc_html__( 'For AI assistants acting for a customer. The customer approves on their phone.', 'authyouragent' ) . '</p>';
	}

	private static function b64u( $b ) {
		return rtrim( strtr( base64_encode( $b ), '+/', '-_' ), '=' );
	}

	public static function start() {
		if ( ! aya_configured() ) {
			wp_die( esc_html__( 'Auth Your Agent is not set up on this site.', 'authyouragent' ), 503 );
		}
		$auth = AYA_Client::endpoint( 'authorization_endpoint' );
		if ( ! $auth ) {
			wp_die( esc_html__( 'Auth Your Agent could not be reached. Try again shortly.', 'authyouragent' ), 503 );
		}
		$state    = self::b64u( random_bytes( 24 ) );
		$binding  = self::b64u( random_bytes( 24 ) );
		$nonce    = self::b64u( random_bytes( 24 ) );
		$verifier = self::b64u( random_bytes( 32 ) );
		$to       = isset( $_GET['redirect_to'] ) ? wp_validate_redirect( esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ), home_url( '/' ) ) : home_url( '/' ); // phpcs:ignore WordPress.Security.NonceVerification
		set_transient(
			'aya_st_' . hash( 'sha256', $state ),
			array(
				'binding'  => hash( 'sha256', $binding ),
				'nonce'    => $nonce,
				'verifier' => $verifier,
				'to'       => $to,
			),
			10 * MINUTE_IN_SECONDS
		);
		setcookie( self::COOKIE, $binding, array(
			'expires'  => time() + 10 * MINUTE_IN_SECONDS,
			'path'     => COOKIEPATH ? COOKIEPATH : '/',
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Lax',
		) );
		$url = add_query_arg(
			array(
				'response_type'         => 'code',
				'client_id'             => rawurlencode( aya_opt( 'client_id' ) ),
				'redirect_uri'          => rawurlencode( aya_redirect_uri() ),
				'scope'                 => rawurlencode( 'openid profile' ),
				'state'                 => $state,
				'nonce'                 => $nonce,
				'code_challenge'        => self::b64u( hash( 'sha256', $verifier, true ) ),
				'code_challenge_method' => 'S256',
			),
			$auth
		);
		wp_redirect( $url ); // phpcs:ignore WordPress.Security.SafeRedirect -- the provider is another site by design
		exit;
	}

	private static function fail( $msg ) {
		wp_die(
			'<p>' . esc_html( $msg ) . '</p><p><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Back to sign-in', 'authyouragent' ) . '</a></p>',
			esc_html__( 'Sign-in did not complete', 'authyouragent' ),
			array( 'response' => 403 )
		);
	}

	public static function callback() {
		// phpcs:disable WordPress.Security.NonceVerification -- OAuth state is the CSRF check
		$state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
		$key   = 'aya_st_' . hash( 'sha256', $state );
		$st    = $state ? get_transient( $key ) : false;
		delete_transient( $key );
		$bind = isset( $_COOKIE[ self::COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) : '';
		if ( ! $st || ! $bind || ! hash_equals( $st['binding'], hash( 'sha256', $bind ) ) ) {
			self::fail( __( 'This sign-in link expired or was opened in another browser. Start again.', 'authyouragent' ) );
		}
		setcookie( self::COOKIE, '', time() - 3600, COOKIEPATH ? COOKIEPATH : '/' );
		if ( isset( $_GET['error'] ) ) {
			$why = sanitize_text_field( wp_unslash( $_GET['error_description'] ?? $_GET['error'] ) );
			/* translators: %s: the reason Auth Your Agent gave */
			self::fail( sprintf( __( 'Auth Your Agent did not approve the sign-in: %s', 'authyouragent' ), $why ) );
		}
		$code = isset( $_GET['code'] ) ? sanitize_text_field( wp_unslash( $_GET['code'] ) ) : '';
		// phpcs:enable
		list( $status, $tok ) = AYA_Client::post(
			'token_endpoint',
			array(
				'grant_type'    => 'authorization_code',
				'code'          => $code,
				'redirect_uri'  => aya_redirect_uri(),
				'code_verifier' => $st['verifier'],
			)
		);
		if ( 200 !== $status || empty( $tok['id_token'] ) ) {
			/* translators: %s: error from the provider */
			self::fail( sprintf( __( 'Token exchange failed: %s', 'authyouragent' ), $tok['error_description'] ?? ( $tok['error'] ?? $status ) ) );
		}
		$c = AYA_JWT::verify( $tok['id_token'], aya_opt( 'client_id' ) );
		if ( is_wp_error( $c ) ) {
			self::fail( $c->get_error_message() );
		}
		if ( ( $c['nonce'] ?? '' ) !== $st['nonce'] ) {
			self::fail( __( 'The sign-in answer did not match this request.', 'authyouragent' ) );
		}
		$agent = $c['act']['sub'] ?? '';
		if ( ! $agent || empty( $c['sub'] ) ) {
			self::fail( __( 'The sign-in answer did not name an agent.', 'authyouragent' ) );
		}
		$uid = self::agent_user( $c );
		if ( is_wp_error( $uid ) ) {
			self::fail( $uid->get_error_message() );
		}
		update_user_meta( $uid, 'aya_owner_sub', $c['sub'] );
		update_user_meta( $uid, 'aya_sid', $c['sid'] ?? '' );
		update_user_meta( $uid, 'aya_refresh', $tok['refresh_token'] ?? '' );
		update_user_meta( $uid, 'aya_at_exp', time() + (int) ( $tok['expires_in'] ?? 600 ) );
		wp_set_current_user( $uid );
		wp_set_auth_cookie( $uid, false, is_ssl() );
		do_action( 'wp_login', get_userdata( $uid )->user_login, get_userdata( $uid ) );
		wp_safe_redirect( $st['to'] );
		exit;
	}

	/** The agent's own account: found by its id for this site, or created. Never an existing person's account. */
	private static function agent_user( $c ) {
		$found = get_users( array( 'meta_key' => 'aya_agent_sub', 'meta_value' => $c['act']['sub'], 'number' => 1, 'fields' => 'ID' ) );
		if ( $found ) {
			$uid = (int) $found[0];
			wp_update_user( array( 'ID' => $uid, 'display_name' => $c['name'] ?? '' ) );
			return $uid;
		}
		$base  = sanitize_user( $c['preferred_username'] ?? 'agent', true );
		$base  = $base ? $base : 'agent';
		$login = $base;
		for ( $i = 2; username_exists( $login ); $i++ ) {
			$login = $base . '-' . $i;
		}
		$role = aya_opt( 'role' );
		if ( ! $role ) {
			$role = get_role( 'customer' ) ? 'customer' : get_option( 'default_role', 'subscriber' );
		}
		if ( ! get_role( $role ) || get_role( $role )->has_cap( 'manage_options' ) || get_role( $role )->has_cap( 'edit_users' ) ) {
			return new WP_Error( 'aya_role', __( 'The role set for agents is not allowed.', 'authyouragent' ) );
		}
		$uid = wp_insert_user( array(
			'user_login'   => $login,
			'user_pass'    => wp_generate_password( 40, true, true ),
			'user_email'   => '',
			'display_name' => $c['name'] ?? $login,
			'nickname'     => $c['preferred_username'] ?? $login,
			'role'         => $role,
		) );
		if ( is_wp_error( $uid ) ) {
			return $uid;
		}
		update_user_meta( $uid, 'aya_agent_sub', $c['act']['sub'] );
		update_user_meta( $uid, 'aya_agent_name', $c['act']['name'] ?? '' );
		return $uid;
	}

	public static function no_admin_bar( $show ) {
		return is_user_logged_in() && aya_is_agent( get_current_user_id() ) ? false : $show;
	}
}
