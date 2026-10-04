<?php
/**
 * Talking to the Auth Your Agent provider: discovery, keys, token calls.
 * The client secret is sent with HTTP Basic auth (client_secret_basic).
 */
defined( 'ABSPATH' ) || exit;

class AYA_Client {

	public static function issuer() {
		return untrailingslashit( aya_opt( 'issuer' ) );
	}

	public static function discovery() {
		$d = get_transient( 'aya_discovery' );
		if ( is_array( $d ) && ( $d['issuer'] ?? '' ) === self::issuer() ) {
			return $d;
		}
		$r = wp_remote_get( self::issuer() . '/.well-known/openid-configuration', array( 'timeout' => 10 ) );
		if ( is_wp_error( $r ) || 200 !== wp_remote_retrieve_response_code( $r ) ) {
			return null;
		}
		$d = json_decode( wp_remote_retrieve_body( $r ), true );
		if ( ! is_array( $d ) || ( $d['issuer'] ?? '' ) !== self::issuer() ) {
			return null;
		}
		set_transient( 'aya_discovery', $d, HOUR_IN_SECONDS );
		return $d;
	}

	public static function endpoint( $name ) {
		$d = self::discovery();
		return $d[ $name ] ?? null;
	}

	/** PEM public key for $kid; refetches the key set once for an unknown kid. */
	public static function key( $kid ) {
		foreach ( array( false, true ) as $fresh ) {
			$set = $fresh ? null : get_transient( 'aya_jwks' );
			if ( ! is_array( $set ) ) {
				$uri = self::endpoint( 'jwks_uri' );
				if ( ! $uri ) {
					return null;
				}
				$r = wp_remote_get( $uri, array( 'timeout' => 10 ) );
				if ( is_wp_error( $r ) || 200 !== wp_remote_retrieve_response_code( $r ) ) {
					return null;
				}
				$set = json_decode( wp_remote_retrieve_body( $r ), true );
				if ( ! is_array( $set ) ) {
					return null;
				}
				set_transient( 'aya_jwks', $set, HOUR_IN_SECONDS );
			}
			foreach ( $set['keys'] ?? array() as $k ) {
				if ( ( $k['kid'] ?? '' ) === $kid && 'RSA' === ( $k['kty'] ?? '' ) ) {
					return AYA_JWT::jwk_to_pem( $k );
				}
			}
		}
		return null;
	}

	/** POST to a provider endpoint with client authentication. Returns [status, body array]. */
	public static function post( $endpoint, $fields ) {
		$url = self::endpoint( $endpoint );
		if ( ! $url ) {
			return array( 0, array( 'error' => 'unreachable', 'error_description' => 'Auth Your Agent could not be reached' ) );
		}
		$auth = base64_encode( rawurlencode( aya_opt( 'client_id' ) ) . ':' . rawurlencode( aya_opt( 'client_secret' ) ) );
		$r    = wp_remote_post(
			$url,
			array(
				'timeout' => 15,
				'headers' => array(
					'Authorization' => 'Basic ' . $auth,
					'Accept'        => 'application/json',
				),
				'body'    => $fields,
			)
		);
		if ( is_wp_error( $r ) ) {
			return array( 0, array( 'error' => 'unreachable', 'error_description' => $r->get_error_message() ) );
		}
		$body = json_decode( wp_remote_retrieve_body( $r ), true );
		return array( wp_remote_retrieve_response_code( $r ), is_array( $body ) ? $body : array() );
	}
}
