<?php
/**
 * RS256 JWT checks against the provider's published keys (JWKS).
 * No libraries: the JWK is turned into a PEM key for openssl_verify().
 */
defined( 'ABSPATH' ) || exit;

class AYA_JWT {

	public static function b64d( $s ) {
		$s = strtr( $s, '-_', '+/' );
		return base64_decode( $s . str_repeat( '=', ( 4 - strlen( $s ) % 4 ) % 4 ), true );
	}

	private static function der_len( $n ) {
		if ( $n < 128 ) {
			return chr( $n );
		}
		$s = ltrim( pack( 'N', $n ), "\0" );
		return chr( 0x80 | strlen( $s ) ) . $s;
	}

	private static function der_int( $b ) {
		if ( ord( $b[0] ) > 0x7f ) {
			$b = "\0" . $b;
		}
		return "\x02" . self::der_len( strlen( $b ) ) . $b;
	}

	/** RSA JWK (n, e) -> PEM SubjectPublicKeyInfo. */
	public static function jwk_to_pem( $jwk ) {
		$n = self::b64d( $jwk['n'] );
		$e = self::b64d( $jwk['e'] );
		if ( ! $n || ! $e ) {
			return null;
		}
		$rsa   = self::der_int( $n ) . self::der_int( $e );
		$rsa   = "\x30" . self::der_len( strlen( $rsa ) ) . $rsa;
		$bits  = "\x00" . $rsa;
		$bits  = "\x03" . self::der_len( strlen( $bits ) ) . $bits;
		$alg   = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
		$spki  = $alg . $bits;
		$spki  = "\x30" . self::der_len( strlen( $spki ) ) . $spki;
		return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $spki ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
	}

	/**
	 * Verify signature, issuer, audience and lifetime. Returns the claims
	 * array or a WP_Error. $typ, when given, must match the header's typ.
	 */
	public static function verify( $token, $audience, $typ = null ) {
		$parts = explode( '.', (string) $token );
		if ( 3 !== count( $parts ) ) {
			return new WP_Error( 'aya_jwt', 'not a JWT' );
		}
		$h = json_decode( self::b64d( $parts[0] ), true );
		$c = json_decode( self::b64d( $parts[1] ), true );
		$s = self::b64d( $parts[2] );
		if ( ! is_array( $h ) || ! is_array( $c ) || false === $s ) {
			return new WP_Error( 'aya_jwt', 'malformed JWT' );
		}
		if ( 'RS256' !== ( $h['alg'] ?? '' ) ) {
			return new WP_Error( 'aya_jwt', 'unexpected algorithm' );
		}
		if ( $typ && strtolower( $h['typ'] ?? '' ) !== strtolower( $typ ) ) {
			return new WP_Error( 'aya_jwt', 'unexpected token type' );
		}
		$key = AYA_Client::key( $h['kid'] ?? '' );
		if ( ! $key ) {
			return new WP_Error( 'aya_jwt', 'unknown signing key' );
		}
		if ( 1 !== openssl_verify( $parts[0] . '.' . $parts[1], $s, $key, OPENSSL_ALGO_SHA256 ) ) {
			return new WP_Error( 'aya_jwt', 'bad signature' );
		}
		$now = time();
		$aud = (array) ( $c['aud'] ?? array() );
		if ( ( $c['iss'] ?? '' ) !== AYA_Client::issuer() ) {
			return new WP_Error( 'aya_jwt', 'wrong issuer' );
		}
		if ( ! in_array( $audience, $aud, true ) ) {
			return new WP_Error( 'aya_jwt', 'wrong audience' );
		}
		if ( isset( $c['exp'] ) && $c['exp'] < $now - 30 ) {
			return new WP_Error( 'aya_jwt', 'expired' );
		}
		if ( ! isset( $c['iat'] ) || $c['iat'] > $now + 60 ) {
			return new WP_Error( 'aya_jwt', 'issued in the future' );
		}
		return $c;
	}
}
