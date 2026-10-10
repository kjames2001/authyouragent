<?php
/**
 * Web Bot Auth (draft-ietf-webbotauth-httpsig-protocol-00, on HTTP Message
 * Signatures, RFC 9421): check the signature ANY agent puts on its requests.
 * A PHP port of the verifier in the Auth Your Agent Python and JavaScript
 * SDKs, with the same outcomes and limits:
 *
 *   verified   the signature checks out against a key the agent's address publishes
 *   invalid    wrong, expired, made for another page or method, or a published test key
 *   unverified not enough to decide (key list unreachable, key not in it, ...)
 *   unsigned   no Web Bot Auth signature
 *
 * Ed25519 (sodium, which WordPress also polyfills), ECDSA P-256/P-384 and
 * RSA (PKCS#1 v1.5 via openssl; PSS checked here on a raw RSA operation).
 * Key lists are fetched over HTTPS from public addresses only (the connection
 * is pinned to the checked address when cURL is the transport), 5 s, 64 kB,
 * no redirects, cached as their Cache-Control says.
 */
defined( 'ABSPATH' ) || exit;

class AYA_WBA_Invalid extends Exception {}
class AYA_WBA_Unverified extends Exception {}

/** The RFC 8941 subset RFC 9421 needs. Bare values: array( 't' => str|tok|bytes|bool|num, 'v' => ..., 'i' => is integer ). */
final class AYA_SFV {
	private $s;
	private $i = 0;

	private function __construct( $s ) {
		if ( preg_match( '/[^\x20-\x7e\t]/', $s ) ) {
			throw new UnexpectedValueException( 'non-ASCII or control character in field' );
		}
		$this->s = $s;
	}

	private function peek() {
		return $this->i < strlen( $this->s ) ? $this->s[ $this->i ] : '';
	}

	private function sp() {
		while ( ' ' === $this->peek() ) {
			$this->i++;
		}
	}

	private function ows() {
		while ( ' ' === $this->peek() || "\t" === $this->peek() ) {
			$this->i++;
		}
	}

	private function re( $pattern, $what ) {
		if ( ! preg_match( $pattern . 'A', $this->s, $m, 0, $this->i ) ) {
			throw new UnexpectedValueException( "bad $what at {$this->i}" );
		}
		$this->i += strlen( $m[0] );
		return $m;
	}

	private function key() {
		return $this->re( '/[a-z*][a-z0-9_\-.*]*/', 'key' )[0];
	}

	private function bare() {
		$c = $this->peek();
		if ( '"' === $c ) {
			$this->i++;
			$out = '';
			for ( ;; ) {
				if ( $this->i >= strlen( $this->s ) ) {
					throw new UnexpectedValueException( 'unterminated string' );
				}
				$c = $this->s[ $this->i++ ];
				if ( '\\' === $c ) {
					$n = $this->peek();
					if ( '"' !== $n && '\\' !== $n ) {
						throw new UnexpectedValueException( 'bad escape' );
					}
					$out .= $n;
					$this->i++;
				} elseif ( '"' === $c ) {
					return array( 't' => 'str', 'v' => $out );
				} else {
					$out .= $c;
				}
			}
		}
		if ( ':' === $c ) {
			$end = strpos( $this->s, ':', $this->i + 1 );
			if ( false === $end ) {
				throw new UnexpectedValueException( 'unterminated byte sequence' );
			}
			$raw = substr( $this->s, $this->i + 1, $end - $this->i - 1 );
			if ( ! preg_match( '#^[A-Za-z0-9+/=]*$#', $raw ) ) {
				throw new UnexpectedValueException( 'bad byte sequence' );
			}
			$this->i = $end + 1;
			$b       = base64_decode( rtrim( $raw, '=' ) . str_repeat( '=', ( 4 - strlen( rtrim( $raw, '=' ) ) % 4 ) % 4 ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
			if ( false === $b ) {
				throw new UnexpectedValueException( 'bad base64' );
			}
			return array( 't' => 'bytes', 'v' => $b );
		}
		if ( '?' === $c ) {
			$v = substr( $this->s, $this->i + 1, 1 );
			if ( '0' !== $v && '1' !== $v ) {
				throw new UnexpectedValueException( 'bad boolean' );
			}
			$this->i += 2;
			return array( 't' => 'bool', 'v' => '1' === $v );
		}
		if ( '-' === $c || ( $c >= '0' && $c <= '9' && '' !== $c ) ) {
			$m = $this->re( '/-?[0-9]{1,15}(\.[0-9]{1,3})?/', 'number' );
			return isset( $m[1] ) ? array( 't' => 'num', 'v' => (float) $m[0], 'i' => false ) : array( 't' => 'num', 'v' => (int) $m[0], 'i' => true );
		}
		return array( 't' => 'tok', 'v' => $this->re( '#[A-Za-z*][!\#$%&\'*+\-.^_`|~0-9A-Za-z:/]*#', 'item' )[0] );
	}

	private function params() {
		$out = array();
		while ( ';' === $this->peek() ) {
			$this->i++;
			$this->sp();
			$k = $this->key();
			$v = array( 't' => 'bool', 'v' => true );
			if ( '=' === $this->peek() ) {
				$this->i++;
				$v = $this->bare();
			}
			$out[ $k ] = $v;
		}
		return $out;
	}

	private function item() {
		$v = $this->bare();
		return array( $v, $this->params() );
	}

	private function member() {
		if ( '(' !== $this->peek() ) {
			return $this->item();
		}
		$this->i++;
		$items = array();
		for ( ;; ) {
			$this->sp();
			if ( ')' === $this->peek() ) {
				$this->i++;
				return array( array( 't' => 'list', 'v' => $items ), $this->params() );
			}
			$items[] = $this->item();
			if ( ' ' !== $this->peek() && ')' !== $this->peek() ) {
				throw new UnexpectedValueException( 'bad inner list' );
			}
		}
	}

	/** Dictionary -> array( key => array( value, params ) ). Later duplicates win. */
	public static function dict( $s ) {
		$p = new self( (string) $s );
		$p->sp();
		$out = array();
		if ( '' === $p->peek() ) {
			return $out;
		}
		for ( ;; ) {
			$k = $p->key();
			if ( '=' === $p->peek() ) {
				$p->i++;
				$out[ $k ] = $p->member();
			} else {
				$out[ $k ] = array( array( 't' => 'bool', 'v' => true ), $p->params() );
			}
			$p->ows();
			if ( '' === $p->peek() ) {
				return $out;
			}
			if ( ',' !== $p->peek() ) {
				throw new UnexpectedValueException( "expected ',' at {$p->i}" );
			}
			$p->i++;
			$p->ows();
			if ( '' === $p->peek() ) {
				throw new UnexpectedValueException( 'trailing comma' );
			}
		}
	}

	public static function item_of( $s ) {
		$p = new self( (string) $s );
		$p->sp();
		$v = $p->item();
		$p->sp();
		if ( '' !== $p->peek() ) {
			throw new UnexpectedValueException( 'trailing characters' );
		}
		return $v;
	}

	public static function ser_bare( $v ) {
		switch ( $v['t'] ) {
			case 'bool':
				return $v['v'] ? '?1' : '?0';
			case 'tok':
				return $v['v'];
			case 'num':
				return $v['i'] ? (string) $v['v'] : rtrim( rtrim( number_format( $v['v'], 3, '.', '' ), '0' ), '.' );
			case 'bytes':
				return ':' . base64_encode( $v['v'] ) . ':'; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
			case 'str':
				return '"' . str_replace( array( '\\', '"' ), array( '\\\\', '\\"' ), $v['v'] ) . '"';
		}
		throw new UnexpectedValueException( 'cannot serialise' );
	}

	public static function ser_params( $params ) {
		$out = '';
		foreach ( $params as $k => $v ) {
			$out .= ( 'bool' === $v['t'] && true === $v['v'] ) ? ";$k" : ";$k=" . self::ser_bare( $v );
		}
		return $out;
	}

	public static function ser_item( $v, $params ) {
		return self::ser_bare( $v ) . self::ser_params( $params );
	}

	public static function ser_member( $m ) {
		list( $v, $params ) = $m;
		if ( 'list' === $v['t'] ) {
			$parts = array();
			foreach ( $v['v'] as $it ) {
				$parts[] = self::ser_item( $it[0], $it[1] );
			}
			return '(' . implode( ' ', $parts ) . ')' . self::ser_params( $params );
		}
		return self::ser_item( $v, $params );
	}
}

class AYA_WBA {

	const TAG        = 'web-bot-auth';
	const DIR_TAG    = 'http-message-signatures-directory';
	const WELL_KNOWN = '/.well-known/http-message-signatures-directory';
	const MEDIA_TYPE = 'application/http-message-signatures-directory+json';
	const UA         = 'authyouragent-wordpress (+https://authyouragent.com/docs/developers/web-bot-auth)';

	/** Thumbprints of the RFC 9421 Appendix B.1 example keys. Draft 6.8: refuse them. */
	const TEST_KEYS = array(
		'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U',
		'oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA',
		'BHj8s0GPnMEQtkaULIM-PLgEhLBbuGUQ1vMxmBWZzEo',
		'ydQXMtvbsOsZyFir-Y7A8t7fKEM1gbKPvyFkdpu4fvI',
	);

	public $o;

	public function __construct( $opt = array() ) {
		$this->o = array_merge(
			array(
				'max_lifetime'    => 86400,
				'clock_skew'      => 60,
				'timeout'         => 5,
				'max_bytes'       => 65536,
				'max_keys'        => 32,
				'default_ttl'     => 300,
				'min_ttl'         => 60,
				'max_ttl'         => 86400,
				'max_stale'       => 86400,
				'negative_ttl'    => 60,
				'refetch_after'   => 60,
				'allow_test_keys' => false,
				'allow_private'   => false,
				'cache'           => true,
			),
			$opt
		);
	}

	/* ── small helpers ── */

	public static function b64u( $b ) {
		return rtrim( strtr( base64_encode( $b ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
	}

	public static function unb64u( $s ) {
		if ( ! is_string( $s ) ) {
			return false;
		}
		$s = strtr( $s, '-_', '+/' );
		return base64_decode( $s . str_repeat( '=', ( 4 - strlen( $s ) % 4 ) % 4 ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
	}

	public static function result( $outcome, $reason = '', $extra = array() ) {
		return array_merge(
			array(
				'outcome'         => $outcome,
				'verified'        => 'verified' === $outcome,
				'reason'          => $reason,
				'agent'           => null,
				'signature_agent' => null,
				'keyid'           => null,
				'label'           => null,
				'domain_proof'    => null,
				'stale'           => false,
				'created'         => null,
				'expires'         => null,
				'others'          => array(),
			),
			$extra
		);
	}

	/** Split an absolute URL without normalising it (@path and @query are the bytes sent). */
	public static function url_parts( $url ) {
		if ( ! preg_match( '#^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?\#]*)([^?\#]*)(?:\?([^\#]*))?#', (string) $url, $m ) ) {
			throw new AYA_WBA_Unverified( 'not an absolute URL' );
		}
		$auth     = $m[2];
		$userinfo = false;
		$at       = strrpos( $auth, '@' );
		if ( false !== $at ) {
			$userinfo = true;
			$auth     = substr( $auth, $at + 1 );
		}
		if ( ! preg_match( '#^(\[[^\]]*\]|[^:]*)(?::(\d*))?$#', $auth, $hm ) ) {
			throw new AYA_WBA_Unverified( 'bad authority' );
		}
		$port = null;
		if ( isset( $hm[2] ) && '' !== $hm[2] ) {
			$port = (int) $hm[2];
			if ( strlen( $hm[2] ) > 5 || $port > 65535 ) {
				throw new AYA_WBA_Unverified( 'bad port' );
			}
		}
		return array(
			'scheme'    => strtolower( $m[1] ),
			'host'      => strtolower( trim( $hm[1], '[]' ) ),
			'port'      => $port,
			'path'      => $m[3],
			'query'     => isset( $m[4] ) ? $m[4] : '',
			'has_query' => isset( $m[4] ),
			'userinfo'  => $userinfo,
		);
	}

	public static function authority( $url ) {
		$u    = self::url_parts( $url );
		$host = false !== strpos( $u['host'], ':' ) ? '[' . $u['host'] . ']' : $u['host'];
		if ( $u['port'] && ! ( ( 'https' === $u['scheme'] && 443 === $u['port'] ) || ( 'http' === $u['scheme'] && 80 === $u['port'] ) ) ) {
			$host .= ':' . $u['port'];
		}
		return $host;
	}

	/** RFC 7638 thumbprint for Ed25519, EC and RSA JWKs. */
	public static function thumbprint( $jwk ) {
		if ( 'RSA' === $jwk['kty'] ) {
			$c = array( 'e' => $jwk['e'], 'kty' => 'RSA', 'n' => $jwk['n'] );
		} elseif ( 'EC' === $jwk['kty'] ) {
			$c = array( 'crv' => $jwk['crv'], 'kty' => 'EC', 'x' => $jwk['x'], 'y' => $jwk['y'] );
		} else {
			$c = array( 'crv' => $jwk['crv'], 'kty' => $jwk['kty'], 'x' => $jwk['x'] );
		}
		return self::b64u( hash( 'sha256', wp_json_encode( $c, JSON_UNESCAPED_SLASHES ), true ) );
	}

	private static function form_encode( $s ) {
		$out = '';
		$n   = strlen( $s );
		for ( $i = 0; $i < $n; $i++ ) {
			$c    = $s[ $i ];
			$out .= preg_match( '/[A-Za-z0-9*\-._]/', $c ) ? $c : '%' . strtoupper( bin2hex( $c ) );
		}
		return $out;
	}

	private static function parse_query( $q ) {
		$out = array();
		foreach ( explode( '&', $q ) as $p ) {
			if ( '' === $p ) {
				continue;
			}
			$i     = strpos( $p, '=' );
			$k     = false === $i ? $p : substr( $p, 0, $i );
			$v     = false === $i ? '' : substr( $p, $i + 1 );
			$out[] = array( rawurldecode( str_replace( '+', ' ', $k ) ), rawurldecode( str_replace( '+', ' ', $v ) ) );
		}
		return $out;
	}

	/* ── the signature base (RFC 9421 2.5) ── */

	private static function field( $headers, $name ) {
		return isset( $headers[ $name ] ) ? trim( $headers[ $name ], " \t" ) : null;
	}

	private static function component( $method, $url, $headers, $name, $p ) {
		if ( '@' === substr( $name, 0, 1 ) ) {
			foreach ( array_keys( $p ) as $k ) {
				if ( ! ( '@query-param' === $name && 'name' === $k ) ) {
					throw new AYA_WBA_Unverified( "component parameter $k on $name not supported" );
				}
			}
			$u = self::url_parts( $url );
			switch ( $name ) {
				case '@method':
					return $method;
				case '@target-uri':
					return $url;
				case '@authority':
					return self::authority( $url );
				case '@scheme':
					return $u['scheme'];
				case '@path':
					return '' === $u['path'] ? '/' : $u['path'];
				case '@query':
					return '?' . $u['query'];
				case '@request-target':
					return ( '' === $u['path'] ? '/' : $u['path'] ) . ( '' !== $u['query'] ? '?' . $u['query'] : '' );
				case '@query-param':
					if ( empty( $p['name'] ) || 'str' !== $p['name']['t'] ) {
						throw new AYA_WBA_Invalid( '@query-param needs a name' );
					}
					$hits = array();
					foreach ( self::parse_query( $u['query'] ) as $kv ) {
						if ( self::form_encode( $kv[0] ) === $p['name']['v'] ) {
							$hits[] = $kv[1];
						}
					}
					if ( 1 !== count( $hits ) ) {
						throw new AYA_WBA_Invalid( 'query parameter ' . $p['name']['v'] . ( $hits ? ' repeated' : ' missing' ) );
					}
					return self::form_encode( $hits[0] );
			}
			throw new AYA_WBA_Unverified( "component $name not supported" );
		}
		foreach ( array_keys( $p ) as $k ) {
			if ( 'key' !== $k ) {
				throw new AYA_WBA_Unverified( "component parameter $k on $name not supported" );
			}
		}
		$raw = self::field( $headers, $name );
		if ( null === $raw ) {
			throw new AYA_WBA_Invalid( "covered header $name is missing" );
		}
		if ( isset( $p['key'] ) ) {
			try {
				$d = AYA_SFV::dict( $raw );
			} catch ( UnexpectedValueException $e ) {
				throw new AYA_WBA_Invalid( "header $name is not a dictionary" );
			}
			if ( ! array_key_exists( $p['key']['v'], $d ) ) {
				throw new AYA_WBA_Invalid( "header $name has no member " . $p['key']['v'] );
			}
			return AYA_SFV::ser_member( $d[ $p['key']['v'] ] );
		}
		return $raw;
	}

	public static function base( $method, $url, $headers, $member ) {
		$lines = array();
		foreach ( $member[0]['v'] as $it ) {
			list( $n, $p ) = $it;
			if ( 'str' !== $n['t'] || strtolower( $n['v'] ) !== $n['v'] ) {
				throw new AYA_WBA_Invalid( 'component names must be lower-case strings' );
			}
			$val = self::component( $method, $url, $headers, $n['v'], $p );
			if ( false !== strpbrk( $val, "\r\n" ) ) {
				throw new AYA_WBA_Invalid( 'component ' . $n['v'] . ' contains a line break' );
			}
			$lines[] = AYA_SFV::ser_item( $n, $p ) . ': ' . $val;
		}
		$lines[] = '"@signature-params": ' . AYA_SFV::ser_member( $member );
		return implode( "\n", $lines );
	}

	/* ── keys ── */

	private static function der_len( $n ) {
		if ( $n < 128 ) {
			return chr( $n );
		}
		$s = ltrim( pack( 'N', $n ), "\0" );
		return chr( 0x80 | strlen( $s ) ) . $s;
	}

	private static function der_int( $b ) {
		$b = ltrim( $b, "\0" );
		if ( '' === $b || ord( $b[0] ) > 0x7f ) {
			$b = "\0" . $b;
		}
		return "\x02" . self::der_len( strlen( $b ) ) . $b;
	}

	private static function pem( $spki ) {
		return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $spki ), 64, "\n" ) . "-----END PUBLIC KEY-----\n"; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
	}

	/** A key list entry -> array( thumbprint, kind, material ) or null. Material is storable (strings only). */
	public static function load_jwk( $jwk ) {
		if ( ! is_array( $jwk ) ) {
			return null;
		}
		foreach ( array( 'd', 'p', 'q', 'k' ) as $priv ) {
			if ( array_key_exists( $priv, $jwk ) ) {
				return null;
			}
		}
		$kty = $jwk['kty'] ?? '';
		if ( 'OKP' === $kty && 'Ed25519' === ( $jwk['crv'] ?? '' ) ) {
			$x = self::unb64u( $jwk['x'] ?? null );
			return ( false !== $x && 32 === strlen( $x ) ) ? array( self::thumbprint( $jwk ), 'ed25519', base64_encode( $x ) ) : null; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		}
		if ( 'EC' === $kty && in_array( $jwk['crv'] ?? '', array( 'P-256', 'P-384' ), true ) ) {
			$n = 'P-256' === $jwk['crv'] ? 32 : 48;
			$x = self::unb64u( $jwk['x'] ?? null );
			$y = self::unb64u( $jwk['y'] ?? null );
			if ( false === $x || false === $y || strlen( $x ) !== $n || strlen( $y ) !== $n ) {
				return null;
			}
			$curve = 32 === $n ? "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07" : "\x06\x05\x2b\x81\x04\x00\x22";
			$alg   = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" . $curve;
			$alg   = "\x30" . self::der_len( strlen( $alg ) ) . $alg;
			$bits  = "\x00\x04" . $x . $y;
			$spki  = $alg . "\x03" . self::der_len( strlen( $bits ) ) . $bits;
			$pem   = self::pem( "\x30" . self::der_len( strlen( $spki ) ) . $spki );
			return openssl_pkey_get_public( $pem ) ? array( self::thumbprint( $jwk ), $jwk['crv'], $pem ) : null;
		}
		if ( 'RSA' === $kty && is_string( $jwk['n'] ?? null ) && is_string( $jwk['e'] ?? null ) ) {
			$n = self::unb64u( $jwk['n'] );
			$e = self::unb64u( $jwk['e'] );
			if ( false === $n || false === $e ) {
				return null;
			}
			$n = ltrim( $n, "\0" );
			if ( '' === $n || ( strlen( $n ) - 1 ) * 8 + strlen( decbin( ord( $n[0] ) ) ) < 2048 ) {
				return null;
			}
			$rsa  = self::der_int( $n ) . self::der_int( $e );
			$rsa  = "\x30" . self::der_len( strlen( $rsa ) ) . $rsa;
			$bits = "\x00" . $rsa;
			$spki = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03" . self::der_len( strlen( $bits ) ) . $bits;
			$pem  = self::pem( "\x30" . self::der_len( strlen( $spki ) ) . $spki );
			return openssl_pkey_get_public( $pem ) ? array( self::thumbprint( $jwk ), 'RSA:' . ( $jwk['alg'] ?? '' ), $pem ) : null;
		}
		return null;
	}

	/** RFC 8017 EMSA-PSS-VERIFY with SHA-512, MGF1-SHA-512, salt 64 (rsa-pss-sha512). */
	private static function pss_sha512_ok( $pem, $sig, $msg ) {
		$key = openssl_pkey_get_public( $pem );
		$det = $key ? openssl_pkey_get_details( $key ) : null;
		if ( ! $det || empty( $det['rsa']['n'] ) ) {
			return false;
		}
		$n      = ltrim( $det['rsa']['n'], "\0" );
		$k      = strlen( $n );
		$mod    = ( $k - 1 ) * 8 + strlen( decbin( ord( $n[0] ) ) );
		$em_bit = $mod - 1;
		$em_len = (int) ceil( $em_bit / 8 );
		if ( strlen( $sig ) !== $k || ! openssl_public_decrypt( $sig, $m, $key, OPENSSL_NO_PADDING ) ) {
			return false;
		}
		$m = str_pad( $m, $k, "\0", STR_PAD_LEFT );
		if ( $em_len < $k && "\0" !== substr( $m, 0, $k - $em_len ) ) {
			return false;
		}
		$em = substr( $m, $k - $em_len );
		$h  = 64;
		$s  = 64;
		if ( $em_len < $h + $s + 2 || "\xbc" !== substr( $em, -1 ) ) {
			return false;
		}
		$masked = substr( $em, 0, $em_len - $h - 1 );
		$hh     = substr( $em, $em_len - $h - 1, $h );
		$zbits  = 8 * $em_len - $em_bit;
		$top    = 0xff >> $zbits;
		if ( ord( $masked[0] ) & ~$top & 0xff ) {
			return false;
		}
		$mask = '';
		for ( $c = 0; strlen( $mask ) < strlen( $masked ); $c++ ) {
			$mask .= hash( 'sha512', $hh . pack( 'N', $c ), true );
		}
		$db    = $masked ^ substr( $mask, 0, strlen( $masked ) );
		$db[0] = chr( ord( $db[0] ) & $top );
		$ps    = $em_len - $h - $s - 2;
		if ( str_repeat( "\0", $ps ) !== substr( $db, 0, $ps ) || "\x01" !== $db[ $ps ] ) {
			return false;
		}
		$salt = substr( $db, -$s );
		return hash_equals( $hh, hash( 'sha512', str_repeat( "\0", 8 ) . hash( 'sha512', $msg, true ) . $salt, true ) );
	}

	public static function check_sig( $kind, $material, $alg_item, $sig, $base ) {
		if ( $alg_item && 'str' !== $alg_item['t'] ) {
			throw new AYA_WBA_Invalid( 'alg must be a string' );
		}
		$alg = $alg_item ? $alg_item['v'] : null;
		if ( 'hmac-sha256' === $alg ) {
			throw new AYA_WBA_Invalid( 'shared-secret signatures are not allowed (draft 6.4)' );
		}
		if ( 'RSA:' === substr( $kind, 0, 4 ) ) {
			$map = array( 'PS512' => 'rsa-pss-sha512', 'RS256' => 'rsa-v1_5-sha256' );
			$alg = $alg ? $alg : ( $map[ substr( $kind, 4 ) ] ?? null );
			if ( 'rsa-pss-sha512' !== $alg && 'rsa-v1_5-sha256' !== $alg ) {
				throw new AYA_WBA_Invalid( 'RSA signature without a usable alg' );
			}
		} else {
			$ok  = array( 'ed25519' => 'ed25519', 'P-256' => 'ecdsa-p256-sha256', 'P-384' => 'ecdsa-p384-sha384' );
			$alg = $alg ? $alg : $ok[ $kind ];
			if ( $alg !== $ok[ $kind ] ) {
				throw new AYA_WBA_Invalid( "alg $alg does not match the $kind key" );
			}
		}
		$good = false;
		if ( 'ed25519' === $alg ) {
			$good = 64 === strlen( $sig ) && sodium_crypto_sign_verify_detached( $sig, $base, base64_decode( $material ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
		} elseif ( 'rsa-pss-sha512' === $alg ) {
			$good = self::pss_sha512_ok( $material, $sig, $base );
		} elseif ( 'rsa-v1_5-sha256' === $alg ) {
			$good = 1 === openssl_verify( $base, $sig, $material, OPENSSL_ALGO_SHA256 );
		} else {
			$n = 'ecdsa-p256-sha256' === $alg ? 32 : 48;
			if ( strlen( $sig ) === 2 * $n ) {
				$der  = self::der_int( substr( $sig, 0, $n ) ) . self::der_int( substr( $sig, $n ) );
				$der  = "\x30" . self::der_len( strlen( $der ) ) . $der;
				$good = 1 === openssl_verify( $base, $der, $material, 32 === $n ? OPENSSL_ALGO_SHA256 : OPENSSL_ALGO_SHA384 );
			}
		}
		if ( ! $good ) {
			throw new AYA_WBA_Invalid( 'signature does not verify' );
		}
	}

	/* ── fetching key lists (draft 6.7) ── */

	public static function is_public_ip( $ip ) {
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$b = inet_pton( $ip );
			if ( substr( $b, 0, 12 ) === str_repeat( "\0", 10 ) . "\xff\xff" ) {
				return self::is_public_ip( inet_ntop( substr( $b, 12 ) ) );
			}
			$g0 = ( ord( $b[0] ) << 8 ) | ord( $b[1] );
			$g1 = ( ord( $b[2] ) << 8 ) | ord( $b[3] );
			if ( 0x2000 !== ( $g0 & 0xe000 ) || ( 0x2001 === $g0 && ( 0x0db8 === $g1 || $g1 < 0x0200 ) ) || 0x2002 === $g0 ) {
				return false;
			}
			return true;
		}
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return false;
		}
		$a = array_map( 'intval', explode( '.', $ip ) );
		return ! ( 0 === $a[0] || 10 === $a[0] || 127 === $a[0] || $a[0] >= 224
			|| ( 100 === $a[0] && $a[1] >= 64 && $a[1] <= 127 ) || ( 169 === $a[0] && 254 === $a[1] )
			|| ( 172 === $a[0] && $a[1] >= 16 && $a[1] <= 31 ) || ( 192 === $a[0] && 168 === $a[1] )
			|| ( 192 === $a[0] && 0 === $a[1] && in_array( $a[2], array( 0, 2 ), true ) ) || ( 192 === $a[0] && 88 === $a[1] && 99 === $a[2] )
			|| ( 198 === $a[0] && in_array( $a[1], array( 18, 19 ), true ) ) || ( 198 === $a[0] && 51 === $a[1] && 100 === $a[2] )
			|| ( 203 === $a[0] && 0 === $a[1] && 113 === $a[2] ) );
	}

	private static function resolve_host( $host ) {
		if ( filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return array( $host );
		}
		$ips = array();
		foreach ( (array) @dns_get_record( $host, DNS_A | DNS_AAAA ) as $r ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( ! empty( $r['ip'] ) ) {
				$ips[] = $r['ip'];
			} elseif ( ! empty( $r['ipv6'] ) ) {
				$ips[] = $r['ipv6'];
			}
		}
		if ( ! $ips ) {
			$ips = (array) gethostbynamel( $host );
		}
		return array_values( array_filter( $ips ) );
	}

	/** GET one https URL with the draft's limits. Returns array( status, headers (lower-case => string), body ). */
	public function https_get( $url ) {
		$pre = apply_filters( 'authyouragent_wba_fetch', null, $url );
		if ( null !== $pre ) {
			if ( $pre instanceof Exception ) {
				throw new AYA_WBA_Unverified( 'fetching the key list failed: ' . $pre->getMessage() );
			}
			return $pre;
		}
		$u = self::url_parts( $url );
		if ( 'https' !== $u['scheme'] || '' === $u['host'] ) {
			throw new AYA_WBA_Unverified( 'key list must be fetched over https' );
		}
		$ips    = self::resolve_host( $u['host'] );
		$usable = $this->o['allow_private'] ? $ips : array_values( array_filter( $ips, array( __CLASS__, 'is_public_ip' ) ) );
		if ( ! $usable ) {
			throw new AYA_WBA_Unverified( $ips ? $u['host'] . ' resolves only to non-public addresses' : 'cannot resolve ' . $u['host'] );
		}
		$port = $u['port'] ? $u['port'] : 443;
		$pin  = $usable[0];
		// connect to the address that was checked, so DNS rebinding cannot swap it
		$cb = function ( $handle ) use ( $u, $port, $pin ) {
			if ( defined( 'CURLOPT_RESOLVE' ) ) {
				curl_setopt( $handle, CURLOPT_RESOLVE, array( $u['host'] . ':' . $port . ':' . ( false !== strpos( $pin, ':' ) ? "[$pin]" : $pin ) ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			}
		};
		add_action( 'http_api_curl', $cb );
		$r = wp_remote_get(
			$url,
			array(
				'timeout'             => $this->o['timeout'],
				'redirection'         => 0,
				'limit_response_size' => $this->o['max_bytes'] + 1,
				'decompress'          => false,
				'sslverify'           => true,
				'user-agent'          => self::UA,
				'headers'             => array(
					'Accept'          => self::MEDIA_TYPE,
					'Accept-Encoding' => 'identity',
				),
			)
		);
		remove_action( 'http_api_curl', $cb );
		if ( is_wp_error( $r ) ) {
			$m = $r->get_error_message();
			throw new AYA_WBA_Unverified( preg_match( '/timed? ?out/i', $m ) ? 'key list fetch timed out' : 'fetching the key list failed: ' . $m );
		}
		$hdrs = array();
		foreach ( wp_remote_retrieve_headers( $r ) as $k => $v ) {
			$hdrs[ strtolower( $k ) ] = is_array( $v ) ? implode( ', ', $v ) : (string) $v;
		}
		$body = wp_remote_retrieve_body( $r );
		if ( strlen( $body ) > $this->o['max_bytes'] ) {
			throw new AYA_WBA_Unverified( 'key list larger than ' . $this->o['max_bytes'] . ' bytes' );
		}
		$enc = strtolower( trim( $hdrs['content-encoding'] ?? 'identity' ) );
		if ( 'gzip' === $enc || 'x-gzip' === $enc || 'deflate' === $enc ) {
			$body = 'deflate' === $enc ? @gzuncompress( $body, $this->o['max_bytes'] + 1 ) : @gzdecode( $body, $this->o['max_bytes'] + 1 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false === $body || strlen( $body ) > $this->o['max_bytes'] ) {
				throw new AYA_WBA_Unverified( 'key list larger than ' . $this->o['max_bytes'] . ' bytes, or not decodable' );
			}
		} elseif ( '' !== $enc && 'identity' !== $enc ) {
			throw new AYA_WBA_Unverified( "key list sent with unsupported content-encoding $enc" );
		}
		return array( (int) wp_remote_retrieve_response_code( $r ), $hdrs, $body );
	}

	/* ── key lists ── */

	private static function origin( $u ) {
		$host = false !== strpos( $u['host'], ':' ) ? '[' . $u['host'] . ']' : $u['host'];
		return 'https://' . $host . ( $u['port'] && 443 !== $u['port'] ? ':' . $u['port'] : '' );
	}

	private static function norm_path( $p ) {
		$out = preg_replace_callback(
			'/%([0-9A-Fa-f]{2})/',
			function ( $m ) {
				$c = chr( hexdec( $m[1] ) );
				return preg_match( '/[A-Za-z0-9\-._~]/', $c ) ? $c : '%' . strtoupper( $m[1] );
			},
			$p
		);
		$segs = array();
		foreach ( explode( '/', $out ) as $s ) {
			if ( '..' === $s ) {
				if ( count( $segs ) > 1 ) {
					array_pop( $segs );
				}
			} elseif ( '.' !== $s ) {
				$segs[] = $s;
			}
		}
		$r = implode( '/', $segs );
		return '' === $r ? '/' : $r;
	}

	/** array( identifier, fetch URL ) for one Signature-Agent member (draft 5.5). */
	public static function identifier( $value, $type = 'directory' ) {
		try {
			$u = self::url_parts( $value );
		} catch ( AYA_WBA_Unverified $e ) {
			throw new AYA_WBA_Unverified( 'bad port' === $e->getMessage() ? 'Signature-Agent has a bad port' : 'Signature-Agent must be an https URL' );
		}
		if ( 'https' !== $u['scheme'] || '' === $u['host'] || $u['userinfo'] ) {
			throw new AYA_WBA_Unverified( 'Signature-Agent must be an https URL' );
		}
		if ( 'directory' === $type ) {
			if ( ( '' !== $u['path'] && '/' !== $u['path'] ) || $u['has_query'] || false !== strpos( $value, '#' ) ) {
				throw new AYA_WBA_Unverified( 'a directory Signature-Agent must be an origin (scheme and host only)' );
			}
			$url = self::origin( $u ) . self::WELL_KNOWN;
			return array( $url, $url );
		}
		if ( 'jwks_uri' === $type ) {
			return array( self::origin( $u ) . self::norm_path( '' === $u['path'] ? '/' : $u['path'] ), $value );
		}
		throw new AYA_WBA_Unverified( "Signature-Agent type $type not supported" );
	}

	public static function ttl( $hdrs, $def, $cap ) {
		$cc = array();
		foreach ( explode( ',', $hdrs['cache-control'] ?? '' ) as $part ) {
			$kv = explode( '=', $part, 2 );
			$k  = strtolower( trim( $kv[0] ) );
			if ( '' !== $k ) {
				$cc[ $k ] = isset( $kv[1] ) ? trim( trim( $kv[1] ), '"' ) : '';
			}
		}
		if ( isset( $cc['no-store'] ) || isset( $cc['no-cache'] ) ) {
			return 0;
		}
		$t = null;
		if ( isset( $cc['max-age'] ) && ctype_digit( $cc['max-age'] ) ) {
			$t = (int) $cc['max-age'];
		} elseif ( ! empty( $hdrs['expires'] ) ) {
			$exp  = strtotime( $hdrs['expires'] );
			$date = ! empty( $hdrs['date'] ) ? strtotime( $hdrs['date'] ) : time();
			$t    = ( $exp && $date ) ? max( 0, $exp - $date ) : 0;
		}
		if ( null === $t ) {
			$t = $def;
		}
		if ( isset( $hdrs['age'] ) && ctype_digit( (string) $hdrs['age'] ) ) {
			$t -= (int) $hdrs['age'];
		}
		return max( 0, min( $t, $cap ) );
	}

	private static function seconds( $v ) {
		if ( ! is_int( $v ) && ! is_float( $v ) ) {
			return null;
		}
		return $v > 1e11 ? $v / 1000 : $v;   // Cloudflare's demo list writes milliseconds
	}

	private static function digest_ok( $field, $body ) {
		try {
			$d = AYA_SFV::dict( $field );
		} catch ( UnexpectedValueException $e ) {
			return false;
		}
		$seen = false;
		foreach ( array( 'sha-256' => 'sha256', 'sha-512' => 'sha512' ) as $name => $algo ) {
			if ( isset( $d[ $name ] ) ) {
				if ( 'bytes' !== $d[ $name ][0]['t'] || ! hash_equals( hash( $algo, $body, true ), $d[ $name ][0]['v'] ) ) {
					return false;
				}
				$seen = true;
			}
		}
		return $seen;
	}

	/** Parse one key-list response into array( keys => thumb => array( kind, material ), test => [], proof => [] ). */
	public function parse_list( $status, $hdrs, $body, $type, $host, $now ) {
		if ( 200 !== $status ) {
			throw new AYA_WBA_Unverified( "key list answered HTTP $status" );
		}
		$ctype = strtolower( trim( explode( ';', $hdrs['content-type'] ?? '' )[0] ) );
		if ( 'directory' === $type && self::MEDIA_TYPE !== $ctype ) {
			throw new AYA_WBA_Unverified( 'key list served as ' . ( $ctype ? $ctype : 'no content-type' ) . ', not ' . self::MEDIA_TYPE );
		}
		$doc  = json_decode( $body, true );
		$keys = is_array( $doc ) && isset( $doc['keys'] ) ? $doc['keys'] : null;
		if ( ! is_array( $keys ) || ( $keys && array_keys( $keys ) !== range( 0, count( $keys ) - 1 ) ) ) {
			throw new AYA_WBA_Unverified( 'key list has no keys array' );
		}
		if ( count( $keys ) > $this->o['max_keys'] ) {
			throw new AYA_WBA_Unverified( 'key list holds more than ' . $this->o['max_keys'] . ' keys' );
		}
		$kl = array( 'keys' => array(), 'test' => array(), 'proof' => array() );
		foreach ( $keys as $jwk ) {
			$got = self::load_jwk( $jwk );
			if ( ! $got ) {
				continue;
			}
			list( $thumb, $kind, $material ) = $got;
			if ( 'directory' === $type && array_key_exists( 'kid', $jwk ) && $jwk['kid'] !== $thumb ) {
				continue;   // draft 5.5: kid is the thumbprint
			}
			$nbf = self::seconds( $jwk['nbf'] ?? null );
			$exp = self::seconds( $jwk['exp'] ?? null );
			if ( ( null !== $nbf && $nbf > $now + 60 ) || ( null !== $exp && $exp <= $now ) ) {
				continue;
			}
			if ( in_array( $thumb, self::TEST_KEYS, true ) ) {
				$kl['test'][] = $thumb;
			}
			$kl['keys'][ $thumb ] = array( $kind, $material );
		}
		if ( 'directory' === $type ) {
			$kl['proof'] = self::directory_proof( $hdrs, $body, $host, $kl['keys'], $now );
		}
		return $kl;
	}

	/** Appendix B: which keys signed this response for this host. */
	private static function directory_proof( $hdrs, $body, $host, $keys, $now ) {
		$out = array();
		if ( empty( $hdrs['signature-input'] ) || empty( $hdrs['signature'] ) || empty( $hdrs['content-digest'] ) || ! self::digest_ok( $hdrs['content-digest'], $body ) ) {
			return $out;
		}
		try {
			$inputs = AYA_SFV::dict( $hdrs['signature-input'] );
			$sigs   = AYA_SFV::dict( $hdrs['signature'] );
		} catch ( UnexpectedValueException $e ) {
			return $out;
		}
		foreach ( $inputs as $label => $member ) {
			list( $cov, $p ) = $member;
			if ( 'list' !== $cov['t'] || ( $p['tag']['v'] ?? '' ) !== self::DIR_TAG || 'str' !== ( $p['keyid']['t'] ?? '' ) || ! isset( $keys[ $p['keyid']['v'] ] ) ) {
				continue;
			}
			$names = array();
			foreach ( $cov['v'] as $it ) {
				$names[] = $it[0]['v'] . '|' . implode( ',', array_keys( $it[1] ) );
			}
			sort( $names );
			if ( array( '@authority|req', 'content-digest|' ) !== $names ) {
				continue;
			}
			$c = $p['created'] ?? null;
			$e = $p['expires'] ?? null;
			if ( ! $c || empty( $c['i'] ) || ! $e || empty( $e['i'] ) || $c['v'] > $now + 60 || $e['v'] <= $now ) {
				continue;
			}
			$sig = $sigs[ $label ][0] ?? null;
			if ( ! $sig || 'bytes' !== $sig['t'] ) {
				continue;
			}
			$lines = array();
			foreach ( $cov['v'] as $it ) {
				$lines[] = '@authority' === $it[0]['v'] ? "\"@authority\";req: $host" : '"content-digest": ' . trim( $hdrs['content-digest'] );
			}
			$lines[] = '"@signature-params": ' . AYA_SFV::ser_member( $member );
			list( $kind, $material ) = $keys[ $p['keyid']['v'] ];
			try {
				self::check_sig( $kind, $material, $p['alg'] ?? null, $sig['v'], implode( "\n", $lines ) );
				$out[] = $p['keyid']['v'];
			} catch ( AYA_WBA_Invalid $ex ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement
			}
		}
		return $out;
	}

	/* ── cache (transients; a last good copy outlives its freshness for max_stale) ── */

	private $mem = array();

	private function cache_get( $k ) {
		if ( array_key_exists( $k, $this->mem ) ) {
			return $this->mem[ $k ];
		}
		return $this->o['cache'] ? get_transient( $k ) : false;
	}

	private function cache_set( $k, $v, $ttl ) {
		$this->mem[ $k ] = $v;
		if ( $this->o['cache'] ) {
			set_transient( $k, $v, max( 1, (int) $ttl ) );
		}
	}

	private function cache_del( $k ) {
		unset( $this->mem[ $k ] );
		if ( $this->o['cache'] ) {
			delete_transient( $k );
		}
	}

	/** array( key list, stale ) for one identifier. */
	public function resolve_ident( $ident, $url, $type, $now, $force = false ) {
		$ck   = 'aya_wba_' . md5( $ident );
		$nk   = 'aya_wban_' . md5( $ident );
		$held = $this->cache_get( $ck );
		if ( is_array( $held ) && ! $force && $now < $held['fresh_until'] ) {
			return array( $held, false );
		}
		$neg = $this->cache_get( $nk );
		if ( is_array( $neg ) && $now < $neg[0] ) {
			if ( is_array( $held ) && $now - $held['fetched'] < $this->o['max_stale'] ) {
				return array( $held, true );
			}
			throw new AYA_WBA_Unverified( $neg[1] );
		}
		try {
			list( $status, $hdrs, $body ) = $this->https_get( $url );
			$low = array();
			foreach ( (array) $hdrs as $k => $v ) {
				$low[ strtolower( $k ) ] = (string) $v;
			}
			$kl = $this->parse_list( (int) $status, $low, (string) $body, $type, self::authority( $url ), $now );
		} catch ( AYA_WBA_Unverified $e ) {
			$this->cache_set( $nk, array( $now + min( $this->o['negative_ttl'], 300 ), $e->getMessage() ), min( $this->o['negative_ttl'], 300 ) );
			if ( is_array( $held ) && $now - $held['fetched'] < $this->o['max_stale'] ) {
				return array( $held, true );
			}
			throw $e;
		}
		$kl['fetched']     = $now;
		$kl['fresh_until'] = $now + max( $this->o['min_ttl'], self::ttl( $low, $this->o['default_ttl'], $this->o['max_ttl'] ) );
		$this->cache_set( $ck, $kl, $this->o['max_stale'] );
		$this->cache_del( $nk );
		return array( $kl, false );
	}

	/* ── verifying a request ── */

	/**
	 * Check every Web Bot Auth signature on one request. $headers: lower-case
	 * name => value. $url: as the client sent it, including the query.
	 */
	public function verify( $method, $url, $headers, $now = null ) {
		$now = null === $now ? time() : (int) $now;
		try {
			self::url_parts( $url );
			$si = self::field( $headers, 'signature-input' );
			$sg = self::field( $headers, 'signature' );
			if ( ! $si && ! $sg ) {
				return self::result( 'unsigned', 'no signature' );
			}
			try {
				$inputs = AYA_SFV::dict( (string) $si );
				$sigs   = AYA_SFV::dict( (string) $sg );
			} catch ( UnexpectedValueException $e ) {
				return self::result( 'invalid', 'cannot parse Signature-Input or Signature: ' . $e->getMessage() );
			}
			$results = array();
			foreach ( $inputs as $label => $member ) {
				if ( 'list' !== $member[0]['t'] || 'str' !== ( $member[1]['tag']['t'] ?? '' ) || self::TAG !== $member[1]['tag']['v'] ) {
					continue;   // draft 5.4: not a Web Bot Auth signature
				}
				$results[] = $this->one( (string) $method, $url, $headers, (string) $label, $member, $sigs[ $label ] ?? null, $now );
			}
			if ( ! $results ) {
				return self::result( 'unsigned', 'no web-bot-auth signature' );
			}
			$rank = array( 'verified' => 0, 'invalid' => 1, 'unverified' => 2 );
			usort(
				$results,
				function ( $a, $b ) use ( $rank ) {
					return $rank[ $a['outcome'] ] - $rank[ $b['outcome'] ];
				}
			);
			$best           = array_shift( $results );
			$best['others'] = $results;
			return $best;
		} catch ( AYA_WBA_Unverified $e ) {
			return self::result( 'unverified', $e->getMessage() );
		}
	}

	private function one( $method, $url, $headers, $label, $member, $sig_member, $now ) {
		list( $cov, $p ) = $member;
		$int             = function ( $x ) {
			return ( $x && 'num' === $x['t'] && ! empty( $x['i'] ) ) ? $x['v'] : null;
		};
		$r               = self::result(
			'unverified',
			'',
			array(
				'label'   => $label,
				'keyid'   => 'str' === ( $p['keyid']['t'] ?? '' ) ? $p['keyid']['v'] : null,
				'created' => $int( $p['created'] ?? null ),
				'expires' => $int( $p['expires'] ?? null ),
			)
		);
		try {
			$sig = $sig_member[0] ?? null;
			if ( ! $sig || 'bytes' !== $sig['t'] ) {
				throw new AYA_WBA_Invalid( 'no matching Signature value' );
			}
			$created = $r['created'];
			$expires = $r['expires'];
			if ( null === $created || null === $expires ) {
				throw new AYA_WBA_Invalid( 'created and expires are required' );
			}
			if ( $created > $now + $this->o['clock_skew'] ) {
				throw new AYA_WBA_Invalid( 'signature created in the future' );
			}
			if ( $expires <= $now - $this->o['clock_skew'] ) {
				throw new AYA_WBA_Invalid( 'signature expired' );
			}
			if ( null !== $this->o['max_lifetime'] && $expires - $created > $this->o['max_lifetime'] ) {
				throw new AYA_WBA_Invalid( 'signature valid for ' . ( $expires - $created ) . ' s, more than ' . $this->o['max_lifetime'] . ' s' );
			}
			if ( null === $r['keyid'] ) {
				throw new AYA_WBA_Invalid( 'keyid is required' );
			}
			$names = array();
			$agent = array();
			foreach ( $cov['v'] as $it ) {
				$names[] = $it[0]['v'];
				if ( 'signature-agent' === $it[0]['v'] ) {
					$agent[] = $it[1];
				}
			}
			if ( ! in_array( '@authority', $names, true ) && ! in_array( '@target-uri', $names, true ) ) {
				throw new AYA_WBA_Invalid( 'signature covers neither @authority nor @target-uri' );
			}
			$base = self::base( $method, $url, $headers, $member );
			// the Signature-Agent member this signature covers (draft 5.2.1, 5.2.2)
			if ( 1 !== count( $agent ) ) {
				throw new AYA_WBA_Unverified( $agent ? 'signature must cover exactly one Signature-Agent member' : 'signature does not cover Signature-Agent' );
			}
			$raw = (string) self::field( $headers, 'signature-agent' );
			try {
				if ( isset( $agent[0]['key'] ) ) {
					$d = AYA_SFV::dict( $raw );
					if ( ! isset( $d[ $agent[0]['key']['v'] ] ) ) {
						throw new UnexpectedValueException( 'no such member' );
					}
					list( $value, $mp ) = $d[ $agent[0]['key']['v'] ];
				} else {
					list( $value, $mp ) = AYA_SFV::item_of( $raw );   // legacy sf-string form
				}
			} catch ( UnexpectedValueException $e ) {
				throw new AYA_WBA_Unverified( 'cannot read Signature-Agent: ' . $e->getMessage() );
			}
			if ( 'str' !== $value['t'] ) {
				throw new AYA_WBA_Unverified( 'Signature-Agent member is not a string' );
			}
			$r['signature_agent'] = $value['v'];
			$type                 = isset( $mp['type'] ) ? (string) $mp['type']['v'] : 'directory';
			list( $ident, $furl ) = self::identifier( $value['v'], $type );
			list( $kl, $stale )   = $this->resolve_ident( $ident, $furl, $type, $now );
			if ( ! isset( $kl['keys'][ $r['keyid'] ] ) && ! $stale && $now - $kl['fetched'] >= $this->o['refetch_after'] ) {
				list( $kl, $stale ) = $this->resolve_ident( $ident, $furl, $type, $now, true );   // a key may have been added
			}
			if ( ! isset( $kl['keys'][ $r['keyid'] ] ) ) {
				throw new AYA_WBA_Unverified( 'the key list does not hold this keyid' );
			}
			if ( in_array( $r['keyid'], $kl['test'], true ) && ! $this->o['allow_test_keys'] ) {
				throw new AYA_WBA_Invalid( 'signed with a published test key (draft 6.8)' );
			}
			list( $kind, $material ) = $kl['keys'][ $r['keyid'] ];
			self::check_sig( $kind, $material, $p['alg'] ?? null, $sig['v'], $base );
			$r['outcome']      = 'verified';
			$r['verified']     = true;
			$r['agent']        = $ident;
			$r['stale']        = $stale;
			$r['domain_proof'] = 'directory' === $type ? in_array( $r['keyid'], $kl['proof'], true ) : null;
			$r['reason']       = 'signature verified' . ( $stale ? ' with a stale key list' : '' );
		} catch ( AYA_WBA_Invalid $e ) {
			$r['outcome'] = 'invalid';
			$r['reason']  = $e->getMessage();
		} catch ( AYA_WBA_Unverified $e ) {
			$r['outcome'] = 'unverified';
			$r['reason']  = $e->getMessage();
		}
		return $r;
	}

	/** (method, URL as sent, headers) of the current request. */
	public static function current_request() {
		// WordPress adds slashes to $_SERVER (wp_magic_quotes); the signature covers the raw bytes
		$server  = wp_unslash( $_SERVER ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$headers = array();
		foreach ( $server as $k => $v ) {
			if ( ! is_string( $v ) ) {
				continue;
			}
			if ( 0 === strpos( $k, 'HTTP_' ) ) {
				$headers[ strtolower( str_replace( '_', '-', substr( $k, 5 ) ) ) ] = (string) $v;
			} elseif ( 'CONTENT_TYPE' === $k || 'CONTENT_LENGTH' === $k ) {
				$headers[ strtolower( str_replace( '_', '-', $k ) ) ] = (string) $v;
			}
		}
		$host   = isset( $server['HTTP_HOST'] ) ? (string) $server['HTTP_HOST'] : (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$target = isset( $server['REQUEST_URI'] ) ? (string) $server['REQUEST_URI'] : '/';
		$url    = ( is_ssl() ? 'https' : 'http' ) . '://' . $host . $target;
		$method = isset( $server['REQUEST_METHOD'] ) ? strtoupper( (string) $server['REQUEST_METHOD'] ) : 'GET';
		return array( $method, apply_filters( 'authyouragent_wba_request_url', $url ), $headers );
	}
}
