<?php
/**
 * The plugin's Web Bot Auth verifier (class-aya-wba.php) outside WordPress:
 * RFC 9421 Appendix B and draft Appendix E vectors, signatures made by the
 * Python and JS SDKs, refusals, cache, address checks.
 * Input: a JSON file of cases written by wba_php_cases.py (argv[1]).
 * Run inside the wordpress:php8.3 image: php wba_php_test.php cases.json
 */
define( 'ABSPATH', '/' );
$GLOBALS['T']       = array();
$GLOBALS['FETCH']   = array();
$GLOBALS['CALLS']   = array();
function wp_json_encode( $d, $f = 0 ) { return json_encode( $d, $f ); }
function apply_filters( $tag, $v, ...$a ) {
	if ( 'authyouragent_wba_fetch' === $tag ) {
		$url = $a[0];
		$GLOBALS['CALLS'][] = $url;
		if ( ! array_key_exists( $url, $GLOBALS['FETCH'] ) ) { return new Exception( 'no route' ); }
		$r = $GLOBALS['FETCH'][ $url ];
		return is_string( $r ) ? new Exception( $r ) : array( $r[0], $r[1], base64_decode( $r[2] ) );
	}
	return $v;
}
function get_transient( $k ) { return $GLOBALS['T'][ $k ] ?? false; }
function set_transient( $k, $v, $t ) { $GLOBALS['T'][ $k ] = $v; return true; }
function delete_transient( $k ) { unset( $GLOBALS['T'][ $k ] ); return true; }
require __DIR__ . '/class-aya-wba.php';

$cases = json_decode( file_get_contents( $argv[1] ), true );
$ok = 0; $n = 0;
function check( $name, $cond, $extra = '' ) {
	global $ok, $n;
	$n++; if ( $cond ) { $ok++; }
	echo ( $cond ? '  PASS  ' : '  FAIL  ' ) . $name . ( $cond || '' === $extra ? '' : '  [' . ( is_string( $extra ) ? $extra : json_encode( $extra ) ) . ']' ) . "\n";
}
function show( $r ) { return $r['outcome'] . ' ' . ( $r['agent'] ?? $r['signature_agent'] ?? '-' ) . ' ' . $r['reason']; }
function lc( $h ) { $o = array(); foreach ( $h as $k => $v ) { $o[ strtolower( $k ) ] = $v; } return $o; }

echo "== 1 RFC 9421 Appendix B\n";
foreach ( $cases['bvec'] as $c ) {
	$d      = AYA_SFV::dict( $c['si'] );
	$member = reset( $d );
	$base   = AYA_WBA::base( 'POST', 'https://example.com/foo?param=Value&Pet=dog', lc( $c['headers'] ), $member );
	list( , $kind, $mat ) = AYA_WBA::load_jwk( $c['jwk'] );
	$good = true;
	try { AYA_WBA::check_sig( $kind, $mat, array( 't' => 'str', 'v' => $c['alg'] ), base64_decode( $c['sig'] ), $base ); } catch ( Exception $e ) { $good = false; }
	check( $c['name'], $good, $base );
	$bad = base64_decode( $c['sig'] );
	$bad[7] = chr( ord( $bad[7] ) ^ 1 );
	$refused = false;
	try { AYA_WBA::check_sig( $kind, $mat, array( 't' => 'str', 'v' => $c['alg'] ), $bad, $base ); } catch ( AYA_WBA_Invalid $e ) { $refused = true; }
	check( $c['name'] . ': one flipped bit is refused', $refused );
	$refused = false;
	try { AYA_WBA::check_sig( $kind, $mat, array( 't' => 'str', 'v' => $c['alg'] ), base64_decode( $c['sig'] ), $base . ' ' ); } catch ( AYA_WBA_Invalid $e ) { $refused = true; }
	check( $c['name'] . ': a changed base is refused', $refused );
}
// ECDSA P-256 raw r||s, made by openssl here
$ec  = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1' ) );
$det = openssl_pkey_get_details( $ec );
openssl_sign( 'x', $der, $ec, OPENSSL_ALGO_SHA256 );
$o = 4; $rl = ord( $der[3] ); $r = substr( $der, 4, $rl ); $sl = ord( $der[ 5 + $rl ] ); $s = substr( $der, 6 + $rl, $sl );
$raw = str_pad( ltrim( $r, "\0" ), 32, "\0", STR_PAD_LEFT ) . str_pad( ltrim( $s, "\0" ), 32, "\0", STR_PAD_LEFT );
list( , $kind, $mat ) = AYA_WBA::load_jwk( array( 'kty' => 'EC', 'crv' => 'P-256', 'x' => AYA_WBA::b64u( $det['ec']['x'] ), 'y' => AYA_WBA::b64u( $det['ec']['y'] ) ) );
$good = true;
try { AYA_WBA::check_sig( $kind, $mat, array( 't' => 'str', 'v' => 'ecdsa-p256-sha256' ), $raw, 'x' ); } catch ( Exception $e ) { $good = false; }
check( 'ecdsa-p256-sha256 raw r||s verifies', $good );
$good = true;
try { AYA_WBA::check_sig( $kind, $mat, array( 't' => 'str', 'v' => 'ecdsa-p256-sha256' ), $raw, 'y' ); } catch ( Exception $e ) { $good = false; }
check( 'ecdsa-p256-sha256 over another message is refused', ! $good );
check( 'an RSA key under 2048 bits is refused', null === AYA_WBA::load_jwk( array( 'kty' => 'RSA', 'n' => AYA_WBA::b64u( str_repeat( "\xff", 128 ) ), 'e' => 'AQAB' ) ) );
foreach ( $cases['sfv'] as $s ) {
	$out = array();
	foreach ( AYA_SFV::dict( $s ) as $k => $m ) { $out[] = $k . '=' . AYA_SFV::ser_member( $m ); }
	check( "SFV round trip: $s", implode( ', ', $out ) === $s, implode( ', ', $out ) );
}

echo "\n== 2 draft Appendix E + 3 interop + 4 refusals + 5 cache (shared cases)\n";
foreach ( $cases['verify'] as $c ) {
	$GLOBALS['T'] = array(); $GLOBALS['CALLS'] = array();
	$GLOBALS['FETCH'] = $c['routes'];
	$v = new AYA_WBA( $c['opts'] ?? array() );
	$steps = $c['steps'] ?? array( array( 'method' => $c['method'], 'url' => $c['url'], 'headers' => $c['headers'], 'now' => $c['now'] ?? null, 'expect' => $c['expect'] ) );
	$all = true; $why = '';
	foreach ( $steps as $s ) {
		if ( isset( $s['routes'] ) ) { $GLOBALS['FETCH'] = $s['routes']; }
		$r = $v->verify( $s['method'], $s['url'], lc( $s['headers'] ), $s['now'] ?? null );
		$e = $s['expect'];
		$good = $r['outcome'] === $e['outcome']
			&& ( ! array_key_exists( 'agent', $e ) || $r['agent'] === $e['agent'] )
			&& ( ! isset( $e['reason'] ) || false !== strpos( $r['reason'], $e['reason'] ) )
			&& ( ! isset( $e['stale'] ) || $r['stale'] === $e['stale'] )
			&& ( ! isset( $e['domain_proof'] ) || $r['domain_proof'] === $e['domain_proof'] )
			&& ( ! isset( $e['label'] ) || $r['label'] === $e['label'] )
			&& ( ! isset( $e['others'] ) || count( $r['others'] ) === $e['others'] )
			&& ( ! isset( $e['calls'] ) || count( $GLOBALS['CALLS'] ) === $e['calls'] );
		if ( ! $good ) { $all = false; $why = show( $r ) . ' calls=' . count( $GLOBALS['CALLS'] ); break; }
	}
	check( $c['name'], $all, $why );
}

echo "\n== E.2.3 domain proof\n";
$e = $cases['e23'];
$v = new AYA_WBA();
$kl = $v->parse_list( 200, $e['headers'], $e['body'], 'directory', 'signature-agent.test', 1735690000 );
check( 'E.2.3 directory proof validates for signature-agent.test', $kl['proof'] === array( 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U' ) );
$kl = $v->parse_list( 200, $e['headers'], $e['body'], 'directory', 'copy.example', 1735690000 );
check( 'E.2.3 the same response served by another host carries no proof', ! $kl['proof'] );
$kl = $v->parse_list( 200, $e['headers'], str_replace( '"use":"sig"', '"use":"enc"', $e['body'] ), 'directory', 'signature-agent.test', 1735690000 );
check( 'E.2.3 a changed body breaks the proof', ! $kl['proof'] );

echo "\n== 6 addresses\n";
foreach ( array( '127.0.0.1', '10.1.2.3', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', '::ffff:127.0.0.1', 'fd00::1', 'fe80::1', '2001:db8::1' ) as $ip ) {
	check( "$ip is not public", ! AYA_WBA::is_public_ip( $ip ) );
}
check( '8.8.8.8 and 2606:4700::1111 are public', AYA_WBA::is_public_ip( '8.8.8.8' ) && AYA_WBA::is_public_ip( '2606:4700::1111' ) );
check( 'ttl: max-age capped, Age subtracted, no-store = 0', AYA_WBA::ttl( array( 'cache-control' => 'max-age=999999' ), 300, 86400 ) === 86400
	&& AYA_WBA::ttl( array( 'cache-control' => 'max-age=600', 'age' => '500' ), 300, 86400 ) === 100 && 0 === AYA_WBA::ttl( array( 'cache-control' => 'no-store' ), 300, 86400 ) );
check( 'identifier normalisation: AGENT.example == agent.example/', AYA_WBA::identifier( 'https://AGENT.example' )[0] === AYA_WBA::identifier( 'https://agent.example/' )[0] );

echo "\n$ok/$n passed\n";
exit( $ok === $n ? 0 : 1 );
