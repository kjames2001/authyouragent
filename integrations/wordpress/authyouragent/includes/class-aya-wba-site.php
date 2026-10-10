<?php
/**
 * Signed agents on this site (Web Bot Auth). For every request that carries
 * a Web Bot Auth signature: check it, remember the agent's address, apply the
 * owner's block / allow rules, and label orders the agent places.
 * Requests without a signature are not touched.
 */
defined( 'ABSPATH' ) || exit;

class AYA_WBA_Site {

	const SEEN      = 'aya_wba_seen';    // agent address => row (not autoloaded)
	const RULES     = 'aya_wba_rules';   // agent address => block | allow
	const MAX_SEEN  = 200;
	const OURS      = '.agents.authyouragent.com';

	/** The result for the current request, or null when it carries no signature. */
	public static $current = null;

	public static function init() {
		add_action( 'init', array( __CLASS__, 'check' ), 1 );
		add_action( 'woocommerce_checkout_order_created', array( __CLASS__, 'order' ) );
		add_action( 'woocommerce_store_api_checkout_order_processed', array( __CLASS__, 'order' ) );
		add_action( 'admin_post_aya_wba_rule', array( __CLASS__, 'rule_action' ) );
		add_action( 'admin_post_aya_wba_forget', array( __CLASS__, 'forget_action' ) );
	}

	public static function enabled() {
		return '1' === (string) aya_opt( 'wba' );
	}

	/** Run the check once per request. */
	public static function check() {
		if ( ! self::enabled() || ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return;
		}
		if ( empty( $_SERVER['HTTP_SIGNATURE_INPUT'] ) && empty( $_SERVER['HTTP_SIGNATURE'] ) ) {
			return;   // unsigned: nothing to do
		}
		list( $method, $url, $headers ) = AYA_WBA::current_request();
		$v             = new AYA_WBA( apply_filters( 'authyouragent_wba_options', array() ) );
		self::$current = $v->verify( $method, $url, $headers );
		$r             = self::$current;
		self::record( $r, $url );
		do_action( 'authyouragent_signed_request', $r );

		$why = self::refusal( $r );
		if ( $why ) {
			status_header( 403 );
			nocache_headers();
			wp_die( esc_html( $why ), esc_html__( 'Agent not allowed', 'authyouragent' ), array( 'response' => 403 ) );
		}
	}

	/** Why the site refuses this request, or ''. Exposed for tests. */
	public static function refusal( $r ) {
		if ( 'verified' === $r['outcome'] ) {
			$rules = get_option( self::RULES, array() );
			$rule  = $rules[ $r['agent'] ] ?? '';
			if ( 'block' === $rule ) {
				return __( 'This site does not accept requests from this agent.', 'authyouragent' );
			}
			if ( 'listed' === aya_opt( 'wba_mode' ) && 'allow' !== $rule ) {
				return __( 'This site accepts only agents it has allowed.', 'authyouragent' );
			}
			return '';
		}
		if ( 'invalid' === $r['outcome'] && '1' === (string) aya_opt( 'wba_refuse_invalid' ) ) {
			/* translators: %s: why the signature is invalid */
			return sprintf( __( 'The request carries an invalid agent signature (%s).', 'authyouragent' ), $r['reason'] );
		}
		return '';
	}

	/** Remember the agent (written at most once a minute per agent). */
	private static function record( $r, $url ) {
		$seen = get_option( self::SEEN, array() );
		$seen = is_array( $seen ) ? $seen : array();
		$now  = time();
		$key  = 'verified' === $r['outcome'] ? $r['agent'] : '_' . $r['outcome'];
		$row  = $seen[ $key ] ?? array( 'first' => $now, 'last' => 0, 'visits' => 0 );
		if ( $now - $row['last'] < 60 && ( $row['outcome'] ?? '' ) === $r['outcome'] ) {
			return;
		}
		$path = (string) wp_parse_url( $url, PHP_URL_PATH );
		$row  = array_merge(
			$row,
			array(
				'last'      => $now,
				'visits'    => $row['visits'] + 1,
				'outcome'   => $r['outcome'],
				'reason'    => substr( $r['reason'], 0, 200 ),
				'claimed'   => substr( (string) $r['signature_agent'], 0, 300 ),
				'proof'     => $r['domain_proof'],
				'path'      => substr( $path, 0, 200 ),
				'stale'     => $r['stale'],
			)
		);
		$seen[ $key ] = $row;
		if ( count( $seen ) > self::MAX_SEEN ) {
			uasort(
				$seen,
				function ( $a, $b ) {
					return $b['last'] - $a['last'];
				}
			);
			$seen = array_slice( $seen, 0, self::MAX_SEEN, true );
		}
		update_option( self::SEEN, $seen, false );
	}

	/** Label an order placed during a signed request. */
	public static function order( $order ) {
		$r = self::$current;
		if ( ! $order || ! $r || 'verified' !== $r['outcome'] ) {
			return;
		}
		$order->update_meta_data( '_aya_wba_agent', $r['agent'] );
		$order->update_meta_data( '_aya_wba_proof', $r['domain_proof'] ? '1' : '0' );
		$order->add_order_note(
			sprintf(
				/* translators: %s: the agent's address */
				__( 'Placed by a signed agent: %s (Web Bot Auth signature verified).', 'authyouragent' ),
				preg_replace( '#/\.well-known/http-message-signatures-directory$#', '', $r['agent'] )
			)
		);
		$order->save();
	}

	public static function is_ours( $agent ) {
		$host = (string) wp_parse_url( $agent, PHP_URL_HOST );
		return 'https' === wp_parse_url( $agent, PHP_URL_SCHEME ) && substr( $host, -strlen( self::OURS ) ) === self::OURS;
	}

	/* ── admin ── */

	public static function rule_action() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '', 403 );
		}
		check_admin_referer( 'aya_wba_rule' );
		$agent = isset( $_POST['agent'] ) ? esc_url_raw( wp_unslash( $_POST['agent'] ), array( 'https' ) ) : '';
		$rule  = isset( $_POST['rule'] ) ? sanitize_key( wp_unslash( $_POST['rule'] ) ) : '';
		if ( $agent ) {
			$rules = get_option( self::RULES, array() );
			if ( in_array( $rule, array( 'block', 'allow' ), true ) ) {
				$rules[ $agent ] = $rule;
			} else {
				unset( $rules[ $agent ] );
			}
			update_option( self::RULES, $rules, true );
		}
		wp_safe_redirect( admin_url( 'options-general.php?page=authyouragent#signed-agents' ) );
		exit;
	}

	public static function forget_action() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '', 403 );
		}
		check_admin_referer( 'aya_wba_forget' );
		delete_option( self::SEEN );
		wp_safe_redirect( admin_url( 'options-general.php?page=authyouragent#signed-agents' ) );
		exit;
	}

	private static function button( $agent, $rule, $label ) {
		return '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline">'
			. wp_nonce_field( 'aya_wba_rule', '_wpnonce', true, false )
			. '<input type="hidden" name="action" value="aya_wba_rule"><input type="hidden" name="agent" value="' . esc_attr( $agent ) . '">'
			. '<input type="hidden" name="rule" value="' . esc_attr( $rule ) . '">'
			. '<button class="button button-small">' . esc_html( $label ) . '</button></form> ';
	}

	/** The "Signed agents" section of the settings page. */
	public static function section() {
		$seen  = get_option( self::SEEN, array() );
		$rules = get_option( self::RULES, array() );
		echo '<h2 id="signed-agents">' . esc_html__( 'Signed agents', 'authyouragent' ) . '</h2>';
		echo '<p>' . esc_html__( 'Agents that sign their requests (Web Bot Auth) can be told apart: each has its own address, and its signature proves the request came from it. Requests without a signature are not affected. An agent that stops signing is treated like any other visitor, so blocking here stops a signed agent, not every bot.', 'authyouragent' ) . '</p>';
		if ( ! self::enabled() ) {
			echo '<p><em>' . esc_html__( 'Checking signatures is switched off above.', 'authyouragent' ) . '</em></p>';
		}
		$agents = array();
		$other  = array();
		foreach ( (array) $seen as $k => $row ) {
			if ( '_' === substr( $k, 0, 1 ) ) {
				$other[ substr( $k, 1 ) ] = $row;
			} else {
				$agents[ $k ] = $row;
			}
		}
		foreach ( $rules as $agent => $rule ) {
			if ( ! isset( $agents[ $agent ] ) ) {
				$agents[ $agent ] = array( 'first' => 0, 'last' => 0, 'visits' => 0, 'proof' => null, 'path' => '' );
			}
		}
		uasort(
			$agents,
			function ( $a, $b ) {
				return $b['last'] - $a['last'];
			}
		);
		$fmt = get_option( 'date_format' ) . ' ' . get_option( 'time_format' );
		if ( ! $agents ) {
			echo '<p>' . esc_html__( 'No signed agent has visited yet.', 'authyouragent' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Agent address', 'authyouragent' ) . '</th><th>' . esc_html__( 'Last seen', 'authyouragent' )
				. '</th><th>' . esc_html__( 'Visits', 'authyouragent' ) . '</th><th>' . esc_html__( 'Last page', 'authyouragent' ) . '</th><th>' . esc_html__( 'Rule', 'authyouragent' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $agents as $agent => $row ) {
				$rule  = $rules[ $agent ] ?? '';
				$shown = preg_replace( '#/\.well-known/http-message-signatures-directory$#', '', $agent );
				$tags  = array();
				if ( self::is_ours( $agent ) ) {
					$tags[] = __( 'Auth Your Agent: its owner approves sign-ins and orders on their phone', 'authyouragent' );
				}
				if ( ! empty( $row['proof'] ) ) {
					$tags[] = __( 'key list signed for its own address', 'authyouragent' );
				}
				echo '<tr><td><code>' . esc_html( $shown ) . '</code>' . ( $tags ? '<br><small>' . esc_html( implode( '; ', $tags ) ) . '</small>' : '' ) . '</td>'
					. '<td>' . ( $row['last'] ? esc_html( wp_date( $fmt, $row['last'] ) ) : '&mdash;' ) . '</td>'
					. '<td>' . (int) $row['visits'] . '</td><td><code>' . esc_html( $row['path'] ?? '' ) . '</code></td>'
					. '<td>' . esc_html( 'block' === $rule ? __( 'Blocked', 'authyouragent' ) : ( 'allow' === $rule ? __( 'Allowed', 'authyouragent' ) : __( 'Default', 'authyouragent' ) ) ) . '</td><td>';
				// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- button() escapes
				echo 'block' !== $rule ? self::button( $agent, 'block', __( 'Block', 'authyouragent' ) ) : '';
				echo 'allow' !== $rule ? self::button( $agent, 'allow', __( 'Allow', 'authyouragent' ) ) : '';
				echo '' !== $rule ? self::button( $agent, 'clear', __( 'Reset', 'authyouragent' ) ) : '';
				// phpcs:enable
				echo '</td></tr>';
			}
			echo '</tbody></table><p class="description">' . esc_html__( 'Visits are counted at most once a minute per agent. The list keeps the 200 most recent agents.', 'authyouragent' ) . '</p>';
		}
		if ( $other ) {
			echo '<p>';
			$names = array(
				'invalid'    => __( 'Requests with an invalid signature', 'authyouragent' ),
				'unverified' => __( 'Signed requests that could not be checked', 'authyouragent' ),
				'unsigned'   => __( 'Signed requests that were not Web Bot Auth', 'authyouragent' ),
			);
			foreach ( $other as $outcome => $row ) {
				/* translators: 1: kind of request, 2: count, 3: date, 4: reason */
				echo esc_html( sprintf( __( '%1$s: %2$d, last %3$s (%4$s).', 'authyouragent' ), $names[ $outcome ] ?? $outcome, (int) $row['visits'], wp_date( $fmt, $row['last'] ), $row['reason'] ) ) . '<br>';
			}
			echo '</p>';
		}
		if ( $seen ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">' . wp_nonce_field( 'aya_wba_forget', '_wpnonce', true, false ) // phpcs:ignore WordPress.Security.EscapeOutput
				. '<input type="hidden" name="action" value="aya_wba_forget"><button class="button">' . esc_html__( 'Clear the list (rules stay)', 'authyouragent' ) . '</button></form>';
		}
	}
}
