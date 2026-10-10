<?php
/**
 * WooCommerce: an order placed by an agent account waits for its OWNER to
 * confirm on their phone (OpenID Connect CIBA, poll mode), with the shop's
 * own words, for example "Pay R 450.00 for 2 items: Brass lamp, Wick (x1)".
 *
 * How it plays out for the agent: the first "Place order" is refused with
 * "Waiting for the customer to confirm on their phone"; placing the order
 * again after they approve goes through. The approval is tied to the exact
 * basket and total: change the basket and a new confirmation is needed.
 * Works with any payment method, because nothing is charged before it.
 */
defined( 'ABSPATH' ) || exit;

class AYA_Checkout {

	const META = 'aya_confirm';

	public static function init() {
		add_action( 'woocommerce_after_checkout_validation', array( __CLASS__, 'classic' ), 20, 2 );
		add_action( 'woocommerce_store_api_checkout_update_order_from_request', array( __CLASS__, 'store_api' ), 20, 2 );
		add_action( 'woocommerce_checkout_order_created', array( __CLASS__, 'note' ) );
		add_action( 'woocommerce_store_api_checkout_order_processed', array( __CLASS__, 'note' ) );
		add_action( 'woocommerce_admin_order_data_after_order_details', array( __CLASS__, 'admin_badge' ) );
		// orders list: classic (posts) and HPOS screens
		add_filter( 'manage_edit-shop_order_columns', array( __CLASS__, 'column' ) );
		add_action( 'manage_shop_order_posts_custom_column', array( __CLASS__, 'column_cell_post' ), 10, 2 );
		add_filter( 'manage_woocommerce_page_wc-orders_columns', array( __CLASS__, 'column' ) );
		add_action( 'manage_woocommerce_page_wc-orders_custom_column', array( __CLASS__, 'column_cell' ), 10, 2 );
		add_action( 'admin_head', array( __CLASS__, 'badge_css' ) );
	}

	private static function applies() {
		return aya_configured() && '1' === (string) aya_opt( 'confirm_orders' ) && function_exists( 'WC' )
			&& is_user_logged_in() && aya_is_agent( get_current_user_id() ) && WC()->cart;
	}

	/** What the customer reads on their phone. One line, at most 120 characters. */
	public static function message() {
		$cart  = WC()->cart;
		$total = html_entity_decode( wp_strip_all_tags( wc_price( $cart->get_total( 'edit' ) ) ), ENT_QUOTES, 'UTF-8' );
		$names = array();
		$count = 0;
		foreach ( $cart->get_cart() as $item ) {
			$count  += (int) $item['quantity'];
			$names[] = $item['data']->get_name() . ( $item['quantity'] > 1 ? ' (x' . (int) $item['quantity'] . ')' : '' );
		}
		$head = sprintf( 'Pay %s at %s for ', $total, wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) );
		$body = 1 === $count ? $names[0] : $count . ' items: ' . implode( ', ', $names );
		$msg  = preg_replace( '/[\x00-\x1f\x7f]+/u', ' ', $head . $body );
		$msg  = apply_filters( 'authyouragent_confirm_message', $msg, $cart );
		return mb_strlen( $msg ) > 120 ? mb_substr( $msg, 0, 119 ) . '…' : $msg;
	}

	/** Fingerprint of what is being confirmed: items, quantities, total, currency. */
	private static function basket_hash() {
		$cart = WC()->cart;
		$rows = array();
		foreach ( $cart->get_cart() as $item ) {
			$rows[] = array( $item['product_id'], $item['variation_id'], (int) $item['quantity'] );
		}
		sort( $rows );
		return hash( 'sha256', wp_json_encode( array( $rows, wc_format_decimal( $cart->get_total( 'edit' ), 2 ), get_woocommerce_currency() ) ) );
	}

	/**
	 * Returns null when the order may proceed, or the message to show.
	 * Keeps one open confirmation per agent account, in user meta.
	 */
	public static function gate() {
		$uid  = get_current_user_id();
		$hash = self::basket_hash();
		$st   = get_user_meta( $uid, self::META, true );
		$st   = is_array( $st ) ? $st : array();

		if ( ( $st['hash'] ?? '' ) === $hash && ( $st['status'] ?? '' ) === 'approved' && ( $st['exp'] ?? 0 ) > time() ) {
			return null;
		}
		if ( ( $st['hash'] ?? '' ) === $hash && ( $st['status'] ?? '' ) === 'pending' && ( $st['exp'] ?? 0 ) > time() ) {
			return self::poll( $uid, $st );
		}
		return self::ask( $uid, $hash );
	}

	private static function ask( $uid, $hash ) {
		$agent = get_user_meta( $uid, 'aya_agent_sub', true );
		$msg   = self::message();
		list( $status, $r ) = AYA_Client::post( 'backchannel_authentication_endpoint', array(
			'scope'            => 'openid profile',
			'login_hint'       => $agent,
			'binding_message'  => $msg,
			'requested_expiry' => '300',
		) );
		if ( 200 !== $status || empty( $r['auth_req_id'] ) ) {
			/* translators: %s: error from Auth Your Agent */
			return sprintf( __( 'Could not ask the customer to confirm: %s', 'authyouragent' ), $r['error_description'] ?? ( $r['error'] ?? 'unreachable' ) );
		}
		update_user_meta( $uid, self::META, array(
			'hash'        => $hash,
			'status'      => 'pending',
			'auth_req_id' => $r['auth_req_id'],
			'message'     => $msg,
			'exp'         => time() + (int) ( $r['expires_in'] ?? 300 ),
		) );
		/* translators: %s: the text the customer confirms */
		return sprintf( __( 'Waiting for the customer to confirm on their phone: "%s". Place the order again once they have approved.', 'authyouragent' ), $msg );
	}

	private static function poll( $uid, $st ) {
		list( $status, $r ) = AYA_Client::post( 'token_endpoint', array(
			'grant_type'  => 'urn:openid:params:grant-type:ciba',
			'auth_req_id' => $st['auth_req_id'],
		) );
		$err = $r['error'] ?? '';
		if ( 'authorization_pending' === $err || 'slow_down' === $err || 0 === $status ) {
			/* translators: %s: the text the customer confirms */
			return sprintf( __( 'Still waiting for the customer to confirm on their phone: "%s".', 'authyouragent' ), $st['message'] );
		}
		if ( 200 === $status && ! empty( $r['id_token'] ) ) {
			$c = AYA_JWT::verify( $r['id_token'], aya_opt( 'client_id' ) );
			// the confirmation must come from this agent's owner, for this agent
			if ( ! is_wp_error( $c ) && ( $c['act']['sub'] ?? '' ) === get_user_meta( $uid, 'aya_agent_sub', true )
				&& ( $c['sub'] ?? '' ) === get_user_meta( $uid, 'aya_owner_sub', true ) ) {
				$st['status'] = 'approved';
				$st['exp']    = time() + 10 * MINUTE_IN_SECONDS;
				$st['how']    = implode( ', ', array_diff( (array) ( $c['amr'] ?? array() ), array( 'agent' ) ) );
				update_user_meta( $uid, self::META, $st );
				return null;
			}
			delete_user_meta( $uid, self::META );
			return __( 'The confirmation did not come from this agent\'s customer.', 'authyouragent' );
		}
		delete_user_meta( $uid, self::META );
		return 'access_denied' === $err ? __( 'The customer declined this order.', 'authyouragent' )
			: __( 'The confirmation expired. Place the order again to ask once more.', 'authyouragent' );
	}

	public static function classic( $data, $errors ) {
		if ( ! self::applies() || $errors->has_errors() ) {
			return;
		}
		$m = self::gate();
		if ( $m ) {
			$errors->add( 'authyouragent', esc_html( $m ) );
		}
	}

	public static function store_api( $order, $request ) {
		if ( ! self::applies() ) {
			return;
		}
		$m = self::gate();
		if ( $m ) {
			throw new \Automattic\WooCommerce\StoreApi\Exceptions\RouteException( 'authyouragent_confirm', $m, 409 ); // phpcs:ignore WordPress.Security.EscapeOutput
		}
	}

	/** Record the confirmation on the order and use it up. */
	public static function note( $order ) {
		if ( ! $order || ! is_user_logged_in() || ! aya_is_agent( get_current_user_id() ) ) {
			return;
		}
		$uid = get_current_user_id();
		$st  = get_user_meta( $uid, self::META, true );
		$order->update_meta_data( '_aya_agent', get_user_meta( $uid, 'aya_agent_name', true ) );
		if ( is_array( $st ) && 'approved' === ( $st['status'] ?? '' ) ) {
			$order->update_meta_data( '_aya_confirmed', $st['message'] );
			$order->update_meta_data( '_aya_confirmed_how', $st['how'] ?? '' );
			$order->add_order_note( sprintf( 'Placed by an AI agent (%s). The customer confirmed on their phone via Auth Your Agent (%s): "%s"',
				get_user_meta( $uid, 'aya_agent_name', true ), $st['how'] ?? '', $st['message'] ) );
			delete_user_meta( $uid, self::META );
		} else {
			$order->add_order_note( sprintf( 'Placed by an AI agent (%s) via Auth Your Agent.', get_user_meta( $uid, 'aya_agent_name', true ) ) );
		}
		$order->save();
	}

	/** The badges an order has earned: approved on the phone, placed by a signed agent. Escaped HTML. */
	public static function badges( $order ) {
		$out = '';
		if ( $order->get_meta( '_aya_confirmed' ) ) {
			$how  = $order->get_meta( '_aya_confirmed_how' );
			$tip  = sprintf(
				/* translators: 1: the text the owner approved, 2: how they approved (e.g. passkey) */
				__( 'The agent\'s owner approved "%1$s" on their phone%2$s before the order was placed.', 'authyouragent' ),
				$order->get_meta( '_aya_confirmed' ),
				$how ? ' (' . $how . ')' : ''
			);
			$out .= '<mark class="aya-badge aya-approved" title="' . esc_attr( $tip ) . '">' . esc_html__( 'Owner approved on phone', 'authyouragent' ) . '</mark> ';
		} elseif ( $order->get_meta( '_aya_agent' ) ) {
			$out .= '<mark class="aya-badge aya-agent" title="' . esc_attr__( 'Placed by an agent account without a phone confirmation.', 'authyouragent' ) . '">' . esc_html__( 'Agent order, not confirmed', 'authyouragent' ) . '</mark> ';
		}
		if ( $order->get_meta( '_aya_wba_agent' ) ) {
			$out .= '<mark class="aya-badge aya-signed" title="' . esc_attr( $order->get_meta( '_aya_wba_agent' ) ) . '">' . esc_html__( 'Signed agent', 'authyouragent' ) . '</mark>';
		}
		return $out;
	}

	public static function badge_css() {
		echo '<style>.aya-badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:12px;line-height:1.6;margin:2px 0}'
			. '.aya-approved{background:#c6e1c6;color:#2c4700}.aya-agent{background:#f8dda7;color:#573b00}.aya-signed{background:#c8d7e1;color:#2e4453}</style>';
	}

	public static function column( $cols ) {
		$out = array();
		foreach ( $cols as $k => $v ) {
			$out[ $k ] = $v;
			if ( 'order_status' === $k ) {
				$out['aya'] = esc_html__( 'Agent', 'authyouragent' );
			}
		}
		if ( ! isset( $out['aya'] ) ) {
			$out['aya'] = esc_html__( 'Agent', 'authyouragent' );
		}
		return $out;
	}

	public static function column_cell( $col, $order ) {
		if ( 'aya' === $col && $order ) {
			echo self::badges( $order ); // phpcs:ignore WordPress.Security.EscapeOutput -- built escaped
		}
	}

	public static function column_cell_post( $col, $post_id ) {
		if ( 'aya' === $col ) {
			self::column_cell( $col, wc_get_order( $post_id ) );
		}
	}

	public static function admin_badge( $order ) {
		$badges = self::badges( $order );
		if ( ! $badges ) {
			return;
		}
		echo '<p class="form-field form-field-wide aya-badges">' . $badges; // phpcs:ignore WordPress.Security.EscapeOutput -- built escaped
		if ( $order->get_meta( '_aya_confirmed' ) ) {
			echo '<br><small>' . esc_html(
				sprintf(
					/* translators: 1: agent name, 2: the text the owner approved */
					__( '%1$s placed it; its owner approved: "%2$s"', 'authyouragent' ),
					$order->get_meta( '_aya_agent' ),
					$order->get_meta( '_aya_confirmed' )
				)
			) . '</small>';
		}
		if ( $order->get_meta( '_aya_wba_agent' ) ) {
			echo '<br><small>' . esc_html__( 'Signed by', 'authyouragent' ) . ' <code>' . esc_html( preg_replace( '#/\.well-known/http-message-signatures-directory$#', '', $order->get_meta( '_aya_wba_agent' ) ) ) . '</code></small>';
		}
		echo '</p>';
	}
}
