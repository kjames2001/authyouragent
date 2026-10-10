<?php
/** Settings > Auth Your Agent. */
defined( 'ABSPATH' ) || exit;

class AYA_Settings {

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
		add_filter( 'plugin_action_links_authyouragent/authyouragent.php', array( __CLASS__, 'link' ) );
	}

	public static function link( $links ) {
		array_unshift( $links, '<a href="' . esc_url( admin_url( 'options-general.php?page=authyouragent' ) ) . '">' . esc_html__( 'Settings', 'authyouragent' ) . '</a>' );
		return $links;
	}

	public static function menu() {
		add_options_page( 'Auth Your Agent', 'Auth Your Agent', 'manage_options', 'authyouragent', array( __CLASS__, 'page' ) );
	}

	public static function register() {
		register_setting( 'aya', 'aya_settings', array( 'sanitize_callback' => array( __CLASS__, 'clean' ) ) );
	}

	public static function clean( $in ) {
		$old = get_option( 'aya_settings', array() );
		$out = array(
			'issuer'         => esc_url_raw( trim( $in['issuer'] ?? '' ), array( 'https' ) ),
			'client_id'      => sanitize_text_field( $in['client_id'] ?? '' ),
			'button_label'   => sanitize_text_field( $in['button_label'] ?? '' ),
			'role'           => sanitize_key( $in['role'] ?? '' ),
			'confirm_orders' => empty( $in['confirm_orders'] ) ? '0' : '1',
			'wba'            => empty( $in['wba'] ) ? '0' : '1',
			'wba_mode'       => in_array( $in['wba_mode'] ?? '', array( 'all', 'listed' ), true ) ? $in['wba_mode'] : 'all',
			'wba_refuse_invalid' => empty( $in['wba_refuse_invalid'] ) ? '0' : '1',
		);
		// an empty secret field keeps the saved secret
		$s                    = trim( $in['client_secret'] ?? '' );
		$out['client_secret'] = '' !== $s ? $s : ( $old['client_secret'] ?? '' );
		if ( $out['role'] && get_role( $out['role'] ) && ( get_role( $out['role'] )->has_cap( 'manage_options' ) || get_role( $out['role'] )->has_cap( 'edit_users' ) ) ) {
			add_settings_error( 'aya_settings', 'role', __( 'Agents cannot be given a role that manages the site.', 'authyouragent' ) );
			$out['role'] = '';
		}
		delete_transient( 'aya_discovery' );
		delete_transient( 'aya_jwks' );
		return $out;
	}

	private static function row( $label, $html, $help = '' ) {
		echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>' . $html . ( $help ? '<p class="description">' . esc_html( $help ) . '</p>' : '' ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput
	}

	public static function page() {
		$o      = get_option( 'aya_settings', array() );
		$secret = $o['client_secret'] ?? '';
		$shown  = $secret ? substr( $secret, 0, 4 ) . '…' . substr( $secret, -4 ) : '';
		echo '<div class="wrap"><h1>Auth Your Agent</h1>';
		echo '<p>' . esc_html__( 'Let AI assistants sign in as your customer\'s approved agent and complete orders. The customer approves on their phone.', 'authyouragent' ) . '</p>';
		echo '<h2>' . esc_html__( 'Register this site', 'authyouragent' ) . '</h2><ol>';
		/* translators: %s: link to the Sites page of the Auth Your Agent account */
		echo '<li>' . wp_kses_post( sprintf( __( 'Open <a href="%s" target="_blank" rel="noopener">Sites</a> in your Auth Your Agent account and add this site.', 'authyouragent' ), esc_url( AYA_Client::issuer() . '/app#sites' ) ) ) . '</li>';
		echo '<li>' . esc_html__( 'Redirect URI:', 'authyouragent' ) . ' <code>' . esc_html( aya_redirect_uri() ) . '</code></li>';
		echo '<li>' . esc_html__( 'Sign-out (back-channel logout) URI:', 'authyouragent' ) . ' <code>' . esc_html( aya_logout_uri() ) . '</code></li>';
		echo '<li>' . esc_html__( 'Copy the client ID and secret below.', 'authyouragent' ) . '</li></ol>';
		echo '<form method="post" action="options.php">';
		settings_fields( 'aya' );
		echo '<table class="form-table" role="presentation">';
		self::row( __( 'Provider', 'authyouragent' ), '<input class="regular-text" name="aya_settings[issuer]" value="' . esc_attr( aya_opt( 'issuer' ) ) . '">', __( 'Change only if you run your own Auth Your Agent server.', 'authyouragent' ) );
		self::row( __( 'Client ID', 'authyouragent' ), '<input class="regular-text" name="aya_settings[client_id]" value="' . esc_attr( $o['client_id'] ?? '' ) . '">' );
		/* translators: %s: first and last characters of the saved secret */
		$keep = $shown ? sprintf( __( 'saved (%s); leave empty to keep', 'authyouragent' ), $shown ) : '';
		self::row( __( 'Client secret', 'authyouragent' ), '<input class="regular-text" type="password" autocomplete="new-password" name="aya_settings[client_secret]" placeholder="' . esc_attr( $keep ) . '">' );
		self::row( __( 'Button label', 'authyouragent' ), '<input class="regular-text" name="aya_settings[button_label]" value="' . esc_attr( aya_opt( 'button_label' ) ) . '">', __( 'Shown on the WordPress and WooCommerce sign-in forms. Elsewhere, use the [authyouragent_button] shortcode.', 'authyouragent' ) );
		$roles = '<select name="aya_settings[role]"><option value="">' . esc_html__( 'Default (Customer, or the site\'s default role)', 'authyouragent' ) . '</option>';
		foreach ( wp_roles()->roles as $k => $r ) {
			if ( empty( $r['capabilities']['manage_options'] ) && empty( $r['capabilities']['edit_users'] ) ) {
				$roles .= '<option value="' . esc_attr( $k ) . '"' . selected( $o['role'] ?? '', $k, false ) . '>' . esc_html( translate_user_role( $r['name'] ) ) . '</option>';
			}
		}
		self::row( __( 'Role for agent accounts', 'authyouragent' ), $roles . '</select>', __( 'Each agent gets its own account, named for what it is, for example "Jarvis (agent of James)". It never signs in to an existing customer\'s account.', 'authyouragent' ) );
		if ( class_exists( 'WooCommerce' ) ) {
			self::row( __( 'Order confirmation', 'authyouragent' ), '<label><input type="checkbox" name="aya_settings[confirm_orders]" value="1"' . checked( aya_opt( 'confirm_orders' ), '1', false ) . '> '
				. esc_html__( 'Before an agent\'s order is placed, the customer confirms the basket and total on their phone', 'authyouragent' ) . '</label>' );
		}
		self::row( __( 'Signed agents', 'authyouragent' ), '<label><input type="checkbox" name="aya_settings[wba]" value="1"' . checked( aya_opt( 'wba' ), '1', false ) . '> '
			. esc_html__( 'Check Web Bot Auth signatures, list the agents that visit, and label their orders', 'authyouragent' ) . '</label><br>'
			. '<label><input type="radio" name="aya_settings[wba_mode]" value="all"' . checked( aya_opt( 'wba_mode' ), 'all', false ) . '> ' . esc_html__( 'Let every signed agent in, except those you block', 'authyouragent' ) . '</label><br>'
			. '<label><input type="radio" name="aya_settings[wba_mode]" value="listed"' . checked( aya_opt( 'wba_mode' ), 'listed', false ) . '> ' . esc_html__( 'Let signed agents in only once you allow them', 'authyouragent' ) . '</label><br>'
			. '<label><input type="checkbox" name="aya_settings[wba_refuse_invalid]" value="1"' . checked( aya_opt( 'wba_refuse_invalid' ), '1', false ) . '> '
			. esc_html__( 'Refuse requests whose signature is invalid (forged, expired, or copied from another page)', 'authyouragent' ) . '</label>',
			__( 'Works with any agent that signs, not only Auth Your Agent ones. Ordinary visitors and unsigned requests are never affected.', 'authyouragent' ) );
		echo '</table>';
		submit_button();
		echo '</form>';
		AYA_WBA_Site::section();
		if ( aya_configured() ) {
			$ok = AYA_Client::discovery() ? __( 'Provider reachable.', 'authyouragent' ) : __( 'Provider NOT reachable: check the address.', 'authyouragent' );
			echo '<p><strong>' . esc_html( $ok ) . '</strong></p>';
		}
		echo '</div>';
	}
}
