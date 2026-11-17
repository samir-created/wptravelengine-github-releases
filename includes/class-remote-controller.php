<?php

namespace WPTEDZGithub;

defined( 'ABSPATH' ) || exit;

/**
 * Remote access for the QA hub: report what is installed, install a release by tag,
 * and hand a test browser a one-time login.
 *
 * Authenticated with a WordPress Application Password (Basic auth) of a user who can
 * manage options. Registered only when the "Remote access" toggle is on and the site's
 * environment type is local, development or staging — never on production.
 */
class RemoteController {

	private const NAMESPACE      = 'github/v1';
	private const LOGIN_PARAM    = 'wpte_dz_login';
	private const LOGIN_TTL      = 5 * MINUTE_IN_SECONDS;
	private const LOGIN_PREFIX   = 'wpte_dz_gh_login_';
	private const ALLOWED_ENVS   = [ 'local', 'development', 'staging' ];

	public static function environment_allowed(): bool {
		return in_array( wp_get_environment_type(), self::ALLOWED_ENVS, true );
	}

	public static function enabled(): bool {
		return get_option( WPTE_DZ_GITHUB_OPTION_REMOTE, 'no' ) === 'yes' && self::environment_allowed();
	}

	public static function boot(): void {
		if ( ! self::enabled() ) {
			return;
		}
		add_action( 'rest_api_init', [ self::class, 'register_routes' ] );
		add_action( 'init', [ self::class, 'consume_login_link' ] );
	}

	public static function register_routes(): void {
		$auth = [ self::class, 'permission_check' ];

		register_rest_route( self::NAMESPACE, '/remote/status', [
			'methods'             => 'GET',
			'callback'            => [ self::class, 'status' ],
			'permission_callback' => $auth,
		] );

		register_rest_route( self::NAMESPACE, '/remote/install', [
			'methods'             => 'POST',
			'callback'            => [ self::class, 'install' ],
			'permission_callback' => $auth,
			'args'                => [
				'repo' => [ 'type' => 'string', 'required' => true ],
				'tag'  => [ 'type' => 'string', 'required' => true ],
			],
		] );

		register_rest_route( self::NAMESPACE, '/remote/login-link', [
			'methods'             => 'POST',
			'callback'            => [ self::class, 'login_link' ],
			'permission_callback' => $auth,
		] );
	}

	public static function permission_check(): bool|\WP_Error {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new \WP_Error( 'forbidden', 'Use an Application Password of an administrator.', [ 'status' => rest_authorization_required_code() ] );
		}
		return true;
	}

	/**
	 * WP/PHP versions and every plugin with its version, state and whether its folder is a git clone.
	 */
	public static function status(): \WP_REST_Response {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		$plugins = [];
		foreach ( get_plugins() as $file => $data ) {
			$dir       = WP_PLUGIN_DIR . '/' . dirname( $file );
			$plugins[] = [
				'file'    => $file,
				'name'    => $data['Name'],
				'version' => $data['Version'],
				'active'  => is_plugin_active( $file ),
				'git'     => '.' !== dirname( $file ) && is_dir( ( realpath( $dir ) ?: $dir ) . '/.git' ),
			];
		}

		$user = get_option( 'wpte_dz_github_user', [] );

		return new \WP_REST_Response( [
			'wp'          => get_bloginfo( 'version' ),
			'php'         => PHP_VERSION,
			'environment' => wp_get_environment_type(),
			'github_user' => $user['login'] ?? '',
			'has_token'   => (bool) get_option( WPTE_DZ_GITHUB_OPTION_TOKEN, '' ),
			'plugins'     => $plugins,
		], 200 );
	}

	/**
	 * Install a release by tag with the site's own GitHub token, then activate it.
	 * Git clones are refused by GithubInstaller; the result is logged in GitHub Downloads.
	 */
	public static function install( \WP_REST_Request $request ): \WP_REST_Response|\WP_Error {
		@set_time_limit( 300 );

		$repo = (string) $request->get_param( 'repo' );
		$tag  = (string) $request->get_param( 'tag' );

		if ( ! preg_match( '#^[a-zA-Z0-9._\-]+/[a-zA-Z0-9._\-]+$#', $repo ) ) {
			return new \WP_Error( 'invalid_repo', 'repo must be owner/name.', [ 'status' => 400 ] );
		}
		if ( '' === $tag ) {
			return new \WP_Error( 'invalid_tag', 'tag is required.', [ 'status' => 400 ] );
		}
		if ( ! get_option( WPTE_DZ_GITHUB_OPTION_TOKEN, '' ) ) {
			return new \WP_Error( 'no_token', 'Connect a GitHub token in DevZone → GitHub first.', [ 'status' => 409 ] );
		}

		// Same rule as the webhook: only the connected account's repos and its orgs' repos.
		$owner   = strtolower( explode( '/', $repo )[0] );
		$trusted = GithubApi::trusted_owners();
		if ( ! $trusted || ! in_array( $owner, $trusted, true ) ) {
			return new \WP_Error( 'untrusted_owner', "{$owner} is not the connected GitHub account or one of its orgs.", [ 'status' => 403 ] );
		}

		$releases = GithubApi::get_releases( $repo );
		if ( is_wp_error( $releases ) ) {
			return new \WP_Error( $releases->get_error_code(), $releases->get_error_message(), [ 'status' => 502 ] );
		}
		$release = current( array_filter( $releases, fn( $r ) => $r['tag'] === $tag ) );
		if ( ! $release || empty( $release['zip_url'] ) ) {
			return new \WP_Error( 'no_release_zip', "No release with a zip for {$repo}@{$tag}.", [ 'status' => 404 ] );
		}

		$summary = [ 'number' => 0, 'title' => 'QA hub (remote)', 'full_name' => $repo, 'html_url' => '' ];
		$result  = GithubInstaller::install_from_url( $release['zip_url'], $repo );

		if ( is_wp_error( $result ) ) {
			GithubRestController::log_error( $summary, [ 'pr' => 0, 'pr_repo' => $repo, 'tag' => $tag, 'message' => $result->get_error_message() ] );
			$status = 'git_clone' === $result->get_error_code() ? 409 : 500;
			return new \WP_Error( $result->get_error_code(), $result->get_error_message(), [ 'status' => $status ] );
		}

		$entry = array_merge( $result, [ 'pr' => 0, 'pr_repo' => $repo, 'tag' => $tag, 'zip_url' => $release['zip_url'], 'activated' => false ] );

		$plugin_file = $result['plugin_file'] ?? '';
		if ( $plugin_file && file_exists( WP_PLUGIN_DIR . '/' . $plugin_file ) ) {
			$activated = activate_plugin( $plugin_file );
			if ( is_wp_error( $activated ) ) {
				$entry['activate_error'] = $activated->get_error_message();
			} else {
				$entry['activated'] = true;
			}
		}

		GithubRestController::log_download( $summary, $entry );

		return new \WP_REST_Response( [
			'repo'           => $repo,
			'tag'            => $tag,
			'slug'           => $entry['slug'] ?? '',
			'plugin_file'    => $plugin_file,
			'action'         => $entry['action'] ?? 'installed',
			'activated'      => $entry['activated'],
			'activate_error' => $entry['activate_error'] ?? '',
		], 200 );
	}

	/**
	 * A single-use URL that logs a browser in as the calling user, valid for five minutes.
	 * Application Passwords cannot log in through wp-login.php; this is how a test browser gets a session.
	 */
	public static function login_link( \WP_REST_Request $request ): \WP_REST_Response {
		$token = wp_generate_password( 40, false );
		set_transient( self::LOGIN_PREFIX . hash( 'sha256', $token ), get_current_user_id(), self::LOGIN_TTL );

		$redirect = wp_validate_redirect( (string) $request->get_param( 'redirect' ), admin_url() );

		return new \WP_REST_Response( [
			'url'        => add_query_arg( [ self::LOGIN_PARAM => $token, 'redirect_to' => rawurlencode( $redirect ) ], home_url( '/' ) ),
			'expires_in' => self::LOGIN_TTL,
		], 200 );
	}

	public static function consume_login_link(): void {
		if ( empty( $_GET[ self::LOGIN_PARAM ] ) ) {
			return;
		}

		$key     = self::LOGIN_PREFIX . hash( 'sha256', sanitize_text_field( wp_unslash( $_GET[ self::LOGIN_PARAM ] ) ) );
		$user_id = (int) get_transient( $key );
		delete_transient( $key ); // single use, whether it was valid or not

		if ( ! $user_id || ! get_userdata( $user_id ) ) {
			wp_die( esc_html__( 'This login link has expired or was already used.', 'wpte-devzone-github' ), '', [ 'response' => 403 ] );
		}

		wp_set_current_user( $user_id );
		wp_set_auth_cookie( $user_id );

		$redirect = isset( $_GET['redirect_to'] ) ? wp_unslash( $_GET['redirect_to'] ) : ''; // $_GET is already decoded once
		wp_safe_redirect( wp_validate_redirect( $redirect, admin_url() ) );
		exit;
	}
}
