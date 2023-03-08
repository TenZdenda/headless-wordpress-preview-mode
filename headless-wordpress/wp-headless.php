<?php

/*
Plugin Name: Headless Wordpress
Description: Modifies Wordpress to better suit headless use cases.
Author: Zdeněk Pašek
Version: 2.0
*/

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GraphQL\Error\UserError;
use WPGraphQL\Model\User;

class ZdenekHeadlessWp
{
    private static $fieldId = 'client_domain_name';
    private static $frontDomain;
    private static $previewUser;

    protected static $issued;
    protected static $expiration;
	protected static $is_refresh_token = false;


    public static function init()
    {
        self::$frontDomain = get_option(self::$fieldId);
        // Create preview user
        add_action('init', [self::class, 'handlePreviewUser']);
        // Add input into permalink setting
        add_action('load-options-permalink.php', [self::class, 'addSettings']);
        // Preview redirect
        add_action("template_redirect", function () {
            if (!is_admin() && isset($_GET["preview"]) && $_GET["preview"] == true) {
                $actual_link = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
                $parsed_url = trim(parse_url($actual_link, PHP_URL_PATH), '/');

                $token = self::getToken();
                
                wp_redirect( self::$frontDomain . "/api/preview?secret=" . getenv('GRAPHQL_JWT_AUTH_SECRET_KEY') . "&slug=" . $parsed_url);
            }
        });
    }

    public static function get_secret_key() {
		// Use the defined secret key, if it exists
		$secret_key = defined( 'GRAPHQL_JWT_AUTH_SECRET_KEY' ) && ! empty( GRAPHQL_JWT_AUTH_SECRET_KEY ) ? GRAPHQL_JWT_AUTH_SECRET_KEY : null;
		return apply_filters( 'graphql_jwt_auth_secret_key', $secret_key );

	}

    public static function handlePreviewUser()
    {
        self::$previewUser = [
            'user_login' => getenv('BRAID_PREVIEW_USER_LOGIN'),
            'user_pass' => getenv('BRAID_PREVIEW_USER_PASSWORD'),
            'role' => 'editor'
        ];

        wp_insert_user(self::$previewUser);
    }

    public static function addSettings()
    {
        if (isset($_POST[self::$fieldId])) {
            update_option(self::$fieldId, sanitize_url($_POST[self::$fieldId]));
        }

        add_settings_field(
            self::$fieldId,
            'Front End Domain Name',
            [self::class, 'renderSettings'],
            'permalink',
            'optional'
        );
    }

    public static function getToken()
    {
        $username = self::$previewUser['user_login'];
        $password = self::$previewUser['user_pass'];

        /**
		 * Do whatever you need before authenticating the user.
		 *
		 * @param string $username Username as sent by the user
		 * @param string $password Password as sent by the user
		 */
		do_action( 'graphql_jwt_auth_before_authenticate', $username, $password );

		/**
		 * Authenticate the user and get the Authenticated user object in response
		 */
		$user = self::authenticate_user( $username, $password );

        /**
		 * Set the current user to the authenticated user
		 */
		if ( empty( $user->data->ID ) ) {
			return;
		}

        $response = [
			'authToken' => self::get_signed_token( wp_get_current_user() ),
		];


        return $response['authToken'];
    }

    protected static function get_signed_token( $user, $cap_check = true ) {

		/**
		 * Only allow the currently signed in user access to a JWT token
		 */
		if ( true === $cap_check && get_current_user_id() !== $user->ID || 0 === $user->ID ) {
			// See https://github.com/wp-graphql/wp-graphql-jwt-authentication/issues/111
			self::set_status(400);
			return new \WP_Error( 'graphql-jwt-no-permissions', __( 'Only the user requesting a token can get a token issued for them', 'wp-graphql-jwt-authentication' ) );
		}

		/**
		 * Determine the "not before" value for use in the token
		 *
		 * @param string   $issued The timestamp of the authentication, used in the token
		 * @param \WP_User $user   The authenticated user
		 */
		$not_before = apply_filters( 'graphql_jwt_auth_not_before', self::get_token_issued(), $user );


		/**
		 * Configure the token array, which will be encoded
		 */
		$token = [
			'iss'  => get_bloginfo( 'url' ),
			'iat'  => self::get_token_issued(),
			'nbf'  => $not_before,
			'exp'  => self::get_token_expiration(),
			'data' => [
				'user' => [
					'id' => $user->data->ID,
				],
			],
		];

		/**
		 * Filter the token, allowing for individual systems to configure the token as needed
		 *
		 * @param array    $token The token array that will be encoded
		 * @param \WP_User $token The authenticated user
		 */
		$token = apply_filters( 'graphql_jwt_auth_token_before_sign', $token, $user );

		/**
		 * Encode the token
		 */
		JWT::$leeway = 60;
		$token       = JWT::encode( $token, self::get_secret_key(), 'HS256' );

		/**
		 * Filter the token before returning it, allowing for individual systems to override what's returned.
		 *
		 * For example, if the user should not be granted a token for whatever reason, a filter could have the token return null.
		 *
		 * @param string $token   The signed JWT token that will be returned
		 * @param int    $user_id The User the JWT is associated with
		 */
		$token = apply_filters( 'graphql_jwt_auth_signed_token', $token, $user->ID );

		/**
		 * Return the token
		 */
		return ! empty( $token ) ? $token : null;

	}

    protected static function authenticate_user( $username, $password ) {

		/**
		 * Try to authenticate the user with the passed credentials
		 */
		$user = wp_authenticate( sanitize_user( $username ), trim( $password ) );

		/**
		 * If the authentication fails return a error
		 */
		if ( is_wp_error( $user ) ) {
			$error_code = ! empty( $user->get_error_code() ) ? $user->get_error_code() : 'invalid login';
			throw new UserError( esc_html( $error_code ) );
		}

		return ! empty( $user ) ? $user : null;

	}

    public static function get_token_issued() {
		if ( ! isset( self::$issued ) ) {
			self::$issued = time();
		}

		return self::$issued;
	}

    public static function get_token_expiration() {

		if ( ! isset( self::$expiration ) ) {

			/**
			 * Set the expiration time, default is 300 seconds.
			 */
			$expiration = 300;

			/**
			 * Determine the expiration value. Default is 5 minutes, but is filterable to be configured as needed
			 *
			 * @param string $expiration The timestamp for when the token should expire
			 */
			self::$expiration = self::get_token_issued() + apply_filters( 'graphql_jwt_auth_expire', $expiration );
		}

		return ! empty( self::$expiration ) ? self::$expiration : null;
	}

    public static function renderSettings()
    {
        ?>
            <input
                type="text"
                value="<?= esc_attr(self::$frontDomain) ?>"
                name="client_domain_name"
                id="client_domain_name"
                class="regular-text"
            >
        <?php
    }
}

ZdenekHeadlessWp::init();
