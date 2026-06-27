<?php
/**
 * The base configuration for WordPress
 */

// ** Database settings ** //
define( 'DB_NAME', '{{.WPDBName}}' );
define( 'DB_USER', '{{.WPDBUser}}' );
define( 'DB_PASSWORD', '{{.WPDBPass}}' );
define( 'DB_HOST', '{{.DBIP}}' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

define( 'AUTH_KEY',         '{{index .WPSalts 0}}' );
define( 'SECURE_AUTH_KEY',  '{{index .WPSalts 1}}' );
define( 'LOGGED_IN_KEY',    '{{index .WPSalts 2}}' );
define( 'NONCE_KEY',        '{{index .WPSalts 3}}' );
define( 'AUTH_SALT',        '{{index .WPSalts 4}}' );
define( 'SECURE_AUTH_SALT', '{{index .WPSalts 5}}' );
define( 'LOGGED_IN_SALT',   '{{index .WPSalts 6}}' );
define( 'NONCE_SALT',       '{{index .WPSalts 7}}' );

$table_prefix = 'wp_';

define( 'WP_DEBUG', false );
define( 'FS_METHOD', 'direct' );

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

require_once ABSPATH . 'wp-settings.php';
