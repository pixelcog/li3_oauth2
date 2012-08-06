<?php
/**
 * Lithium OAuth Plugin
 *
 * @copyright     Copyright 2012, PixelCog Inc. (http://pixelcog.com)
 * @license       http://opensource.org/licenses/bsd-license.php The BSD License
 */

/**
 * This bootstrap configures your OAuth connections and persistant storage settings.
 *
 * The following lines help Li3 core find the classes within this library.
 *
 * Make sure to add the following line to your app's bootstrap.php so that it can find all
 * of this:
 * Libraries::add('li3_oauth2');
 *
 */
use lithium\core\Libraries;

Libraries::paths( array(
	'adapter' => array_merge_recursive( (array) Libraries::paths('adapter'), array(
		'{:library}\{:namespace}\{:class}\adapter\{:name}' => array('libraries' => 'li3_oauth2'),
		'{:library}\extensions\{:namespace}\{:class}\adapter\{:name}' => array('libraries' => 'li3_oauth2')
	))
));


/**
 * The section below configures the storage methods for OAuth request and access tokens.  These data
 * must persist someplace they can be readily retrieved as the user agent is redirected to the
 * service provider and back again.  Whether you want these tokens to persist in the session, a
 * cache file, a database table, or via any other method, you can configure your methods here.
 *
 * @see li3_oauth2\extensions\storage\TokenCache
 */
// use li3_oauth2\extensions\storage\TokenCache;

// TokenCache::config(array(
// 	'session' => array(
// 		'adapter' => 'session'
// 	),
// 	'file' => array(
// 		'adapter' => 'file',
// 		'strategies' => array('serializer')
// 	),
// 	'model' => array(
// 		'adapter' => 'model',
// 		'model' => 'tokens'
// 	)
// ));


/**
 * The section below configures the OAuth consumer class.  Adapters exist for OAuth 1.0a and 2.0
 * as `oauth` and `oauth2` respectively.  These can be extended to accomodate the different nuances
 * and quirks of various OAuth service providers out there.  An example configuration for accessing
 * Yahoo's OAuth 1.0a service is shown below.
 *
 * Two important configuration parameters below are `temp_cache` and `token_cache` which determine
 * which TokenCache adapter to use for the request token data and the access/refresh token data
 * respectively.  You may, for instance, want to store keep the request process data in the user
 * session but store the access token and refresh token information in a user-specific database table.
 * These parameters let you specify how to persist the data per service provider.
 *
 * It is recommended that you use a TokenCache adapter capable of blocking for the access token cache.
 * This prevents race conditions arising from refresh token requests on high traffic websites in which
 * a single access token is shared by a large number of users.  This is only necessary for OAuth
 * providers which expire access and refresh tokens very strictly.
 *
 * See individual adapter files for further configuration information.
 *
 * @see li3_oauth2\oauth\OAuthConsumer
 * @see li3_oauth2\oauth\oauth_consumer\adapter
 */
// use li3_oauth2\oauth\OAuthConsumer;

// OAuthConsumer::config(array(
// 	'yahoo' => array(
// 		'development' => array(
// 			'consumer_app_id' => 'GxfBT6mK',
// 			'consumer_key'    => 'dj0yJmk9WjH3eHdkRjFUOUNhJmQ9WVdrOVMyWkNWRWQ0Tz2wbWNHbzlOalU0TmpjMU1qWXkmcz1jb25zdW1lcnNlY3JldCZ4PTFj',
// 			'consumer_secret' => '1661ed31a05026eb3dbb8e436438df8012bfb12a'
// 		),
// 		'production' => array(
// 			'consumer_app_id' => '3cfdm8yE',
// 			'consumer_key'    => 'yr0yJmk9dVRNVHY2Q1A5Z3pOJmQ9WVdrOU0IaZ1aRzFGTTJNbWNHbzlPQFk1T0RFek1qWXkmcz4jb25zdW1lcnNlY3JldCZ4PTNl',
// 			'consumer_secret' => 'x7b85480b21feea8fd5d5bf156fa49568f6df165'
// 		),
// 		true => array(
// 			'adapter'         => 'oauth',
// 			'temp_cache'      => 'session',
// 			'token_cache'     => 'model',
// 			'base'            => 'https://api.login.yahoo.com/',
// 			'request_token'   => '/oauth/v2/get_request_token',
// 			'access_token'    => '/oauth/v2/get_token',
// 			'authorize'       => '/oauth/v2/request_auth',
// 			'yql'             => 'http://query.yahooapis.com/v1/yql?format=json'
// 		)
// 	)
// ));


?>