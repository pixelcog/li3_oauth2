<?php
/**
 * Lithium OAuth Plugin
 *
 * @copyright     Copyright 2012, PixelCog Inc. (http://pixelcog.com)
 * @license       http://opensource.org/licenses/bsd-license.php The BSD License
 */

namespace li3_oauth2\oauth;

use lithium\core\Environment;
use lithium\analysis\Logger;
use li3_oauth2\extensions\storage\TokenCache;

/**
 * The `OAuthConsumer` static class provides a consistent interface to configure and utilize
 * the different remote authorization adapters included this library.
 *
 * The OAuth Consumer class inherits from the common `Adaptable` class, and provides the logic
 * for access token requests, storage and retrieval of access credentials, as well as the logic
 * required to communicate with remote servers using any obtained access credentials.
 *
 * The token data is stored using the TokenCache adaptable class and treated as a 'black box'
 * of data to be understood, passed to, and updated by the underlying OAuth adapter.
 *
 * In addition to `adapter`, this class allows for two additional config parameters,
 * `temp_cache` and `token_cache`.  These can be used to specify which TokenCache adapter to
 * use for both temporary authorization request data, and the resulting access credentials
 * respectively.
 *
 * Each adapter provides a consistent interface for the basic OAuth operations handling all
 * server-to-server communication and user interaction queues necessary to obtain and utilize
 * access to remote resources.
 *
 * For more information on `OAuthConsumer` methods and specific adapters, please see their
 * individual documentation.
 *
 * @see lithium\core\Adaptable
 * @see li3_oauth2\oauth\oauth_consumer\adapter
 * @see li3_oauth2\extensions\storage\TokenCache
 */
class OAuthConsumer extends \lithium\core\Adaptable {

	/**
	 * Stores configurations arrays for OAuth adapters, keyed by configuration name.
	 *
	 * @var array
	 */
	protected static $_configurations = array();

	/**
	 * A dot-separated path for use by `Libraries::locate()`. Used to look up the correct type of
	 * adapters for this class.
	 *
	 * @var string
	 */
	protected static $_adapters = 'adapter.oauth.oauth_consumer';

	/**
	 * Check whether we have remote authroization conforming to the given request parameters for
	 * this service.  Do we have a valid token with the permissions required in `$request`?
	 *
	 * @param string $service Named OAuthConsumer configuration.
	 * @param array $request Optional specification of access parameters to test against.
	 *              Formatted the same as the corresponding input in the `request` method.
	 * @return boolean Returns `true` if a the the token is valid, `false` otherwise.
	 */
	public static function hasAccess($service, array $request = array()) {
		if (!$cache = self::_refresh($service, $error, 300)) {
			return false;
		}
		return static::adapter($service)->hasAccess($cache['token'], $request);
	}

	/**
	 * Request an access token from a remote authorization provider.  This will either return a
	 * boolean indicating success or a url string to queue the caller of thie method to redirect
	 * the user agent to the remote server for authentication and permission.
	 *
	 * All data within the `$request` parameter can optionally be retrieved later via the `verify`
	 * method.  The can be helpful if you wish to store additional information such as a url to
	 * redirect the user on success, or some other flag indicating what to do next based on the
	 * request outcome, et cetera...
	 *
	 * Optionally a unique value can be assigned to `nonce` within the `$request` parameter to
	 * prevent possible race conditions if a user attempts to perform multiple authorization
	 * requests at once.  This value will be appended as a request parameter to the `callback`
	 * url sent to the authorization server, and must be included in any subsequent call to
	 * `verify()`.
	 *
	 * @param string $service Named OAuthConsumer configuration.
	 * @param array $request Optional request parameters to be sent to the adapter class.
	 * @param string $error Optional reference to variable in which to place error information.
	 * @return mixed Returns `true` if a the we have obtained an access token, or a url string if
	 *               the user is needed to interact with the remote authorization server, or false
	 *               if there an error in the request process.
	 */
	public static function request($service, array $request = array(), &$error = null) {
		if (!is_array($config = static::config($service))) {
			return false;
		}
		
		if ($config['logging']) {
			Logger::info('OAuth requesting access for `'.$service.'` service.');
		}
		
		$defaults = array(
			'nonce'    => null,
			'callback' => null
		);
		$request += $defaults;
		
		if ($nonce = $request['nonce']) {
			$request['callback'] = self::_addUrlParams($request['callback'], compact('nonce'));
		}
		
		$token = array();
		$error = null;
		
		$authorized = true === ($response = static::adapter($service)->request($token, $request, $error));
		
		$cache = compact('request','authorized','token','error');
		
		TokenCache::write($config['temp_cache'], self::_key($service, 'temp' . $nonce), $cache, '+1 hour');
		
		if ($authorized) {
			TokenCache::write($config['token_cache'], self::_key($service), $cache, '+2 Years');
			
			if ($config['logging']) {
				$expires = static::adapter($service)->expires($cache['token']);
				Logger::info('OAuth access granted for `'.$service.'` service.  Expires in '.($expire - time()).' seconds');
			}
		}
		
		return $response;
	}

	/**
	 * When a user agent returns from the authorization provider with a response, this method
	 * handles the remaining server-to-server communication necessary to obtain access or return
	 * an appropriate status message.
	 *
	 * @param string $service Named OAuthConsumer configuration.
	 * @param array $response Data returned from the authentication server via the user agent.
	 * @param string $error Optional reference to variable in which to place error information.
	 * @param array $request Optional reference to variable in which to return the parameters
	 *              from the initial call to the `request` method, in case the caller has a use
	 *              for it.
	 * @return boolean Returns `true` if the requested authorization has been granted, `false`
	 *                 otherwise.
	 */
	public static function verify($service, array $response, &$error = null, array &$request = null) {
		if (!is_array($config = static::config($service))) {
			return false;
		}
		
		if ($config['logging']) {
			Logger::info('OAuth verifying access for `'.$service.'` service.');
		}
		
		$error = null;
		$nonce = null;
		if (!empty($response['nonce'])) {
			$nonce = $response['nonce'];
		}
		
		$cache = TokenCache::read($config['temp_cache'], self::_key($service, 'temp' . $nonce));
		
		if (!$cache || $cache['authorized'] && array_diff($response, $cache['response'])) {
			// Input does not correspond to an existing request.
			$error = "Unable to locate authorization request";
			return false;
		}
		
		if ($cache['authorized']) {
			// User likely hit refresh accidentally, just replay the output.
			$request = $cache['request'];
			return true;
		}
		
		$token   = $cache['token'];
		$request = $cache['request'];
		$authorized = static::adapter($service)->verify($token, $response, $error);
		
		$cache = compact('request','response','authorized','token','error');
		
		TokenCache::write($config['temp_cache'], self::_key($service, 'temp' . $nonce), $cache, '+1 hour');
		
		if ($authorized) {
			TokenCache::write($config['token_cache'], self::_key($service), $cache, '+2 Years');
			
			if ($config['logging']) {
				$expires = static::adapter($service)->expires($cache['token']);
				Logger::info('OAuth access granted for `'.$service.'` service.  Expires in '.($expire - time()).' seconds');
			}
		}
		
		return $authorized;
	}

	/**
	 * Check the time at which our access credentials must be renewed.
	 *
	 * @param string $service Named OAuthConsumer configuration.
	 * @param string $error Optional reference to variable in which to place error information.
	 * @return integer Returns a Unix epoch timestamp at which the token must be renewed, or
	 *                 `null` on error.
	 */
	public static function expires($service, &$error = null) {
		if (!is_array($config = static::config($service))) {
			return null;
		}
		
		if ((!$cache = TokenCache::read($config['token_cache'], self::_key($service))) || !$cache['authorized']) {
			$error = "Unable to locate valid access credentials.";
			return null;
		}
		return static::adapter($service)->expires($cache['token'], $error);
	}

	/**
	 * Attempt to refresh user access credentials, regardless of expiration status.
	 *
	 * @param string $service Named OAuthConsumer configuration.
	 * @param string $error Optional reference to variable in which to place error information.
	 * @return boolean Returns `true` if the token has been successfully refreshed, `false`
	 *                 otherwise.
	 */
	public static function refresh($service, &$error = null) {
		return (boolean) self::_refresh($service, $error);
	}

	/**
	 * Abdicate user access credentials.
	 *
	 * @param string $service Named OAuthConsumer configuration.
	 * @param string $error Optional reference to variable in which to place error information.
	 * @return boolean Returns `true` if the token has been successfully refreshed, `false`
	 *                 otherwise.
	 */
	public static function release($service, &$error = null) {
		if (!is_array($config = static::config($service))) {
			return null;
		}
		
		if ((!$cache = TokenCache::read($config['token_cache'], self::_key($service))) || !$cache['authorized']) {
			return true;
		}
		$cache['authorized'] = false;
		TokenCache::write($config['token_cache'], self::_key($service), $cache, '+2 Years');
		
		if ($config['logging']) {
			$expires = static::adapter($service)->expires($cache['token']);
			Logger::info('OAuth access released for `'.$service.'` service');
		}
		return static::adapter($service)->release($cache['token'], $error);
	}

	/**
	 * Perform a generic HTTP request using OAuth access credentials.
	 *
	 * @param string $service Named OAuthConsumer configuration.
	 * @param string $error Optional reference to variable in which to place error information.
	 * @return boolean Returns `true` if the token has been successfully refreshed, `false`
	 *                 otherwise.
	 */
	public static function access($method, $service, $path = null, array $data = array(), &$error = null) {
		$error = null;
		
		if (!$cache = self::_refresh($service, $error, 300)) {
			return false;
		}
		return static::adapter($service)->access($method, $cache['token'], $path, $data, $error);
	}

	/**
	 * Magic method to pass through HTTP methods. i.e.`OAuthConsumer::post()`
	 *
	 * @param string $method
	 * @param string $params
	 * @return mixed
	 */
	public static function __callStatic($method, $params) {
		array_unshift($params, $method);
		return self::invokeMethod('access', $params);
	}

	/**
	 * Obtain access credentials. Attempts to refresh them if they are past an expiration
	 * threshold.
	 *
	 * Handles the process of blocking the cache as necessary to prevent race conditions in the
	 * event that multiple users or processes attempt to refresh the token at the same time.
	 *
	 * Read operations wait for blocks (by default). Read operations with `block = true` attempt
	 * to obtain a lock and return false immediately if it cannot.  Write operations automatically
	 * release blocks (by default). More information on TokenCache blocking can be found in the
	 * TokenCache class documentation.
	 *
	 * @param string $service Named OAuthConsumer configuration.
	 * @param string $error Optional reference to variable in which to place error information.
	 * @param integer $threshold Optional value (in seconds) before token expiration at which to
	 *                renew access credentials.
	 * @return array Returns token cache data or `false` on error.
	 */
	private static function _refresh($service, &$error = null, $threshold = null) {
		if (!is_array($config = static::config($service))) {
			return false;
		}
		$attempt = 0;
		$adapter = $config['token_cache'];
		$key = self::_key($service);
		
		if (!($cache = TokenCache::read($adapter, $key)) || !$cache['authorized']) {
			$error = "Unable to locate valid access credentials.";
			return false;
		}
		
		$expires = static::adapter($service)->expires($cache['token']);
		while ($expires && (!$threshold || time() + $threshold > $expires)) {
			
			if ($attempt++ > 5) {
				$error = "Unable to refresh token.";
				return false;
			}
			
			if ($cache = TokenCache::read($adapter, $key, array('block' => true))){
				
				if (!$cache['authorized']) {
					$error = $cache['error'];
					return false;
				}
				if (!static::adapter($service)->refresh($cache['token'], $error)) {
					$cache['authorized'] = false;
					$cache['error'] = $error;
					TokenCache::write($adapter, $key, $cache, '+2 Years');
					
					if ($config['logging']) {
						$expires = static::adapter($service)->expires($cache['token']);
						Logger::info('OAuth access refreshed failed for `'.$service.'` service.  Error: '.$error);
					}
					return false;
				}
				TokenCache::write($adapter, $key, $cache, '+2 Years');
				
				if ($config['logging']) {
					$expires = static::adapter($service)->expires($cache['token']);
					Logger::info('OAuth access granted for `'.$service.'` service.  Expires in '.($expire - time()).' seconds');
				}
				break;
			}
			elseif (!$cache = TokenCache::read($adapter, $key) || !$cache['authorized']) {
				$error = $cache['error'] ?: "Unable to locate valid access credentials.";
				return false;
			}
		}
		
		return $cache;
	}

	/**
	 * Generate unique cache keys for token and temporary token data stores.
	 *
	 * @param string $service Named OAuthConsumer configuration.
	 * @param string $key Optional string to identify data type and/or add entropy for uniqueness.
	 * @return string Key for the token or temporary token data cache.
	 */
	private static function _key($service, $key = 'token') {
		return implode('-', array($service, Environment::get(), $key));
	}

	/**
	 * Append GET string parameters to a url.
	 *
	 * @param string $url URL to append.
	 * @param mixed $params Parameters to append to the GET query. Will be typecast as an array.
	 * @return string Key for the token or temporary token data cache.
	 */
	private static function _addUrlParams($url, $params) {
		$params = http_build_query((array) $params);
		
		if (($pos = strpos($url, '?')) === false) {
			$url .= '?' . $params;
		}
		elseif ($pos == strlen($url) - 1) {
			$url .= $params;
		}
		else {
			$url .= '&' . $params;
		}
		return $url;
	}

	/**
	 * A stub method called by `_config()` which allows us to automatically assign or auto-generate
	 * additional configuration data when a configuration is first accessed.
	 *
	 * @param string $name The name of the configuration which is being accessed. This is the key
	 *               name containing the specific set of configuration passed into `config()`.
	 * @param array $config Contains the configuration assigned to `$name`. If this configuration is
	 *              segregated by environment, then this will contain the configuration for the
	 *              current environment.
	 * @return array Returns the final array of settings for the given named configuration.
	 */
	protected static function _initConfig($name, $config) {
		$defaults = array('temp_cache' => null, 'token_cache' => null, 'logging' => false);
		return parent::_initConfig($name, (array) $config + $defaults);
	}
}

?>