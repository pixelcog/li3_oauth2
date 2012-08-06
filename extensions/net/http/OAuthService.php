<?php
/**
 * Lithium OAuth Plugin
 *
 * @copyright     Copyright 2012, PixelCog Inc. (http://pixelcog.com)
 * @license       http://opensource.org/licenses/bsd-license.php The BSD License
 */

namespace li3_oauth2\extensions\net\http;

use lithium\util\String;

/**
 * OAuth service layer class for handling requests/response to consumers and from providers
 *
 */
class OAuthService extends \lithium\net\http\Service {

	/**
	 * OAuth service layer constructor
	 *
	 * @param array $config Array with the following parameters:
	 *
	 *        [service layer options]
	 *           - socket: socket class to utilize
	 *           - scheme: the transfer protocol
	 *           - host: the oauth domain
	 *           - proxy: alternate host to send request (still signed with original host)
	 *           - port: the oauth port
	 *           - path: the oauth base path
	 *           - base: a base url string to be parsed and formatted into the above schema
	 *
	 *        [common paths]
	 *           - request_token: path to request token url
	 *           - access_token: path to access token url
	 *           - authorize: path to authorize  url
	 */
	public function __construct($config = array()) {
		$defaults = array(
			'socket' => 'Curl',
			'scheme' => 'http',
			'host'   => 'localhost',
			'proxy'  => false,
			'port'   => 80,
			'path'   => '',
			'query'  => null,
			'request_token' => '/oauth/get_request_token',
			'access_token'  => '/oauth/get_token',
			'authorize'     => '/oauth/request_auth'
		);
		$config = $this->_parseUrl($config) + $defaults;
		
		if (!empty($config['base'])) {
			$config = $this->_parseUrl($config['base']) + $config;
		}
		parent::__construct($config);
	}

	/**
	 * Returns specified config parameter if it exists, null otherwise.  If no key provided
	 * returns the full config array.
	 *
	 * @param string $key eg `oauth_consumer_key`
	 * @return mixed Value corresponding to $key, config array, or null.
	 */
	public function config($key = null) {
		if ($key === null) {
			return $this->_config;
		}
		if (isset($this->_config[$key])) {
			return $this->_config[$key];
		}
		return null;
	}

	/**
	 * Send request with the given options and data. OAuth data is specified in options.
	 *
	 * @param string $method `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, etc.
	 * @param string $path A full url or a path relative to the configured request settings.
	 * @param array $data Data to be encoded for the request.
	 * @param array $options Parameters to override `$_config` and specify additional options:
	 *              - oauth: authorization parameters to be sent with the request
	 *              - sign: key with which to sign the request
	 *              - return: how to format the return (token, body, or response)
	 *              - headers : send oauth parameters in the header. (default: true)
	 *              - realm : the realm to authenticate. (default: app directory name)
	 * @return mixed Returns response object, response body, or parsed oauth parameters depending
	 *               on the `return` parameter.
	 */
	public function send($method, $path = null, array $data = array(), array $options = array()) {
		$defaults = array(
			'oauth' => array(),
			'sign' => false,
			'return' => 'body',
			'headers' => true,
			'realm' => basename(LITHIUM_APP_PATH)
		);
		$options += $defaults + $this->_config;
		$oauth = (array) $options['oauth'];
		ksort($oauth);
		
		// break down path into components if necessary, and merge them with our options
		$request = $this->_parseUrl($this->config($path) ?: $path);
		$path = $request['path'];
		if ($request['path'][0] !== '/' && empty($request['host'])) {
			$path = $options['path'] . $path;
		}
		$request['path'] = null;
		$options = $request + $options;
		
		// append extra query parameters to our data
		$query = $options['query'];
		if (!is_array($query)) {
			$query = array();
			parse_str($options['query'],$query);
		}
		$data += $query;
		$options['query'] = '';
		
		// calculate signature if requested
		if ($options['sign']) {
			$oauth['oauth_signature'] = $this->_sign($options['sign'], $oauth['oauth_signature_method'], array(
				'method' => $method,
				'url'    => $this->url($path, array(), $options),
				'params' => $oauth + $data
			));
		}
		
		// generate header if requested
		if ($options['headers']) {
			$header = 'OAuth realm="' . $options['realm'] . '"';
			foreach($oauth as $key => $val) {
				$header .= ',' . $key . '="' . rawurlencode($val) . '"';
			}
			$options['headers'] = array('Authorization' => $header);
			$oauth = array();
		}
		
		// send our request and get a response
		$options['host'] = $options['proxy'] ?: $options['host'];
		$response = parent::send($method, $path, $oauth + $data, $options);
		
		// format and return the response
		if ($response && $options['return'] == 'token') {
			$code = $response->status['code'];
			$body = array();
			parse_str($response->body(), $data);
			if (!empty($response->headers['WWW-Authenticate'])) {
				preg_match('/OAuth ([^\s]+)/s', $response->headers['WWW-Authenticate'], $match);
				if (!empty($match[1])) {
					parse_str($match[1], $head);
					$data += $head;
				}
			}
			return compact('code','data');
		}
		return $response;
	}

	/**
	 * A utility method to compile a url string using the same parameters as `send()`.
	 *
	 * @param string $path A named path from `$_config` or a url fragment to be parsed and
	 *        compiled using `options`.
	 * @param array $data Query parameters to include in the url
	 * @param array $options Parsed url options used to compile the url (scheme, host, etc.)
	 * @return string The compiled url.
	 */
	public function url($path, array $data = array(), array $options = array()) {
		$options += $this->_config;
		
		// compile our path
		$request = $this->_parseUrl($this->config($path) ?: $path);
		if ($request['path'][0] !== '/' && empty($request['host'])) {
			$request['path'] = $options['path'] . $request['path'];
		}
		$options = $request + $options;
		
		// compile our query string
		$query = $options['query'];
		if (!is_array($query)) {
			$query = array();
			parse_str($options['query'],$query);
		}
		if ($data || $query) {
			$options['query'] = '?' . http_build_query($data + $query);
		}
		
		// use port only if non-default
		if (($options['scheme'] == 'http' && $options['port'] == 80) ||
			($options['scheme'] == 'https' && $options['port'] == 443)) {
			$options['port'] = null;
		}
		elseif ($options['port']) {
			$options['port'] = ':'.$options['port'];
		}
		
		$options['authority'] = '';
		if ($options['username']) {
			$options['authority'] .= $options['username'];
			if ($options['password']) {
				$options['authority'] .= ':' . $options['password'];
			}
			$options['authority'] .= '@';
		}
		
		return String::insert("{:scheme}://{:authority}{:host}{:port}{:path}{:query}", $options);
	}
	
	/**
	 * Break a url down to its components and normalize them for our config schema
	 *
	 * @param mixed $url A string representing a url or an array with the following fields:	 
	 *              - scheme: optional
	 *              - host: optional
	 *              - port: optional
	 *              - username: (or 'pass') optional
	 *              - password: (or 'user') optional
	 *              - path: required
	 */
	private function _parseUrl($url) {
		if (!is_array($url)) {
			$url = parse_url($url);
		}
		
		// normalize ports where possible
		$ports = array(20=>'ftp', 21=>'ftp', 22=>'ssh', 80=>'http', 443=>'https');
		
		if (!isset($url['scheme']) && !empty($url['port'])) {
			if (isset($ports[$url['port']])) {
				$url['scheme'] = $ports[$url['port']];
			}
			else {
				$url['scheme'] = 'http';
			}
		}
		elseif (!isset($url['port']) && !empty($url['scheme'])) {
			$schemes = array_flip($ports);
			if (isset($schemes[$url['scheme']])) {
				$url['port'] = $schemes[$url['scheme']];
			}
			else {
				$url['port'] = 80;
			}
		}
		
		// normalize http auth keys
		$auth = array('username'=>'', 'user'=>'', 'password'=>'', 'pass'=>'');
		
		if (array_intersect_key($url,$auth)) {
			$url += $auth;
			
			$url['username'] = $url['username'] ?: $url['user'] ?: '';
			$url['password'] = $url['password'] ?: $url['pass'] ?: '';
			
			unset($url['user'],$url['pass']);
		}
		
		unset($url['fragment']);
		return $url;
	}

	/**
	 * Calculate a signature for the given request parameters.
	 *
	 * @see http://oauth.net/core/1.0/#anchor14
	 *
	 * @param string $key Key with which to sign the request.
	 * @param string $method Method to be used to sign the request (HMAC-SHA1).
	 * @param string $request Request parameters to be normalized for the signature base string.
	 *               - method: http method for the request
	 *               - url: absolute url of request
	 *               - params: request parameters
	 * @return string Compiled signature digest.
	 */
	protected function _sign($key, $method = null, array $request = array()) {
		$defaults = array(
			'method' => 'POST',
			'url' => '',
			'params' => array()
		);
		$request += $defaults;
		
		
		// calculate the base
		$params = array();
		foreach((array) $request['params'] as $k => $v) {
			$params[$k] = $k . '=' . rawurlencode($v);
		}
		uksort($params, 'strcmp');
		
		$base = join('&', array(
			strtoupper($request['method']),
			rawurlencode(strtolower($request['url'])),
			rawurlencode(join('&',$params))
		));
		
		switch ($method) {
			case 'HMAC-SHA1':
				$signature = base64_encode(hash_hmac('sha1', $base, $key, true));
				break;
			case 'PLAINTEXT':
			default:
				$signature = $key;
				break;
		}
		return $signature;
	}
}

?>