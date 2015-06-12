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
	 *        - socket: socket class to utilize
	 *        - scheme: the transfer protocol
	 *        - host: the oauth domain
	 *        - proxy: alternate host to send request (still signed with original host)
	 *        - port: the oauth port
	 *        - path: the oauth base path
	 */
	public function __construct($config = array()) {
		$defaults = array(
			'socket' => 'Curl',
			'scheme' => 'http',
			'host'   => 'localhost',
			'proxy'  => false,
			'port'   => 80,
			'path'   => '',
			'query'  => array()
		);
		parent::__construct($config + $defaults);

		$this->_responseTypes += array(
			'token' => function($response) {
				$code = $response->status['code'];
				$data = $body = $response->body();
				if (!is_array($body)) {
					parse_str($body, $data);
				}
				if (!empty($response->headers['WWW-Authenticate'])) {
					preg_match('/OAuth ([^\s]+)/s', $response->headers['WWW-Authenticate'], $match);
					if (!empty($match[1])) {
						$head = array();
						parse_str($match[1], $head);
						$data += $head;
					}
				}
				return compact('code','data');
			}
		);
	}

	/**
	 * Instantiates a request object (usually an instance of `http\Request`) and tests its
	 * properties based on the request type and data to be sent.
	 *
	 * @param string $method The HTTP method of the request, i.e. `'GET'`, `'HEAD'`, `'OPTIONS'`,
	 *        etc. Can be passed in upper- or lower-case.
	 * @param string $path The
	 * @param string $data
	 * @param string $options
	 * @return object Returns an instance of `http\Request`, configured with an HTTP method, query
	 *         string or POST/PUT/PATCH data, and URL.
	 */
	protected function _request($method, $path, $data, $options) {
		$defaults = array(
			'sign' => false,
			'oauth' => array(),
			'headers' => true,
			'realm' => basename(LITHIUM_APP_PATH)
		);
		$options += $defaults + $this->_config;
		$oauth = (array) $options['oauth'];
		ksort($oauth);

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

		$options['host'] = $options['proxy'] ?: $options['host'];
		return parent::_request($method, $path, $data + $oauth, $options);
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
		if ($path[0] !== '/' && empty($options['host'])) {
			$path = $options['path'] . $path;
		}
		$options = compact('path') + $options;

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