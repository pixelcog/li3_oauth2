<?php
/**
 * Lithium OAuth Plugin
 *
 * @copyright     Copyright 2012, PixelCog Inc. (http://pixelcog.com)
 * @license       http://opensource.org/licenses/bsd-license.php The BSD License
 */

namespace li3_oauth2\extensions\storage\cache\adapter;


/**
 * A session-based cache.
 *
 * This Session cache adapter provides an interface for generic key/value storage via whatever
 * session class we have configured.  This allows it to be used interchangably with other cache
 * adapters as a means to store temporary persistant data on per user-agent.
 *
 * @see lithium\storage\cache\adapter
 * @see li3_oauth2\extensions\storage\cache\adapter
 */

class Session extends \lithium\core\Object {

	/**
	 * Dynamic class dependencies.
	 *
	 * @var array Associative array of class names & their namespaces.
	 */
	protected static $_classes = array(
		'session' => 'lithium\storage\Session'
	);

	/**
	 * Class constructor.
	 *
	 * @see lithium\storage\Cache::config()
	 * @param array $config Configuration parameters for this cache adapter. These settings are
	 *        indexed by name and queryable through `Cache::config('name')`.
	 *        The defaults are:
	 *        - 'session' : Path to our Session class.
	 *        - 'options' : Default options to pass to Session functions
	 *        - 'expiry' : Default expiry time used if none is explicitly set when calling
	 *          `Cache::write()`.
	 */
	public function __construct(array $config = array()) {
		$defaults = array(
			'session' => static::$_classes['session'],
			'options' => array(),
			'expiry' => '+1 day'
		);
		parent::__construct($config + $defaults);
	}

	/**
	 * Write value(s) to the cache.
	 *
	 * @param string $key The key to uniquely identify the cached item.
	 * @param mixed $data The value to be cached.
	 * @param null|string $expiry A strtotime() compatible cache time. If no expiry time is set,
	 *        then the default cache expiration time set with the cache configuration will be used.
	 * @return closure Function returning boolean `true` on successful write, `false` otherwise.
	 */
	public function write($key, $data, $expiry = null) {
		$session = $this->_config['session'];
		$options = $this->_config['options'];
		$expiry = $expiry ?: $this->_config['expiry'];

		return function($self, $params) use ($session, $options, $expiry) {
			$expiry = strtotime($expiry);

			return $session::write($params['key'],array(
				'expiry' => $expiry,
				'data' => $params['data'],
			),$options);
		};
	}

	/**
	 * Read value(s) from the cache.
	 *
	 * @param string $key The key to uniquely identify the cached item.
	 * @return closure Function returning cached value if successful, `false` otherwise.
	 */
	public function read($key) {
		$session = $this->_config['session'];
		$options = $this->_config['options'];

		return function($self, $params) use ($session, $options) {

			$cache = $session::read($params['key'], $options);

			if (!$cache || !isset($cache['data'])) {
				return false;
			}

			if (!empty($cache['expiry']) && $cache['expiry'] < time()) {
				$session::delete($params['key'], $options);
				return false;
			}

			return $cache['data'];
		};
	}

	/**
	 * Delete an entry from the cache.
	 *
	 * @param string $key The key to uniquely identify the cached item.
	 * @return closure Function returning boolean `true` on successful delete, `false` otherwise.
	 */
	public function delete($key) {
		$session = $this->_config['session'];
		$options = $this->_config['options'];

		return function($self, $params) use ($session, $options) {
			return $session::delete($params['key'], $options);
		};
	}

	/**
	 * The Session adapter does not provide any facilities for atomic incrementing
	 * of cache items. If you need this functionality, please use a cache adapter
	 * which provides native support for atomic increment.
	 *
	 * This method is not implemented, and will simply return false.
	 *
	 * @param string $key Key of numeric cache item to increment
	 * @param integer $offset Offset to increment - defaults to 1.
	 * @return boolean False - this method is not implemented
	 */
	public function increment($key, $offset = 1) {
		return false;
	}

	/**
	 * The Session adapter does not provide any facilities for atomic decrementing
	 * of cache items. If you need this functionality, please use a cache adapter
	 * which provides native support for atomic decrement.
	 *
	 * This method is not implemented, and will simply return false.
	 *
	 * @param string $key Key of numeric cache item to decrement
	 * @param integer $offset Offset to increment - defaults to 1.
	 * @return boolean False - this method is not implemented
	 */
	public function decrement($key, $offset = 1) {
		return false;
	}

	/**
	 * Perform garbage collection.  Not implemented for this adapter. Session data is temporary
	 * and there is little nead for clearing or garbage collection.
	 *
	 * @return boolean True.
	 */
	public function clean() {
		return true;
	}

	/**
	 * Clears user-space cache.  Not implemented for this adapter. Session data is temporary and
	 * there is little nead for clearing or garbage collection.
	 *
	 * @return boolean True.
	 */
	public function clear() {
		return true;
	}

	/**
	 * Implements cache adapter support-detection interface.
	 *
	 * @return boolean Always returns `true`.
	 */
	public static function enabled() {
		return true;
	}
}

?>