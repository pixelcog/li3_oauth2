<?php
/**
 * Lithium OAuth Plugin
 *
 * @copyright     Copyright 2015, PixelCog Inc. (http://pixelcog.com)
 * @license       http://opensource.org/licenses/bsd-license.php The BSD License
 */

namespace li3_oauth2\extensions\storage;


/**
 * The `TokenCache` static class extends the standard li3 `Cache` class and provides a consistent
 * interface to store data which requires `blocking` to prevent certain race conditions.
 *
 * This storage class layer inherits from the common `Adaptable` class, which provides the generic
 * configuration setting & retrieval logic, as well as the logic required to locate & instantiate
 * the proper adapter class.
 *
 * For adapters that support it, blocking is achieved in the following way:
 * - Read operations wait for locks by default.
 * - Read operations with `block = true` attempt to obtain a lock and return false immediately
 *   if it cannot. This is effectively the same as calling `block() && read()`.
 * - Write operations automatically release locks by default.
 *
 * @see lithium\core\Adaptable
 * @see lithium\storage\Cache
 * @see lithium\storage\cache\adapter
 * @see li3_oauth2\extensions\storage\cache\adapter
 */
class TokenCache extends \lithium\storage\Cache {

	/**
	 * Stores configurations for token cache adapters
	 *
	 * @var array
	 */
	protected static $_configurations = array();

	/**
	 * Stores an array of locks we are holding for internal reference
	 *
	 * @var array
	 */
	protected static $_locks = array();

	/**
	 * Writes to the specified cache configuration.
	 *
	 * @param string $name Configuration to be used for writing
	 * @param mixed $key Key to uniquely identify the cache entry
	 * @param mixed $data Data to be cached
	 * @param string $expiry A strtotime() compatible cache time
	 * @param mixed $options Options for the method, filters and strategies.
	 * @return boolean True on successful cache write, false otherwise
	 * @filter This method may be filtered.
	 */
	public static function write($name, $key, $data, $expiry = null, array $options = array()) {
		$defaults = array(
			'wait' => true,
			'block' => false,
			'unblock' => true
		);
		$options += $defaults;

		if ($options['block']) {
			if(!self::block($name, $key, $options['wait'])) {
				return false;
			}
		}
		elseif ($options['wait']) {
			self::wait($name, $key);
		}
		$result = parent::write($name, $key, $data, $expiry, $options);

		if ($options['unblock']) {
			self::unblock($name, $key);
		}
		return $result;
	}

	/**
	 * Reads from the specified cache configuration.
	 *
	 * Will wait for a block by default unless `block` is set to true in which case it will wait
	 * only if `wait` is explicitly set to true.
	 *
	 * @param string $name Configuration to be used for reading
	 * @param mixed $key Key to be retrieved
	 * @param mixed $options Options for the method and strategies.
	 * @return mixed Read results on successful cache read, null otherwise
	 * @filter This method may be filtered. (via parent class)
	 */
	public static function read($name, $key, array $options = array()) {
		$defaults = array(
			'wait' => empty($options['block']),
			'block' => false
		);
		$options += $defaults;

		if ($options['block']) {
			if(!self::block($name, $key, $options['wait'])) {
				return false;
			}
		}
		elseif ($options['wait']) {
			self::wait($name, $key);
		}
		return parent::read($name, $key, $options);
	}

	/**
	 * Delete a value from the specified cache configuration
	 *
	 * @param string $name The cache configuration to delete from
	 * @param mixed $key Key to be deleted
	 * @param mixed $options Options for the method and strategies.
	 * @return boolean True on successful deletion, false otherwise
	 * @filter This method may be filtered.
	 */
	public static function delete($name, $key, array $options = array()) {
		$defaults = array(
			'wait' => true,
			'block' => true
		);
		$options += $defaults;

		if ($options['block']) {
			if(!self::block($name, $key, $options['wait'])) {
				return false;
			}
		}
		elseif ($options['wait']) {
			self::wait($name, $key);
		}
		$result = parent::delete($name, $key, $options);

		if ($options['block']) {
			self::unblock($name, $key);
		}
		return $result;
	}

	/**
	 * Obtain an exclusive lock to a particular cache key.
	 *
	 * This method is not filterable.
	 *
	 * @param string $name The cache configuration to use
	 * @param mixed $key Key to obtain a lock on
	 * @param boolean $wait Whether to wait for an existing lock or return right away
	 * @return boolean Returns `true` if lock obtained, `false` otherwise
	 */
	public static function block($name, $key, $wait = false) {
		if (!$adapter = static::adapter($name)) {
			return false;
		}
		if (!method_exists($adapter,'block') || !empty(self::$_locks[$name][$key])) {
			return true;
		}
		return self::$_locks[$name][$key] = $adapter->block($name, $key, $wait);
	}

	/**
	 * Release an exclusive lock to a particular cache key.
	 *
	 * This method is not filterable.
	 *
	 * @param string $name The cache configuration to use
	 * @param mixed $key Key to release a lock on
	 * @return boolean Returns `true` if lock released, `false` otherwise
	 */
	public static function unblock($name, $key) {
		if (!$adapter = static::adapter($name)) {
			return false;
		}
		if (!method_exists($adapter,'unblock') || empty(self::$_locks[$name][$key])) {
			return true;
		}
		self::$_locks[$name][$key] = false;
		return $adapter->unblock($name, $key);
	}

	/**
	 * Wait for the lock to a particular cache key to be released.
	 *
	 * This method is not filterable.
	 *
	 * @param string $name The cache configuration to use
	 * @param mixed $key Key to wait on
	 * @return void
	 */
	public static function wait($name, $key) {
		if (!$adapter = static::adapter($name)) {
			return;
		}
		if (!method_exists($adapter,'wait') || !empty(self::$_locks[$name][$key])) {
			return;
		}
		return $adapter->wait($name, $key);
	}

	/**
	 * Called when an adapter configuration is first accessed.
	 *
	 * @param string $name The name of the adapter configuration being accessed.
	 * @param array $config The user-specified configuration.
	 * @return array Returns an array that merges the user-specified configuration with the
	 *         generated default values.
	 */
	protected static function _initConfig($name, $config) {
		if ( !isset(self::$_locks[$name]) ) {
			self::$_locks[$name] = array();
		}
		return parent::_initConfig($name, $config);
	}
}

?>