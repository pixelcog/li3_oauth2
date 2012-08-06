<?php
/**
 * Lithium OAuth Plugin
 *
 * @copyright     Copyright 2012, PixelCog Inc. (http://pixelcog.com)
 * @license       http://opensource.org/licenses/bsd-license.php The BSD License
 */

namespace li3_oauth2\extensions\storage\cache\adapter;

use lithium\core\Libraries;
use lithium\core\ClassNotFoundException;

/**
 * A database model-based cache.
 *
 * The Model cache adapter provides an interface for generic key/value storage via a li3 Model
 * class specified in the adapter configuration.
 *
 * @todo Implement `upsert` or `ON DUPLICATE KEY UPDATE` method to avoid rare race conditions
 *       where table row is deleted in between `SELECT` and `UPDATE` within `write` and `block`
 * @todo Implement `block` and `unblock` using `Model::update()` to perform an atomic update
 *
 * @see lithium\storage\cache\adapter
 * @see li3_oauth2\extensions\storage\cache\adapter
 */

class Model extends \lithium\core\Object {

	/**
	 * The name of the model class to query against. This can either be a model name (i.e.
	 * `'Tokens'`), or a fully-namespaced class reference (i.e. `'app\models\Tokens'`).
	 *
	 * @var string
	 */
	protected $_model = '';

	/**
	 * The list of fields to map our `key`, `data`, and `lock` variables to when querying the
	 * database. This can either be a simple array of field names, or a set of key/value pairs,
	 * which map the field names in the request to database field names.
	 *
	 * @var array
	 */
	protected $_fields = array();

	/**
	 * The list of locks we are currently holding.  This stores cache model instances referenced
	 * by key.
	 *
	 * @var array
	 */
	protected $_locks = array();

	/**
	 * List of configuration properties to automatically assign to the properties of the adapter
	 * when the class is constructed.
	 *
	 * @var array
	 */
	protected $_autoConfig = array('model', 'fields');
	
	/**
	 * Class constructor.
	 *
	 * @see lithium\storage\Cache::config()
	 * @param array $config Configuration parameters for this cache adapter. These settings are
	 *              indexed by name and queryable through `Cache::config('name')`. Defaults are:
	 *              - `'model'` _string_: The name of the model class to use. See the `$_model`
	 *                property for details.
	 *              - `'fields'` _array_: The model fields to query against when taking input from
	 *                the read/write methods. See the `$_fields` property for details.
	 *              - 'expiry' : Default expiry time used if none is explicitly set when calling
	 *                `Cache::write()`.
	 */
	public function __construct(array $config = array()) {
		$defaults = array(
			'model' => 'Tokens',
			'fields' => array('key' => '_id', 'data', 'lock', 'expiry'),
			'expiry' => '+5 years'
		);
		parent::__construct($config + $defaults);
	}

	/**
	 * Initializes values configured in the constructor.
	 *
	 * @return void
	 */
	protected function _init() {
		parent::_init();

		foreach ($this->_fields as $key => $val) {
			if (is_int($key)) {
				unset($this->_fields[$key]);
				$this->_fields[$val] = $val;
			}
		}
		$this->_fields += array(
			'key' => '_id', 'data' => 'data', 
			'lock' => 'lock', 'expiry' => 'expiry');
			
		if (!$model = Libraries::locate('models', $this->_model)) {
			throw new ClassNotFoundException('Model class `'.$this->_model.'` not found.');
		}
		$this->_model = $model;
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
		$model = $this->_model;
		$fields = $this->_fields;
		$locks = $this->_locks;
		$expiry = $expiry ?: $this->_config['expiry'];
		
		return function($self, $params) use ($model, $fields, $expiry, $locks) {
			$expiry = strtotime($expiry);
			$conditions = array($fields['key'] => $params['key']);
			
			if (!empty($locks[$params['key']])) {
				$cache = $locks[$params['key']];
			}
			elseif (!$cache = $model::first($conditions)){
				$cache = $model::create($conditions);
			}
			return $cache->save(array(
				$fields['data'] => $params['data'],
				$fields['expiry'] => $expiry
			));
		};
	}

	/**
	 * Read value(s) from the cache.
	 *
	 * @param string $key The key to uniquely identify the cached item.
	 * @return closure Function returning cached value if successful, `false` otherwise.
	 */
	public function read($key) {
		$model = $this->_model;
		$fields = $this->_fields;
		$locks = &$this->_locks;
		
		return function($self, $params) use ($model, $fields, &$locks) {
			$key = $params['key'];
			
			if (!empty($locks[$key])) {
				$cache = $locks[$key];
			}
			else {
				$cache = $model::first(array($fields['key'] => $params['key']));
			}
			
			if (!$cache || !isset($cache['data'])) {
				return false;
			}
			
			if (!empty($cache['expiry']) && $cache['expiry'] < time()) {
				$cache->delete();
				unset($locks[$key]);
				return false;
			}
			
			$cache = $cache->to('array');
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
		$model = $this->_model;
		$fields = $this->_fields;
		$locks = &$this->_locks;

		return function($self, $params) use ($model, $fields, &$locks) {
			$key = $params['key'];
			if (!empty($locks[$key])) {
				$cache = $locks[$key];
				unset($locks[$key]);
				return $cache->delete();
			}
			return $model::remove(array($fields['key'] => $params['key']));
		};
	}

	/**
	 * The Model adapter does not provide any facilities for atomic incrementing of cache items.
	 * If you need this functionality, please use a cache adapter which provides native support
	 * for atomic increment.
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
	 * The Model adapter does not provide any facilities for atomic incrementing of cache items.
	 * If you need this functionality, please use a cache adapter which provides native support
	 * for atomic increment.
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
	 * Clears user-space cache.  Function not yet implemented.
	 *
	 * @return mixed True on successful clear, false otherwise.
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