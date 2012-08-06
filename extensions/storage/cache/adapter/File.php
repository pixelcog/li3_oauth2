<?php
/**
 * Lithium OAuth Plugin
 *
 * @copyright     Copyright 2012, PixelCog Inc. (http://pixelcog.com)
 * @license       http://opensource.org/licenses/bsd-license.php The BSD License
 */

namespace li3_oauth2\extensions\storage\cache\adapter;

/**
 * A minimal file-based cache.
 *
 * This File adapter extends the default File cache adapter within the li3 core library
 * and adds two important functions; `block` and `wait`.  These two functions can be
 * used to lock cache files and prevent race conditions from occuring in an adaptable
 * class deriving from `Cache` which make use of them.
 *
 * See the original File adapter for more information on configuration and use.
 *
 * @see lithium\storage\cache\adapter
 * @see li3_oauth2\extensions\storage\cache\adapter
 */

class File extends \lithium\storage\cache\adapter\File {

	/**
	 * Class constructor.
	 *
	 * @see lithium\storage\cache\adapter\File::__construct()
	 */
	public function __construct(array $config = array()) {
		$defaults = array(
			'expiry' => '+5 years'
		);
		parent::__construct($config + $defaults);
	}
}

?>