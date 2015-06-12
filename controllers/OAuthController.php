<?php
/**
 * Lithium OAuth Plugin
 *
 * @copyright     Copyright 2012, PixelCog Inc. (http://pixelcog.com)
 * @license       http://opensource.org/licenses/bsd-license.php The BSD License
 */

namespace li3_oauth2\controllers;

use lithium\net\http\Router;
use li3_oauth2\oauth\OAuthConsumer;
use li3_oauth2\extensions\storage\TokenCache;

/**
 * This is an example generic controller to utilize OAuthConsumer for remote authorization.
 *
 * @see li3_oauth2\oauth\OAuthConsumer
 */

class OAuthController extends \lithium\action\Controller {

	/**
	 * Check if we have authorization to the requested resources for a given OAuthConsumer adapter
	 * and attempt to authorize if we do not.
	 *
	 * @return A redirect to the authorization provider for user permission and authentication,
	 *         a success message, or a failure message.
	 */
	public function index() {
		$service = $this->_getService();
		$request = $this->_parseRequest();

		if ( OAuthConsumer::hasAccess($service, $request) ) {
			return $this->_success($request);
		}
		return $this->authorize();
	}

	/**
	 * Attempt to request access to remote resources for a given OAuthConsumer adapter
	 * configuration.
	 *
	 * Redirect the user-agent to the authorization server if necessary to complete the process.
	 *
	 * @return A redirect to the authorization provider for user permission and authentication,
	 *         a success message, or a failure message.
	 */
	public function authorize() {
		$service = $this->_getService();
		$request = $this->_parseRequest();
		$request['nonce'] = substr(md5(uniqid(rand(), true)), 0, 5);
		$request['callback'] = $this->request->to('url', array(
			'path' => Router::match(array('action'=>'confirm') + $this->request->params),
			'query' => false
		));
		// fix for bug in to() function...
		list($request['callback']) = explode('?',$request['callback']);
		$error = null;

		if (true === $url = OAuthConsumer::request($service, $request, $error)) {
			return $this->_success($request);
		}
		if ($url) {
			return $this->redirect($url);
		}
		return $this->_failure($error, $request);
	}

	/**
	 * Attempt to finalize remote authorization process following approval and redirect from the
	 * authorization server via the user-agent.
	 *
	 * @return A success message, or a failure message.
	 */
	public function confirm() {
		$service = $this->_getService();
		$response = $this->request->query;
		$request = array();
		$error = null;

		if (OAuthConsumer::verify($service, $response, $error, $request)) {
			return $this->_success($request);
		}
		return $this->_failure($error, $request);
	}

	/**
	 * Attempt to refresh access to remote resources for a given OAuthConsumer adapter
	 * configuration.
	 *
	 * Redirect the user-agent to the authorization server if necessary to complete the process.
	 *
	 * @return A redirect to the authorization provider for user permission and authentication,
	 *         a success message, or a failure message.
	 */
	public function refresh() {
		$service = $this->_getService();
		$request = $this->_parseRequest();
		$error = null;

		if (OAuthConsumer::refresh($service, $error)) {
			return $this->_success($request);
		}
		return $this->_failure($error, $request);
	}

	/**
	 * Abdicate authorization to remote resources for a given OAuthConsumer adapter configuration.
	 *
	 * @return A success message, or a failure message.
	 */
	public function deauthorize() {
		$service = $this->_getService();
		$request = $this->_parseRequest();
		$error = null;

		if (OAuthConsumer::release($service, $error)) {
			return $this->_success($request);
		}
		return $this->_failure($error, $request);
	}

	/**
	 * Based on the request and error message, display the appropriate error output.
	 *
	 */
	private function _failure($message, array $request = array()) {

		$return = null;

		if (!empty($request['return'])) {
			$return = $request['return'];
		}

		$this->set(compact('message','return'));
		return $this->render(array('template' => 'failure'));
	}

	/**
	 * Based on the request data, display an appropriate success output.
	 *
	 */
	private function _success(array $request = array()) {

		if (!empty($request['return'])) {
			return $this->redirect($request['return']);
		}

		return $this->render(array('template' => 'success'));
	}

	/**
	 * Parse the input.
	 *
	 * @return array normalized authorization request to pass to OAuthConsumer
	 */
	private function _parseRequest() {
		$defaults = array(
			'return' => 'referer'
		);
		$request = $this->request->query + $defaults;

		// use implicitly defined return url?
		if ($request['return'] == 'referer') {
			$referer = parse_url($this->request->referer('/'));

			if (empty($referer['host']) || $referer['host'] == $this->request->env('HTTP_HOST')) {
				$request['return'] = $referer['path'];
				if (!empty($referer['query'])) {
					$request['return'] .= '?' . $referer['query'];
				}
				if (!empty($referer['fragment'])) {
					$request['return'] .= '#' . $referer['fragment'];
				}
			}
		}

		return $request;
	}

	/**
	 * Parse the service parameter.
	 *
	 * @return string Service name.
	 */
	private function _getService() {
		if (isset($this->request->params['service'])) {
			return $this->request->params['service'];
		}
		return 'default';
	}
}

?>