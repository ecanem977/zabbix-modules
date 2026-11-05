<?php declare(strict_types = 0);
/*
** RADIUS authentication module for Zabbix - settings page.
*/

namespace Modules\RadiusAuth\Actions;

require_once __DIR__.'/../lib/RadiusClient.php';
require_once __DIR__.'/../lib/Config.php';

use CController,
	CControllerResponseData,
	RadiusAuthLib\Config;

class RadiusSettingsEdit extends CController {

	protected function init(): void {
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		return true;
	}

	protected function checkPermissions(): bool {
		return $this->getUserType() == USER_TYPE_SUPER_ADMIN;
	}

	protected function doAction(): void {
		$module = Config::loadModule();
		$config = $module !== null ? $module['config'] : Config::DEFAULTS;

		$data = [
			'config' => array_diff_key($config, ['secret' => true]),
			'secret_is_set' => $config['secret'] !== '',
			'hook_loaded' => defined('RADIUS_AUTH_HOOK_LOADED'),
			'module_found' => $module !== null
		];

		$response = new CControllerResponseData($data);
		$response->setTitle(_('RADIUS authentication'));
		$this->setResponse($response);
	}
}
