<?php declare(strict_types = 0);
/*
** RADIUS authentication module for Zabbix - "Test" button.
** Sends a real Access-Request with the values currently in the form (not yet saved).
*/

namespace Modules\RadiusAuth\Actions;

require_once __DIR__.'/../lib/RadiusClient.php';
require_once __DIR__.'/../lib/Config.php';
require_once __DIR__.'/RadiusSettingsUpdate.php';

use CController,
	CControllerResponseData,
	RadiusAuthLib\Config,
	RadiusAuthLib\RadiusClient;

class RadiusSettingsTest extends CController {

	protected function checkInput(): bool {
		$rules = RadiusSettingsUpdate::fieldRules() + [
			'test_username' => 'required|string|not_empty',
			'test_password' => 'required|string|not_empty'
		];

		$ret = $this->validateInput($rules);

		if (!$ret) {
			$this->respond(false, _('Invalid input'), array_column(get_and_clear_messages(), 'message'));
		}

		return $ret;
	}

	protected function checkPermissions(): bool {
		return $this->getUserType() == USER_TYPE_SUPER_ADMIN;
	}

	protected function doAction(): void {
		$module = Config::loadModule();
		$stored = $module !== null ? $module['config'] : Config::DEFAULTS;
		$config = RadiusSettingsUpdate::configFromInput($this->getInputAll(), $stored);

		if ($config['server1_host'] === '' || $config['secret'] === '') {
			$this->respond(false, _('Primary server and shared secret are required.'));

			return;
		}

		$started = microtime(true);
		$outcome = Config::makeClient($config)->authenticate($this->getInput('test_username'),
			$this->getInput('test_password')
		);
		$elapsed = sprintf('%d ms', (microtime(true) - $started) * 1000);

		$details = [];

		if ($outcome['server'] !== null) {
			$details[] = _('Server').': '.$outcome['server'];
		}

		$details[] = _('Time').': '.$elapsed;

		foreach ($outcome['reply_messages'] as $message) {
			$details[] = 'Reply-Message: '.$message;
		}

		if ($outcome['error'] !== null) {
			$details[] = $outcome['error'];
		}

		switch ($outcome['result']) {
			case RadiusClient::RESULT_ACCEPT:
				$this->respond(true, _('Access-Accept: credentials are valid.'), $details);
				break;

			case RadiusClient::RESULT_REJECT:
				$title = Config::isUnknownUserReject($config, $outcome['reply_messages'])
					? _('Access-Reject (user unknown to RADIUS, local password would be used).')
					: _('Access-Reject: wrong password or user not allowed.');
				$this->respond(false, $title, $details);
				break;

			case RadiusClient::RESULT_UNREACHABLE:
				$this->respond(false, _('No answer from any RADIUS server.'), $details);
				break;

			default:
				$this->respond(false, _('Invalid or unverifiable answer.'), $details);
		}
	}

	private function respond(bool $success, string $title, array $details = []): void {
		$this->setResponse(new CControllerResponseData(['main_block' => json_encode([
			'success' => $success,
			'title' => $title,
			'details' => array_values($details)
		])]));
	}
}
