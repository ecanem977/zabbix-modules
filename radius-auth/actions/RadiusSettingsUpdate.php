<?php declare(strict_types = 0);
/*
** RADIUS authentication module for Zabbix - save settings.
*/

namespace Modules\RadiusAuth\Actions;

require_once __DIR__.'/../lib/RadiusClient.php';
require_once __DIR__.'/../lib/Config.php';

use API,
	CController,
	CControllerResponseRedirect,
	CMessageHelper,
	CUrl,
	RadiusAuthLib\Config;

class RadiusSettingsUpdate extends CController {

	public static function fieldRules(): array {
		return [
			'enabled' =>						'in 0,1',
			'server1_host' =>					'string',
			'server1_port' =>					'required|int32|ge 1|le 65535',
			'server2_host' =>					'string',
			'server2_port' =>					'required|int32|ge 1|le 65535',
			'secret' =>							'string',
			'clear_secret' =>					'in 0,1',
			'timeout' =>						'required|int32|ge 1|le 30',
			'retries' =>						'required|int32|ge 0|le 5',
			'nas_identifier' =>					'string',
			'require_message_authenticator' =>	'in 0,1',
			'fallback_mode' =>					'required|in '.implode(',', [Config::FALLBACK_UNKNOWN_USER,
				Config::FALLBACK_UNREACHABLE, Config::FALLBACK_NEVER
			]),
			'unknown_user_marker' =>			'string',
			'excluded_users' =>					'string',
			'debug_log' =>						'in 0,1'
		];
	}

	protected function checkInput(): bool {
		$ret = $this->validateInput(self::fieldRules());

		if (!$ret) {
			CMessageHelper::setErrorTitle(_('Cannot update RADIUS settings'));
			$this->setResponse($this->redirectToEdit());
		}

		return $ret;
	}

	protected function checkPermissions(): bool {
		return $this->getUserType() == USER_TYPE_SUPER_ADMIN;
	}

	protected function doAction(): void {
		$module = Config::loadModule();

		if ($module === null) {
			CMessageHelper::setErrorTitle(_('RADIUS module is not registered. Scan the modules directory first.'));
			$this->setResponse($this->redirectToEdit());

			return;
		}

		$config = self::configFromInput($this->getInputAll(), $module['config']);

		$errors = [];

		if ($config['enabled'] && $config['server1_host'] === '') {
			$errors[] = _('Primary RADIUS server is required when RADIUS authentication is enabled.');
		}

		if ($config['enabled'] && $config['secret'] === '') {
			$errors[] = _('Shared secret is required when RADIUS authentication is enabled.');
		}

		if ($errors) {
			CMessageHelper::setErrorTitle(_('Cannot update RADIUS settings'));
			array_map([CMessageHelper::class, 'addError'], $errors);

			$this->setResponse($this->redirectToEdit());

			return;
		}

		$result = API::Module()->update([[
			'moduleid' => $module['moduleid'],
			'config' => $config
		]]);

		if ($result) {
			CMessageHelper::setSuccessTitle(_('RADIUS settings updated'));
		}
		else {
			CMessageHelper::setErrorTitle(_('Cannot update RADIUS settings'));
		}

		$this->setResponse($this->redirectToEdit());
	}

	/**
	 * Build a full config from form input. An empty secret field keeps the stored secret.
	 */
	public static function configFromInput(array $input, array $stored): array {
		$config = $stored;

		foreach (array_keys(Config::DEFAULTS) as $key) {
			if ($key === 'secret') {
				continue;
			}

			if (in_array($key, ['enabled', 'require_message_authenticator', 'debug_log'], true)) {
				$config[$key] = array_key_exists($key, $input) ? (int) $input[$key] : 0;
			}
			elseif (array_key_exists($key, $input)) {
				$config[$key] = is_string($input[$key]) ? trim($input[$key]) : $input[$key];
			}
		}

		if (array_key_exists('clear_secret', $input) && $input['clear_secret'] == 1) {
			$config['secret'] = '';
		}
		elseif (array_key_exists('secret', $input) && $input['secret'] !== '') {
			$config['secret'] = $input['secret'];
		}

		return Config::normalize($config);
	}

	private function redirectToEdit(): CControllerResponseRedirect {
		return new CControllerResponseRedirect(
			(new CUrl('zabbix.php'))->setArgument('action', 'radius.settings.edit')
		);
	}
}
