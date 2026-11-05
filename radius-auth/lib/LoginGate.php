<?php declare(strict_types = 0);
/*
** RADIUS authentication module for Zabbix
** Login hook: runs inside the normal frontend bootstrap, right before index.php checks the password.
**
** Decision table for a login form submit of an existing, internally authenticated Zabbix user:
**   RADIUS Access-Accept                  -> logged in (MFA still applies if configured for the user).
**   RADIUS Access-Reject                  -> denied, local password is NOT tried.
**   Reject with "unknown user" marker     -> local password is checked   (fallback mode "unknown_user").
**   RADIUS unreachable / invalid answer   -> local password is checked   (fallback modes "unknown_user", "unreachable").
** Users that are excluded, LDAP-provisioned or in LDAP-authenticated groups are never touched.
*/

namespace RadiusAuthLib;

final class LoginGate {

	/**
	 * Cheap check that runs on every PHP request before Zabbix is bootstrapped.
	 */
	public static function isLoginRequest(): bool {
		if (PHP_SAPI === 'cli' || basename((string) ($_SERVER['SCRIPT_NAME'] ?? '')) !== 'index.php') {
			return false;
		}

		if (strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? '')) !== 'POST') {
			return false;
		}

		return isset($_POST['enter'], $_POST['name'], $_POST['password'])
			&& is_string($_POST['name']) && is_string($_POST['password'])
			&& $_POST['enter'] !== 'guest';
	}

	public static function handle(): void {
		$fail_closed = false;

		try {
			self::process($fail_closed);
		}
		catch (\Throwable $e) {
			error_log('radius-auth: internal error: '.$e->getMessage());

			if ($fail_closed) {
				self::denyLocalLogin();
			}
		}
	}

	private static function process(bool &$fail_closed): void {
		$username = trim($_POST['name']);
		$password = $_POST['password'];

		if ($username === '' || $password === '') {
			return;
		}

		$module = Config::loadModule();

		if ($module === null || $module['status'] != MODULE_STATUS_ENABLED || !$module['config']['enabled']) {
			return;
		}

		$config = $module['config'];
		$log = static function(string $message) use ($config): void {
			if ($config['debug_log']) {
				error_log('radius-auth: '.$message);
			}
		};

		$fail_closed = $config['fallback_mode'] === Config::FALLBACK_NEVER;

		if (in_array($username, Config::excludedUsers($config), true)) {
			$log('user "'.$username.'" is excluded, using local authentication.');
			$fail_closed = false;

			return;
		}

		// Only existing local Zabbix users (exact, case-sensitive match) are checked against RADIUS.
		$db_user = \DBfetch(\DBselect(
			'SELECT userid,username,userdirectoryid,attempt_failed,attempt_clock'.
			' FROM users'.
			' WHERE username='.\zbx_dbstr($username)
		));

		if (!$db_user) {
			$fail_closed = false;

			return;
		}

		if ($db_user['userdirectoryid'] != 0) {
			$log('user "'.$username.'" is provisioned from a user directory, skipping.');
			$fail_closed = false;

			return;
		}

		\CUser::addUserGroupFields($db_user, $group_status, $group_auth_type);

		if ($group_auth_type != ZBX_AUTH_INTERNAL) {
			$log('user "'.$username.'" uses LDAP authentication, skipping.');
			$fail_closed = false;

			return;
		}

		// Let the core produce its usual error for disabled or blocked accounts.
		if ($group_status == GROUP_STATUS_DISABLED || $db_user['gui_access'] == GROUP_GUI_ACCESS_DISABLED
				|| self::isTemporarilyBlocked($db_user)) {
			$fail_closed = false;

			return;
		}

		$outcome = Config::makeClient($config)->authenticate($username, $password);

		switch ($outcome['result']) {
			case RadiusClient::RESULT_ACCEPT:
				$log('Access-Accept for "'.$username.'" from '.$outcome['server'].'.');
				self::login($db_user);

				return;

			case RadiusClient::RESULT_REJECT:
				if ($config['fallback_mode'] === Config::FALLBACK_UNKNOWN_USER
						&& Config::isUnknownUserReject($config, $outcome['reply_messages'])) {
					$log('"'.$username.'" unknown to RADIUS ('.$outcome['server'].'), using local password.');

					return;
				}

				$log('Access-Reject for "'.$username.'" from '.$outcome['server'].'.');
				self::denyLocalLogin();

				return;

			default:
				// Unreachable or invalid/unverifiable answer.
				error_log('radius-auth: no usable RADIUS answer for "'.$username.'": '.$outcome['error']);

				if ($config['fallback_mode'] === Config::FALLBACK_NEVER) {
					self::denyLocalLogin();
				}
				else {
					$log('falling back to local password for "'.$username.'".');
				}
		}
	}

	private static function isTemporarilyBlocked(array $db_user): bool {
		if ($db_user['attempt_failed'] < \CSettingsHelper::getPublic(\CSettingsHelper::LOGIN_ATTEMPTS)) {
			return false;
		}

		$block = \timeUnitToSeconds(\CSettingsHelper::getPublic(\CSettingsHelper::LOGIN_BLOCK));

		return (time() - $db_user['attempt_clock']) < $block;
	}

	/**
	 * Make the following core password check fail. The core then counts the failed attempt,
	 * applies login blocking, writes the audit entry and shows its standard error message.
	 */
	private static function denyLocalLogin(): void {
		$bogus = 'radius-auth-denied:'.bin2hex(random_bytes(32));
		$_POST['password'] = $bogus;
		$_REQUEST['password'] = $bogus;
	}

	/**
	 * Create the Zabbix session for a RADIUS-verified user, mirroring what index.php does after a
	 * successful password login (autologin flag, MFA step, redirect).
	 */
	private static function login(array $db_user): void {
		try {
			$user_data = \CUser::loginByUsername($db_user['username'], true);
		}
		catch (\Throwable $e) {
			error_log('radius-auth: cannot create session for "'.$db_user['username'].'": '.$e->getMessage());
			self::denyLocalLogin();

			return;
		}

		if (!$user_data || !array_key_exists('sessionid', $user_data)) {
			self::denyLocalLogin();

			return;
		}

		\CWebUser::$data = $user_data;
		$sessionid = $user_data['sessionid'];

		\API::getWrapper()->auth = [
			'type' => \CJsonRpc::AUTH_TYPE_COOKIE,
			'auth' => $sessionid
		];

		if ($db_user['attempt_failed'] != 0) {
			\DB::update('users', [
				'values' => ['attempt_failed' => 0],
				'where' => ['userid' => $db_user['userid']]
			]);
		}

		\CSessionHelper::set('sessionid', $sessionid);

		$autologin = (int) \getRequest('autologin', 0) === 1 ? 1 : 0;

		if ($user_data['autologin'] != $autologin) {
			\API::User()->update(['userid' => $user_data['userid'], 'autologin' => $autologin]);
		}

		$request = (string) \getRequest('request', '');

		if ($request !== '' && !self::isValidRequestUrl($request)) {
			$request = '';
		}

		// Second factor: hand over to the standard MFA page, exactly like a password login.
		if ($user_data['mfaid']) {
			\DB::update('sessions', [
				'values' => ['status' => ZBX_SESSION_CONFIRMATION_REQUIRED],
				'where' => ['sessionid' => $sessionid]
			]);

			\CSessionHelper::set('confirmid', $sessionid);

			if (\CSessionHelper::has('state')) {
				\CSessionHelper::unset(['state', 'username']);
			}

			$mfa_url = new \CUrl('index_mfa.php');

			if ($request !== '') {
				$mfa_url->setArgument('request', $request);
			}

			\redirect($mfa_url->toString());
		}

		// Zabbix 8.0+: role/user redirect URL with validation.
		if (method_exists(\CWebUser::class, 'getRedirectUrl')) {
			\CMessageHelper::clear();

			$redirect = \CWebUser::getRedirectUrl();

			if ($redirect['error']) {
				\CMessageHelper::addError(_('Invalid redirect URL.'));
			}

			$redirect = array_filter([$request, $redirect['url'], \CMenuHelper::getFirstUrl()]);

			(new \CControllerResponseRedirect(new \CUrl(reset($redirect))))->redirect();

			exit;
		}

		// Zabbix 7.x: user's own "URL after login".
		$redirect = array_filter([$request, $user_data['url'], \CMenuHelper::getFirstUrl()]);

		\redirect(reset($redirect));
	}

	/**
	 * Validate the "request" (return-to) URL the same way the running Zabbix version does.
	 */
	private static function isValidRequestUrl(string $url): bool {
		if (class_exists(\CFrontendActionValidator::class)) {
			return (new \CFrontendActionValidator())->validate($url);		// 8.0+
		}

		return \CHtmlUrlValidator::validateSameSite($url);					// 7.x
	}
}
