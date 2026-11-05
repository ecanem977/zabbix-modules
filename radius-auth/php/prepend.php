<?php
/*
** RADIUS authentication module for Zabbix - login hook.
**
** Loaded on every PHP request through auto_prepend_file (see radius-auth.ini).
** Does nothing unless the request is a login form submit to index.php.
** Must stay in global scope: the Zabbix bootstrap below expects to be included from global scope,
** exactly as index.php does it. index.php's own require_once calls then become no-ops.
*/

const RADIUS_AUTH_HOOK_LOADED = true;

require_once __DIR__.'/../lib/LoginGate.php';

if (\RadiusAuthLib\LoginGate::isLoginRequest()) {
	require_once __DIR__.'/../lib/RadiusClient.php';
	require_once __DIR__.'/../lib/Config.php';

	require_once dirname($_SERVER['SCRIPT_FILENAME']).'/include/classes/user/CWebUser.php';
	require_once dirname($_SERVER['SCRIPT_FILENAME']).'/include/config.inc.php';

	\RadiusAuthLib\LoginGate::handle();
}
