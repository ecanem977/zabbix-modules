<?php declare(strict_types = 0);
/*
** RADIUS authentication module for Zabbix
** Settings storage. Settings live in the module's own row in the Zabbix "module" table
** (column "config"), so they survive frontend and container upgrades.
*/

namespace RadiusAuthLib;

final class Config {

	public const MODULE_ID = 'radius-auth';

	public const FALLBACK_UNKNOWN_USER = 'unknown_user';
	public const FALLBACK_UNREACHABLE = 'unreachable';
	public const FALLBACK_NEVER = 'never';

	public const DEFAULTS = [
		'enabled' => 0,
		'server1_host' => '',
		'server1_port' => 1812,
		'server2_host' => '',
		'server2_port' => 1812,
		'secret' => '',
		'timeout' => 3,
		'retries' => 1,
		'nas_identifier' => 'zabbix-frontend',
		'require_message_authenticator' => 1,
		'fallback_mode' => self::FALLBACK_UNKNOWN_USER,
		'unknown_user_marker' => 'Unknown user',
		'excluded_users' => '',
		'debug_log' => 0
	];

	/**
	 * Read the module row directly from the database (works before a user is logged in).
	 *
	 * @return array{moduleid: string, status: int, config: array}|null
	 */
	public static function loadModule(): ?array {
		$row = \DBfetch(\DBselect(
			'SELECT moduleid,status,config FROM module WHERE id='.\zbx_dbstr(self::MODULE_ID)
		));

		if (!$row) {
			return null;
		}

		return [
			'moduleid' => $row['moduleid'],
			'status' => (int) $row['status'],
			'config' => self::normalize(json_decode((string) $row['config'], true) ?: [])
		];
	}

	public static function normalize(array $config): array {
		$config = array_intersect_key($config, self::DEFAULTS) + self::DEFAULTS;

		foreach (['enabled', 'server1_port', 'server2_port', 'timeout', 'retries', 'require_message_authenticator',
				'debug_log'] as $key) {
			$config[$key] = (int) $config[$key];
		}

		foreach (['server1_host', 'server2_host', 'secret', 'nas_identifier', 'unknown_user_marker',
				'excluded_users'] as $key) {
			$config[$key] = (string) $config[$key];
		}

		if (!in_array($config['fallback_mode'],
				[self::FALLBACK_UNKNOWN_USER, self::FALLBACK_UNREACHABLE, self::FALLBACK_NEVER], true)) {
			$config['fallback_mode'] = self::DEFAULTS['fallback_mode'];
		}

		return $config;
	}

	public static function servers(array $config): array {
		return [
			['host' => trim($config['server1_host']), 'port' => $config['server1_port']],
			['host' => trim($config['server2_host']), 'port' => $config['server2_port']]
		];
	}

	public static function excludedUsers(array $config): array {
		return array_values(array_filter(array_map('trim', preg_split('/[\s,;]+/', $config['excluded_users']))));
	}

	public static function makeClient(array $config): RadiusClient {
		return new RadiusClient(self::servers($config), $config['secret'], $config['timeout'], $config['retries'],
			$config['nas_identifier'], (bool) $config['require_message_authenticator']
		);
	}

	/**
	 * Does an Access-Reject carry the configured "unknown user" marker?
	 */
	public static function isUnknownUserReject(array $config, array $reply_messages): bool {
		$marker = trim($config['unknown_user_marker']);

		if ($marker === '') {
			return false;
		}

		foreach ($reply_messages as $message) {
			if (stripos($message, $marker) !== false) {
				return true;
			}
		}

		return false;
	}
}
