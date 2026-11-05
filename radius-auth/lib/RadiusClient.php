<?php declare(strict_types = 0);
/*
** RADIUS authentication module for Zabbix
** Minimal, dependency-free RADIUS client (RFC 2865) with PAP and Message-Authenticator (RFC 3579 / Blast-RADIUS).
*/

namespace RadiusAuthLib;

final class RadiusClient {

	public const CODE_ACCESS_REQUEST = 1;
	public const CODE_ACCESS_ACCEPT = 2;
	public const CODE_ACCESS_REJECT = 3;
	public const CODE_ACCESS_CHALLENGE = 11;

	public const ATTR_USER_NAME = 1;
	public const ATTR_USER_PASSWORD = 2;
	public const ATTR_SERVICE_TYPE = 6;
	public const ATTR_REPLY_MESSAGE = 18;
	public const ATTR_NAS_IDENTIFIER = 32;
	public const ATTR_NAS_PORT_TYPE = 61;
	public const ATTR_MESSAGE_AUTHENTICATOR = 80;

	public const SERVICE_TYPE_AUTHENTICATE_ONLY = 8;
	public const NAS_PORT_TYPE_VIRTUAL = 5;

	public const RESULT_ACCEPT = 'accept';
	public const RESULT_REJECT = 'reject';
	public const RESULT_UNREACHABLE = 'unreachable';
	public const RESULT_ERROR = 'error';

	/** @var array<int, array{host: string, port: int}> */
	private array $servers;
	private string $secret;
	private int $timeout;
	private int $retries;
	private string $nas_identifier;
	private bool $require_message_authenticator;

	/**
	 * @param array  $servers  List of ['host' => string, 'port' => int], tried in order (failover).
	 */
	public function __construct(array $servers, string $secret, int $timeout = 3, int $retries = 1,
			string $nas_identifier = 'zabbix-frontend', bool $require_message_authenticator = true) {
		$this->servers = array_values(array_filter($servers, static fn($s) => trim((string) $s['host']) !== ''));
		$this->secret = $secret;
		$this->timeout = max(1, min(30, $timeout));
		$this->retries = max(0, min(5, $retries));
		$this->nas_identifier = $nas_identifier;
		$this->require_message_authenticator = $require_message_authenticator;
	}

	/**
	 * Send an Access-Request and return the outcome.
	 *
	 * @return array{result: string, reply_messages: string[], server: ?string, error: ?string}
	 */
	public function authenticate(string $username, string $password): array {
		if (!$this->servers) {
			return self::outcome(self::RESULT_ERROR, [], null, 'No RADIUS server configured.');
		}
		if ($this->secret === '') {
			return self::outcome(self::RESULT_ERROR, [], null, 'No shared secret configured.');
		}
		if ($username === '' || strlen($username) > 253) {
			return self::outcome(self::RESULT_ERROR, [], null, 'Invalid user name length.');
		}
		if (strlen($password) > 128) {
			return self::outcome(self::RESULT_ERROR, [], null, 'Password longer than 128 bytes is not supported by PAP.');
		}

		$last_error = null;
		$last_result = self::RESULT_UNREACHABLE;

		foreach ($this->servers as $server) {
			$outcome = $this->authenticateAgainst($server['host'], (int) $server['port'], $username, $password);

			if ($outcome['result'] === self::RESULT_ACCEPT || $outcome['result'] === self::RESULT_REJECT) {
				return $outcome;
			}

			// Unreachable or invalid answer: try next server.
			$last_result = $outcome['result'];
			$last_error = $outcome['error'];
		}

		return self::outcome($last_result, [], null, $last_error);
	}

	private function authenticateAgainst(string $host, int $port, string $username, string $password): array {
		$label = $host.':'.$port;
		$target = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'udp://['.$host.']:'.$port : 'udp://'.$host.':'.$port;

		$socket = @stream_socket_client($target, $errno, $errstr, $this->timeout);

		if ($socket === false) {
			return self::outcome(self::RESULT_UNREACHABLE, [], $label, 'Cannot open socket: '.$errstr);
		}

		$identifier = random_int(0, 255);
		$request_authenticator = random_bytes(16);
		$packet = $this->buildAccessRequest($identifier, $request_authenticator, $username, $password);

		$invalid_reason = null;

		try {
			for ($attempt = 0; $attempt <= $this->retries; $attempt++) {
				if (@fwrite($socket, $packet) === false) {
					return self::outcome(self::RESULT_UNREACHABLE, [], $label, 'Cannot send request.');
				}

				$deadline = microtime(true) + $this->timeout;

				while (($remaining = $deadline - microtime(true)) > 0) {
					$read = [$socket];
					$write = $except = null;
					$sec = (int) floor($remaining);
					$usec = (int) (($remaining - $sec) * 1000000);

					$ready = @stream_select($read, $write, $except, $sec, $usec);

					if ($ready === false) {
						break;
					}
					if ($ready === 0) {
						break;
					}

					$response = @fread($socket, 4096);

					if ($response === false || $response === '') {
						// E.g. ICMP port unreachable surfaced as a read error.
						break;
					}

					$parsed = $this->parseResponse($response, $identifier, $request_authenticator);

					if ($parsed['error'] !== null) {
						// Ignore packets that fail validation (spoofed, stale, wrong secret) and keep waiting.
						$invalid_reason = $parsed['error'];
						continue;
					}

					switch ($parsed['code']) {
						case self::CODE_ACCESS_ACCEPT:
							return self::outcome(self::RESULT_ACCEPT, $parsed['reply_messages'], $label, null);

						case self::CODE_ACCESS_REJECT:
							return self::outcome(self::RESULT_REJECT, $parsed['reply_messages'], $label, null);

						case self::CODE_ACCESS_CHALLENGE:
							return self::outcome(self::RESULT_REJECT, $parsed['reply_messages'], $label,
								'Server sent Access-Challenge (challenge/response is not supported).'
							);

						default:
							$invalid_reason = 'Unexpected RADIUS code '.$parsed['code'].'.';
					}
				}
			}
		}
		finally {
			fclose($socket);
		}

		if ($invalid_reason !== null) {
			return self::outcome(self::RESULT_ERROR, [], $label, 'Invalid response: '.$invalid_reason);
		}

		return self::outcome(self::RESULT_UNREACHABLE, [], $label, 'No response (timeout).');
	}

	/**
	 * Build an Access-Request packet. Message-Authenticator is placed first, as recommended after Blast-RADIUS.
	 */
	public function buildAccessRequest(int $identifier, string $request_authenticator, string $username,
			string $password): string {
		$attributes = self::attribute(self::ATTR_MESSAGE_AUTHENTICATOR, str_repeat("\0", 16))
			.self::attribute(self::ATTR_USER_NAME, $username)
			.self::attribute(self::ATTR_USER_PASSWORD, $this->encodePassword($password, $request_authenticator))
			.self::attribute(self::ATTR_SERVICE_TYPE, pack('N', self::SERVICE_TYPE_AUTHENTICATE_ONLY))
			.self::attribute(self::ATTR_NAS_PORT_TYPE, pack('N', self::NAS_PORT_TYPE_VIRTUAL));

		if ($this->nas_identifier !== '') {
			$attributes .= self::attribute(self::ATTR_NAS_IDENTIFIER, substr($this->nas_identifier, 0, 253));
		}

		$length = 20 + strlen($attributes);
		$packet = pack('CCn', self::CODE_ACCESS_REQUEST, $identifier, $length).$request_authenticator.$attributes;

		// Message-Authenticator value starts at offset 22 (header 20 + type 1 + length 1).
		$mac = hash_hmac('md5', $packet, $this->secret, true);

		return substr_replace($packet, $mac, 22, 16);
	}

	/**
	 * RFC 2865 section 5.2 User-Password hiding.
	 */
	public function encodePassword(string $password, string $request_authenticator): string {
		$padded_length = max(16, (int) ceil(strlen($password) / 16) * 16);
		$password = str_pad($password, $padded_length, "\0");

		$result = '';
		$previous = $request_authenticator;

		for ($offset = 0; $offset < $padded_length; $offset += 16) {
			$block = substr($password, $offset, 16) ^ md5($this->secret.$previous, true);
			$result .= $block;
			$previous = $block;
		}

		return $result;
	}

	/**
	 * Validate and parse a response packet.
	 *
	 * @return array{code: int, reply_messages: string[], error: ?string}
	 */
	public function parseResponse(string $response, int $identifier, string $request_authenticator): array {
		$fail = static fn(string $error) => ['code' => 0, 'reply_messages' => [], 'error' => $error];

		if (strlen($response) < 20) {
			return $fail('Packet too short.');
		}

		['code' => $code, 'id' => $id, 'length' => $length] = unpack('Ccode/Cid/nlength', $response);

		if ($id !== $identifier) {
			return $fail('Identifier mismatch.');
		}
		if ($length < 20 || $length > strlen($response)) {
			return $fail('Invalid length.');
		}

		$response = substr($response, 0, $length);
		$response_authenticator = substr($response, 4, 16);
		$attributes_raw = substr($response, 20);

		$expected = md5(substr($response, 0, 4).$request_authenticator.$attributes_raw.$this->secret, true);

		if (!hash_equals($expected, $response_authenticator)) {
			return $fail('Response Authenticator mismatch (wrong shared secret?).');
		}

		$reply_messages = [];
		$message_authenticator_offset = null;
		$offset = 0;

		while ($offset < strlen($attributes_raw)) {
			if ($offset + 2 > strlen($attributes_raw)) {
				return $fail('Truncated attribute.');
			}

			$type = ord($attributes_raw[$offset]);
			$attr_length = ord($attributes_raw[$offset + 1]);

			if ($attr_length < 2 || $offset + $attr_length > strlen($attributes_raw)) {
				return $fail('Malformed attribute.');
			}

			$value = substr($attributes_raw, $offset + 2, $attr_length - 2);

			if ($type === self::ATTR_REPLY_MESSAGE) {
				$reply_messages[] = $value;
			}
			elseif ($type === self::ATTR_MESSAGE_AUTHENTICATOR) {
				if ($attr_length !== 18) {
					return $fail('Malformed Message-Authenticator.');
				}

				$message_authenticator_offset = 20 + $offset + 2;
			}

			$offset += $attr_length;
		}

		if ($message_authenticator_offset !== null) {
			$received = substr($response, $message_authenticator_offset, 16);
			$check = substr_replace($response, $request_authenticator, 4, 16);
			$check = substr_replace($check, str_repeat("\0", 16), $message_authenticator_offset, 16);

			if (!hash_equals(hash_hmac('md5', $check, $this->secret, true), $received)) {
				return $fail('Message-Authenticator mismatch.');
			}
		}
		elseif ($this->require_message_authenticator) {
			return $fail('Message-Authenticator missing in response (required by configuration).');
		}

		return ['code' => $code, 'reply_messages' => $reply_messages, 'error' => null];
	}

	private static function attribute(int $type, string $value): string {
		return chr($type).chr(strlen($value) + 2).$value;
	}

	private static function outcome(string $result, array $reply_messages, ?string $server, ?string $error): array {
		return [
			'result' => $result,
			'reply_messages' => $reply_messages,
			'server' => $server,
			'error' => $error
		];
	}
}
