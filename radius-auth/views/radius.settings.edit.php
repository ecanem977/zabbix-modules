<?php declare(strict_types = 0);
/*
** RADIUS authentication module for Zabbix - settings view.
**
** @var CView $this
** @var array $data
*/

$config = $data['config'];

$status_messages = [];

if (!$data['hook_loaded']) {
	$status_messages[] = makeMessageBox(ZBX_STYLE_MSG_BAD, [[
		'message' => _('The login hook is not active, so RADIUS is not used at login yet. Set PHP_INI_SCAN_DIR=":/usr/share/zabbix/modules/radius-auth/php" on the web container and restart it (see README).')
	]], _('Login hook not loaded'), false, true);
}

if (!$data['module_found']) {
	$status_messages[] = makeMessageBox(ZBX_STYLE_MSG_BAD, [[
		'message' => _('Module row not found. Run "Scan directory" in Administration > General > Modules and enable the module.')
	]], _('Module not registered'), false, true);
}

$fallback_select = (new CSelect('fallback_mode'))
	->setId('fallback_mode')
	->setFocusableElementId('label-fallback_mode')
	->setValue($config['fallback_mode'])
	->addOptions(CSelect::createOptionsFromArray([
		'unknown_user' => _('If user is unknown to RADIUS or RADIUS is unreachable'),
		'unreachable' => _('Only if RADIUS is unreachable'),
		'never' => _('Never (RADIUS only)')
	]));

$secret_field = (new CPassBox('secret', '', 255))
	->setWidth(ZBX_TEXTAREA_STANDARD_WIDTH)
	->setAttribute('autocomplete', 'new-password')
	->setAttribute('placeholder', $data['secret_is_set'] ? _('Stored. Leave empty to keep it.') : '');

$form_list = (new CFormList('radius-form-list'))
	->addRow(new CLabel(_('Enable RADIUS authentication'), 'enabled'),
		(new CCheckBox('enabled'))->setChecked($config['enabled'] == 1)->setUncheckedValue(0)
	)
	->addRow((new CLabel(_('Primary server'), 'server1_host'))->setAsteriskMark(),
		[
			(new CTextBox('server1_host', $config['server1_host']))
				->setWidth(ZBX_TEXTAREA_STANDARD_WIDTH - 110)
				->setAttribute('placeholder', 'freeradius'),
			' : ',
			(new CNumericBox('server1_port', (string) $config['server1_port'], 5))->setWidth(80)
		]
	)
	->addRow(new CLabel(_('Secondary server'), 'server2_host'),
		[
			(new CTextBox('server2_host', $config['server2_host']))
				->setWidth(ZBX_TEXTAREA_STANDARD_WIDTH - 110)
				->setAttribute('placeholder', _('optional, used if primary does not answer')),
			' : ',
			(new CNumericBox('server2_port', (string) $config['server2_port'], 5))->setWidth(80)
		]
	)
	->addRow((new CLabel(_('Shared secret'), 'secret'))->setAsteriskMark(),
		$data['secret_is_set']
			? [$secret_field, ' ', (new CCheckBox('clear_secret'))->setUncheckedValue(0), ' ', _('clear')]
			: $secret_field
	)
	->addRow(new CLabel(_('Timeout (seconds)'), 'timeout'),
		(new CNumericBox('timeout', (string) $config['timeout'], 2))->setWidth(80)
	)
	->addRow(new CLabel(_('Retries per server'), 'retries'),
		(new CNumericBox('retries', (string) $config['retries'], 1))->setWidth(80)
	)
	->addRow(new CLabel(_('NAS-Identifier'), 'nas_identifier'),
		(new CTextBox('nas_identifier', $config['nas_identifier']))->setWidth(ZBX_TEXTAREA_STANDARD_WIDTH)
	)
	->addRow(new CLabel(_('Require Message-Authenticator in responses'), 'require_message_authenticator'),
		(new CCheckBox('require_message_authenticator'))
			->setChecked($config['require_message_authenticator'] == 1)
			->setUncheckedValue(0)
	)
	->addRow(new CLabel(_('Fall back to local password'), 'label-fallback_mode'), $fallback_select)
	->addRow(new CLabel(_('"Unknown user" Reply-Message'), 'unknown_user_marker'),
		(new CTextBox('unknown_user_marker', $config['unknown_user_marker']))
			->setWidth(ZBX_TEXTAREA_STANDARD_WIDTH)
	)
	->addRow(new CLabel(_('Excluded users (local only)'), 'excluded_users'),
		(new CTextArea('excluded_users', $config['excluded_users']))
			->setWidth(ZBX_TEXTAREA_STANDARD_WIDTH)
			->setAttribute('placeholder', _('One per line, e.g. a break-glass admin'))
	)
	->addRow(new CLabel(_('Debug logging'), 'debug_log'),
		(new CCheckBox('debug_log'))->setChecked($config['debug_log'] == 1)->setUncheckedValue(0)
	);

$test_list = (new CFormList('radius-test-list'))
	->addRow(new CLabel(_('Username'), 'test_username'),
		(new CTextBox('test_username', ''))->setWidth(ZBX_TEXTAREA_STANDARD_WIDTH)
	)
	->addRow(new CLabel(_('Password'), 'test_password'),
		(new CPassBox('test_password', ''))
			->setWidth(ZBX_TEXTAREA_STANDARD_WIDTH)
			->setAttribute('autocomplete', 'off')
	)
	->addRow('', [
		(new CSimpleButton(_('Test')))->setId('radius-test-button')->addClass(ZBX_STYLE_BTN_ALT),
		(new CDiv())->setId('radius-test-result')->addStyle('margin-top: 10px;')
	]);

$tabs = (new CTabView())
	->addTab('radius-settings', _('RADIUS settings'), $form_list)
	->addTab('radius-test', _('Test'), $test_list)
	->setFooter(makeFormFooter(new CSubmit('update', _('Update'))));

$form = (new CForm('post', (new CUrl('zabbix.php'))->setArgument('action', 'radius.settings.update')->getUrl()))
	->setId('radius-settings-form')
	->addItem((new CVar(CSRF_TOKEN_NAME, CCsrfTokenHelper::get('radius.settings.update')))->removeId())
	->addItem($tabs);

(new CHtmlPage())
	->setTitle(_('RADIUS authentication'))
	->addItem($status_messages)
	->addItem($form)
	->show();

(new CScriptTag('
	(function() {
		const form = document.getElementById("radius-settings-form");
		const button = document.getElementById("radius-test-button");
		const result = document.getElementById("radius-test-result");
		const test_token = '.json_encode(CCsrfTokenHelper::get('radius.settings.test')).';

		const show = (success, title, details) => {
			result.innerHTML = "";
			const box = document.createElement("div");
			box.className = success ? "'.ZBX_STYLE_MSG_GOOD.'" : "'.ZBX_STYLE_MSG_BAD.'";
			box.style.display = "block";
			const strong = document.createElement("span");
			strong.textContent = title;
			box.appendChild(strong);

			if (details && details.length) {
				const list = document.createElement("ul");
				list.className = "'.ZBX_STYLE_MSG_DETAILS.'";
				list.style.display = "block";
				for (const line of details) {
					const li = document.createElement("li");
					li.textContent = line;
					list.appendChild(li);
				}
				box.appendChild(list);
			}

			result.appendChild(box);
		};

		button.addEventListener("click", () => {
			const body = new FormData(form);
			body.set("'.CSRF_TOKEN_NAME.'", test_token);

			button.disabled = true;
			show(true, '.json_encode(_('Sending Access-Request…')).', []);

			fetch("zabbix.php?action=radius.settings.test", {method: "POST", body})
				.then((response) => response.json())
				.then((data) => show(data.success, data.title, data.details || []))
				.catch((error) => show(false, '.json_encode(_('Request failed')).', [String(error)]))
				.finally(() => button.disabled = false);
		});
	})();
'))
	->setOnDocumentReady()
	->show();
