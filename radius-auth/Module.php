<?php declare(strict_types = 0);
/*
** RADIUS authentication module for Zabbix
** Adds "Users -> RADIUS" next to "Users -> Authentication" for Super admins.
*/

namespace Modules\RadiusAuth;

use APP,
	CMenuItem,
	CWebUser,
	Zabbix\Core\CModule;

class Module extends CModule {

	public function init(): void {
		if (CWebUser::getType() != USER_TYPE_SUPER_ADMIN || !APP::Component()->has('menu.main')) {
			return;
		}

		$users_menu = APP::Component()->get('menu.main')->find(_('Users'));

		if ($users_menu === null || !$users_menu->hasSubMenu()) {
			return;
		}

		$users_menu->getSubMenu()->insertAfter(_('Authentication'),
			(new CMenuItem(_('RADIUS')))->setAction('radius.settings.edit')
		);
	}
}
