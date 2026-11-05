# RADIUS authentication for Zabbix 7.4 and 8.0

Checks the password of **existing local Zabbix users** against a RADIUS server when they sign in on the normal
login form. No user provisioning, no groups: the Zabbix user must exist, RADIUS only verifies the password.

Tested end to end against the Zabbix 7.4.16 and 8.0.0 frontends: RADIUS login, local fallback, failover, excluded users,
login blocking, MFA (TOTP) after RADIUS, settings page, test button and CSRF protection.

## How a login is decided

| Situation | Result |
|---|---|
| RADIUS answers **Access-Accept** | Signed in (MFA still applies if the user's group requires it) |
| RADIUS answers **Access-Reject** | Denied. The local password is **not** tried |
| Reject with the "unknown user" Reply-Message | Local password is checked (fallback mode 1) |
| No answer / answer cannot be verified | Local password is checked (fallback modes 1 and 2) |
| User is in "Excluded users" | Local password only, RADIUS is not asked |
| User does not exist in Zabbix, is LDAP/SAML-provisioned, or in an LDAP-authenticated group | Untouched, normal Zabbix behaviour |

Fallback modes (setting "Fall back to local password"):

1. **If user is unknown to RADIUS or RADIUS is unreachable** (default)
2. **Only if RADIUS is unreachable**
3. **Never** (RADIUS only)

Failed RADIUS logins go through Zabbix's own failed-login counter, temporary blocking and audit log.

## Files

```
radius-auth/
├── manifest.json        module definition (Zabbix module API v2)
├── Module.php           adds Users > RADIUS to the menu (Super admins)
├── actions/             settings page, save, test button
├── views/               settings page markup
├── lib/
│   ├── RadiusClient.php RADIUS client (PAP, Message-Authenticator, failover), pure PHP
│   ├── Config.php       settings, stored in the module's DB row
│   └── LoginGate.php    login decision logic
└── php/
    ├── radius-auth.ini  sets auto_prepend_file
    └── prepend.php      login hook
```

### Why there is a "hook" besides the module

Zabbix loads frontend modules **only for logged-in users**, so a module never sees the login form.
`php/prepend.php` runs before every PHP request and immediately returns unless the request is a login form
submit. For a login it starts the normal Zabbix bootstrap, asks RADIUS, and then either creates the session
(using the same internal function as Zabbix's HTTP and SAML login) or lets `index.php` continue with its
local password check. No Zabbix file is modified.

## Installation (Docker, official zabbix-web image)

1. Put this folder at `./zabbix-modules/radius-auth` next to `compose.yaml` (files readable by everyone, 644/755).
2. In the `zabbix-web` service:
   ```yaml
   environment:
     PHP_INI_SCAN_DIR: ":/usr/share/zabbix/modules/radius-auth/php"
   volumes:
     - ./zabbix-modules/radius-auth:/usr/share/zabbix/modules/radius-auth:ro
   ```
3. `docker compose up -d zabbix-web`
4. Zabbix: **Administration > General > Modules > Scan directory**, then enable **RADIUS authentication**.
5. **Users > RADIUS**: set server, shared secret, enable, **Update**. Use the **Test** tab first.

The settings page shows a red warning if the login hook is not active.

### Without Docker

Copy the folder to `<frontend>/modules/radius-auth` and add to your PHP-FPM pool or php.ini:
```
auto_prepend_file = /usr/share/zabbix/modules/radius-auth/php/prepend.php
```
then restart PHP-FPM.

## Upgrades

The same module code runs on 7.4 and 8.0, so the 7.4 → 8.0 upgrade needs nothing from you either.
Nothing to redo. The module lives in your mounted folder, its settings in the Zabbix database, and the hook
is attached through an environment variable. Change `ZABBIX_VERSION`, pull, start.

The module uses these Zabbix internals, which a future major version could change:
`CUser::loginByUsername()`, `CUser::addUserGroupFields()`, the `sessions`/`module` tables and the
`index.php` login fields. If a login via RADIUS stops working after an upgrade, local fallback still applies
(depending on the fallback mode), and errors are written to the container log (`docker compose logs zabbix-web`).

## Notes and limits

* PAP only (the password is sent hidden with the shared secret, as RADIUS PAP defines). Every request carries
  Message-Authenticator; responses must carry a valid one unless that setting is turned off.
* Only the web login form. API `user.login` and API tokens are not affected.
* The shared secret is stored in the module's row in the database and is never shown again on the page.
* Keep one "break-glass" admin in **Excluded users**, especially with fallback mode "Never".
* **Uninstall:** remove `PHP_INI_SCAN_DIR` first and restart the web container, then remove the folder.
  If the folder disappears while the variable is set, PHP cannot find the hook and the frontend stops working.
* Debug logging (setting) writes each decision to the container log, never passwords.
