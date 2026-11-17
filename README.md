# WPTE DevZone – GitHub

Sub-plugin for **WP Travel Engine Dev Zone**. Adds a GitHub tab for release management, issue-driven installs, and a webhook auto-install pipeline.

---

> ### Requirements
> - **_wptravelengine-devzone-plugin** active
> - GitHub PAT with `repo`, `read:org` scopes

---

> ### Features
> - **Issues tab** — search by URL, project board URL, or keyword; auto-loads linked PRs and release tags
> - **Repos tab** — personal + org repos grouped by owner, with favourites
> - **Releases** — one-click install/activate from a release zip, with installed-version and last-installed badges
> - **Webhook auto-install** — GitHub Projects v2 webhook installs a plugin when its issue moves to *Testing* or *Push Zips*
> - **GitHub Downloads log** — last 100 webhook-triggered installs

---

> ### Webhook Setup
>
> 1. `define( 'WPTE_DZ_GITHUB_WEBHOOK_SECRET', 'your-secret' );` in `wp-config.php`
> 2. Add a GitHub webhook: Payload URL from the Issues tab, content type `application/json`, same secret, event **Projects v2 item**
> 3. Move an issue to *Testing* or *Push Zips* — linked PR releases install automatically
>
> Endpoint only registers when **Auto-install on webhook** is enabled (Issues tab toggle).

---

> ### Remote access (QA hub)
>
> Lets the WTE Hub install a release by tag and log a test browser in, over a WordPress
> **Application Password** of an administrator (Basic auth). Turn it on with the **Remote access (QA hub)**
> toggle in the Issues tab. It only works when `WP_ENVIRONMENT_TYPE` is `local`, `development` or `staging`.
>
> | Route (`/wp-json/github/v1/remote/…`) | Does |
> |---|---|
> | `GET status` | WP/PHP, environment, connected GitHub user, every plugin with version, active state and `git` (folder is a git clone) |
> | `POST install` `{repo: "owner/name", tag}` | finds the tag's release zip, installs or replaces it with the site's token, activates it, logs it in GitHub Downloads |
> | `POST login-link` `{redirect?}` | single-use login URL, valid 5 minutes, for a Playwright browser |
>
> ```bash
> curl -u admin:'xxxx xxxx xxxx xxxx xxxx xxxx' -X POST https://staging.example.com/wp-json/github/v1/remote/install \
>   -d repo=Codewing-Solutions/wptravelengine -d tag=v6.7.2-patch-2940.2
> ```
>
> A plugin folder that is a **git clone** is never replaced, by remote installs or by the webhook.

---

> ### Security
> - AJAX handlers verify nonce + `manage_options`; webhook verifies HMAC-SHA256 with replay protection
> - Only repos owned by the stored user or their orgs can be installed
> - Remote routes need an administrator's Application Password, an opt-in toggle and a non-production environment type

