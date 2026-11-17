## 1.2.0
> Remote access (QA hub): opt-in toggle in the Issues tab; adds `github/v1/remote/status`, `remote/install` (repo + tag) and `remote/login-link` routes, authenticated with an administrator's Application Password, and only on local, development or staging sites
>
> Installer never replaces a plugin folder that is a git clone — protects local clones from webhook and remote installs
>
> Trusted-owner allowlist shared by webhook and remote installs (`GithubApi::trusted_owners()`)
>

## 1.1.0
> Repos/Favs/Issues sub-tab order fixed, Repos is now the default tab on load
>
> Repos/Favs tab count badges no longer get stuck on load — repos now fetch automatically instead of waiting for a manual "Load 
>repositories" click
> Favourites now persist server-side in a single option instead of `localStorage`
>
> Releases list is scrollable instead of paginated; the page indicator auto-updates on scroll and still supports prev/next
>
> Per-repo "Refetch tags" control refreshes just that repo's releases, bypassing the cache
>
> "Last installed" pill on the release row matching a repo's most recently installed tag, tracked in a new option
>

## 1.0.1
> Webhook auto-install via GitHub Projects v2 (HMAC-SHA256, replay protection, column gate, trusted-owner allowlist)
>
> GitHub Downloads log tab — last 100 installs with success/failure rows
>

## 1.0.0
> Initial release