# Configuration

Configure BLCKSNAKE Command from the **Settings** page. A normal Docker installation does not need an `.env` file, `config.json`, or a secrets directory.

## First owner

After starting the container, run:

```bash
docker compose exec app npm run setup:show
```

Install the displayed CA certificate, open the dashboard address, and create the owner with the setup token.

## Maps and RCON

Each map needs:

- a short, unique map ID;
- a display name;
- the private RCON address and port; and
- a strong password used only for that map.

RCON is plaintext. Keep it on a private LAN, VPN, or encrypted tunnel. Public RCON addresses are rejected by the managed setup.

## Player-profile access

Per-map SFTP access is optional. Use a dedicated download-only account. The dashboard copies the map's RCON IP into the SFTP host field and recognizes common official ASA map names. Select **Scan host key** to fill the SHA-256 fingerprint without sending the SFTP password; compare the result with your hosting provider when possible. Both the usual `SHA256:...` OpenSSH form and 64-character hexadecimal form are accepted. If a managed game host regenerates its SSH key, scan and apply the new key for that map. Hosts that rotate keys on every restart can use the per-map **Verify host identity** switch; disabling it avoids key rejection but allows an impersonating machine on that network to receive the SFTP password. Enter the save directory or map token required by the ARK host.

Profile access allows BLCKSNAKE Command to verify connected-player targets for supported administrative actions. It does not need upload or delete permissions.

## Discord and Cluster Chat

Discord integration is optional. Settings accepts the bot token, application ID, guild ID, chat channel, optional audit channel, and staff role IDs.

Enable Discord's Message Content Intent if Discord messages should relay into ARK. Give the bot permission to view the configured channels, read message history, send messages, and use application commands.

## Operators

Administrators can manage settings, operators, protected player information, and advanced commands. Moderators receive the smaller moderation and operations surface.

Administrators can grant selected moderators additional access to **Save World**, **Give Items**, **Give XP**, **Refresh Player ID**, **Ban Player**, and join-allowlist management from the Operators page. Permission changes end that moderator's active dashboard sessions so the new access takes effect at the next sign-in. Settings, diagnostics, operator management, protected identifier disclosure, raw RCON, and destructive wild-dino wipes remain administrator-only. Administrators can also delete individual moderation notes from a protected player staff record; note deletion is confirmed and audited.

Reusable messages are managed under **Settings → Broadcast templates**. New and upgraded installations receive starter templates for welcomes, maintenance, world saves, events, and rule reminders. Administrators may create, edit, delete, or restore templates; at most 32 are accepted, and each message follows the configured in-game announcement length. Save with **Apply & restart** before using a changed template.

Player cards report **Discord link** and **Cluster Chat access** separately. A Discord account may be unlinked while Cluster Chat access is still allowed. New staff-record entries retain the responsible dashboard username (or Discord display attribution), a category, and a timestamp. Warnings, Cluster Chat mute/unmute actions, kicks, and bans are added to moderation history automatically; manual notes can be categorized as general, incident/tribe dispute, positive, or warning.

The Activity page identifies the username and role that executed each dashboard command, along with the action, affected map or cluster, outcome, and sanitized command summary. Administrators and the server owner see activity from every operator. Moderators see only commands executed by their own account. The friendly Activity view covers the current service session; the encrypted audit logs remain the durable security record across restarts.

New operators receive a temporary password that must be changed at first sign-in.

Shared item packages are managed under **Settings → Item packages** and take effect without an application restart. New and previously empty installations receive 48 boss-fight packages, three manual engagement freebies, and three automatic starter packages once; existing custom packages are never replaced, and deleting every package does not restore them on restart. Only administrators can create, edit, delete, enable, or mark up to 128 packages for first-join delivery. Moderators with **Give Items** permission can manually grant any enabled package. More than one package may be enabled for automatic delivery; the enabled set is captured when an eligible player first joins and is never expanded retroactively. Eligibility is cluster-wide, so moving to another map does not grant the packages again. Players already known before the feature is enabled and players present in the first snapshot after startup are not treated as new. Automatic grants wait for a verified numeric PlayerDataID. Each item is durably marked before its RCON command is sent, preventing an ambiguous response or restart from automatically duplicating the grant.

## Optional product analytics

Product analytics is disabled by default. An Administrator can enable or disable it from **Settings → Analytics**, then select **Review & apply** to save the choice. Enabling it sends an initial contact immediately; disabling it stops future analytics immediately.

When first enabled, the application sends an initial-contact event. It then sends a startup event, one heartbeat every 24 hours, and a shutdown event. Each JSON event contains:

- the BLCKSNAKE Command and Node.js versions;
- operating system and CPU architecture;
- whether Discord and managed installation mode are enabled;
- configured map count;
- event time and, for shutdown events, uptime; and
- a random installation identifier used to distinguish installations.

It does not send server names or addresses, credentials, player or Discord identifiers, chat messages, RCON commands, configuration values, or logs. As with any network request, the analytics service receives the public IP used to connect.

Delivery failures do not stop the application. The dashboard reports whether the initial contact was accepted. Disabling analytics stops future analytics requests immediately.

The collector must accept non-browser `POST /collect` requests. If Cloudflare protects the collector, exclude this API route from interactive browser challenges while retaining authentication and rate limiting at the collector. A response containing `Cf-Mitigated: challenge` cannot be completed by the server process; the dashboard reports that condition explicitly and does not retry the rejected event.

## Advanced console

The advanced RCON console is disabled until an Administrator enables it and defines allowed command verbs. Add only commands your staff needs. Arguments still pass application validation and every command requires review and confirmation.

## Secrets and restarts

Secret fields do not display stored values. Leave a secret field empty to keep its current value. Disable an integration before using its delete control.

For ordinary changes, select **Apply & restart** in the review dialog. You can also use **Restart now** in the pending-settings banner. With the supplied Compose configuration, Docker brings the service back automatically. If the dashboard cannot request a restart, use:

```bash
docker compose restart app
```

## Remote dashboard access

The default dashboard is bound to `127.0.0.1:8787`. Use a VPN or SSH tunnel for access from another device.

If you publish the dashboard on a private management address, update the Compose binding and add the exact DNS name or IP address to the HTTPS identity. Do not expose the dashboard directly to the internet.
