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

Per-map SFTP access is optional. Use a dedicated download-only account and verify the server's SHA-256 host-key fingerprint through a separate trusted channel. Enter the save directory or map token required by the ARK host.

Profile access allows BLCKSNAKE Command to verify connected-player targets for supported administrative actions. It does not need upload or delete permissions.

## Discord and Cluster Chat

Discord integration is optional. Settings accepts the bot token, application ID, guild ID, chat channel, optional audit channel, and staff role IDs.

Enable Discord's Message Content Intent if Discord messages should relay into ARK. Give the bot permission to view the configured channels, read message history, send messages, and use application commands.

## Operators

Administrators can manage settings, operators, protected player information, and advanced commands. Moderators receive the smaller moderation and operations surface.

New operators receive a temporary password that must be changed at first sign-in.

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

## Advanced console

The advanced RCON console is disabled until an Administrator enables it and defines allowed command verbs. Add only commands your staff needs. Arguments still pass application validation and every command requires review and confirmation.

## Secrets and restarts

Secret fields do not display stored values. Leave a secret field empty to keep its current value. Disable an integration before using its delete control.

Saved settings become active after the container restarts:

```bash
docker compose restart app
```

## Remote dashboard access

The default dashboard is bound to `127.0.0.1:8787`. Use a VPN or SSH tunnel for access from another device.

If you publish the dashboard on a private management address, update the Compose binding and add the exact DNS name or IP address to the HTTPS identity. Do not expose the dashboard directly to the internet.
