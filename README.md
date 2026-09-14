# BLCKSNAKE Command

<img src="src/http/assets/blcksnake-mark.png" alt="BLCKSNAKE mark" width="120">

BLCKSNAKE Command is an ARK: Survival Ascended server and cluster administration tool. The web dashboard covers server health, connected players, RCON actions, maintenance, moderation, settings, and diagnostics. Cluster Chat and Discord integration are optional features.

This is an independent community project. It is not affiliated with or endorsed by Studio Wildcard, Snail Games, Discord, or CurseForge.

## Install with Docker

You need Docker Engine with Docker Compose v2 and private network access from the Docker host to each ARK RCON endpoint. Never expose Source RCON to the internet.

Download and start the application:

```bash
docker compose pull
docker compose up -d
docker compose ps
```

Get the first-owner setup token and HTTPS certificate:

```bash
docker compose exec app npm run setup:show
```

Install the displayed CA certificate on the administrator device, then open:

```text
https://localhost:8787/dashboard
```

Create the owner account with the setup token. Passwords must contain 15 to 128 characters.

Open **Settings** and configure:

1. The cluster name.
2. Each map's private RCON address, port, and unique password.
3. Optional per-map SFTP profile access.
4. Optional Discord bot, guild, channel, and role settings.
5. Whether to share optional product analytics.
6. Any advanced RCON verbs you intend to allow.

Use **Apply & restart** in Settings. With the supplied Compose configuration, Docker brings the service back automatically. You can also restart it manually:

```bash
docker compose restart app
```

Use **Operators → Permissions** to give individual moderators selected operational rights such as item/XP grants, bans, save-world, PlayerDataID refresh, or join-allowlist management. Critical settings and destructive tools stay administrator-only. Administrators can also delete individual notes from a player's protected staff record.

Five starter broadcasts are available under **Settings → Broadcast templates**. Administrators can add, edit, restore, or delete reusable messages, then activate changes with **Apply & restart**. Player staff records attribute new entries to the responsible username and automatically retain warnings, Cluster Chat mute changes, kicks, and bans alongside categorized manual notes.

Administrators can create shared multi-item packages under **Settings → Item packages**. Each package can be enabled for manual staff grants and can optionally be delivered once when a player first joins the cluster. Multiple starter packages may be active together. Moderators who have **Give Items** permission can grant enabled packages to any connected player, including their own connected survivor. Automatic delivery requires a verified numeric PlayerDataID from the map's profile import or an existing saved mapping.

## Docker commands

```bash
# Status
docker compose ps

# Container output
docker compose logs -f --tail 100 app

# Restart
docker compose restart app

# Stop without deleting data
docker compose down

# Start again
docker compose up -d
```

Do not run `docker compose down -v` on an installation you want to keep. It deletes the application data, accounts, configuration, keys, and retained logs.

## Persistent volumes

| Volume | Contents |
| --- | --- |
| `blcksnake-command_data` | Application state and settings |
| `blcksnake-command_keystore` | Installation key material |
| `blcksnake-command_logs` | Operational and security records |

Back up the data and keystore volumes together. Store their backups under separate access controls. Include the log volume if you need retained activity records.

## Updates

Back up the volumes, then run:

```bash
docker compose down
docker compose pull
docker compose up -d
docker compose ps
```

If an existing installation unexpectedly asks for a new owner, stop it. The original data or keystore volume is not attached.

## Remote access

The default Compose file publishes `127.0.0.1:8787`, so the dashboard is available only from the Docker host. Use a VPN or SSH tunnel for another administrator device. If you bind the dashboard to a private management address, add that exact DNS name or IP address to the HTTPS identity before using it.

Do not publish the dashboard or RCON ports directly to the internet.

## Build from source

```bash
docker build --pull -t blcksnake/blcksnake-command:1.2.0 .
```

Product analytics is disabled by default and requires an administrator to enable it in **Settings**. See [Configuration](docs/CONFIGURATION.md#optional-product-analytics) for the exact data sent.

## Documentation

- [Configuration](docs/CONFIGURATION.md)
- [Docker operations and recovery](docs/OPERATIONS.md)
- [Security](docs/SECURITY.md)
- [Feedback and contributions](CONTRIBUTING.md)
- [Release history](CHANGELOG.md)

See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for licensing information.
