# Security

BLCKSNAKE Command can run privileged ARK commands. Access to the dashboard, Docker host, persistent volumes, and server network should be limited to administrators.

## Network boundaries

- Keep Source RCON on a private LAN, VPN, or encrypted tunnel. RCON is plaintext.
- Keep the dashboard on loopback or a private management network.
- Trust the generated CA on administrator devices instead of bypassing certificate checks.
- Use a different RCON password for every map.
- Use a dedicated download-only SFTP account and verify its host-key fingerprint separately.
- If a host regenerates SSH keys and host verification is disabled for that map, keep SFTP on an isolated trusted network and use a unique download-only password; without key verification, an impersonating host can receive that credential.
- Limit the Discord bot and staff roles to the permissions they need.

## Accounts and actions

Use named dashboard accounts for each staff member. Give Administrator access only to people who manage configuration, accounts, protected player information, or advanced commands.

Review the target and scope before confirming an action. If an RCON response is lost, check the ARK server before repeating the command. The first command may have completed.

## Storage and backups

The data volume contains application state and settings. The keystore volume contains the matching installation key material. Anyone with access to both should be treated as having access to stored application secrets.

Back up both volumes and protect their copies separately. Include the log volume when retained activity records are required.

## Public reports

Do not include these items in a public issue:

- passwords or setup, automation, Discord, RCON, and SFTP tokens;
- database and keystore copies;
- private keys or raw setup output;
- player EOS IDs, PlayerDataIDs, profiles, or private chat;
- unsanitized logs, diagnostics, crash dumps, or internal addresses.

Rotate any credential that may have been disclosed. Send vulnerability reports privately to the repository owner or deployment administrator.

## Product analytics

Optional product analytics is off by default. Its disclosure and control are available under **Settings → Analytics**. See [Configuration](CONFIGURATION.md#optional-product-analytics) for the complete event contents.
