# Changelog

## 1.2.1 - 2026-09-14

- Bundle and safely seed the 54 starter, engagement, and boss-fight item packages into new or previously empty installations.
- Preserve existing custom package collections and remember intentional removal so bundled presets are never restored unexpectedly.
- Increase package capacity to 128 so the bundled catalog leaves ample room for administrator-created packages.

## 1.2.0 - 2026-09-14

- Add administrator-managed multi-item packages for starter supplies, boss-fight preparation, and other reusable grants. Moderators with **Give Items** access can grant enabled packages to connected players.
- Allow multiple packages to be marked for automatic, once-per-cluster delivery when a player first joins. Delivery eligibility and per-item attempts are stored durably to prevent duplicate automatic grants across maps or restarts.
- Correct the missing space between the player count and the “player(s) connected” label on map cards.
- Keep the item-package editor fully visible and usable at desktop, tablet, and mobile widths.

## 1.1.1 - 2026-09-11

- Recover map-specific item and XP targeting after transient SFTP failures, suppress repeated profile-backoff warnings, and report pre-RCON lookup failures deterministically.
- Keep SFTP host-key verification enabled by default while allowing administrators to explicitly disable it per map for private hosts that regenerate SSH keys.

## 1.1.0 - 2026-09-10

- Remove CodeQL-reported regular-expression denial-of-service risks from command tokenization and profile-path redaction.
- Accept standard OpenSSH `SHA256:...` and hexadecimal SFTP host-key fingerprints.
- Add an authenticated, pre-SSH-authentication SFTP host-key scan that does not transmit stored credentials.
- Inherit the RCON host for new or previously unconfigured SFTP profiles and suggest recognized ASA map tokens.
- Add one-click **Apply & restart** and **Restart now** controls for managed Docker installations.
- Stop retrying Cloudflare analytics browser challenges and classify routine TLS certificate rejections separately from malformed handshakes.
- Let signed-in administrators confirm their current password in place when the recent-authentication window expires, without discarding pending Settings edits.
- Classify the SSH library's host-verifier rejection as `HOST_KEY_REJECTED` instead of the generic `SFTP_READ_FAILED`.
- Deliver administrator announcements and restart notices through ASA `ServerChat` because some servers accept RCON `Broadcast` without displaying it.
- Add per-moderator grants for selected operational actions while reserving critical administration capabilities for administrators.
- Let administrators delete individual moderation notes from protected staff records with confirmation and audit logging.
- Identify the operator, role, action, and map clearly in Activity; administrators see all operators while moderators see only themselves.
- Seed five editable broadcast templates and add Administrator controls to create, edit, restore, and delete templates.
- Attribute new staff-record entries to the signed-in username, categorize manual notes, and automatically record warnings, relay mutes, kicks, and bans.
- Separate Discord-link status from Cluster Chat access consistently across the player list, player card, and staff record.

## 1.0.0 - 2026-09-08

Initial public release of BLCKSNAKE Command.

- Web dashboard for ARK: Survival Ascended server and cluster administration.
- Cluster and map health, connected-player views, maintenance controls, and moderation tools.
- Guided RCON actions for broadcasts, world saves, restarts, item grants, XP grants, and wild-dino wipes.
- Optional Cluster Chat relay between ARK maps and Discord.
- Optional Discord commands and per-map player-profile verification.
- Optional, disabled-by-default product analytics with an in-app privacy disclosure.
- Named Administrator and Moderator accounts with protected sessions and action confirmations.
- Docker image at `blcksnake/blcksnake-command:1.0.0` with a Compose installation and persistent volumes.
- Native HTTPS with a generated installation certificate.
- In-app settings for maps, RCON, Discord, SFTP, analytics, operators, and HTTPS identity.

This is the first public release. Please report installation problems, broken workflows, and game-server compatibility issues using the guidance in [CONTRIBUTING.md](CONTRIBUTING.md).
