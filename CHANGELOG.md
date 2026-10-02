# Changelog

## 1.4.0 - 2026-10-02

### Added

- Add a floating Add Map wizard with separate ASA and ASE presets, unused-port suggestions, RCON/SFTP validation, and a review step before applying settings.
- Add exact, case-sensitive identifiers for 24 ASA and ASE maps, including `TheIsland_WP` for ASA and `TheIsland` for ASE, while preserving existing server IDs and custom maps.
- Add bulk map enablement, disablement, and removal, plus bulk broadcast-template categorization and deletion through the existing settings review flow.
- Add cross-section search with Ctrl/Command+K, keyboard navigation, and mobile shortcuts for search, players, operations, and maps.
- Add mixed carts for multiple catalog items and packages, with quantities, quality, blueprint options, and review of up to 50 expanded grant lines.
- Add per-operator favorite items and recently granted items, persisted in encrypted state.
- Add 20 ASA boss tribute packages, including Nunatak, Grendel, and Astraeos encounters, with searchable map and difficulty filters.

### Changed

- Use compact, searchable map cards and collapsible settings sections with retained drafts, focus, and disclosure state. Keep dialog headers and review controls visible on mobile and desktop.
- Add broadcast-template categories, filters, duplication, and presets; group boss packages by map, boss, or difficulty while retaining shared grants and immediate package saves.
- Show map health and live player summaries, including offline, degraded, stale, and unknown observations.
- Select ASA/ASE item blueprints and package suggestions from recognized configured map identifiers. Unknown maps remain unverified; ASE grants require an administrator-verified character-ID mapping.
- Verify 2,215 catalog entries and 65 boss recipes against the bundled source registry. Correct 27 inherited recipe defaults only when their complete records are untouched; preserve custom, edited, disabled, and deleted packages and label unverified recipes clearly.
- Revalidate player identity, map context, package revisions, and exact blueprint paths before grants. Show per-item outcomes and stop remaining commands after failure or uncertainty without automatic retries.
- Retain the native JavaScript/HTML/CSS stack, existing permissions, and encrypted settings/state persistence without database migrations.

### Fixed

- Stop item-search layout jumps with debounced requests, fixed-height results, virtual rows, DOM reuse, and stale-response protection.
- Preserve player dropdown selections and option nodes during polling, and refresh expired player selections before review without narrowing the roster.
- Restore the cart, search, focus, and scroll position when returning from confirmation; keep drafts on validation and request errors.
- Improve invalid-field handling, keyboard navigation, reduced-motion behavior, and narrow-screen layouts without horizontal overflow.
- Report the current package version in optional analytics instead of a stale hard-coded release number.

## 1.3.0 - 2026-09-19

- Add a dedicated Analytics dashboard with live map availability, current player distribution, Discord relay state, service uptime, scheduled-restart status, and per-map activity.
- Preserve the fixed BLCKSNAKE sidebar identity, show configured map names, and keep Analytics updates scoped to its own metric cards.
- Show restart-safe player activity with persistent total playtime, completed-session counts, last-seen times, and current live-session duration without exposing stable player identifiers.
- Add administrator-managed recurring announcements at 1, 3, 6, 12, or 24-hour intervals for help prompts, community reminders, and Discord invitations.
- Support a validated `{discordInvite}` placeholder so one configured Discord invite URL can be reused safely in scheduled messages.
- Keep each item-package catalog lookup independent so searching one row no longer cancels another row's request.
- Make the package and single-item catalog pickers reserve visible space for suggestions, expand package results across the editor, and show loading, empty, and retry states instead of failing silently.

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
