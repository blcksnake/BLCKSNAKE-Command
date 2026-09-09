export const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="theme-color" content="#001628">
  <meta name="application-name" content="BLCKSNAKE Command">
  <meta name="description" content="Secure ARK server and cluster administration.">
  <title>BLCKSNAKE Command | ARK Server Command Center</title>
  <link rel="icon" href="/favicon.ico" sizes="any">
  <link rel="icon" type="image/png" href="/brand/favicon-32.png" sizes="32x32">
  <link rel="apple-touch-icon" href="/brand/app-icon-192.png">
  <link rel="manifest" href="/brand/site.webmanifest">
  <link rel="stylesheet" href="/dashboard.css">
  <script src="/dashboard-client.js" defer></script>
</head>
<body>
  <a class="skip-link" href="#workspace">Skip to operations</a>

  <section class="auth-view" id="auth-view" aria-labelledby="auth-title">
    <div class="auth-card">
      <div class="brand-mark"><img src="/brand/blcksnake-mark.png" alt="BLCKSNAKE"></div>
      <p class="eyebrow">Operator access</p>
      <h1 id="auth-title">BLCKSNAKE Command</h1>
      <p class="product-descriptor">ARK Server Command Center</p>
      <p class="auth-copy" id="auth-copy">Connecting...</p>
      <form id="login-form" class="login-form" autocomplete="on" hidden>
        <label for="login-username">Username</label>
        <input id="login-username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="32" required>
        <label for="login-password">Password</label>
        <div class="secret-input">
          <input id="login-password" name="password" type="password" autocomplete="current-password" maxlength="128" required>
          <button class="icon-button password-toggle" type="button" data-password-target="login-password" aria-label="Show password" aria-pressed="false">Show</button>
        </div>
        <button class="primary-button wide" id="login-button" type="submit">Sign in</button>
      </form>
      <form id="setup-form" class="login-form" autocomplete="on" hidden>
        <label for="setup-username">Owner username</label>
        <input id="setup-username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" minlength="3" maxlength="32" pattern="[A-Za-z0-9._-]{3,32}" aria-describedby="setup-username-help" required>
        <span class="field-help" id="setup-username-help">Use 3-32 letters, numbers, periods, underscores, or hyphens.</span>
        <label id="setup-token-label" for="setup-token" hidden>Setup token</label>
        <input id="setup-token" name="setup-token" type="password" autocomplete="off" autocapitalize="none" spellcheck="false" maxlength="256" aria-describedby="setup-token-help" disabled hidden>
        <span class="field-help" id="setup-token-help" hidden>Run <code>docker compose exec app npm run setup:show</code> on the Docker host.</span>
        <label for="setup-password">Password</label>
        <div class="secret-input">
          <input id="setup-password" name="new-password" type="password" autocomplete="new-password" minlength="15" maxlength="128" aria-describedby="setup-password-help" required>
          <button class="icon-button password-toggle" type="button" data-password-target="setup-password" aria-label="Show password" aria-pressed="false">Show</button>
        </div>
        <span class="field-help" id="setup-password-help">Use at least 15 characters. Password-manager generated passwords are supported.</span>
        <label for="setup-password-confirmation">Confirm password</label>
        <input id="setup-password-confirmation" name="new-password-confirmation" type="password" autocomplete="new-password" minlength="15" maxlength="128" required>
        <button class="primary-button wide" id="setup-button" type="submit">Create server owner</button>
      </form>
      <p class="form-error" id="login-error" role="alert" hidden></p>
    </div>
  </section>

  <div class="app-shell" id="app-shell" hidden>
    <aside class="sidebar" id="sidebar" aria-label="Operator navigation">
      <div class="sidebar-brand">
        <div class="brand-mark compact"><img src="/brand/blcksnake-mark.png" alt=""></div>
        <div>
          <strong>BLCKSNAKE</strong>
          <span>Command</span>
        </div>
      </div>

      <nav class="primary-nav" aria-label="Console sections">
        <button class="nav-item active" type="button" data-tab="overview" aria-current="page">
          <span class="nav-glyph" aria-hidden="true">OV</span><span>Overview</span>
        </button>
        <button class="nav-item" type="button" data-tab="players">
          <span class="nav-glyph" aria-hidden="true">PL</span><span>Players</span><span class="nav-count" id="nav-player-count">0</span>
        </button>
        <button class="nav-item" type="button" data-tab="operations">
          <span class="nav-glyph" aria-hidden="true">OP</span><span>Operations</span>
        </button>
        <button class="nav-item" type="button" data-tab="console" data-admin-only hidden>
          <span class="nav-glyph" aria-hidden="true">&gt;_</span><span>Advanced Console</span>
        </button>
        <button class="nav-item" type="button" data-tab="activity">
          <span class="nav-glyph" aria-hidden="true">AC</span><span>Activity</span>
        </button>
        <button class="nav-item" type="button" data-tab="diagnostics" data-admin-only hidden>
          <span class="nav-glyph" aria-hidden="true">DG</span><span>Diagnostics</span>
        </button>
        <button class="nav-item" type="button" data-tab="operators" data-admin-only hidden>
          <span class="nav-glyph" aria-hidden="true">AU</span><span>Operators</span><span class="nav-count" id="nav-operator-count">0</span>
        </button>
        <button class="nav-item" type="button" data-tab="settings" data-admin-only hidden>
          <span class="nav-glyph" aria-hidden="true">ST</span><span>Settings</span>
        </button>
      </nav>

      <div class="sidebar-foot">
        <div class="operator-identity" aria-label="Signed-in operator">
          <span class="operator-avatar" id="operator-avatar" aria-hidden="true">?</span>
          <div><strong id="operator-name">Operator</strong><span class="role-badge" id="operator-role">Role</span></div>
        </div>
        <button class="quiet-button wide" id="change-password-button" type="button">Change password</button>
        <div class="sidebar-health">
          <span class="status-dot pending" id="sidebar-dot" aria-hidden="true"></span>
          <div><strong id="sidebar-state">Connecting</strong><span id="sidebar-detail">Waiting for status</span></div>
        </div>
        <button class="quiet-button wide" id="logout-button" type="button">Sign out</button>
      </div>
    </aside>

    <div class="sidebar-scrim" id="sidebar-scrim" hidden></div>

    <div class="app-main">
      <header class="topbar">
        <button class="icon-button menu-button" id="menu-button" type="button" aria-label="Open navigation" aria-expanded="false" aria-controls="sidebar">Menu</button>
        <div class="page-heading">
          <p class="eyebrow" id="cluster-kicker">Live cluster</p>
          <h1 id="page-title">Overview</h1>
          <p id="page-subtitle">Maps, players, and active issues</p>
        </div>
        <div class="topbar-actions">
          <label class="scope-select" for="server-scope"><span>Map scope</span>
            <select id="server-scope" aria-label="Filter dashboard by map"><option value="">Entire cluster</option></select>
          </label>
          <div class="live-state pending" id="live-state" role="status"><span class="status-dot pending" aria-hidden="true"></span><span>Connecting</span></div>
          <button class="icon-button" id="refresh-button" type="button" aria-label="Refresh dashboard">Refresh</button>
        </div>
      </header>

      <main class="workspace" id="workspace" tabindex="-1">
        <section class="tab-panel active" id="panel-overview" data-panel="overview" aria-labelledby="overview-heading">
          <div class="section-heading">
            <div><p class="eyebrow">Command center</p><h2 id="overview-heading">Cluster overview</h2><p>Maps, players, and active issues.</p></div>
            <button class="secondary-button" type="button" data-open-action="announce">Send server broadcast</button>
          </div>

          <div class="metric-grid" aria-label="Cluster metrics">
            <article class="metric-card" id="metric-maps"><span>Maps online</span><strong>--</strong><small>Waiting for status</small></article>
            <article class="metric-card" id="metric-players"><span>Connected players</span><strong>--</strong><small>Across the cluster</small></article>
            <article class="metric-card" id="metric-discord"><span>Discord relay</span><strong>--</strong><small>Gateway state</small></article>
            <article class="metric-card" id="metric-targeting"><span>Admin targeting</span><strong>--</strong><small>Profile verification</small></article>
          </div>

          <div class="overview-columns">
            <section class="surface attention-surface" aria-labelledby="attention-heading">
              <div class="surface-heading"><div><h3 id="attention-heading">Needs attention</h3></div><span class="counter" id="attention-count">0</span></div>
              <div class="attention-list" id="attention-list" aria-live="polite"><div class="skeleton tall"></div></div>
            </section>
            <section class="surface restart-surface" aria-labelledby="restart-heading">
              <div class="surface-heading"><div><h3 id="restart-heading">Restart schedule</h3></div><button class="text-button" type="button" data-open-action="restart">Schedule</button></div>
              <div id="restart-list"><div class="skeleton tall"></div></div>
            </section>
          </div>

          <div class="section-heading compact-heading"><div><h2>Map servers</h2><p id="map-summary">Waiting for map status.</p></div></div>
          <div class="map-grid" id="map-grid" aria-live="polite"><div class="surface skeleton-card"></div><div class="surface skeleton-card"></div></div>
        </section>

        <section class="tab-panel" id="panel-players" data-panel="players" aria-labelledby="players-heading" hidden>
          <div class="section-heading">
            <div><p class="eyebrow">Connected now</p><h2 id="players-heading">Players</h2><p>Select a survivor to manage.</p></div>
            <button class="secondary-button" id="reload-players" type="button">Refresh players</button>
          </div>
          <div class="toolbar surface">
            <label class="search-field" for="player-search"><span class="visually-hidden">Search players</span><input id="player-search" type="search" placeholder="Search player or survivor" autocomplete="off" spellcheck="false"></label>
            <label for="player-state-filter"><span class="visually-hidden">Filter player readiness</span><select id="player-state-filter"><option value="">All targeting states</option><option value="ready">Ready for grants</option><option value="needed">Needs setup</option><option value="failed">Needs attention</option></select></label>
            <span class="toolbar-summary" id="player-summary">Loading players...</span>
          </div>
          <div class="player-table-wrap surface">
            <table class="player-table">
              <thead><tr><th scope="col">Player</th><th scope="col">Map</th><th scope="col">Targeting</th><th scope="col">Relay</th><th scope="col">Playtime</th><th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead>
              <tbody id="player-rows"></tbody>
            </table>
            <div class="empty-state" id="player-empty" hidden><strong>No matching players</strong><span>Try another search or map scope.</span></div>
          </div>
        </section>

        <section class="tab-panel" id="panel-operations" data-panel="operations" aria-labelledby="operations-heading" hidden>
          <div class="section-heading">
            <div><p class="eyebrow">Server controls</p><h2 id="operations-heading">Operations</h2></div>
          </div>
          <div class="operation-groups" id="operation-groups">
            <section class="operation-group surface">
              <div class="group-heading"><span class="group-icon" aria-hidden="true">CM</span><div><h3>Communication</h3></div></div>
              <div class="action-grid">
                <button class="action-card" type="button" data-open-action="announce"><strong>Server broadcast</strong><span>Send to every player in scope.</span></button>
                <button class="action-card" type="button" data-open-action="announce-template"><strong>Use broadcast template</strong><span>Send a saved broadcast.</span></button>
              </div>
            </section>
            <section class="operation-group surface">
              <div class="group-heading"><span class="group-icon" aria-hidden="true">SV</span><div><h3>Server maintenance</h3></div></div>
              <div class="action-grid">
                <button class="action-card" type="button" data-open-action="save-world"><strong>Save world</strong><span>Save one map or the cluster.</span></button>
                <button class="action-card" type="button" data-open-action="restart"><strong>Schedule restart</strong><span>Broadcast countdown warnings and save at the deadline.</span></button>
                <button class="action-card" type="button" data-open-action="cancel-restart"><strong>Cancel restart</strong><span>Remove an active maintenance countdown.</span></button>
                <button class="action-card danger-card" type="button" data-open-action="destroy-wild-dinos"><strong>Wild dino wipe</strong><span>Destroy wild dinos in scope.</span></button>
              </div>
            </section>
            <section class="operation-group surface">
              <div class="group-heading"><span class="group-icon" aria-hidden="true">GR</span><div><h3>Player grants</h3></div></div>
              <div class="action-grid">
                <button class="action-card" type="button" data-open-action="give-item"><strong>Give item</strong><span>Search the item catalog or use a favorite.</span></button>
                <button class="action-card" type="button" data-open-action="give-xp"><strong>Give XP</strong><span>Grant experience to a player or tribe.</span></button>
                <button class="action-card" type="button" data-open-action="refresh-player-id"><strong>Verify targeting</strong><span>Refresh a player's profile ID.</span></button>
              </div>
            </section>
            <section class="operation-group surface">
              <div class="group-heading"><span class="group-icon" aria-hidden="true">MD</span><div><h3>Moderation</h3></div></div>
              <div class="action-grid">
                <button class="action-card" type="button" data-open-action="player"><strong>Staff record</strong><span>Review live status, moderation notes, and protected admin data.</span></button>
                <button class="action-card" type="button" data-open-action="warn"><strong>Warn player</strong><span>Send a private staff warning.</span></button>
                <button class="action-card" type="button" data-open-action="note"><strong>Add note</strong><span>Save private moderation context for staff.</span></button>
                <button class="action-card" type="button" data-open-action="mute-player"><strong>Mute relay</strong><span>Temporarily block Cluster Chat participation.</span></button>
                <button class="action-card" type="button" data-open-action="kick"><strong>Kick player</strong><span>Remove a connected player from their map.</span></button>
                <button class="action-card danger-card" type="button" data-open-action="ban"><strong>Ban player</strong><span>Ban the selected connected account.</span></button>
              </div>
            </section>
          </div>
        </section>

        <section class="tab-panel" id="panel-console" data-panel="console" data-admin-only aria-labelledby="console-heading" hidden>
          <div class="section-heading">
            <div><p class="eyebrow">Administrator only</p><h2 id="console-heading">Advanced console</h2><p>Allowlisted RCON verbs only. Raw server responses are never displayed.</p></div>
          </div>
          <div class="console-lock surface" id="console-lock">
            <span class="lock-symbol" aria-hidden="true">×</span>
            <div><h3>Raw RCON is disabled</h3><p>Enable it explicitly in configuration only when a dedicated typed operation cannot do the job.</p></div>
          </div>
          <form class="console-form surface" id="console-form" autocomplete="off" hidden>
            <div class="terminal-bar"><span></span><span></span><span></span><strong>ALLOWLISTED RCON</strong></div>
            <div class="console-fields">
              <label for="console-server">Map server<select id="console-server" name="server" required></select></label>
              <label class="console-command" for="console-command">Command<input id="console-command" name="command" type="text" maxlength="1000" required spellcheck="false" autocomplete="off" placeholder="Enter one configured allowlisted command"></label>
              <button class="primary-button" type="submit">Review command</button>
            </div>
            <p class="console-warning">Command separators and control characters are rejected. A lost response may be ambiguous; commands are never retried automatically.</p>
          </form>
          <section class="surface console-history" aria-labelledby="console-history-heading">
            <div class="surface-heading"><div><h3 id="console-history-heading">Console activity</h3></div></div>
            <div id="console-activity" class="activity-list compact-list"><div class="empty-copy">No console activity in this session.</div></div>
          </section>
        </section>

        <section class="tab-panel" id="panel-activity" data-panel="activity" aria-labelledby="activity-heading" hidden>
          <div class="section-heading">
            <div><p class="eyebrow">Audit trail</p><h2 id="activity-heading">Activity</h2></div>
            <button class="secondary-button" id="reload-activity" type="button">Refresh activity</button>
          </div>
          <div class="toolbar surface">
            <label class="search-field" for="activity-search"><span class="visually-hidden">Search activity</span><input id="activity-search" type="search" placeholder="Filter by action, map, or actor" autocomplete="off"></label>
            <label for="activity-state-filter"><span class="visually-hidden">Filter activity status</span><select id="activity-state-filter"><option value="">All outcomes</option><option value="succeeded">Succeeded</option><option value="failed">Failed</option><option value="ambiguous">Ambiguous</option><option value="pending">Pending</option></select></label>
            <span class="toolbar-summary" id="activity-summary">Loading activity...</span>
          </div>
          <div class="activity-list surface" id="activity-list" aria-live="polite"><div class="skeleton tall"></div></div>
        </section>

        <section class="tab-panel" id="panel-diagnostics" data-panel="diagnostics" data-admin-only aria-labelledby="diagnostics-heading" hidden>
          <div class="section-heading">
            <div><p class="eyebrow">Live troubleshooting</p><h2 id="diagnostics-heading">Diagnostics</h2><p>Recent events from this process.</p></div>
            <button class="secondary-button" id="reload-diagnostics" type="button">Refresh diagnostics</button>
          </div>
          <div class="toolbar surface diagnostic-toolbar">
            <label class="search-field" for="diagnostic-search"><span class="visually-hidden">Search diagnostic events</span><input id="diagnostic-search" type="search" maxlength="128" placeholder="Search event, message, map, or reason" autocomplete="off" spellcheck="false"></label>
            <label for="diagnostic-channel"><span class="visually-hidden">Filter diagnostic channel</span><select id="diagnostic-channel"><option value="">All channels</option><option value="application">Application</option><option value="security">Security</option><option value="audit">Audit</option></select></label>
            <label for="diagnostic-level"><span class="visually-hidden">Filter minimum diagnostic level</span><select id="diagnostic-level"><option value="warn">Warnings and errors</option><option value="error">Errors only</option><option value="info">Info and above</option><option value="debug">All levels</option></select></label>
            <span class="toolbar-summary" id="diagnostic-summary">Open this page to load live events.</span>
          </div>
          <p class="diagnostic-note">Viewing is audited. This list resets when the service restarts.</p>
          <div class="diagnostic-list surface" id="diagnostic-list" aria-live="polite"><div class="empty-copy">Select Refresh diagnostics to load events.</div></div>
        </section>

        <section class="tab-panel" id="panel-operators" data-panel="operators" data-admin-only aria-labelledby="operators-heading" hidden>
          <div class="section-heading">
            <div><p class="eyebrow">Access control</p><h2 id="operators-heading">Operators</h2></div>
            <button class="primary-button" id="create-operator-button" type="button">Create operator</button>
          </div>
          <p class="operator-note">Moderators can run operations. Administrators also manage accounts, diagnostics, settings, and the console. Disabling an operator ends their sessions.</p>
          <p class="visually-hidden" id="operator-status" role="status" aria-live="polite"></p>
          <div class="operator-table-wrap surface">
            <table class="operator-table">
              <thead><tr><th scope="col">Username</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Updated</th><th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead>
              <tbody id="operator-rows"></tbody>
            </table>
            <div class="empty-state" id="operator-empty" hidden><strong>No operators available</strong><span>Create an operator to grant dashboard access.</span></div>
          </div>
        </section>

        <section class="tab-panel" id="panel-settings" data-panel="settings" data-admin-only aria-labelledby="settings-heading" hidden>
          <div class="section-heading settings-page-heading">
            <div><p class="eyebrow">Administrator only</p><h2 id="settings-heading">Settings</h2></div>
            <button class="secondary-button" id="reload-settings" type="button">Refresh settings</button>
          </div>

          <div class="settings-banner warn" id="settings-restart-banner" role="status" hidden>
            <span class="settings-banner-mark" aria-hidden="true">!</span>
            <div><strong>Restart required</strong><p id="settings-restart-copy">Restart the application service to activate the saved configuration. It will not restart automatically.</p></div>
          </div>

          <div class="settings-status-grid" aria-label="Configuration status">
            <article class="settings-status-card surface"><span class="settings-status-mark" aria-hidden="true">IN</span><div><span>Instance security</span><strong id="settings-instance-status">Loading</strong><small id="settings-keystore-status">Checking managed storage</small></div></article>
            <article class="settings-status-card surface"><span class="settings-status-mark" aria-hidden="true">MP</span><div><span>Map connections</span><strong id="settings-map-status">--</strong><small id="settings-map-detail">Waiting for configuration</small></div></article>
            <article class="settings-status-card surface"><span class="settings-status-mark" aria-hidden="true">DC</span><div><span>Discord</span><strong id="settings-discord-status">--</strong><small id="settings-discord-detail">Waiting for configuration</small></div></article>
            <article class="settings-status-card surface"><span class="settings-status-mark" aria-hidden="true">CH</span><div><span>Local changes</span><strong id="settings-change-status">None</strong><small id="settings-revision-status">Configuration not loaded</small></div></article>
          </div>

          <form id="settings-form" class="settings-form" autocomplete="off">
            <div class="settings-layout">
              <nav class="settings-section-nav surface" aria-label="Settings sections">
                <p class="eyebrow">Configuration</p>
                <button type="button" data-settings-jump="settings-general">General</button>
                <button type="button" data-settings-jump="settings-maps">Map servers</button>
                <button type="button" data-settings-jump="settings-discord">Discord</button>
                <button type="button" data-settings-jump="settings-analytics">Analytics</button>
                <button type="button" data-settings-jump="settings-security">Security</button>
                <p class="settings-nav-note">Stored credentials are never returned to this page. Empty secret fields keep the current value.</p>
              </nav>

              <div class="settings-sections">
                <section class="settings-card surface" id="settings-general" aria-labelledby="settings-general-heading">
                  <div class="settings-card-heading"><div><p class="eyebrow">Identity</p><h3 id="settings-general-heading">General</h3><p>The name staff and players see for this cluster.</p></div><span class="settings-section-number" aria-hidden="true">01</span></div>
                  <div class="settings-field-grid">
                    <label class="settings-field full" for="settings-cluster-name"><span>Cluster name</span><input id="settings-cluster-name" name="clusterName" type="text" maxlength="96" required autocomplete="off"><small>Used in dashboard labels, relay messages, and operator password checks.</small></label>
                  </div>
                </section>

                <section class="settings-card surface" id="settings-maps" aria-labelledby="settings-maps-heading">
                  <div class="settings-card-heading"><div><p class="eyebrow">Cluster maps</p><h3 id="settings-maps-heading">Map servers</h3><p>RCON controls each map. Profile import can securely resolve connected-player targeting.</p></div><button class="secondary-button" id="settings-add-server" type="button">Add map</button></div>
                  <div class="settings-server-list" id="settings-server-list" aria-live="polite"><div class="settings-loading"><span class="skeleton tall"></span><span class="skeleton tall"></span></div></div>
                </section>

                <section class="settings-card surface" id="settings-discord" aria-labelledby="settings-discord-heading">
                  <div class="settings-card-heading"><div><p class="eyebrow">Integration</p><h3 id="settings-discord-heading">Discord</h3><p>Connect the bot and choose where relay and staff events are delivered.</p></div><label class="settings-switch"><input id="settings-discord-enabled" type="checkbox"><span>Enabled</span></label></div>
                  <div class="settings-field-grid" id="settings-discord-fields">
                    <div class="settings-field full"><label for="settings-discord-token">Bot token</label><div class="secret-input"><input class="settings-secret-input" id="settings-discord-token" type="password" maxlength="512" autocomplete="off" spellcheck="false" data-secret-label="Discord bot token" aria-describedby="settings-discord-token-help"><button class="icon-button password-toggle" type="button" data-password-target="settings-discord-token" aria-label="Show Discord bot token" aria-pressed="false">Show</button></div><small id="settings-discord-token-help">Leave empty to keep the stored token.</small></div>
                    <label class="settings-field" for="settings-discord-application"><span>Application ID</span><input id="settings-discord-application" type="text" maxlength="20" pattern="[0-9]{17,20}" inputmode="numeric" autocomplete="off"></label>
                    <label class="settings-field" for="settings-discord-guild"><span>Server / guild ID</span><input id="settings-discord-guild" type="text" maxlength="20" pattern="[0-9]{17,20}" inputmode="numeric" autocomplete="off"></label>
                    <label class="settings-field" for="settings-discord-chat-channel"><span>Chat channel ID</span><input id="settings-discord-chat-channel" type="text" maxlength="20" pattern="[0-9]{17,20}" inputmode="numeric" autocomplete="off"></label>
                    <label class="settings-field" for="settings-discord-audit-channel"><span>Audit channel ID</span><input id="settings-discord-audit-channel" type="text" maxlength="20" pattern="[0-9]{17,20}" inputmode="numeric" autocomplete="off"></label>
                    <label class="settings-field full" for="settings-discord-admin-roles"><span>Administrator role IDs</span><textarea id="settings-discord-admin-roles" rows="2" maxlength="2000" autocomplete="off" placeholder="One ID per line or separated by commas"></textarea></label>
                    <label class="settings-field full" for="settings-discord-moderator-roles"><span>Moderator role IDs</span><textarea id="settings-discord-moderator-roles" rows="2" maxlength="2000" autocomplete="off" placeholder="One ID per line or separated by commas"></textarea></label>
                    <label class="settings-field full" for="settings-discord-relay-roles"><span>Relay role IDs</span><textarea id="settings-discord-relay-roles" rows="2" maxlength="2000" autocomplete="off" placeholder="Empty allows everyone when unlinked chat is enabled"></textarea></label>
                    <label class="settings-check"><input id="settings-discord-unlinked" type="checkbox"><span><strong>Allow unlinked chat</strong><small>Permit relay messages before a Discord account is linked.</small></span></label>
                    <label class="settings-check"><input id="settings-discord-register" type="checkbox"><span><strong>Register slash commands</strong><small>Refresh application commands when the integration starts.</small></span></label>
                  </div>
                  <label class="settings-check settings-clear-credential"><input id="settings-discord-clear-token" type="checkbox"><span><strong>Delete stored bot token</strong><small>Disable Discord first. The encrypted credential is permanently removed when this change is applied.</small></span></label>
                </section>

                <section class="settings-card surface" id="settings-analytics" aria-labelledby="settings-analytics-heading">
                  <div class="settings-card-heading"><div><p class="eyebrow">Optional</p><h3 id="settings-analytics-heading">Product analytics</h3><p>Share limited technical data to help improve BLCKSNAKE Command.</p></div><label class="settings-switch"><input id="settings-analytics-enabled" type="checkbox"><span>Enabled</span></label></div>
                  <div class="settings-analytics-disclosure">
                    <strong>What is sent</strong>
                    <p>App version, Node.js version, operating system, CPU architecture, enabled feature flags, map count, uptime, event time, and a random installation identifier. The analytics server also receives the public IP used for the request.</p>
                    <strong>What is never sent</strong>
                    <p>Server names or addresses, credentials, player or Discord identifiers, chat messages, RCON commands, configuration values, or logs.</p>
                    <p>Analytics is off by default. Turn it on, then select Review &amp; apply to send the initial contact. You can disable it at any time.</p>
                  </div>
                </section>

                <section class="settings-card surface" id="settings-security" aria-labelledby="settings-security-heading">
                  <div class="settings-card-heading"><div><p class="eyebrow">Managed locally</p><h3 id="settings-security-heading">Instance security</h3><p>Secrets are encrypted; the root key is stored separately.</p></div><span class="state-badge good" id="settings-managed-badge">Managed</span></div>
                  <dl class="settings-security-list">
                    <div><dt>Instance ID</dt><dd id="settings-instance-id">Unavailable</dd></div>
                    <div><dt>Keystore</dt><dd id="settings-keystore">Checking</dd></div>
                    <div><dt>HTTPS identity</dt><dd><strong id="settings-tls-mode">Checking</strong><span id="settings-tls-detail">Certificate details unavailable</span><a class="settings-ca-download" href="/dashboard-ca.pem" download="blcksnake-command-ca.pem">Download current or staged CA</a></dd></div>
                    <div><dt>Automation token</dt><dd><strong id="settings-token-status">Checking</strong><span>Stored values are never displayed. A replacement is shown once after rotation.</span></dd></div>
                  </dl>
                  <div class="settings-security-actions">
                    <button class="secondary-button settings-stage-button" id="settings-rotate-token" type="button" aria-pressed="false"><span>Rotate automation token</span><small>Stage a unique replacement</small></button>
                    <button class="secondary-button settings-stage-button" id="settings-regenerate-tls" type="button" aria-pressed="false"><span>Regenerate HTTPS identity</span><small>Stage a new certificate</small></button>
                  </div>
                  <label class="settings-field full settings-tls-names" for="settings-tls-names"><span>Additional HTTPS names or IP addresses</span><textarea id="settings-tls-names" rows="3" maxlength="4096" autocomplete="off" spellcheck="false" placeholder="dashboard.example.net&#10;192.168.1.20" disabled></textarea><small>Used only when regenerating. Enter at most 16 DNS names or IP addresses, one per line. Localhost, this machine, and loopback addresses are included automatically.</small></label>
                  <div class="settings-console-policy">
                    <label class="settings-check"><input id="settings-raw-rcon-enabled" type="checkbox"><span><strong>Enable Administrator advanced console</strong><small>Commands still require recent Administrator authentication, preview, confirmation, and an allowlisted first verb.</small></span></label>
                    <label class="settings-field full" for="settings-rcon-allowlist"><span>Allowed console verbs</span><textarea id="settings-rcon-allowlist" rows="3" maxlength="4096" autocomplete="off" spellcheck="false" placeholder="One command verb per line"></textarea><small>Single verbs only; arguments are validated separately. Start with ListPlayers and SaveWorld if needed.</small></label>
                  </div>
                  <p class="settings-security-note">Rotation takes effect only after review and Apply. After regeneration, download and trust the staged CA on administrator devices before restarting; retain the old CA until the new listener is verified.</p>
                </section>
              </div>
            </div>

            <p class="form-error settings-error" id="settings-error" role="alert" hidden></p>
            <div class="settings-change-bar" id="settings-change-bar" hidden>
              <div role="status" aria-live="polite"><span class="status-dot pending" aria-hidden="true"></span><div><strong id="settings-change-count">Unsaved changes</strong><span>Review before replacing the active configuration.</span></div></div>
              <div><button class="quiet-button" id="settings-discard" type="button">Discard</button><button class="primary-button" id="settings-review" type="submit">Review &amp; apply</button></div>
            </div>
          </form>
        </section>
      </main>
    </div>
  </div>

  <dialog class="player-drawer" id="player-dialog" aria-labelledby="player-dialog-title">
    <div class="drawer-shell">
      <header class="dialog-header">
        <div><p class="eyebrow">Connected player</p><h2 id="player-dialog-title">Player details</h2><p id="player-dialog-map"></p></div>
        <button class="icon-button close-dialog" type="button" aria-label="Close player details">Close</button>
      </header>
      <div class="player-detail-grid" id="player-detail-grid"></div>
      <section class="drawer-section"><h3>Quick actions</h3><div class="drawer-actions" id="player-actions"></div></section>
    </div>
  </dialog>

  <dialog class="action-dialog" id="action-dialog" aria-labelledby="action-dialog-title">
    <form class="dialog-shell" id="action-form" autocomplete="off">
      <header class="dialog-header">
        <div><p class="eyebrow" id="action-dialog-kicker">Guided operation</p><h2 id="action-dialog-title">Operation</h2><p id="action-dialog-description"></p></div>
        <button class="icon-button close-dialog" type="button" aria-label="Close operation">Close</button>
      </header>
      <div class="form-grid" id="action-fields"></div>
      <p class="form-error" id="action-error" role="alert" hidden></p>
      <footer class="dialog-footer"><button class="quiet-button close-dialog" type="button">Cancel</button><button class="primary-button" id="preview-button" type="submit">Review operation</button></footer>
    </form>
  </dialog>

  <dialog class="confirm-dialog" id="confirm-dialog" aria-labelledby="confirm-dialog-title">
    <form class="dialog-shell confirm-shell" id="confirm-form" autocomplete="off">
      <header class="dialog-header">
        <div><p class="eyebrow" id="confirm-risk">Confirmation</p><h2 id="confirm-dialog-title">Review operation</h2></div>
        <button class="icon-button close-dialog" type="button" aria-label="Close confirmation">Close</button>
      </header>
      <div class="operation-summary" id="operation-summary"></div>
      <label class="challenge-field" id="challenge-field" for="challenge-response" hidden><span id="challenge-label">Confirmation challenge</span><input id="challenge-response" type="text" autocomplete="off" spellcheck="false"></label>
      <p class="form-error" id="confirm-error" role="alert" hidden></p>
      <footer class="dialog-footer"><button class="quiet-button close-dialog" type="button">Go back</button><button class="danger-button" id="execute-button" type="submit">Confirm operation</button></footer>
    </form>
  </dialog>

  <dialog class="result-dialog staff-record-dialog" id="result-dialog" aria-labelledby="result-dialog-title" aria-describedby="staff-record-subtitle">
    <div class="dialog-shell staff-record-shell">
      <header class="dialog-header">
        <div><p class="eyebrow">Protected staff view</p><h2 id="result-dialog-title">Player staff record</h2><p id="staff-record-subtitle">Loading the current connected-player record...</p></div>
        <button class="icon-button close-dialog" type="button" aria-label="Close staff record">Close</button>
      </header>
      <div class="staff-record-loading" id="staff-record-loading" role="status" aria-live="polite">
        <span class="staff-record-loading-mark" aria-hidden="true"></span>
        <span>Loading staff record...</span>
      </div>
      <p class="form-error staff-record-error" id="staff-record-error" role="alert" hidden></p>
      <div class="staff-record-content" id="result-details" hidden>
        <section class="staff-record-hero" aria-labelledby="staff-record-player-name">
          <div class="staff-record-avatar" id="staff-record-avatar" aria-hidden="true">--</div>
          <div class="staff-record-identity">
            <div class="staff-record-badges"><span class="state-badge good">Connected</span><span class="map-badge" id="staff-record-map">Current map</span></div>
            <h3 id="staff-record-player-name">Connected player</h3>
            <p id="staff-record-account-name">Account name unavailable</p>
          </div>
        </section>

        <section class="staff-record-section" aria-labelledby="staff-record-status-heading">
          <div class="staff-record-section-heading">
            <div><p class="eyebrow">Live context</p><h3 id="staff-record-status-heading">Player status</h3></div>
            <span class="staff-record-freshness" id="staff-record-freshness">Checked now</span>
          </div>
          <div class="staff-record-status-grid" id="staff-record-status"></div>
        </section>

        <div class="staff-record-columns">
          <section class="staff-record-section staff-record-notes-section" aria-labelledby="staff-record-notes-heading">
            <div class="staff-record-section-heading">
              <div><p class="eyebrow">Moderation history</p><h3 id="staff-record-notes-heading">Recent staff notes</h3></div>
              <span class="record-count" id="staff-record-note-count">0</span>
            </div>
            <div class="staff-note-list" id="staff-record-notes"></div>
          </section>

          <section class="staff-record-section identifier-disclosure staff-record-identifiers" id="player-identifiers-section" data-admin-only hidden aria-labelledby="player-identifiers-heading">
            <div class="identifier-heading">
              <div>
                <p class="eyebrow">Administrator only</p>
                <h3 id="player-identifiers-heading">Protected identifiers</h3>
              </div>
              <div class="identifier-controls">
                <button class="secondary-button" id="reveal-player-identifiers" type="button" aria-controls="player-identifiers" aria-expanded="false">Reveal identifiers</button>
                <button class="quiet-button" id="hide-player-identifiers" type="button" hidden>Hide</button>
              </div>
            </div>
            <p class="identifier-privacy-warning">Sensitive account data. Values hide after 60 seconds. Do not paste them into public chat or tickets.</p>
            <p class="form-error identifier-error" id="player-identifiers-error" role="alert" hidden></p>
            <dl class="identifier-list" id="player-identifiers" hidden></dl>
            <p class="identifier-status" id="player-identifiers-status" role="status" aria-live="polite"></p>
          </section>
        </div>
      </div>
      <footer class="dialog-footer staff-record-footer"><button class="quiet-button" id="back-to-player" type="button">Back to player</button><button class="primary-button close-dialog" type="button">Done</button></footer>
    </div>
  </dialog>

  <dialog class="account-dialog" id="change-password-dialog" aria-labelledby="change-password-title">
    <form class="dialog-shell confirm-shell" id="change-password-form" autocomplete="on">
      <header class="dialog-header">
        <div><p class="eyebrow">Account security</p><h2 id="change-password-title">Change password</h2><p id="change-password-copy">Changing your password ends your other dashboard sessions.</p></div>
        <button class="icon-button close-dialog" type="button" aria-label="Close password change">Close</button>
      </header>
      <div class="form-grid single-column">
        <label class="full" for="current-password"><span>Current password</span><input id="current-password" name="current-password" type="password" autocomplete="current-password" maxlength="128" required></label>
        <label class="full" for="new-password"><span>New password</span><input id="new-password" name="new-password" type="password" autocomplete="new-password" minlength="15" maxlength="128" aria-describedby="new-password-help" required><span class="field-help" id="new-password-help">Use at least 15 characters.</span></label>
        <label class="full" for="new-password-confirmation"><span>Confirm new password</span><input id="new-password-confirmation" name="new-password-confirmation" type="password" autocomplete="new-password" minlength="15" maxlength="128" required></label>
      </div>
      <p class="form-error" id="change-password-error" role="alert" hidden></p>
      <footer class="dialog-footer"><button class="quiet-button close-dialog" id="cancel-password-change" type="button">Cancel</button><button class="quiet-button" id="forced-password-logout" type="button" hidden>Sign out</button><button class="primary-button" id="save-password-button" type="submit">Change password</button></footer>
    </form>
  </dialog>

  <dialog class="account-dialog" id="create-operator-dialog" aria-labelledby="create-operator-title">
    <form class="dialog-shell confirm-shell" id="create-operator-form" autocomplete="off">
      <header class="dialog-header">
        <div><p class="eyebrow">Access control</p><h2 id="create-operator-title">Create operator</h2><p>A temporary password will be generated and shown once.</p></div>
        <button class="icon-button close-dialog" type="button" aria-label="Close operator creation">Close</button>
      </header>
      <div class="form-grid single-column">
        <label class="full" for="operator-username"><span>Username</span><input id="operator-username" name="username" type="text" autocomplete="off" autocapitalize="none" spellcheck="false" minlength="3" maxlength="32" pattern="[A-Za-z0-9._-]{3,32}" required></label>
        <label class="full" for="operator-role-select"><span>Role</span><select id="operator-role-select" name="role" required><option value="moderator" selected>Moderator</option><option value="admin">Administrator</option></select></label>
      </div>
      <p class="form-error" id="create-operator-error" role="alert" hidden></p>
      <footer class="dialog-footer"><button class="quiet-button close-dialog" type="button">Cancel</button><button class="primary-button" id="save-operator-button" type="submit">Create operator</button></footer>
    </form>
  </dialog>

  <dialog class="account-dialog" id="temporary-password-dialog" aria-labelledby="temporary-password-title">
    <div class="dialog-shell confirm-shell">
      <header class="dialog-header">
        <div><p class="eyebrow">Shown once</p><h2 id="temporary-password-title">Temporary password</h2><p id="temporary-password-copy">Share this password securely. The operator must change it at first sign-in.</p></div>
      </header>
      <div class="temporary-secret"><label for="temporary-password">Temporary password</label><div class="secret-input three-actions"><input id="temporary-password" type="password" readonly spellcheck="false" aria-describedby="temporary-password-note"><button class="icon-button password-toggle" type="button" data-password-target="temporary-password" aria-label="Show temporary password" aria-pressed="false">Show</button><button class="secondary-button" id="copy-temporary-password" type="button">Copy</button></div></div>
      <p class="confirmation-note" id="temporary-password-note">This value cannot be recovered after you close this window.</p>
      <footer class="dialog-footer"><button class="primary-button" id="close-temporary-password" type="button">I saved it</button></footer>
    </div>
  </dialog>

  <dialog class="settings-review-dialog" id="settings-review-dialog" aria-labelledby="settings-review-title">
    <div class="dialog-shell confirm-shell">
      <header class="dialog-header">
        <div><p class="eyebrow">Configuration review</p><h2 id="settings-review-title">Apply settings</h2></div>
        <button class="icon-button close-dialog" type="button" aria-label="Close settings review">Close</button>
      </header>
      <div class="settings-review-body">
        <ol class="settings-review-list" id="settings-review-list"></ol>
        <p class="confirmation-note settings-review-impact" id="settings-review-impact">Restart the service to activate these changes.</p>
      </div>
      <p class="form-error" id="settings-review-error" role="alert" hidden></p>
      <footer class="dialog-footer"><button class="quiet-button close-dialog" type="button">Continue editing</button><button class="primary-button" id="settings-apply" type="button">Apply settings</button></footer>
    </div>
  </dialog>

  <dialog class="account-dialog" id="settings-token-dialog" aria-labelledby="settings-token-title">
    <div class="dialog-shell confirm-shell">
      <header class="dialog-header">
        <div><p class="eyebrow">Shown once</p><h2 id="settings-token-title">New automation token</h2><p id="settings-token-copy">Copy this replacement into a protected secret store now. Keep the running automation client on its current token until the coordinated restart.</p></div>
      </header>
      <div class="temporary-secret"><label for="settings-automation-token">Automation token</label><div class="secret-input three-actions"><input id="settings-automation-token" type="password" readonly spellcheck="false" autocomplete="off" aria-describedby="settings-token-note"><button class="icon-button password-toggle" type="button" data-password-target="settings-automation-token" aria-label="Show automation token" aria-pressed="false">Show</button><button class="secondary-button" id="settings-copy-token" type="button">Copy</button></div></div>
      <p class="confirmation-note" id="settings-token-note">After it is safely retained, select “I saved it.” Then update the client credential immediately before restarting the service. Closing this page permanently clears the displayed value.</p>
      <footer class="dialog-footer"><button class="primary-button" id="settings-close-token" type="button">I saved it</button></footer>
    </div>
  </dialog>

  <div class="toast-region" id="toast-region" aria-live="polite" aria-atomic="false"></div>
</body>
</html>`;

export function renderDashboard() {
  return DASHBOARD_HTML;
}

export default renderDashboard;
