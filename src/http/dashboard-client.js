(function () {
  'use strict';

  var POLL_INTERVAL_MS = 10_000;
  var STALE_AFTER_MS = 25_000;
  var MAX_BACKOFF_MS = 60_000;
  var PLAYER_REFRESH_MS = 10_000;
  var ACTIVITY_REFRESH_MS = 15_000;
  var STARTER_ANNOUNCEMENT_TEMPLATES = {
    'Welcome': 'Welcome survivors! Please review the server rules and contact staff if you need help.',
    'Maintenance soon': 'Server maintenance will begin soon. Move to a safe location and prepare for a restart.',
    'World save': 'A world save is being performed. Brief lag may occur.',
    'Event starting': 'A server event is starting soon. Watch chat for details and follow staff instructions.',
    'Rules reminder': 'Reminder: respect other players, avoid blocking access, and report disputes to staff.'
  };

  var pageMeta = {
    overview: ['Overview', 'Maps, players, and active issues'],
    players: ['Players', 'Connected survivors'],
    operations: ['Operations', 'Server and player controls'],
    console: ['Advanced Console', 'Allowlisted RCON commands'],
    activity: ['Activity', 'Administrator actions'],
    diagnostics: ['Diagnostics', 'Recent service events'],
    operators: ['Operators', 'Accounts and roles'],
    settings: ['Settings', 'Cluster and integrations']
  };

  var state = {
    authMode: null,
    setupRequired: false,
    setupTokenRequired: false,
    remote: false,
    session: null,
    status: null,
    capabilities: {},
    actionCapabilities: new Map(),
    servers: [],
    players: [],
    actionPlayers: [],
    visiblePlayers: [],
    activity: [],
    activityScope: 'own',
    diagnostics: [],
    operators: [],
    operatorGrantableActions: [],
    permissionOperator: null,
    settingsProjection: null,
    settingsBaseline: '',
    settingsController: null,
    settingsInputSequence: 0,
    pendingAutomationTokenDeliveryId: '',
    automationTokenRecoveryReceipt: '',
    automationTokenRecoveryInstanceId: '',
    automationTokenRecoveryNeedsReconciliation: false,
    currentTab: 'overview',
    lastRefreshAt: 0,
    lastPlayerRefreshAt: 0,
    lastActivityRefreshAt: 0,
    lastDiagnosticRefreshAt: 0,
    pollFailures: 0,
    pollTimer: null,
    staleTimer: null,
    bootstrapController: null,
    playerController: null,
    activityController: null,
    diagnosticController: null,
    operatorController: null,
    itemController: null,
    actionPlayerController: null,
    identifierController: null,
    staffRecordController: null,
    playerSearchTimer: null,
    itemSearchTimer: null,
    diagnosticSearchTimer: null,
    selectedPlayer: null,
    currentAction: null,
    actionDefaults: {},
    pendingAction: null,
    lastDialogTrigger: null,
    consoleActivity: [],
    passwordChangeRequired: false,
    lastOperatorActivityAt: 0,
    identifierDisclosureGeneration: 0,
    identifierClearTimer: null,
    staffRecordGeneration: 0
  };

  function $(selector, root) {
    return (root || document).querySelector(selector);
  }

  function $all(selector, root) {
    return Array.from((root || document).querySelectorAll(selector));
  }

  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = safeString(text);
    return node;
  }

  function safeString(value, maximum) {
    var text = value === undefined || value === null ? '' : String(value);
    var limit = maximum || 2_000;
    return text.length > limit ? text.slice(0, limit) + '...' : text;
  }

  function numeric(value, fallback) {
    var number = Number(value);
    return Number.isFinite(number) ? number : (fallback === undefined ? 0 : fallback);
  }

  function timestamp(value) {
    if (value === undefined || value === null || value === '') return null;
    var result = typeof value === 'number' ? value : Date.parse(value);
    return Number.isFinite(result) ? result : null;
  }

  function formatDate(value) {
    var time = timestamp(value);
    if (time === null) return '--';
    return new Date(time).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  }

  function formatTime(value) {
    var time = timestamp(value);
    if (time === null) return '--';
    return new Date(time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function formatAge(value) {
    var time = timestamp(value);
    if (time === null) return '--';
    var seconds = Math.round((Date.now() - time) / 1_000);
    var absolute = Math.abs(seconds);
    var suffix = seconds < 0 ? 'from now' : 'ago';
    if (absolute < 60) return String(absolute) + 's ' + suffix;
    var minutes = Math.round(absolute / 60);
    if (minutes < 60) return String(minutes) + 'm ' + suffix;
    var hours = Math.round(minutes / 60);
    if (hours < 48) return String(hours) + 'h ' + suffix;
    return String(Math.round(hours / 24)) + 'd ' + suffix;
  }

  function formatDuration(seconds) {
    var total = Math.max(0, Math.floor(numeric(seconds)));
    var days = Math.floor(total / 86_400);
    var hours = Math.floor((total % 86_400) / 3_600);
    var minutes = Math.floor((total % 3_600) / 60);
    if (days) return String(days) + 'd ' + String(hours) + 'h';
    if (hours) return String(hours) + 'h ' + String(minutes) + 'm';
    return String(minutes) + 'm';
  }

  function plural(value, noun) {
    return String(value) + ' ' + noun + (value === 1 ? '' : 's');
  }

  function setHidden(node, hidden) {
    if (node) node.hidden = Boolean(hidden);
  }

  function setBusy(button, busy, busyLabel) {
    if (!button) return;
    if (busy) {
      button.dataset.normalLabel = button.textContent;
      button.textContent = busyLabel || 'Working...';
      button.disabled = true;
      button.setAttribute('aria-busy', 'true');
    } else {
      button.textContent = button.dataset.normalLabel || button.textContent;
      button.disabled = false;
      button.removeAttribute('aria-busy');
      delete button.dataset.normalLabel;
    }
  }

  function setTone(node, base, tone) {
    if (!node) return;
    node.className = base + (tone ? ' ' + tone : '');
  }

  function errorMessage(error, fallback) {
    var value = error && error.message ? error.message : fallback || 'The request could not be completed.';
    return safeString(value, 420);
  }

  function showFormError(node, message) {
    if (!node) return;
    node.textContent = safeString(message, 420);
    node.hidden = !message;
  }

  function toast(message, tone, timeout) {
    var container = $('#toast-region');
    if (!container) return;
    var item = element('div', 'toast ' + (tone || ''));
    item.setAttribute('role', tone === 'bad' ? 'alert' : 'status');
    var symbol = element('span', 'toast-symbol', tone === 'good' ? 'OK' : tone === 'bad' ? '!' : tone === 'warn' ? '?' : 'i');
    symbol.setAttribute('aria-hidden', 'true');
    var copy = element('span', '', safeString(message, 500));
    var close = element('button', '', 'Close');
    close.type = 'button';
    close.setAttribute('aria-label', 'Dismiss notification');
    close.addEventListener('click', function () { item.remove(); });
    item.append(symbol, copy, close);
    container.prepend(item);
    while (container.children.length > 4) container.lastElementChild.remove();
    window.setTimeout(function () {
      if (item.isConnected) item.remove();
    }, timeout || (tone === 'bad' ? 10_000 : 6_000));
  }

  function ApiError(message, status, code) {
    this.name = 'ApiError';
    this.message = message;
    this.status = status;
    this.code = code || '';
  }
  ApiError.prototype = Object.create(Error.prototype);

  function mutationOutcomeUnknown(error) {
    return Boolean(error && (error.mutationOutcomeUnknown
      || ['NETWORK_ERROR', 'INVALID_RESPONSE', 'INVALID_SETTINGS_RESPONSE'].includes(error.code)));
  }

  function incompleteMutationResponse(message) {
    var error = new ApiError(message, 200, 'INVALID_RESPONSE');
    error.mutationOutcomeUnknown = true;
    return error;
  }

  async function deriveFirstOwnerSetupProof(token) {
    if (!window.crypto || !window.crypto.subtle || typeof TextEncoder !== 'function' || typeof window.btoa !== 'function') {
      token = '';
      throw new ApiError('This browser cannot create the secure first-owner setup proof. Use a current browser over HTTPS.', 0, 'WEB_CRYPTO_UNAVAILABLE');
    }
    var encoder = new TextEncoder();
    var tokenBytes = null;
    var contextBytes = null;
    var signatureBytes = null;
    var signatureBuffer = null;
    var signingKey = null;
    var binarySignature = '';
    try {
      tokenBytes = encoder.encode(token);
      token = '';
      contextBytes = encoder.encode('asa-crosschat:first-owner-setup:v1');
      signingKey = await window.crypto.subtle.importKey(
        'raw', tokenBytes, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign']
      );
      tokenBytes.fill(0);
      signatureBuffer = await window.crypto.subtle.sign('HMAC', signingKey, contextBytes);
      signatureBytes = new Uint8Array(signatureBuffer);
      for (var index = 0; index < signatureBytes.length; index += 1) {
        binarySignature += String.fromCharCode(signatureBytes[index]);
      }
      var proof = window.btoa(binarySignature).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/gu, '');
      binarySignature = '';
      return proof;
    } catch (_) {
      throw new ApiError('The secure first-owner setup proof could not be created. No setup request was sent.', 0, 'SETUP_PROOF_FAILED');
    } finally {
      token = '';
      if (tokenBytes) tokenBytes.fill(0);
      if (contextBytes) contextBytes.fill(0);
      if (signatureBytes) signatureBytes.fill(0);
      binarySignature = '';
      signatureBuffer = null;
      signatureBytes = null;
      tokenBytes = null;
      contextBytes = null;
      signingKey = null;
      encoder = null;
    }
  }

  async function api(path, options) {
    var settings = options || {};
    var headers = new Headers(settings.headers || {});
    headers.set('Accept', 'application/json');
    var method = (settings.method || 'GET').toUpperCase();
    if (method === 'GET' && state.session && state.lastOperatorActivityAt > 0
      && Date.now() - state.lastOperatorActivityAt <= 60_000) {
      headers.set('X-Operator-Activity', '1');
    }
    if (settings.body !== undefined) headers.set('Content-Type', 'application/json');
    if (settings.csrf) {
      if (!state.session || !state.session.csrfToken) throw new ApiError('Your operator session is unavailable. Unlock the console again.', 401, 'NO_SESSION');
      headers.set('X-CSRF-Token', state.session.csrfToken);
    }
    var response;
    try {
      response = await fetch(path, {
        method: method,
        headers: headers,
        body: settings.body === undefined ? undefined : JSON.stringify(settings.body),
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        signal: settings.signal
      });
    } catch (error) {
      if (error && error.name === 'AbortError') throw error;
      throw new ApiError('The operator service could not be reached.', 0, 'NETWORK_ERROR');
    }
    var payload = {};
    var responseJsonParsed = false;
    var contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      try {
        var parsedPayload = await response.json();
        responseJsonParsed = Boolean(parsedPayload && typeof parsedPayload === 'object' && !Array.isArray(parsedPayload));
        payload = responseJsonParsed ? parsedPayload : {};
      }
      catch (error) {
        if (error && error.name === 'AbortError') throw error;
        payload = {};
      }
    }
    if (!response.ok) {
      var message = payload.message || payload.error || ('Request failed with status ' + String(response.status) + '.');
      var errorCode = payload.code || payload.error || '';
      var failure = new ApiError(safeString(message, 420), response.status, errorCode);
      failure.outcome = safeString(payload.outcome, 40);
      failure.operationId = safeString(payload.operationId, 100);
      failure.settingsCommitted = response.headers.get('x-settings-committed') === 'true'
        || errorCode === 'settings_committed_audit_failed';
      failure.tlsTrustUpdateRequired = response.headers.get('x-tls-trust-update-required') === 'true';
      failure.automationTokenDeliveryFailed = response.headers.get('x-automation-token-delivery-failed') === 'true';
      failure.mutationCommitted = response.headers.get('x-mutation-committed') === 'true'
        || ['owner_setup_committed_audit_failed', 'operator_create_committed_audit_failed',
          'operator_update_committed_audit_failed', 'operator_password_reset_committed_audit_failed',
          'password_change_committed_audit_failed', 'automation_token_ack_committed_audit_failed',
          'staff_note_delete_committed_audit_failed'].includes(errorCode);
      failure.temporaryCredentialDeliveryFailed = response.headers.get('x-temporary-credential-delivery-failed') === 'true'
        || ['operator_create_committed_audit_failed', 'operator_password_reset_committed_audit_failed'].includes(errorCode);
      if (response.status === 401 && !settings.ignoreUnauthorized
        && (!errorCode || errorCode === 'authentication_required')) {
        lockConsole('Your operator session ended. Sign in again.', { preserveAutomationTokenRecovery: true });
      }
      throw failure;
    }
    if (!responseJsonParsed) {
      var invalidResponse = new ApiError('The operator service returned an incomplete response.', response.status, 'INVALID_RESPONSE');
      invalidResponse.mutationOutcomeUnknown = method !== 'GET';
      throw invalidResponse;
    }
    return payload;
  }

  function normalizeCapabilities(capabilities) {
    var source = capabilities && typeof capabilities === 'object' ? capabilities : {};
    state.capabilities = source;
    state.actionCapabilities = new Map();
    var actions = source.actions;
    if (Array.isArray(actions)) {
      actions.forEach(function (candidate) {
        if (typeof candidate === 'string') state.actionCapabilities.set(candidate, { name: candidate });
        else if (candidate && typeof (candidate.id || candidate.name) === 'string') {
          var id = candidate.id || candidate.name;
          state.actionCapabilities.set(id, Object.assign({ name: id }, candidate));
        }
      });
    } else if (actions && typeof actions === 'object') {
      Object.keys(actions).forEach(function (name) {
        var value = actions[name];
        state.actionCapabilities.set(name, value && typeof value === 'object' ? Object.assign({ name: name }, value) : { name: name, enabled: value !== false });
      });
    }
  }

  function actionAvailable(name) {
    var capability = state.actionCapabilities.get(name);
    return Boolean(capability && capability.enabled !== false);
  }

  function rawRconEnabled() {
    var capability = state.capabilities.rawRcon;
    return capability === true || Boolean(capability && typeof capability === 'object' && capability.enabled === true);
  }

  function currentRole() {
    return safeString(state.session && state.session.role, 32).toLowerCase();
  }

  function isAdministrator() {
    return currentRole() === 'admin';
  }

  function templates() {
    var source = state.capabilities.templates;
    if (Array.isArray(source)) {
      return source.map(function (value) {
        if (typeof value === 'string') return { value: value, label: value };
        return { value: safeString(value && (value.name || value.value), 100), label: safeString(value && (value.label || value.name || value.value), 100) };
      }).filter(function (item) { return item.value; });
    }
    if (source && typeof source === 'object') {
      return Object.keys(source).map(function (name) { return { value: name, label: name }; });
    }
    return [];
  }

  function configureAuthentication(message) {
    var setup = Boolean(state.setupRequired);
    var setupTokenRequired = setup && state.setupTokenRequired;
    setHidden($('#login-form'), setup);
    setHidden($('#setup-form'), !setup);
    setHidden($('#setup-token-label'), !setupTokenRequired);
    setHidden($('#setup-token'), !setupTokenRequired);
    setHidden($('#setup-token-help'), !setupTokenRequired);
    $('#setup-token').disabled = !setupTokenRequired;
    $('#setup-token').required = setupTokenRequired;
    $('#setup-token').value = '';
    $('#auth-title').textContent = setup ? 'Create server owner' : 'Sign in';
    $('#auth-copy').textContent = message || (setup
      ? setupTokenRequired
        ? 'Create the first Administrator account with the one-time setup token for this server.'
        : 'Create the first Administrator account. This one-time setup closes as soon as the owner is saved.'
      : 'Sign in with your dashboard operator account.');
    showFormError($('#login-error'), '');
    $all('.password-toggle', $('#auth-view')).forEach(function (button) {
      var input = $('#' + button.dataset.passwordTarget);
      if (input) { input.type = 'password'; input.value = ''; }
      button.textContent = 'Show';
      button.setAttribute('aria-pressed', 'false');
      button.setAttribute('aria-label', 'Show password');
    });
    window.setTimeout(function () {
      var input = setup ? $('#setup-username') : $('#login-username');
      if (input) input.focus();
    }, 0);
  }

  function clearSensitiveClientState(options) {
    var settings = options || {};
    clearStaffRecord();
    clearSettingsState({ preserveAutomationTokenRecovery: Boolean(settings.preserveAutomationTokenRecovery) });
    state.session = null;
    state.status = null;
    state.capabilities = {};
    state.actionCapabilities = new Map();
    state.servers = [];
    state.players = [];
    state.actionPlayers = [];
    state.visiblePlayers = [];
    state.activity = [];
    state.activityScope = 'own';
    state.diagnostics = [];
    state.operators = [];
    state.operatorGrantableActions = [];
    state.permissionOperator = null;
    state.selectedPlayer = null;
    state.currentAction = null;
    state.actionDefaults = {};
    state.pendingAction = null;
    state.lastDialogTrigger = null;
    state.consoleActivity = [];
    state.passwordChangeRequired = false;
    state.lastOperatorActivityAt = 0;
    state.lastRefreshAt = 0;
    state.lastPlayerRefreshAt = 0;
    state.lastActivityRefreshAt = 0;
    state.lastDiagnosticRefreshAt = 0;
    $all('input[type="password"]').forEach(function (input) { input.value = ''; });
    var temporaryPassword = $('#temporary-password');
    if (temporaryPassword) { temporaryPassword.value = ''; temporaryPassword.type = 'password'; }
    $('#temporary-password-copy').textContent = 'Share this password securely. The operator must change it at first sign-in.';
    $('#operator-name').textContent = 'Operator';
    $('#operator-role').textContent = 'Role';
    $('#operator-role').className = 'role-badge';
    $('#operator-avatar').textContent = '?';
    $('#nav-operator-count').textContent = '0';
    $('#operator-status').textContent = '';
    var itemKey = $('[data-option="item"]');
    if (itemKey) itemKey.value = '';
    var diagnosticSearch = $('#diagnostic-search');
    if (diagnosticSearch) diagnosticSearch.value = '';
    ['#action-form', '#confirm-form', '#console-form', '#login-form', '#setup-form', '#change-password-form', '#create-operator-form', '#operator-permissions-form'].forEach(function (selector) {
      var form = $(selector);
      if (form) form.reset();
    });
    ['#action-fields', '#player-detail-grid', '#player-actions', '#operation-summary', '#diagnostic-list', '#operator-rows', '#toast-region'].forEach(function (selector) {
      var node = $(selector);
      if (node) node.replaceChildren();
    });
  }

  function stopNetworkActivity() {
    window.clearTimeout(state.pollTimer);
    state.pollTimer = null;
    if (state.bootstrapController) state.bootstrapController.abort();
    if (state.playerController) state.playerController.abort();
    if (state.activityController) state.activityController.abort();
    if (state.diagnosticController) state.diagnosticController.abort();
    if (state.operatorController) state.operatorController.abort();
    if (state.settingsController) state.settingsController.abort();
    if (state.itemController) state.itemController.abort();
    if (state.actionPlayerController) state.actionPlayerController.abort();
    if (state.identifierController) state.identifierController.abort();
    if (state.staffRecordController) state.staffRecordController.abort();
    window.clearTimeout(state.diagnosticSearchTimer);
  }

  function stopPolling() {
    stopNetworkActivity();
    window.clearInterval(state.staleTimer);
    state.staleTimer = null;
  }

  function lockConsole(message, options) {
    stopPolling();
    $all('dialog[open]').forEach(function (dialog) { dialog.close(); });
    clearSensitiveClientState(options);
    setHidden($('#app-shell'), true);
    setHidden($('#auth-view'), false);
    configureAuthentication(message);
  }

  async function establishSession(username, password) {
    var headers = new Headers({ Accept: 'application/json', 'Content-Type': 'application/json' });
    var request = new Request('/admin/api/session', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ username: username, password: password }),
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error'
    });
    username = ''; password = '';
    var response;
    try { response = await fetch(request); }
    catch (_) { throw new ApiError('The operator service could not be reached.', 0, 'NETWORK_ERROR'); }
    var payload = {}; var parsed = false;
    try {
      var sessionPayload = await response.json();
      parsed = Boolean(sessionPayload && typeof sessionPayload === 'object' && !Array.isArray(sessionPayload));
      payload = parsed ? sessionPayload : {};
    }
    catch (error) { if (error && error.name === 'AbortError') throw error; }
    if (!response.ok) {
      throw new ApiError(safeString(payload.message || payload.error || 'The supplied operator credential was rejected.', 420), response.status, payload.code || payload.error);
    }
    if (!parsed || payload.ok !== true) throw incompleteMutationResponse('The sign-in response was incomplete.');
    return payload;
  }

  async function loadInitialBootstrap() {
    var payload = await api('/admin/api/bootstrap', { ignoreUnauthorized: true });
    state.lastRefreshAt = Date.now();
    applyBootstrap(payload);
    setHidden($('#auth-view'), true);
    setHidden($('#app-shell'), false);
    state.pollFailures = 0;
    startPolling();
    activateTab(tabFromHash(), { updateHash: false });
    enforceRequiredPasswordChange();
  }

  async function initAuthentication() {
    showFormError($('#login-error'), '');
    try {
      var mode = await api('/admin/api/auth-mode', { ignoreUnauthorized: true });
      state.remote = Boolean(mode.remote);
      state.authMode = 'credentials';
      state.setupRequired = Boolean(mode.setupRequired);
      state.setupTokenRequired = Boolean(mode.setupTokenRequired);
      if (mode.authenticated === true) {
        try {
          await loadInitialBootstrap();
          return;
        } catch (existingError) {
          if (!existingError || existingError.status !== 401) throw existingError;
        }
      }
      configureAuthentication();
    } catch (error) {
      state.setupRequired = false;
      configureAuthentication('The operator console could not verify its authentication mode.');
      showFormError($('#login-error'), errorMessage(error));
    }
  }

  async function handleLogin(event) {
    event.preventDefault();
    var usernameInput = $('#login-username');
    var passwordInput = $('#login-password');
    var username = usernameInput.value;
    var password = passwordInput.value;
    passwordInput.value = '';
    showFormError($('#login-error'), '');
    var button = $('#login-button');
    setBusy(button, true, 'Unlocking...');
    try {
      await establishSession(username, password);
      username = ''; password = '';
      await loadInitialBootstrap();
      toast('Signed in successfully.', 'good');
    } catch (error) {
      username = ''; password = '';
      if (mutationOutcomeUnknown(error)) {
        await initAuthentication();
        if (state.session) toast('Sign-in succeeded after an incomplete response.', 'good');
        else showFormError($('#login-error'), 'The connection was interrupted. Sign in again if prompted.');
        return;
      }
      showFormError($('#login-error'), errorMessage(error));
      passwordInput.focus();
    } finally {
      setBusy(button, false);
      passwordInput.value = '';
    }
  }

  async function handleSetup(event) {
    event.preventDefault();
    var form = event.currentTarget;
    if (!form.reportValidity()) return;
    var usernameInput = $('#setup-username');
    var setupTokenInput = $('#setup-token');
    var passwordInput = $('#setup-password');
    var confirmationInput = $('#setup-password-confirmation');
    var setupProofRequired = state.setupTokenRequired;
    var setupToken = setupProofRequired ? setupTokenInput.value : '';
    setupTokenInput.value = '';
    if (passwordInput.value !== confirmationInput.value) {
      setupToken = '';
      confirmationInput.setCustomValidity('Passwords do not match.');
      confirmationInput.reportValidity();
      return;
    }
    confirmationInput.setCustomValidity('');
    var username = usernameInput.value;
    var password = passwordInput.value;
    var passwordConfirmation = confirmationInput.value;
    setupTokenInput.value = ''; passwordInput.value = ''; confirmationInput.value = '';
    showFormError($('#login-error'), '');
    var button = $('#setup-button');
    setBusy(button, true, 'Creating owner...');
    var setupProof = '';
    try {
      if (setupProofRequired) {
        var proofRequest = deriveFirstOwnerSetupProof(setupToken);
        setupToken = '';
        setupProof = await proofRequest;
      }
      var setupHeaders = setupProofRequired ? { Authorization: 'Bearer ' + setupProof } : {};
      setupProof = '';
      var setupRequest = api('/admin/api/setup', {
        method: 'POST',
        headers: setupHeaders,
        body: { username: username, password: password, passwordConfirmation: passwordConfirmation },
        ignoreUnauthorized: true
      });
      username = ''; setupToken = ''; setupProof = ''; password = ''; passwordConfirmation = '';
      delete setupHeaders.Authorization;
      var setupResult = await setupRequest;
      if (!setupResult || setupResult.ok !== true) {
        throw incompleteMutationResponse('The owner-creation response was incomplete.');
      }
      state.setupRequired = false;
      form.reset();
      await loadInitialBootstrap();
      toast('Server owner created.', 'good');
    } catch (error) {
      username = ''; setupToken = ''; setupProof = ''; password = ''; passwordConfirmation = '';
      if (error && error.mutationCommitted) {
        form.reset();
        await initAuthentication();
        showFormError($('#login-error'), 'The owner account was created, but audit confirmation failed and no session was delivered. Repair audit log storage, restart the service, then sign in with the owner credentials you chose. Do not repeat setup.');
        return;
      }
      if (error && error.code === 'setup_complete') {
        state.setupRequired = false;
        form.reset();
        configureAuthentication('The server owner already exists. Sign in to continue.');
        return;
      }
      if (mutationOutcomeUnknown(error)) {
        await initAuthentication();
        if (state.session) toast('Server owner creation succeeded after an incomplete response.', 'good');
        else showFormError($('#login-error'), state.setupRequired
          ? 'Owner creation was not confirmed. Retrieve the local setup token again before repeating setup.'
          : 'The owner may have been created. Sign in with the username and password you just chose.');
        return;
      }
      showFormError($('#login-error'), errorMessage(error));
      (setupProofRequired ? setupTokenInput : passwordInput).focus();
    } finally {
      setBusy(button, false);
      setupToken = ''; setupProof = '';
      setupTokenInput.value = ''; passwordInput.value = ''; confirmationInput.value = '';
    }
  }

  async function logout(event) {
    var button = event && event.currentTarget ? event.currentTarget : $('#logout-button');
    setBusy(button, true, 'Signing out...');
    try {
      if (state.session && state.session.csrfToken) {
        await api('/admin/api/session', { method: 'DELETE', csrf: true, body: {}, ignoreUnauthorized: true });
      }
    } catch (_) {
      // Local state is still cleared when the server is unavailable.
    } finally {
      setBusy(button, false);
      lockConsole('You have been signed out.');
    }
  }

  function tabFromHash() {
    var candidate = window.location.hash.replace(/^#/, '').toLowerCase();
    return Object.prototype.hasOwnProperty.call(pageMeta, candidate) ? candidate : 'overview';
  }

  function tabAllowed(name) {
    if (!state.session) return true;
    if (state.passwordChangeRequired) return name === 'overview';
    return !['console', 'diagnostics', 'operators', 'settings'].includes(name) || isAdministrator();
  }

  function activateTab(name, options) {
    var tab = Object.prototype.hasOwnProperty.call(pageMeta, name) ? name : 'overview';
    var allowed = tabAllowed(tab);
    if (!allowed) tab = 'overview';
    if (state.currentTab && state.currentTab !== tab && oneTimeCredentialVisible()) {
      history.replaceState(null, '', '#' + state.currentTab);
      toast('Save the displayed one-time credential and select “I saved it” before leaving this page.', 'warn');
      return false;
    }
    if (state.currentTab === 'settings' && tab !== 'settings' && settingsHasChanges()) {
      if (!allowed || (options && options.discardSettings === true)) {
        clearSettingsState();
      } else if (!window.confirm('Discard the unsaved settings changes on this page?')) {
        history.replaceState(null, '', '#settings');
        return false;
      } else {
        discardSettingsChanges({ quiet: true });
      }
    }
    if (state.currentTab === 'settings' && tab !== 'settings' && state.settingsProjection) clearSettingsState();
    if (state.currentTab !== tab) {
      clearStaffRecord();
      if ($('#result-dialog').open) $('#result-dialog').close();
      if ($('#player-dialog').open) $('#player-dialog').close();
      state.selectedPlayer = null;
    }
    state.currentTab = tab;
    $all('[data-tab]').forEach(function (button) {
      var active = button.dataset.tab === tab;
      button.classList.toggle('active', active);
      if (active) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    });
    $all('[data-panel]').forEach(function (panel) {
      var active = panel.dataset.panel === tab;
      panel.classList.toggle('active', active);
      panel.hidden = !active;
    });
    $('#page-title').textContent = pageMeta[tab][0];
    $('#page-subtitle').textContent = pageMeta[tab][1];
    closeMobileNavigation();
    if (!options || options.updateHash !== false) {
      history.replaceState(null, '', '#' + tab);
    }
    if (tab === 'players') loadPlayers({ quiet: state.players.length > 0 });
    if (tab === 'activity' || tab === 'console') loadActivity({ quiet: state.activity.length > 0 });
    if (tab === 'diagnostics') loadDiagnostics({ quiet: state.diagnostics.length > 0 });
    if (tab === 'operators') loadOperators({ quiet: state.operators.length > 0 });
    if (tab === 'settings' && !state.settingsProjection) loadSettings({ quiet: false });
    if (tab === 'console' && rawRconEnabled()) {
      window.setTimeout(function () { $('#console-command').focus(); }, 0);
    }
    return true;
  }

  function openMobileNavigation() {
    $('#sidebar').classList.add('open');
    $('#menu-button').setAttribute('aria-expanded', 'true');
    setHidden($('#sidebar-scrim'), false);
    var first = $('[data-tab]', $('#sidebar'));
    if (first) first.focus();
  }

  function closeMobileNavigation() {
    $('#sidebar').classList.remove('open');
    $('#menu-button').setAttribute('aria-expanded', 'false');
    setHidden($('#sidebar-scrim'), true);
  }

  function applyBootstrap(payload) {
    var body = payload && typeof payload === 'object' ? payload : {};
    var previousCsrfToken = safeString(state.session && state.session.csrfToken, 200);
    var previousRole = currentRole();
    state.session = body.session && typeof body.session === 'object' ? body.session : state.session;
    var sessionChanged = previousCsrfToken && previousCsrfToken !== safeString(state.session && state.session.csrfToken, 200);
    if (sessionChanged || (previousRole && previousRole !== currentRole())) {
      clearStaffRecord();
      if ($('#result-dialog').open) $('#result-dialog').close();
      state.selectedPlayer = null;
    } else if (!isAdministrator()) {
      clearPlayerIdentifierDisclosure();
    }
    state.status = body.status && typeof body.status === 'object' ? body.status : {};
    normalizeCapabilities(body.capabilities);
    state.passwordChangeRequired = Boolean(state.session && state.session.mustChangePassword);
    state.servers = Array.isArray(state.status.servers) ? state.status.servers.slice() : [];
    renderOperatorIdentity();
    renderRoleAccess();
    renderServerChoices();
    renderStatus();
    renderCapabilities();
  }

  function renderOperatorIdentity() {
    var username = safeString(state.session && state.session.username || 'Operator', 32);
    var role = currentRole();
    var roleLabel = role === 'admin' ? 'Administrator' : role === 'moderator' ? 'Moderator' : 'Operator';
    $('#operator-name').textContent = username;
    $('#operator-role').textContent = roleLabel;
    $('#operator-role').className = 'role-badge role-' + (role || 'unknown');
    var initials = username.split(/[._\s-]+/u).filter(Boolean).slice(0, 2).map(function (part) {
      return Array.from(part)[0] || '';
    }).join('').toUpperCase();
    $('#operator-avatar').textContent = initials || '?';
  }

  function renderRoleAccess() {
    var admin = isAdministrator();
    if (!admin && state.settingsProjection) clearSettingsState();
    $all('[data-admin-only]:not([data-panel])').forEach(function (node) { setHidden(node, !admin); });
    $all('[data-panel][data-admin-only]').forEach(function (panel) {
      setHidden(panel, !admin || panel.dataset.panel !== state.currentTab);
    });
    if (!tabAllowed(state.currentTab)) activateTab('overview', { discardSettings: true });
  }

  function openPasswordDialog(required) {
    var dialog = $('#change-password-dialog');
    var forced = Boolean(required || state.passwordChangeRequired || (state.session && state.session.mustChangePassword));
    dialog.dataset.forced = forced ? 'true' : 'false';
    $('#change-password-copy').textContent = forced
      ? 'Your temporary password must be replaced before you can use the dashboard.'
      : 'Changing your password ends your other dashboard sessions.';
    $all('.close-dialog', dialog).forEach(function (button) { setHidden(button, forced); });
    setHidden($('#forced-password-logout'), !forced);
    showFormError($('#change-password-error'), '');
    $('#change-password-form').reset();
    if (!dialog.open) dialog.showModal();
    window.setTimeout(function () { $('#current-password').focus(); }, 0);
  }

  function enforceRequiredPasswordChange() {
    if (state.passwordChangeRequired && !$('#change-password-dialog').open) openPasswordDialog(true);
  }

  function startPolling() {
    stopPolling();
    state.staleTimer = window.setInterval(updateLiveState, 1_000);
    schedulePoll(POLL_INTERVAL_MS);
  }

  function schedulePoll(delay) {
    window.clearTimeout(state.pollTimer);
    if (document.hidden || !state.session) return;
    state.pollTimer = window.setTimeout(function () { refreshBootstrap({ quiet: true }); }, delay);
  }

  async function refreshBootstrap(options) {
    var settings = options || {};
    if (!state.session) return;
    if (state.bootstrapController) {
      if (!settings.force) return;
      state.bootstrapController.abort();
    }
    var controller = new AbortController();
    state.bootstrapController = controller;
    var button = $('#refresh-button');
    if (!settings.quiet) setBusy(button, true, 'Refreshing');
    try {
      var payload = await api('/admin/api/bootstrap', { signal: controller.signal });
      if (state.bootstrapController !== controller) return;
      state.lastRefreshAt = Date.now();
      applyBootstrap(payload);
      enforceRequiredPasswordChange();
      state.pollFailures = 0;
      if (state.currentTab === 'players' && Date.now() - state.lastPlayerRefreshAt >= PLAYER_REFRESH_MS) loadPlayers({ quiet: true });
      if ((state.currentTab === 'activity' || state.currentTab === 'console') && Date.now() - state.lastActivityRefreshAt >= ACTIVITY_REFRESH_MS) loadActivity({ quiet: true });
      schedulePoll(POLL_INTERVAL_MS);
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      state.pollFailures += 1;
      updateLiveState();
      if (!settings.quiet) toast(errorMessage(error), 'bad');
      schedulePoll(Math.min(MAX_BACKOFF_MS, POLL_INTERVAL_MS * Math.pow(2, Math.min(3, state.pollFailures))));
    } finally {
      if (state.bootstrapController === controller) state.bootstrapController = null;
      if (!settings.quiet) setBusy(button, false);
    }
  }

  function updateLiveState() {
    if (state.session && (state.session.expiresAt || state.session.idleExpiresAt)) {
      var absoluteExpiry = timestamp(state.session.expiresAt);
      var idleExpiry = timestamp(state.session.idleExpiresAt);
      var expiry = absoluteExpiry === null ? idleExpiry : idleExpiry === null ? absoluteExpiry : Math.min(absoluteExpiry, idleExpiry);
      if (expiry !== null && expiry <= Date.now()) {
        lockConsole('Your operator session expired.', { preserveAutomationTokenRecovery: true });
        return;
      }
    }
    var stale = !state.lastRefreshAt || Date.now() - state.lastRefreshAt > STALE_AFTER_MS;
    var ready = Boolean(state.status && state.status.ready);
    var tone = stale ? 'stale' : ready ? 'good' : 'bad';
    var text = stale ? 'Status stale' : ready ? 'Live' : 'Degraded';
    var live = $('#live-state');
    setTone(live, 'live-state', tone);
    $('.status-dot', live).className = 'status-dot ' + tone;
    $('span:last-child', live).textContent = text;
    live.title = state.lastRefreshAt ? 'Last refreshed ' + new Date(state.lastRefreshAt).toLocaleTimeString() : 'No status received';
  }

  function selectedServers() {
    var scope = $('#server-scope').value;
    return scope ? state.servers.filter(function (server) { return String(server.serverId) === scope; }) : state.servers;
  }

  function profileCounts(servers) {
    return servers.reduce(function (result, server) {
      var profile = server.profileImport || {};
      if (profile.enabled !== false && profile.enabled !== undefined) {
        result.enabled += 1;
        result.eligible += numeric(profile.eligiblePlayers !== undefined ? profile.eligiblePlayers : profile.eligible);
        result.verified += numeric(profile.verifiedPlayers !== undefined ? profile.verifiedPlayers : (profile.mappedPlayers !== undefined ? profile.mappedPlayers : profile.mapped));
        var status = safeString(profile.state).toLowerCase();
        if (['degraded', 'error', 'unavailable', 'failed'].includes(status)) result.failed += 1;
      }
      return result;
    }, { enabled: 0, eligible: 0, verified: 0, failed: 0 });
  }

  function setMetric(id, value, note, tone) {
    var card = $('#metric-' + id);
    $('strong', card).textContent = safeString(value, 80);
    $('small', card).textContent = safeString(note, 150);
    setTone(card, 'metric-card', tone);
  }

  function renderStatus() {
    var status = state.status || {};
    var servers = selectedServers();
    var connected = servers.filter(function (server) { return Boolean(server.connected); }).length;
    var players = servers.reduce(function (sum, server) { return sum + numeric(server.playerCount); }, 0);
    var discord = status.discord || {};
    var discordEnabled = discord.enabled !== false;
    var discordReady = !discordEnabled || Boolean(discord.ready);
    var profiles = profileCounts(servers);
    var allMapsOnline = servers.length > 0 && connected === servers.length;

    $('#cluster-kicker').textContent = safeString(status.clusterName || 'BLCKSNAKE Command', 80);
    $('#nav-player-count').textContent = String(players);
    setMetric('maps', connected + ' / ' + servers.length,
      !servers.length ? 'No maps in this scope' : allMapsOnline ? 'Every map is responding' : plural(servers.length - connected, 'map') + ' offline',
      allMapsOnline ? 'good' : connected ? 'warn' : 'bad');
    setMetric('players', String(players), servers.length === state.servers.length ? 'Across the cluster' : 'In selected map scope', players ? 'good' : '');
    setMetric('discord', !discordEnabled ? 'Disabled' : discord.ready ? 'Connected' : discord.started ? 'Starting' : 'Offline',
      discord.user || 'Gateway relay', !discordEnabled ? '' : discord.ready ? 'good' : 'bad');
    var targetingValue = profiles.enabled ? String(profiles.verified) + ' / ' + String(profiles.eligible) : 'Disabled';
    var targetingTone = !profiles.enabled ? '' : profiles.failed || profiles.verified < profiles.eligible ? 'warn' : 'good';
    setMetric('targeting', targetingValue, profiles.enabled ? 'Connected profiles verified' : 'Profile import is not enabled', targetingTone);

    $('#map-summary').textContent = plural(connected, 'map') + ' online with ' + plural(players, 'player') + '.';
    var sidebarTone = status.ready ? 'good' : connected ? 'stale' : 'bad';
    $('#sidebar-dot').className = 'status-dot ' + sidebarTone;
    $('#sidebar-state').textContent = status.ready ? 'Operational' : connected ? 'Partially online' : 'Unavailable';
    $('#sidebar-detail').textContent = connected + '/' + servers.length + ' ' + (servers.length === 1 ? 'map' : 'maps') + ', ' + plural(players, 'player');

    renderAttention(servers, discord, discordEnabled);
    renderRestarts(Array.isArray(status.scheduledRestarts) ? status.scheduledRestarts : []);
    renderMaps(servers);
    updateLiveState();
  }

  function attentionEntry(tone, symbol, title, detail) {
    var item = element('div', 'attention-item ' + tone);
    var icon = element('span', 'attention-symbol', symbol);
    icon.setAttribute('aria-hidden', 'true');
    var copy = element('div', 'attention-copy');
    copy.append(element('strong', '', title), element('span', '', detail));
    item.append(icon, copy);
    return item;
  }

  function renderAttention(servers, discord, discordEnabled) {
    var items = [];
    servers.forEach(function (server) {
      var name = server.serverName || server.serverId || 'Map';
      if (!server.connected) {
        items.push(attentionEntry('bad', '!', name + ' is offline', server.consecutiveFailures ? plural(numeric(server.consecutiveFailures), 'consecutive failure') : 'RCON is not responding'));
      } else if (numeric(server.consecutiveFailures) > 0) {
        items.push(attentionEntry('', '?', name + ' recently failed', plural(numeric(server.consecutiveFailures), 'consecutive failure')));
      }
      var refreshed = timestamp(server.lastPlayerRefreshAt);
      if (server.connected && refreshed !== null && Date.now() - refreshed > 120_000) {
        items.push(attentionEntry('', '?', name + ' player list is stale', 'Last refreshed ' + formatAge(refreshed)));
      }
      var profile = server.profileImport || {};
      var profileState = safeString(profile.state).toLowerCase();
      if (profile.enabled && ['degraded', 'error', 'unavailable', 'failed'].includes(profileState)) {
        items.push(attentionEntry('', '?', name + ' profile import needs attention',
          profile.lastErrorCode ? 'Error code ' + safeString(profile.lastErrorCode, 80) : 'Automatic grant targeting is degraded'));
      } else if (profile.enabled && numeric(profile.verifiedPlayers) < numeric(profile.eligiblePlayers)) {
        items.push(attentionEntry('', '?', name + ' has unverified targeting',
          numeric(profile.verifiedPlayers) + '/' + numeric(profile.eligiblePlayers) + ' connected profiles verified'));
      }
    });
    if (discordEnabled && !discord.ready) items.push(attentionEntry('bad', '!', 'Discord relay is offline', 'Map-to-map relay may continue independently.'));
    if (!items.length) items.push(attentionEntry('good', 'OK', 'No active operational warnings', 'All services in the selected scope look healthy.'));
    $('#attention-count').textContent = String(items[0].classList.contains('good') ? 0 : items.length);
    $('#attention-list').replaceChildren.apply($('#attention-list'), items);
  }

  function renderRestarts(restarts) {
    var scope = $('#server-scope').value;
    var items = restarts.filter(function (restart) { return !scope || String(restart.serverId) === scope; });
    var container = $('#restart-list');
    if (!items.length) {
      var empty = element('div', 'empty-copy', 'No scheduled restart windows in this scope.');
      container.replaceChildren(empty);
      return;
    }
    var nodes = items.sort(function (a, b) { return numeric(a.deadline) - numeric(b.deadline); }).map(function (restart) {
      var server = state.servers.find(function (candidate) { return String(candidate.serverId) === String(restart.serverId); });
      var item = element('div', 'restart-item');
      var icon = element('span', 'attention-symbol', 'T');
      icon.setAttribute('aria-hidden', 'true');
      var copy = element('div', 'restart-copy');
      copy.append(
        element('strong', '', (server && server.serverName) || restart.serverId || 'Map'),
        element('span', '', formatAge(restart.deadline) + (restart.reason ? ' - ' + safeString(restart.reason, 100) : ''))
      );
      var cancel = element('button', 'small-button', 'Cancel');
      cancel.type = 'button';
      cancel.dataset.openAction = 'cancel-restart';
      cancel.dataset.server = safeString(restart.serverId, 100);
      if (!actionAvailable('cancel-restart')) cancel.disabled = true;
      item.append(icon, copy, cancel);
      return item;
    });
    container.replaceChildren.apply(container, nodes);
  }

  function latencyTone(value) {
    if (value === undefined || value === null) return 'unknown';
    var latency = numeric(value);
    if (latency > 1_000) return 'high';
    if (latency > 500) return 'medium';
    return '';
  }

  function latencyText(value) {
    if (value === undefined || value === null) return '--';
    var latency = numeric(value);
    return latency >= 1_000 ? (latency / 1_000).toFixed(1) + ' s' : Math.round(latency) + ' ms';
  }

  function mapRow(label, value) {
    var row = element('div', 'map-row');
    row.append(element('span', '', label), element('span', '', value));
    return row;
  }

  function renderMaps(servers) {
    var grid = $('#map-grid');
    if (!servers.length) {
      grid.replaceChildren(element('div', 'surface empty-copy', 'No map servers are configured in this scope.'));
      return;
    }
    var nodes = servers.map(function (server) {
      var card = element('article', 'map-card surface ' + (server.connected ? '' : 'offline'));
      var head = element('div', 'map-card-head');
      var title = element('div', 'map-title');
      title.append(element('h3', '', server.serverName || server.serverId || 'Map'), element('span', '', server.serverId || 'configured map'));
      head.append(title, element('span', 'state-badge ' + (server.connected ? 'good' : 'bad'), server.connected ? 'Online' : 'Offline'));

      var stat = element('div', 'map-player-stat');
      var playerCount = element('div');
      var connectedPlayers = numeric(server.playerCount);
      playerCount.append(
        element('strong', '', String(connectedPlayers)),
        element('span', '', connectedPlayers === 1 ? 'player connected' : 'players connected')
      );
      var latency = element('div', 'map-latency');
      latency.append(element('span', '', 'RCON ' + latencyText(server.lastLatencyMs)));
      var track = element('div', 'latency-track ' + latencyTone(server.lastLatencyMs));
      track.append(element('span'));
      latency.append(track);
      stat.append(playerCount, latency);

      var rows = element('div', 'map-rows');
      rows.append(
        mapRow('Polling', server.polling ? 'Active' : 'Stopped'),
        mapRow('Last successful command', formatAge(server.lastSuccessAt)),
        mapRow('Players refreshed', formatAge(server.lastPlayerRefreshAt))
      );
      var profile = server.profileImport || {};
      rows.append(mapRow('Profile targeting', profile.enabled === false || profile.enabled === undefined
        ? 'Disabled'
        : numeric(profile.verifiedPlayers) + '/' + numeric(profile.eligiblePlayers) + ' verified'));

      var playerList = element('div', 'map-players');
      var players = Array.isArray(server.players) ? server.players : [];
      if (!players.length) {
        playerList.append(element('span', 'secondary-value', 'No connected players'));
      } else {
        players.slice(0, 8).forEach(function (player) {
          playerList.append(element('span', 'player-chip', player && player.name ? player.name : 'Connected player'));
        });
        if (players.length > 8) playerList.append(element('span', 'player-chip', '+' + (players.length - 8) + ' more'));
      }

      var actions = element('div', 'map-actions');
      [['announce', 'Announce'], ['save-world', 'Save'], ['restart', 'Restart']].forEach(function (entry) {
        var button = element('button', '', entry[1]);
        button.type = 'button';
        button.dataset.openAction = entry[0];
        button.dataset.server = safeString(server.serverId, 100);
        button.disabled = !actionAvailable(entry[0]);
        actions.append(button);
      });
      card.append(head, stat, rows, playerList, actions);
      return card;
    });
    grid.replaceChildren.apply(grid, nodes);
  }

  function renderServerChoices() {
    var scope = $('#server-scope');
    var previous = scope.value;
    var scopeOptions = [new Option('Entire cluster', '')];
    state.servers.forEach(function (server) {
      scopeOptions.push(new Option(safeString(server.serverName || server.serverId, 100), safeString(server.serverId, 100)));
    });
    scope.replaceChildren.apply(scope, scopeOptions);
    scope.value = state.servers.some(function (server) { return String(server.serverId) === previous; }) ? previous : '';
    populateServerSelect($('#console-server'), { required: true, cluster: false });
    refreshActionServerSelects();
  }

  function populateServerSelect(select, settings) {
    if (!select) return;
    var previous = select.value;
    var options = [];
    if (settings.cluster) options.push(new Option('Entire cluster', ''));
    else if (!settings.required) options.push(new Option('Choose a map', ''));
    state.servers.forEach(function (server) {
      options.push(new Option(safeString(server.serverName || server.serverId, 100), safeString(server.serverId, 100)));
    });
    select.replaceChildren.apply(select, options);
    var preferred = previous || (settings.defaultValue !== undefined ? String(settings.defaultValue) : '') || $('#server-scope').value;
    if (Array.from(select.options).some(function (option) { return option.value === preferred; })) select.value = preferred;
  }

  function refreshActionServerSelects() {
    $all('select[data-field-type="server"]').forEach(function (select) {
      populateServerSelect(select, {
        required: select.required,
        cluster: select.dataset.cluster === 'true',
        defaultValue: state.actionDefaults.server
      });
    });
  }

  function renderCapabilities() {
    $all('[data-open-action]').forEach(function (button) {
      var available = actionAvailable(button.dataset.openAction);
      if (button.dataset.openAction === 'rcon') available = available && rawRconEnabled();
      button.disabled = !available;
      button.classList.toggle('unavailable', !available);
      if (!available) button.title = 'This operation is not available to the current operator.';
      else button.removeAttribute('title');
    });
    var rawEnabled = rawRconEnabled() && actionAvailable('rcon');
    setHidden($('#console-lock'), rawEnabled);
    setHidden($('#console-form'), !rawEnabled);
    populateServerSelect($('#console-server'), { required: true, cluster: false });
    var commandInput = $('#console-command');
    var rawCapability = state.capabilities.rawRcon;
    var verbs = rawCapability && typeof rawCapability === 'object' && Array.isArray(rawCapability.verbs)
      ? rawCapability.verbs.filter(function (verb) { return typeof verb === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(verb); })
      : [];
    var dataList = $('#rcon-verbs');
    if (!dataList) {
      dataList = document.createElement('datalist');
      dataList.id = 'rcon-verbs';
      $('#console-form').append(dataList);
    }
    dataList.replaceChildren.apply(dataList, verbs.map(function (verb) { return new Option(verb); }));
    if (verbs.length) {
      commandInput.setAttribute('list', 'rcon-verbs');
      commandInput.placeholder = 'Choose an allowlisted verb or add validated arguments';
    } else {
      commandInput.removeAttribute('list');
      commandInput.placeholder = 'Enter one configured allowlisted command';
    }
  }

  function targetState(value) {
    var normalized = safeString(value).toLowerCase();
    if (normalized.includes('ready') || normalized.includes('verified')) return { key: 'ready', tone: 'good', text: value || 'Ready' };
    if (normalized === 'not-required') return { key: 'neutral', tone: '', text: 'Protected selection' };
    if (normalized.includes('fail') || normalized.includes('unavailable') || normalized.includes('error') || normalized.includes('eos-unavailable')) return { key: 'failed', tone: 'bad', text: value || 'Unavailable' };
    return { key: 'needed', tone: 'warn', text: value || 'Setup needed' };
  }

  async function loadPlayers(options) {
    if (!state.session) return false;
    var settings = options || {};
    if (settings.quiet && (($('#player-dialog') && $('#player-dialog').open) || ($('#result-dialog') && $('#result-dialog').open))) return false;
    clearPlayerIdentifierDisclosure();
    if (state.playerController) state.playerController.abort();
    var controller = new AbortController();
    state.playerController = controller;
    var query = $('#player-search') ? $('#player-search').value.trim() : '';
    var purpose = settings.purpose || 'player';
    var params = new URLSearchParams();
    if (query) params.set('q', query.slice(0, 100));
    if (purpose) params.set('purpose', purpose.slice(0, 60));
    if (!settings.quiet) $('#player-summary').textContent = 'Loading players...';
    try {
      var result = await api('/admin/api/players?' + params.toString(), { signal: controller.signal });
      if (state.playerController !== controller) return;
      state.players = Array.isArray(result.players) ? result.players.filter(function (player) {
        return player && typeof player.selection === 'string' && player.selection;
      }) : [];
      state.lastPlayerRefreshAt = Date.now();
      renderPlayers();
      return true;
    } catch (error) {
      if (error && error.name === 'AbortError') return false;
      if (!settings.quiet) {
        $('#player-summary').textContent = 'Unable to load players';
        toast(errorMessage(error), 'bad');
      }
      return false;
    } finally {
      if (state.playerController === controller) state.playerController = null;
    }
  }

  function filteredPlayers() {
    var scope = $('#server-scope').value;
    var query = ($('#player-search') && $('#player-search').value || '').trim().toLowerCase();
    var readiness = $('#player-state-filter') ? $('#player-state-filter').value : '';
    return state.players.filter(function (player) {
      if (scope && String(player.serverId) !== scope) return false;
      var target = targetState(player.targeting);
      if (readiness && target.key !== readiness) return false;
      if (!query) return true;
      return [player.name, player.survivorName, player.serverName, player.serverId, player.targeting]
        .some(function (value) { return safeString(value).toLowerCase().includes(query); });
    });
  }

  function relayAccessLabel(player) {
    var muted = timestamp(player.mutedUntil);
    if (muted !== null && muted > Date.now()) return { text: 'Muted until ' + formatDate(muted), tone: 'bad' };
    return { text: 'Allowed', tone: 'good' };
  }

  function renderPlayers() {
    var rows = $('#player-rows');
    if (!rows) return;
    state.visiblePlayers = filteredPlayers();
    var nodes = state.visiblePlayers.map(function (player, index) {
      var row = document.createElement('tr');
      var identityCell = document.createElement('td');
      identityCell.dataset.label = 'Player';
      var identity = element('div', 'player-name');
      identity.append(element('strong', '', player.survivorName || player.name || 'Connected player'));
      if (player.survivorName && player.name && player.survivorName !== player.name) identity.append(element('span', '', player.name));
      identityCell.append(identity);

      var serverCell = element('td', '', player.serverName || player.serverId || '--');
      serverCell.dataset.label = 'Map';
      var targeting = targetState(player.targeting);
      var targetingCell = document.createElement('td');
      targetingCell.dataset.label = 'Targeting';
      targetingCell.append(element('span', 'target-badge ' + targeting.tone, targeting.text));
      var relay = relayAccessLabel(player);
      var relayCell = document.createElement('td');
      relayCell.dataset.label = 'Relay';
      relayCell.append(element('span', 'target-badge ' + relay.tone, relay.text));
      var playtimeCell = element('td', '', player.playtimeSeconds === undefined || player.playtimeSeconds === null ? '--' : formatDuration(player.playtimeSeconds));
      playtimeCell.dataset.label = 'Playtime';
      var actionsCell = document.createElement('td');
      actionsCell.dataset.label = 'Actions';
      var actions = element('div', 'row-actions');
      var manage = element('button', 'small-button', 'Manage');
      manage.type = 'button';
      manage.dataset.playerIndex = String(index);
      actions.append(manage);
      actionsCell.append(actions);
      row.append(identityCell, serverCell, targetingCell, relayCell, playtimeCell, actionsCell);
      return row;
    });
    rows.replaceChildren.apply(rows, nodes);
    setHidden($('#player-empty'), nodes.length > 0);
    $('#player-summary').textContent = plural(nodes.length, 'player') + (state.players.length !== nodes.length ? ' shown' : ' connected');
  }

  function refreshPlayerSelects() {
    $all('select[data-field-type="player"]').forEach(function (select) {
      var previous = select.value || state.actionDefaults.player || '';
      var options = [new Option(state.actionPlayers.length ? 'Choose a connected player' : 'Loading connected players...', '')];
      state.actionPlayers.forEach(function (player) {
        var display = player.survivorName && player.name && player.survivorName !== player.name
          ? player.survivorName + ' / ' + player.name
          : player.survivorName || player.name || 'Connected player';
        var target = targetState(player.targeting);
        options.push(new Option(safeString(display + ' - ' + (player.serverName || player.serverId) + ' - ' + target.text, 180), player.selection));
      });
      select.replaceChildren.apply(select, options);
      if (state.actionPlayers.some(function (player) { return player.selection === previous; })) select.value = previous;
    });
  }

  function sameVisiblePlayer(candidate, context) {
    if (!candidate || !context || String(candidate.serverId) !== String(context.serverId)) return false;
    var candidateName = safeString(candidate.name).trim().toLowerCase();
    var contextName = safeString(context.name).trim().toLowerCase();
    if (candidateName && contextName) return candidateName === contextName;
    var candidateSurvivor = safeString(candidate.survivorName).trim().toLowerCase();
    var contextSurvivor = safeString(context.survivorName).trim().toLowerCase();
    return Boolean(candidateSurvivor && contextSurvivor && candidateSurvivor === contextSurvivor);
  }

  async function loadActionPlayers(action, context) {
    if (state.actionPlayerController) state.actionPlayerController.abort();
    var controller = new AbortController();
    state.actionPlayerController = controller;
    state.actionPlayers = [];
    state.actionDefaults.player = '';
    refreshPlayerSelects();
    var params = new URLSearchParams({ purpose: action });
    if (context) {
      var exactName = safeString(context.name || context.survivorName, 100).trim();
      if (exactName) params.set('q', exactName);
    }
    try {
      var result = await api('/admin/api/players?' + params.toString(), { signal: controller.signal });
      if (state.actionPlayerController !== controller || state.currentAction !== action) return;
      var candidates = Array.isArray(result.players) ? result.players.filter(function (player) {
        return player && typeof player.selection === 'string' && player.selection;
      }) : [];
      if (context) {
        candidates = candidates.filter(function (player) { return sameVisiblePlayer(player, context); });
        if (candidates.length !== 1) {
          throw new ApiError('That player changed maps, disconnected, or could not be matched exactly. Refresh the player list and choose them again.', 409, 'PLAYER_CHANGED');
        }
      }
      state.actionPlayers = candidates;
      state.actionDefaults.player = context && candidates.length === 1 ? candidates[0].selection : '';
      refreshPlayerSelects();
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      state.actionPlayers = [];
      state.actionDefaults.player = '';
      refreshPlayerSelects();
      showFormError($('#action-dialog').querySelector('.form-error'), errorMessage(error));
    } finally {
      if (state.actionPlayerController === controller) state.actionPlayerController = null;
    }
  }

  function showPlayerDialog(player) {
    if (!player) return;
    clearPlayerIdentifierDisclosure();
    state.selectedPlayer = player;
    state.lastDialogTrigger = document.activeElement;
    $('#player-dialog-title').textContent = safeString(player.survivorName || player.name || 'Connected player', 120);
    $('#player-dialog').querySelector('.dialog-header p:last-child').textContent =
      safeString((player.name && player.survivorName && player.name !== player.survivorName ? player.name + ' - ' : '') + (player.serverName || player.serverId || 'Current map'), 180);
    var target = targetState(player.targeting);
    var relay = relayAccessLabel(player);
    var details = [
      ['Map', player.serverName || player.serverId || '--'],
      ['Targeting', target.text],
      ['Discord link', player.linked === true ? 'Linked' : player.linked === false ? 'Not linked' : '--'],
      ['Cluster Chat access', relay.text],
      ['Playtime', player.playtimeSeconds === undefined || player.playtimeSeconds === null ? '--' : formatDuration(player.playtimeSeconds)],
      ['Staff notes', plural(numeric(player.notesCount), 'note')]
    ].map(function (entry) {
      var card = element('div', 'detail-card');
      card.append(element('span', '', entry[0]), element('strong', '', entry[1]));
      return card;
    });
    $('#player-dialog').querySelector('.player-detail-grid').replaceChildren.apply($('#player-dialog').querySelector('.player-detail-grid'), details);
    renderPlayerActions(player);
    $('#player-dialog').showModal();
  }

  function playerInitials(record) {
    var source = safeString(record && (record.survivorName || record.name), 120).trim();
    var initials = source.split(/[._\s-]+/u).filter(Boolean).slice(0, 2).map(function (part) {
      return Array.from(part)[0] || '';
    }).join('').toUpperCase();
    return initials || 'PL';
  }

  function staffStatusCard(glyph, label, value, tone) {
    var card = element('div', 'staff-record-status-card' + (tone ? ' ' + tone : ''));
    var mark = element('span', 'staff-record-status-glyph', glyph);
    mark.setAttribute('aria-hidden', 'true');
    var copy = element('div', 'staff-record-status-copy');
    copy.append(element('span', '', label), element('strong', '', value));
    card.append(mark, copy);
    return card;
  }

  function clearStaffRecord() {
    state.staffRecordGeneration += 1;
    if (state.staffRecordController) state.staffRecordController.abort();
    state.staffRecordController = null;
    clearPlayerIdentifierDisclosure();
    setHidden($('#staff-record-loading'), true);
    setHidden($('#result-details'), true);
    showFormError($('#staff-record-error'), '');
    $('#staff-record-status').replaceChildren();
    $('#staff-record-notes').replaceChildren();
    $('#staff-record-avatar').textContent = '--';
    $('#staff-record-player-name').textContent = 'Connected player';
    $('#staff-record-account-name').textContent = 'Account name unavailable';
    $('#staff-record-map').textContent = 'Current map';
    $('#staff-record-note-count').textContent = '0';
    $('#staff-record-freshness').textContent = 'Checked now';
    $('#result-dialog-title').textContent = 'Player staff record';
    $('#staff-record-subtitle').textContent = 'Loading the current connected-player record...';
  }

  function renderStaffRecord(record) {
    var source = record && typeof record === 'object' ? record : {};
    var survivorName = safeString(source.survivorName || source.name || 'Connected player', 120).trim() || 'Connected player';
    var accountName = safeString(source.name, 120).trim();
    var mapName = safeString(source.serverName || source.serverId || 'Current map', 120).trim() || 'Current map';
    var targeting = targetState(source.targeting);
    var linked = source.linked === true;
    var discordDisplayName = safeString(source.discordDisplayName, 100).trim();
    var muteUntil = timestamp(source.mutedUntil);
    var muted = muteUntil !== null && muteUntil > Date.now();
    var playtime = source.playtimeSeconds === undefined || source.playtimeSeconds === null
      ? '--'
      : formatDuration(source.playtimeSeconds);
    var noteTotal = Math.max(0, Math.floor(numeric(source.notesCount)));
    var notes = Array.isArray(source.notes) ? source.notes.slice(0, 10) : [];

    $('#result-dialog-title').textContent = survivorName;
    $('#staff-record-subtitle').textContent = 'Current staff record for ' + mapName + '.';
    $('#staff-record-avatar').textContent = playerInitials(source);
    $('#staff-record-player-name').textContent = survivorName;
    $('#staff-record-account-name').textContent = accountName && accountName !== survivorName
      ? 'Account name: ' + accountName
      : 'Connected account';
    $('#staff-record-map').textContent = mapName;
    $('#staff-record-freshness').textContent = 'Checked ' + formatTime(Date.now());
    $('#staff-record-note-count').textContent = String(noteTotal);

    var statusCards = [
      staffStatusCard('TG', 'Admin targeting', targeting.text, targeting.tone),
      staffStatusCard('DC', 'Discord link', linked ? (discordDisplayName ? 'Linked as ' + discordDisplayName : 'Linked') : 'Not linked', linked ? 'good' : ''),
      staffStatusCard('RL', 'Cluster Chat access', muted ? 'Muted until ' + formatDate(muteUntil) : 'Allowed', muted ? 'warn' : 'good'),
      staffStatusCard('PT', 'Total playtime', playtime, '')
    ];
    $('#staff-record-status').replaceChildren.apply($('#staff-record-status'), statusCards);

    var noteNodes = notes.map(function (note) {
      var entry = note && typeof note === 'object' ? note : {};
      var item = element('article', 'staff-note-item');
      var noteType = safeString(entry.type || 'note', 24).toLowerCase();
      var typeLabels = { note: 'Note', warning: 'Warning', incident: 'Incident', positive: 'Positive', mute: 'Relay mute', unmute: 'Relay unmute', kick: 'Kick', ban: 'Ban' };
      item.append(element('span', 'staff-note-type staff-note-type-' + noteType, typeLabels[noteType] || 'Note'));
      item.append(element('p', 'staff-note-copy', safeString(entry.text || 'Note details unavailable.', 1_000)));
      var meta = element('div', 'staff-note-meta');
      var rawActor = safeString(entry.actor || '', 64);
      var actorLabel = rawActor === 'http:dashboard'
        ? 'Dashboard operator (legacy entry)' : rawActor.startsWith('discord:')
          ? 'Discord · ' + rawActor.slice(8) : rawActor || 'Staff member';
      meta.append(
        element('span', '', actorLabel),
        element('time', '', timestamp(entry.at) === null ? 'Time unavailable' : formatDate(entry.at))
      );
      if (timestamp(entry.at) !== null) $('time', meta).dateTime = new Date(timestamp(entry.at)).toISOString();
      if (isAdministrator() && /^mn_[A-Za-z0-9_-]{22}$/u.test(entry.id || '')) {
        var remove = element('button', 'danger-quiet-button staff-note-delete', 'Delete');
        remove.type = 'button';
        remove.addEventListener('click', function () { deleteStaffNote(entry, remove); });
        meta.append(remove);
      }
      item.append(meta);
      return item;
    });
    if (!noteNodes.length) {
      noteNodes.push(element('div', 'staff-note-empty', noteTotal
        ? 'No recent note details are available in this view.'
        : 'No staff notes have been added for this player.'));
    } else if (noteTotal > noteNodes.length) {
      noteNodes.push(element('div', 'staff-note-empty', 'Showing the latest ' + String(noteNodes.length) + ' of ' + String(noteTotal) + ' notes.'));
    }
    $('#staff-record-notes').replaceChildren.apply($('#staff-record-notes'), noteNodes);

    var admin = isAdministrator();
    setHidden($('#player-identifiers-section'), !admin);
    $('.staff-record-columns', $('#result-dialog')).classList.toggle('moderator-view', !admin);
    setHidden($('#staff-record-loading'), true);
    setHidden($('#result-details'), false);
  }

  async function deleteStaffNote(note, button) {
    var player = state.selectedPlayer;
    if (!player || !window.confirm('Delete this moderation note? This cannot be undone.')) return;
    setBusy(button, true, 'Deleting...');
    try {
      var result = await api('/admin/api/players/notes', {
        method: 'DELETE', csrf: true, body: { player: player.selection, note: note.id }
      });
      if (!result || result.ok !== true) throw incompleteMutationResponse('The note-deletion response was incomplete.');
      toast('Moderation note deleted.', 'good');
      await showStaffRecord(player, null);
    } catch (error) {
      toast(errorMessage(error), mutationOutcomeUnknown(error) ? 'warn' : 'bad', 10_000);
      setBusy(button, false);
    }
  }

  async function showStaffRecord(player, trigger) {
    if (!player || typeof player.selection !== 'string' || !player.selection) {
      toast('This player selection expired. Refresh the player list and choose them again.', 'warn');
      return;
    }
    if (!actionAvailable('player')) {
      toast('Player staff records are not available to the current operator.', 'warn');
      return;
    }
    var returnTrigger = $('#player-dialog').open && state.lastDialogTrigger && state.lastDialogTrigger.isConnected
      ? state.lastDialogTrigger
      : trigger || document.activeElement;
    clearStaffRecord();
    state.selectedPlayer = player;
    state.lastDialogTrigger = returnTrigger;
    if ($('#player-dialog').open) $('#player-dialog').close();
    if ($('#action-dialog').open) $('#action-dialog').close();
    state.currentAction = null;
    state.actionPlayers = [];
    state.actionDefaults = {};
    setHidden($('#staff-record-loading'), false);
    setHidden($('#result-details'), true);
    $('#result-dialog-title').textContent = safeString(player.survivorName || player.name || 'Player staff record', 120);
    $('#staff-record-subtitle').textContent = 'Loading the current connected-player record...';
    var dialog = $('#result-dialog');
    if (!dialog.open) dialog.showModal();
    var initialClose = $('.close-dialog', dialog);
    if (initialClose) initialClose.focus();
    var controller = new AbortController();
    var generation = state.staffRecordGeneration;
    var sessionToken = safeString(state.session && state.session.csrfToken, 200);
    state.staffRecordController = controller;
    try {
      var result = await api('/admin/api/players/record', {
        method: 'POST', csrf: true, signal: controller.signal, body: { player: player.selection }
      });
      if (state.staffRecordController !== controller || generation !== state.staffRecordGeneration
        || !dialog.open || !state.session || safeString(state.session.csrfToken, 200) !== sessionToken
        || !state.selectedPlayer || state.selectedPlayer.selection !== player.selection) return;
      state.staffRecordController = null;
      renderStaffRecord(result && result.record);
      var close = $('.close-dialog', dialog);
      if (close) close.focus();
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      if (state.staffRecordController !== controller || generation !== state.staffRecordGeneration) return;
      state.staffRecordController = null;
      setHidden($('#staff-record-loading'), true);
      showFormError($('#staff-record-error'), errorMessage(error, 'The player staff record could not be loaded.'));
    } finally {
      if (state.staffRecordController === controller) state.staffRecordController = null;
    }
  }

  function clearPlayerIdentifierDisclosure(message) {
    state.identifierDisclosureGeneration += 1;
    if (state.identifierController) state.identifierController.abort();
    state.identifierController = null;
    window.clearTimeout(state.identifierClearTimer);
    state.identifierClearTimer = null;
    var values = $('#player-identifiers');
    if (values) {
      values.replaceChildren();
      values.hidden = true;
    }
    var reveal = $('#reveal-player-identifiers');
    if (reveal) {
      setBusy(reveal, false);
      reveal.textContent = 'Reveal identifiers';
      reveal.setAttribute('aria-expanded', 'false');
    }
    setHidden($('#hide-player-identifiers'), true);
    showFormError($('#player-identifiers-error'), '');
    var status = $('#player-identifiers-status');
    if (status) status.textContent = safeString(message || '', 180);
  }

  function renderPlayerIdentifiers(identifiers) {
    var source = identifiers && typeof identifiers === 'object' ? identifiers : {};
    var values = [
      ['EOS Product User ID', source.eosProductUserId],
      ['ASA PlayerDataID', source.playerDataId]
    ].map(function (entry) {
      var wrapper = element('div', 'identifier-row');
      var term = element('dt', '', entry[0]);
      var rawValue = typeof entry[1] === 'string' || typeof entry[1] === 'number' ? safeString(entry[1], 160).trim() : '';
      var value = element('dd');
      var code = element('code', rawValue ? '' : 'identifier-unavailable', rawValue || 'Unavailable');
      code.dir = 'ltr';
      value.append(code);
      wrapper.append(term, value);
      return wrapper;
    });
    var list = $('#player-identifiers');
    list.replaceChildren.apply(list, values);
    list.hidden = false;
    $('#reveal-player-identifiers').setAttribute('aria-expanded', 'true');
    setHidden($('#hide-player-identifiers'), false);
    $('#player-identifiers-status').textContent = 'Identifiers visible for 60 seconds.';
    state.identifierClearTimer = window.setTimeout(function () {
      clearPlayerIdentifierDisclosure('Identifiers hidden.');
    }, 60_000);
  }

  async function revealPlayerIdentifiers(event) {
    var button = event.currentTarget;
    clearPlayerIdentifierDisclosure();
    if (!isAdministrator()) {
      showFormError($('#player-identifiers-error'), 'Administrator access is required.');
      return;
    }
    var player = state.selectedPlayer;
    if (!player || typeof player.selection !== 'string' || !player.selection) {
      showFormError($('#player-identifiers-error'), 'This player selection expired. Refresh the player list and choose them again.');
      return;
    }
    var controller = new AbortController();
    var generation = state.identifierDisclosureGeneration;
    state.identifierController = controller;
    setBusy(button, true, 'Revealing...');
    try {
      var result = await api('/admin/api/players/identifiers', {
        method: 'POST', csrf: true, signal: controller.signal, body: { player: player.selection }
      });
      if (state.identifierController !== controller || generation !== state.identifierDisclosureGeneration
        || !state.selectedPlayer || state.selectedPlayer.selection !== player.selection
        || !$('#result-dialog').open || $('#result-details').hidden || !isAdministrator()) return;
      state.identifierController = null;
      renderPlayerIdentifiers(result.identifiers);
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      if (state.identifierController !== controller || generation !== state.identifierDisclosureGeneration) return;
      state.identifierController = null;
      showFormError($('#player-identifiers-error'), errorMessage(error, 'The protected identifiers could not be revealed.'));
    } finally {
      if (state.identifierController === controller) state.identifierController = null;
      if (generation === state.identifierDisclosureGeneration) setBusy(button, false);
    }
  }

  function renderPlayerActions(player) {
    var actions = [
      ['player', 'Staff record', 'Status, notes, and protected data', 'SR'],
      ['give-item', 'Give item', 'Catalog item or blueprint', 'IT'],
      ['give-xp', 'Give XP', 'Grant bounded experience', 'XP'],
      ['refresh-player-id', 'Verify targeting', 'Refresh numeric targeting', 'TG'],
      ['warn', 'Warn', 'Send a private staff warning', 'WN'],
      ['note', 'Add note', 'Save moderation context', 'NT'],
      [timestamp(player.mutedUntil) && timestamp(player.mutedUntil) > Date.now() ? 'unmute-player' : 'mute-player',
        timestamp(player.mutedUntil) && timestamp(player.mutedUntil) > Date.now() ? 'Unmute relay' : 'Mute relay', 'Change Cluster Chat access', 'RL'],
      ['whitelist', 'Add no-check', 'Allow join-list bypass', 'AL'],
      ['unwhitelist', 'Remove no-check', 'Remove join-list bypass', 'RM'],
      ['kick', 'Kick', 'Disconnect from this map', 'KK'],
      ['ban', 'Ban', 'Block this account', 'BN']
    ];
    var nodes = actions.map(function (entry) {
      var button = element('button', 'action-card player-action-card' + (['ban'].includes(entry[0]) ? ' danger-card' : ''));
      button.type = 'button';
      if (entry[0] === 'player') button.dataset.openStaffRecord = 'true';
      else button.dataset.openAction = entry[0];
      button.dataset.player = player.selection;
      button.dataset.server = safeString(player.serverId, 100);
      button.disabled = !actionAvailable(entry[0]);
      var glyph = element('span', 'player-action-glyph', entry[3]);
      glyph.setAttribute('aria-hidden', 'true');
      var copy = element('span', 'player-action-copy');
      copy.append(element('strong', '', entry[1]), element('span', '', entry[2]));
      button.append(glyph, copy);
      return button;
    });
    $('#player-dialog').querySelector('.drawer-actions').replaceChildren.apply($('#player-dialog').querySelector('.drawer-actions'), nodes);
  }

  async function loadActivity(options) {
    if (!state.session) return;
    var settings = options || {};
    if (state.activityController) state.activityController.abort();
    var controller = new AbortController();
    state.activityController = controller;
    if (!settings.quiet && $('#activity-summary')) $('#activity-summary').textContent = 'Loading activity...';
    try {
      var result = await api('/admin/api/activity', { signal: controller.signal });
      if (state.activityController !== controller) return;
      state.activity = Array.isArray(result.activity) ? result.activity : [];
      state.activityScope = result.scope === 'all_operators' ? 'all_operators' : 'own';
      if ($('#activity-scope')) $('#activity-scope').textContent = state.activityScope === 'all_operators'
        ? 'All dashboard commands executed by every administrator and moderator in this service session.'
        : 'Only commands executed by your moderator account in this service session.';
      state.lastActivityRefreshAt = Date.now();
      renderActivity();
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      if (!settings.quiet) {
        if ($('#activity-summary')) $('#activity-summary').textContent = 'Unable to load activity';
        toast(errorMessage(error), 'bad');
      }
    } finally {
      if (state.activityController === controller) state.activityController = null;
    }
  }

  function activityStatus(entry) {
    var value = safeString(entry.status || entry.outcome || entry.state || (entry.ok === true ? 'succeeded' : entry.ok === false ? 'failed' : 'completed'), 40).toLowerCase();
    if (value.includes('success') || value === 'completed' || value === 'ok') return { key: 'succeeded', label: 'Succeeded', tone: 'good' };
    if (value.includes('ambiguous') || value.includes('unknown') || value.includes('uncertain')) return { key: 'ambiguous', label: 'Ambiguous', tone: 'warn' };
    if (value.includes('pending') || value.includes('running') || value.includes('queued')) return { key: 'pending', label: 'Pending', tone: 'warn' };
    if (value.includes('fail') || value.includes('error') || value.includes('reject')) return { key: 'failed', label: 'Failed', tone: 'bad' };
    return { key: value, label: value || 'Completed', tone: '' };
  }

  function normalizedActivity(entry) {
    var source = entry && typeof entry === 'object' ? entry : {};
    var action = safeString(source.actionLabel || source.action || source.type || source.command || 'Operation', 80);
    var server = safeString(source.serverName || source.server || source.serverId || 'Cluster', 100);
    var target = safeString(source.targetName || source.target || source.subject || '', 120);
    var actor = safeString(source.actorName || source.actor || source.operator || 'Operator', 100);
    var actorRole = safeString(source.actorRole || source.role || '', 24).toLowerCase();
    var summary = safeString(source.summary || source.detail || '', 220);
    var outcomeMessage = safeString(source.message || '', 220);
    var detail = summary && outcomeMessage && summary !== outcomeMessage
      ? summary + ' — ' + outcomeMessage : summary || outcomeMessage;
    var operationId = safeString(source.operationId || source.id || '', 100);
    var at = source.at || source.timestamp || source.occurredAt || source.createdAt || source.completedAt;
    var duration = source.durationMs === undefined || source.durationMs === null ? '' : Math.max(0, Math.round(numeric(source.durationMs))) + ' ms';
    return { action: action, server: server, target: target, actor: actor, actorRole: actorRole, detail: detail, operationId: operationId, at: at, duration: duration, status: activityStatus(source) };
  }

  function activityNode(entry) {
    var value = normalizedActivity(entry);
    var item = element('div', 'activity-item');
    var time = element('div', 'activity-time');
    time.append(element('strong', '', formatDate(value.at)), element('span', '', value.duration || formatAge(value.at)));
    var actor = element('div', 'activity-actor');
    var roleLabel = value.actorRole === 'admin' ? 'Administrator' : value.actorRole === 'moderator' ? 'Moderator' : 'Staff';
    actor.append(element('strong', '', value.actor), element('span', '', roleLabel + ' · ' + value.server));
    var detail = element('div', 'activity-detail');
    detail.append(element('strong', '', value.action + (value.target ? ' - ' + value.target : '')),
      element('span', '', value.detail || (value.operationId ? 'Operation ' + value.operationId : 'Sanitized outcome')));
    item.append(time, actor, detail, element('span', 'outcome-badge ' + value.status.tone, value.status.label));
    return item;
  }

  function filteredActivity() {
    var query = ($('#activity-search') && $('#activity-search').value || '').trim().toLowerCase();
    var statusFilter = $('#activity-state-filter') ? $('#activity-state-filter').value : '';
    return state.activity.filter(function (entry) {
      var value = normalizedActivity(entry);
      if (statusFilter && value.status.key !== statusFilter) return false;
      if (!query) return true;
      return [value.action, value.server, value.target, value.actor, value.detail].some(function (text) { return text.toLowerCase().includes(query); });
    });
  }

  function renderActivity() {
    var list = $('#activity-list');
    var entries = filteredActivity();
    var nodes = entries.map(activityNode);
    list.replaceChildren.apply(list, nodes.length ? nodes : [element('div', 'empty-copy', state.activityScope === 'all_operators'
      ? 'No matching operator activity.' : 'You have no matching activity.')]);
    $('#activity-summary').textContent = plural(entries.length, 'event') + (entries.length !== state.activity.length ? ' shown' : '');
    var serverActivity = state.activity.filter(function (entry) {
      return normalizedActivity(entry).action.toLowerCase().includes('rcon');
    }).concat(state.consoleActivity);
    var consoleNodes = serverActivity.slice(0, 25).map(activityNode);
    $('#console-activity').replaceChildren.apply($('#console-activity'),
      consoleNodes.length ? consoleNodes : [element('div', 'empty-copy', 'No console activity in this session.')]);
  }

  function diagnosticNode(record) {
    var source = record && typeof record === 'object' ? record : {};
    var level = safeString(source.level || 'info', 16).toLowerCase();
    if (!['debug', 'info', 'warn', 'error'].includes(level)) level = 'info';
    var item = element('article', 'diagnostic-entry diagnostic-' + level);
    var heading = element('div', 'diagnostic-entry-heading');
    var identity = element('div', 'diagnostic-identity');
    identity.append(
      element('span', 'diagnostic-level', level.toUpperCase()),
      element('span', 'diagnostic-channel', safeString(source.channel || 'application', 24)),
      element('code', 'diagnostic-event', safeString(source.event || 'application.message', 96))
    );
    heading.append(identity, element('time', 'diagnostic-time', formatDate(source.time)));
    item.append(heading, element('p', 'diagnostic-message', safeString(source.message || 'No event message.', 512)));
    var details = safeString(source.details || '', 2_000);
    if (details && details !== '{}') item.append(element('code', 'diagnostic-details', details));
    return item;
  }

  function renderDiagnostics() {
    var list = $('#diagnostic-list');
    var nodes = state.diagnostics.map(diagnosticNode);
    list.replaceChildren.apply(list, nodes.length ? nodes : [element('div', 'empty-copy', 'No events match these filters in the current process buffer.')]);
    $('#diagnostic-summary').textContent = plural(state.diagnostics.length, 'event') + ' shown - newest first';
  }

  async function loadDiagnostics(options) {
    if (!state.session || !isAdministrator()) return;
    var settings = options || {};
    if (state.diagnosticController) state.diagnosticController.abort();
    var controller = new AbortController();
    state.diagnosticController = controller;
    if (!settings.quiet) $('#diagnostic-summary').textContent = 'Loading diagnostics...';
    var params = new URLSearchParams();
    var query = ($('#diagnostic-search').value || '').trim();
    var channel = $('#diagnostic-channel').value;
    var level = $('#diagnostic-level').value || 'warn';
    if (query) params.set('q', query);
    if (channel) params.set('channel', channel);
    params.set('level', level);
    params.set('limit', '100');
    try {
      var result = await api('/admin/api/diagnostics?' + params.toString(), { signal: controller.signal });
      if (state.diagnosticController !== controller) return;
      state.diagnostics = Array.isArray(result.records) ? result.records : [];
      state.lastDiagnosticRefreshAt = Date.now();
      renderDiagnostics();
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      $('#diagnostic-summary').textContent = 'Unable to load diagnostics';
      $('#diagnostic-list').replaceChildren(element('div', 'empty-copy', errorMessage(error, 'Diagnostics could not be loaded.')));
      if (!settings.quiet) toast(errorMessage(error), 'bad');
    } finally {
      if (state.diagnosticController === controller) state.diagnosticController = null;
    }
  }

  function scheduleDiagnosticLoad() {
    window.clearTimeout(state.diagnosticSearchTimer);
    state.diagnosticSearchTimer = window.setTimeout(function () { loadDiagnostics({ quiet: true }); }, 350);
  }

  function normalizeOperator(value) {
    var source = value && typeof value === 'object' ? value : {};
    var id = safeString(source.id || source.operatorId, 128);
    var username = safeString(source.username || 'Operator', 32);
    var role = safeString(source.role || 'moderator', 32).toLowerCase() === 'admin' ? 'admin' : 'moderator';
    return {
      id: id,
      username: username,
      role: role,
      enabled: source.enabled !== false,
      owner: Boolean(source.owner),
      mustChangePassword: Boolean(source.mustChangePassword),
      actionGrants: Array.isArray(source.actionGrants) ? source.actionGrants.map(function (grant) {
        return safeString(grant, 64);
      }).filter(Boolean) : [],
      revision: Math.max(0, Math.floor(numeric(source.recordRevision !== undefined ? source.recordRevision : source.revision, 0))),
      updatedAt: source.updatedAt || source.createdAt || null,
      current: Boolean(source.current || source.isCurrent || source.isSelf) || username.toLowerCase() === safeString(state.session && state.session.username, 32).toLowerCase()
    };
  }

  function operatorRoleLabel(role) {
    return role === 'admin' ? 'Administrator' : 'Moderator';
  }

  function operatorActionButton(label, className, handler) {
    var button = element('button', className || 'quiet-button', label);
    button.type = 'button';
    button.addEventListener('click', handler);
    return button;
  }

  function operatorRow(rawOperator) {
    var operator = normalizeOperator(rawOperator);
    var row = document.createElement('tr');
    var identity = document.createElement('td');
    identity.dataset.label = 'Username';
    var name = element('strong', '', operator.username);
    identity.append(name);
    if (operator.current) identity.append(element('span', 'operator-self', operator.owner ? 'Current server owner' : 'Current account'));
    else if (operator.owner) identity.append(element('span', 'operator-self', 'Server owner'));

    var roleCell = document.createElement('td');
    roleCell.dataset.label = 'Role';
    var roleSelect = document.createElement('select');
    roleSelect.setAttribute('aria-label', 'Role for ' + operator.username);
    roleSelect.append(new Option('Moderator', 'moderator'), new Option('Administrator', 'admin'));
    roleSelect.value = operator.role;
    var roleLocked = operator.current || operator.owner || !operator.enabled;
    roleSelect.disabled = roleLocked;
    var saveRole = operatorActionButton('Save role', 'text-button', async function () {
      if (roleSelect.value === operator.role) return;
      if (!window.confirm('Change ' + operator.username + ' to ' + operatorRoleLabel(roleSelect.value) + '? Their active sessions will end.')) {
        roleSelect.value = operator.role;
        saveRole.disabled = true;
        return;
      }
      await updateOperator(operator, { role: roleSelect.value }, saveRole);
    });
    saveRole.disabled = true;
    roleSelect.addEventListener('change', function () { saveRole.disabled = roleLocked || roleSelect.value === operator.role; });
    var roleControls = element('div', 'operator-role-controls');
    roleControls.append(roleSelect, saveRole);
    roleCell.append(roleControls);
    if (operator.role === 'moderator' && operator.actionGrants.length) {
      roleCell.append(element('span', 'operator-self', plural(operator.actionGrants.length, 'additional permission')));
    }

    var status = document.createElement('td');
    status.dataset.label = 'Status';
    var statusTone = !operator.enabled ? 'bad' : operator.mustChangePassword ? 'warn' : 'good';
    var statusLabel = !operator.enabled ? 'Disabled' : operator.mustChangePassword ? 'Password change required' : 'Active';
    status.append(element('span', 'outcome-badge ' + statusTone, statusLabel));

    var updated = document.createElement('td');
    updated.dataset.label = 'Updated';
    updated.textContent = operator.updatedAt ? formatDate(operator.updatedAt) : '--';

    var actions = document.createElement('td');
    actions.dataset.label = 'Actions';
    actions.className = 'operator-actions';
    var toggle = operatorActionButton(operator.enabled ? 'Disable' : 'Enable', operator.enabled ? 'danger-quiet-button' : 'secondary-button', async function () {
      var verb = operator.enabled ? 'Disable' : 'Enable';
      if (operator.enabled && !window.confirm('Disable ' + operator.username + '? Their active sessions will end immediately.')) return;
      await updateOperator(operator, { enabled: !operator.enabled }, toggle);
    });
    toggle.disabled = operator.current || operator.owner;
    var reset = operatorActionButton('Reset password', 'quiet-button', async function () {
      if (!window.confirm('Reset the password for ' + operator.username + '? Their active sessions will end.')) return;
      state.lastDialogTrigger = reset;
      await resetOperatorPassword(operator, reset);
    });
    reset.disabled = operator.current || operator.owner || !operator.enabled;
    reset.hidden = operator.owner;
    var permissions = operatorActionButton('Permissions', 'quiet-button', function () {
      openOperatorPermissions(operator, permissions);
    });
    permissions.hidden = operator.role !== 'moderator';
    permissions.disabled = !operator.enabled;
    actions.append(permissions, toggle, reset);
    row.append(identity, roleCell, status, updated, actions);
    return row;
  }

  function renderOperators() {
    var rows = state.operators.map(operatorRow);
    $('#operator-rows').replaceChildren.apply($('#operator-rows'), rows);
    setHidden($('#operator-empty'), rows.length > 0);
    $('#nav-operator-count').textContent = String(rows.length);
    $('#operator-status').textContent = plural(rows.length, 'operator') + ' loaded.';
  }

  function openOperatorPermissions(operator, trigger) {
    if (!operator || operator.role !== 'moderator') return;
    state.permissionOperator = operator;
    state.lastDialogTrigger = trigger;
    $('#operator-permissions-title').textContent = 'Permissions for ' + operator.username;
    $('#operator-permissions-copy').textContent = 'Choose additional administrator operations for this moderator. Their active sessions will end after saving.';
    showFormError($('#operator-permissions-error'), '');
    var selected = new Set(operator.actionGrants);
    var options = state.operatorGrantableActions.map(function (action) {
      var label = element('label', 'operator-permission-option');
      var input = document.createElement('input');
      input.type = 'checkbox'; input.name = 'action-grant'; input.value = action.id;
      input.checked = selected.has(action.id);
      label.append(input, element('strong', '', action.label), element('span', '', action.description));
      return label;
    });
    $('#operator-permission-options').replaceChildren.apply($('#operator-permission-options'), options);
    $('#operator-permissions-dialog').showModal();
    var first = $('input', $('#operator-permission-options'));
    if (first) first.focus();
  }

  async function handleOperatorPermissions(event) {
    event.preventDefault();
    var operator = state.permissionOperator; var button = $('#save-operator-permissions');
    if (!operator) return;
    var grants = $all('input[name="action-grant"]:checked', event.currentTarget).map(function (input) { return input.value; });
    var saved = await updateOperator(operator, { actionGrants: grants }, button, $('#operator-permissions-error'));
    if (saved) {
      state.permissionOperator = null;
      $('#operator-permissions-dialog').close();
    }
  }

  async function loadOperators(options) {
    if (!state.session || !isAdministrator()) return;
    var settings = options || {};
    if (state.operatorController) state.operatorController.abort();
    var controller = new AbortController();
    state.operatorController = controller;
    if (!settings.quiet) $('#operator-status').textContent = 'Loading operators.';
    try {
      var result = await api('/admin/api/operators', { signal: controller.signal });
      if (state.operatorController !== controller) return;
      state.operators = Array.isArray(result.operators) ? result.operators : [];
      state.operatorGrantableActions = Array.isArray(result.grantableActions) ? result.grantableActions : [];
      renderOperators();
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      $('#operator-status').textContent = 'Operators could not be loaded.';
      if (!settings.quiet) toast(errorMessage(error, 'Operators could not be loaded.'), 'bad');
    } finally {
      if (state.operatorController === controller) state.operatorController = null;
    }
  }

  async function updateOperator(operator, changes, button, errorNode) {
    if (!operator.id) return toast('This operator record cannot be updated.', 'bad');
    setBusy(button, true, 'Saving...');
    try {
      var result = await api('/admin/api/operators/' + encodeURIComponent(operator.id), {
        method: 'PATCH', csrf: true, body: Object.assign({}, changes, { expectedRevision: operator.revision })
      });
      if (!result || result.ok !== true || !result.operator || typeof result.operator !== 'object') {
        throw incompleteMutationResponse('The operator-change response was incomplete.');
      }
      toast('Operator access updated.', 'good');
      await loadOperators({ quiet: true });
      return true;
    } catch (error) {
      var committed = Boolean(error && error.mutationCommitted);
      toast(committed
        ? 'Operator access was saved, but audit confirmation failed. Repair audit log storage and restart the service; the operator list was refreshed for verification.'
        : mutationOutcomeUnknown(error)
          ? 'The operator change response was lost or incomplete. The operator list was refreshed; verify it before another change.'
          : errorMessage(error), committed || mutationOutcomeUnknown(error) ? 'warn' : 'bad', 12_000);
      if (errorNode) showFormError(errorNode, errorMessage(error));
      await loadOperators({ quiet: true });
      return false;
    } finally {
      setBusy(button, false);
    }
  }

  async function resetOperatorPassword(operator, button) {
    if (!operator.id) return toast('This operator record cannot be reset.', 'bad');
    setBusy(button, true, 'Resetting...');
    try {
      var result = await api('/admin/api/operators/' + encodeURIComponent(operator.id) + '/reset-password', {
        method: 'POST', csrf: true, body: { expectedRevision: operator.revision }
      });
      if (!result || !/^[A-Za-z0-9_-]{32}$/u.test(result.temporaryPassword || '')) {
        throw incompleteMutationResponse('The password-reset response was incomplete.');
      }
      showTemporaryPassword(result.temporaryPassword, result.operator || operator);
      await loadOperators({ quiet: true });
    } catch (error) {
      if (error && error.mutationCommitted) {
        toast('The reset was saved, but audit confirmation failed and its temporary password was withheld. Repair audit log storage, restart the service, refresh Operators, then reset this account again to replace the unknown credential.', 'warn', 15_000);
        await loadOperators({ quiet: true });
      } else if (mutationOutcomeUnknown(error)) {
        toast('The reset may have committed without delivering its temporary password. Refresh Operators, then reset that account again to replace the unknown credential.', 'warn', 12_000);
        await loadOperators({ quiet: true });
      } else toast(errorMessage(error), 'bad');
    } finally {
      setBusy(button, false);
    }
  }

  function showTemporaryPassword(value, operator) {
    var password = safeString(value, 256);
    if (!password) {
      toast('The temporary password was not returned. Reset it again.', 'bad');
      return;
    }
    var username = safeString(operator && operator.username || 'the operator', 32);
    $('#temporary-password-copy').textContent = 'Share this password securely with ' + username + '. It must be changed at first sign-in.';
    var input = $('#temporary-password');
    var toggle = $('[data-password-target="temporary-password"]');
    input.type = 'password'; input.value = password;
    toggle.textContent = 'Show'; toggle.setAttribute('aria-pressed', 'false'); toggle.setAttribute('aria-label', 'Show temporary password');
    var dialog = $('#temporary-password-dialog');
    if (!dialog.open) dialog.showModal();
    window.setTimeout(function () { input.focus(); input.select(); }, 0);
    password = '';
  }

  async function handleCreateOperator(event) {
    event.preventDefault();
    var form = event.currentTarget;
    if (!form.reportValidity()) return;
    var username = $('#operator-username').value.trim();
    var role = $('#operator-role-select').value;
    var button = $('#save-operator-button');
    showFormError($('#create-operator-error'), '');
    setBusy(button, true, 'Creating...');
    try {
      var result = await api('/admin/api/operators', { method: 'POST', csrf: true, body: { username: username, role: role } });
      if (!result || !/^[A-Za-z0-9_-]{32}$/u.test(result.temporaryPassword || '')) {
        throw incompleteMutationResponse('The operator-creation response was incomplete.');
      }
      username = ''; role = '';
      $('#create-operator-dialog').close();
      form.reset();
      showTemporaryPassword(result.temporaryPassword, result.operator);
      await loadOperators({ quiet: true });
    } catch (error) {
      username = ''; role = '';
      if (error && error.mutationCommitted) {
        form.reset();
        $('#create-operator-dialog').close();
        toast('The operator was created, but audit confirmation failed and its temporary password was withheld. Repair audit log storage, restart the service, refresh Operators, then reset the created account to generate a usable temporary password. Do not create it again.', 'warn', 15_000);
        await loadOperators({ quiet: true });
      } else if (mutationOutcomeUnknown(error)) {
        form.reset();
        $('#create-operator-dialog').close();
        toast('The operator may have been created without delivering its temporary password. Refresh Operators; if the account exists, use Reset password instead of creating it again.', 'warn', 12_000);
        await loadOperators({ quiet: true });
      } else showFormError($('#create-operator-error'), errorMessage(error));
    } finally {
      setBusy(button, false);
    }
  }

  function boundedInteger(value, fallback, minimum, maximum) {
    var number = Number(value);
    if (!Number.isFinite(number)) number = fallback;
    return Math.min(maximum, Math.max(minimum, Math.floor(number)));
  }

  function settingsList(value, maximum) {
    if (!Array.isArray(value)) return [];
    return value.slice(0, maximum || 64).map(function (entry) {
      return safeString(entry, 256).trim();
    }).filter(Boolean);
  }

  function settingsAnnouncementTemplates(value) {
    if (!jsonRecord(value)) return {};
    var result = {};
    Object.keys(value).slice(0, 32).forEach(function (name) {
      var cleanName = safeString(name, 40).trim();
      var message = safeString(value[name], 2_000).trim();
      if (cleanName && message) result[cleanName] = message;
    });
    return result;
  }

  function jsonRecord(value) {
    return Boolean(value && typeof value === 'object' && !Array.isArray(value));
  }

  function settingsProjectionSource(payload) {
    if (!jsonRecord(payload)) return null;
    var source = jsonRecord(payload.projection) ? payload.projection : payload;
    if (source.revision === undefined && jsonRecord(source.settings)
      && source.settings.revision !== undefined) source = source.settings;
    return jsonRecord(source) ? source : null;
  }

  function completeManagedSettingsProjection(payload) {
    var source = settingsProjectionSource(payload);
    if (!source || source.managed !== true || !Number.isSafeInteger(source.revision) || source.revision < 1
      || typeof source.restartRequired !== 'boolean' || !jsonRecord(source.settings)
      || typeof source.settings.clusterName !== 'string' || !Array.isArray(source.settings.servers)
      || !source.settings.servers.every(jsonRecord) || !jsonRecord(source.settings.discord)
      || !jsonRecord(source.settings.analytics) || typeof source.settings.analytics.enabled !== 'boolean'
      || !jsonRecord(source.settings.moderation) || !jsonRecord(source.instance)
      || typeof source.instance.instanceId !== 'string' || !source.instance.instanceId || source.instance.instanceId.length > 128
      || !jsonRecord(source.instance.tls) || !jsonRecord(source.instance.automationToken)) return false;
    var tls = source.instance.tls;
    var token = source.instance.automationToken;
    return typeof tls.trustUpdateRequired === 'boolean'
      && typeof tls.rotationRequiresExplicitNames === 'boolean'
      && Array.isArray(tls.subjectAltNames) && Array.isArray(tls.additionalSubjectAltNames)
      && typeof token.configured === 'boolean' && typeof token.activationPending === 'boolean'
      && typeof token.deliveryPending === 'boolean' && typeof token.activationReceipt === 'string'
      && (token.activationReceipt === '' || /^[A-Za-z0-9_-]{43}$/u.test(token.activationReceipt));
  }

  function settingsProjectionFromPayload(payload) {
    var source = settingsProjectionSource(payload) || {};
    var editable = source.settings && typeof source.settings === 'object' ? source.settings : {};
    var rawServers = Array.isArray(editable.servers) ? editable.servers : [];
    var servers = rawServers.slice(0, 64).map(function (raw, index) {
      var server = raw && typeof raw === 'object' ? raw : {};
      var profileSource = server.profileImport && typeof server.profileImport === 'object' ? server.profileImport : {};
      return {
        id: safeString(server.id || ('map' + String(index + 1)), 32),
        name: safeString(server.name || ('Map ' + String(index + 1)), 96),
        host: safeString(server.host || '127.0.0.1', 255),
        port: boundedInteger(server.port, 27020 + index, 1, 65_535),
        enabled: server.enabled !== false,
        pollIntervalMs: boundedInteger(server.pollIntervalMs, 1_000, 250, 3_600_000),
        playerRefreshIntervalMs: boundedInteger(server.playerRefreshIntervalMs, 15_000, 500, 3_600_000),
        connectTimeoutMs: boundedInteger(server.connectTimeoutMs, 3_000, 100, 120_000),
        commandTimeoutMs: boundedInteger(server.commandTimeoutMs, 5_000, 100, 300_000),
        fragmentIdleMs: boundedInteger(server.fragmentIdleMs, 100, 10, 10_000),
        retries: boundedInteger(server.retries, 2, 0, 10),
        passwordConfigured: Boolean(server.passwordConfigured),
        profileImport: {
          enabled: Boolean(profileSource.enabled),
          host: safeString(profileSource.host || server.host || '', 255),
          port: boundedInteger(profileSource.port, 22, 1, 65_535),
          username: safeString(profileSource.username, 128),
          passwordConfigured: Boolean(profileSource.passwordConfigured),
          hostKeySha256: safeString(profileSource.hostKeySha256, 64),
          mapName: safeString(profileSource.mapName, 64),
          directories: settingsList(profileSource.directories, 16),
          connectTimeoutMs: boundedInteger(profileSource.connectTimeoutMs, 5_000, 100, 120_000),
          operationTimeoutMs: boundedInteger(profileSource.operationTimeoutMs, 15_000, 100, 300_000),
          retryIntervalMs: boundedInteger(profileSource.retryIntervalMs, 60_000, 1_000, 86_400_000),
          revalidateIntervalMs: boundedInteger(profileSource.revalidateIntervalMs, 300_000, 10_000, 86_400_000),
          maxFileBytes: boundedInteger(profileSource.maxFileBytes, 16 * 1024 * 1024, 1_024, 64 * 1024 * 1024)
        }
      };
    });
    var discordSource = editable.discord && typeof editable.discord === 'object' ? editable.discord : {};
    var analyticsSource = editable.analytics && typeof editable.analytics === 'object' ? editable.analytics : {};
    var moderationSource = editable.moderation && typeof editable.moderation === 'object' ? editable.moderation : {};
    var instanceSource = source.instance && typeof source.instance === 'object' ? source.instance : {};
    var tlsSource = instanceSource.tls && typeof instanceSource.tls === 'object' ? instanceSource.tls : {};
    var tokenSource = instanceSource.automationToken && typeof instanceSource.automationToken === 'object'
      ? instanceSource.automationToken : {};
    return {
      revision: boundedInteger(source.revision, 0, 0, Number.MAX_SAFE_INTEGER),
      managed: source.managed !== false,
      restartRequired: source.restartRequired || false,
      instance: {
        instanceId: safeString(instanceSource.instanceId, 128),
        keystore: instanceSource.keystore,
        tls: {
          mode: safeString(tlsSource.mode, 64),
          fingerprint: safeString(tlsSource.fingerprint, 256),
          expiresAt: tlsSource.expiresAt || null,
          expiryKnown: Boolean(tlsSource.expiryKnown),
          trustUpdateRequired: Boolean(tlsSource.trustUpdateRequired),
          rotationRequiresExplicitNames: Boolean(tlsSource.rotationRequiresExplicitNames),
          subjectAltNames: settingsList(tlsSource.subjectAltNames, 32),
          additionalSubjectAltNames: settingsList(tlsSource.additionalSubjectAltNames, 16)
        },
        automationToken: {
          configured: Boolean(tokenSource.configured),
          activationPending: Boolean(tokenSource.activationPending),
          deliveryPending: Boolean(tokenSource.deliveryPending),
          activationReceipt: safeString(tokenSource.activationReceipt, 43)
        }
      },
      settings: {
        clusterName: safeString(editable.clusterName || 'ASA Cluster', 96),
        servers: servers,
        discord: {
          enabled: Boolean(discordSource.enabled),
          tokenConfigured: Boolean(discordSource.tokenConfigured),
          applicationId: safeString(discordSource.applicationId, 20),
          guildId: safeString(discordSource.guildId, 20),
          chatChannelId: safeString(discordSource.chatChannelId, 20),
          auditChannelId: safeString(discordSource.auditChannelId, 20),
          adminRoleIds: settingsList(discordSource.adminRoleIds, 64),
          moderatorRoleIds: settingsList(discordSource.moderatorRoleIds, 64),
          relayRoleIds: settingsList(discordSource.relayRoleIds, 64),
          allowUnlinkedChat: discordSource.allowUnlinkedChat !== false,
          registerCommands: discordSource.registerCommands !== false
        },
        analytics: { enabled: analyticsSource.enabled === true },
        moderation: {
          allowRawRcon: Boolean(moderationSource.allowRawRcon),
          rawRconAllowlist: settingsList(moderationSource.rawRconAllowlist, 64),
          announcementTemplates: settingsAnnouncementTemplates(moderationSource.announcementTemplates)
        }
      }
    };
  }

  function keystoreLabel(value) {
    if (typeof value === 'string' && value.trim()) return safeString(value.trim(), 100);
    if (value === true) return 'Protected and available';
    if (value === false) return 'Protection unavailable';
    if (value && typeof value === 'object') {
      for (var key of ['provider', 'mode', 'status']) {
        if (typeof value[key] === 'string' && value[key].trim()) return safeString(value[key].trim(), 100);
      }
      if (value.available === true || value.configured === true) return 'Protected and available';
    }
    return 'Managed storage';
  }

  function restartRequired(value) {
    if (Array.isArray(value)) return value.length > 0;
    if (value && typeof value === 'object') return value.required !== false;
    return Boolean(value);
  }

  function resetPasswordToggle(input) {
    if (!input) return;
    input.type = 'password';
    var wrapper = input.closest('.secret-input');
    var button = wrapper ? $('.password-toggle', wrapper) : null;
    if (button) {
      button.textContent = 'Show';
      button.setAttribute('aria-pressed', 'false');
      button.setAttribute('aria-label', 'Show ' + safeString(input.dataset.secretLabel || 'secret', 80));
    }
  }

  function clearSettingSecretInputs() {
    $all('.settings-secret-input').forEach(function (input) {
      input.value = '';
      resetPasswordToggle(input);
    });
  }

  function clearOneTimeAutomationToken() {
    var input = $('#settings-automation-token');
    if (!input) return;
    input.value = '';
    input.type = 'password';
    var toggle = $('[data-password-target="settings-automation-token"]');
    if (toggle) {
      toggle.textContent = 'Show';
      toggle.setAttribute('aria-pressed', 'false');
      toggle.setAttribute('aria-label', 'Show automation token');
    }
    state.pendingAutomationTokenDeliveryId = '';
  }

  function clearAutomationTokenRecovery() {
    state.automationTokenRecoveryReceipt = '';
    state.automationTokenRecoveryInstanceId = '';
    state.automationTokenRecoveryNeedsReconciliation = false;
  }

  function automationTokenAckDisposition(tokenState, receipt) {
    if (!tokenState || typeof tokenState !== 'object' || !/^[A-Za-z0-9_-]{43}$/u.test(receipt || '')) return 'unverified';
    if (tokenState.activationReceipt === receipt) return 'confirmed';
    return tokenState.deliveryPending === true ? 'pending' : 'unverified';
  }

  function oneTimeCredentialVisible() {
    return Boolean(
      ($('#settings-automation-token') && $('#settings-automation-token').value)
      || ($('#temporary-password') && $('#temporary-password').value),
    );
  }

  function clearSettingsState(options) {
    var settings = options || {};
    if (state.settingsController) state.settingsController.abort();
    state.settingsController = null;
    state.settingsProjection = null;
    state.settingsBaseline = '';
    state.settingsInputSequence = 0;
    clearSettingSecretInputs();
    clearOneTimeAutomationToken();
    if (settings.preserveAutomationTokenRecovery && state.automationTokenRecoveryReceipt) {
      state.automationTokenRecoveryNeedsReconciliation = true;
    } else clearAutomationTokenRecovery();
    var form = $('#settings-form');
    if (form) form.reset();
    var list = $('#settings-server-list');
    if (list) list.replaceChildren(element('div', 'empty-copy', 'Open Settings to load configuration.'));
    for (var selector of ['#settings-rotate-token', '#settings-regenerate-tls']) {
      var staged = $(selector);
      if (staged) staged.setAttribute('aria-pressed', 'false');
    }
    showFormError($('#settings-error'), '');
    showFormError($('#settings-review-error'), '');
    setHidden($('#settings-change-bar'), true);
    if ($('#settings-review-dialog') && $('#settings-review-dialog').open) $('#settings-review-dialog').close();
    if ($('#settings-token-dialog') && $('#settings-token-dialog').open) $('#settings-token-dialog').close();
  }

  function settingInput(labelText, field, value, options) {
    var config = options || {};
    var label = element(config.secret ? 'div' : 'label', 'settings-field' + (config.full ? ' full' : ''));
    var caption = element(config.secret ? 'label' : 'span', '', labelText);
    var input = document.createElement('input');
    input.type = config.secret ? 'password' : (config.type || 'text');
    input.dataset.settingField = field;
    input.value = config.secret ? '' : safeString(value, config.maximum || 1_000);
    input.autocomplete = 'off';
    if (config.inputMode) input.inputMode = config.inputMode;
    if (config.pattern) input.pattern = config.pattern;
    if (config.minimum !== undefined) input.min = String(config.minimum);
    if (config.maximumNumber !== undefined) input.max = String(config.maximumNumber);
    if (config.step !== undefined) input.step = String(config.step);
    if (config.maximum) input.maxLength = config.maximum;
    if (config.minimumLength) input.minLength = config.minimumLength;
    input.required = Boolean(config.required);
    if (config.placeholder) input.placeholder = config.placeholder;
    if (config.secret) {
      input.className = 'settings-secret-input';
      input.spellcheck = false;
      input.dataset.secretLabel = labelText;
      input.dataset.configured = config.configured ? 'true' : 'false';
      state.settingsInputSequence += 1;
      input.id = 'settings-secret-' + String(state.settingsInputSequence);
      caption.htmlFor = input.id;
      var wrapper = element('div', 'secret-input');
      var toggle = element('button', 'icon-button password-toggle', 'Show');
      toggle.type = 'button';
      toggle.setAttribute('aria-label', 'Show ' + labelText);
      toggle.setAttribute('aria-pressed', 'false');
      toggle.addEventListener('click', function () {
        var showing = input.type === 'text';
        input.type = showing ? 'password' : 'text';
        toggle.textContent = showing ? 'Show' : 'Hide';
        toggle.setAttribute('aria-pressed', showing ? 'false' : 'true');
        toggle.setAttribute('aria-label', (showing ? 'Show ' : 'Hide ') + labelText);
      });
      wrapper.append(input, toggle);
      label.append(caption, wrapper);
      var help = element('small', 'secret-status', config.configured
        ? 'Configured. Enter a new value to replace it.'
        : 'Not configured. Enter a credential before applying.');
      help.id = input.id + '-help';
      input.setAttribute('aria-describedby', help.id);
      label.append(help);
      return label;
    }
    label.append(caption, input);
    if (config.help) label.append(element('small', '', config.help));
    return label;
  }

  function settingTextarea(labelText, field, values, help) {
    var label = element('label', 'settings-field full');
    var textarea = document.createElement('textarea');
    textarea.dataset.settingField = field;
    textarea.rows = 3;
    textarea.maxLength = 8_192;
    textarea.autocomplete = 'off';
    textarea.spellcheck = false;
    textarea.value = Array.isArray(values) ? values.join('\n') : safeString(values, 8_192);
    label.append(element('span', '', labelText), textarea);
    if (help) label.append(element('small', '', help));
    return label;
  }

  function settingSwitch(labelText, field, checked) {
    var label = element('label', 'settings-switch');
    var input = document.createElement('input');
    input.type = 'checkbox';
    input.checked = Boolean(checked);
    input.dataset.settingField = field;
    label.append(input, element('span', '', labelText));
    return label;
  }

  function settingSubsection(title, copy) {
    var section = element('section', 'settings-subsection');
    var heading = element('div', 'settings-subsection-heading');
    var text = document.createElement('div');
    text.append(element('strong', '', title), element('small', '', copy));
    heading.append(text);
    section.append(heading);
    return { section: section, heading: heading };
  }

  function suggestedAsaMapName(server) {
    var candidates = [server && server.name, server && server.id].map(function (value) {
      return safeString(value, 96).trim();
    }).filter(Boolean);
    var exact = candidates.find(function (value) { return /^[A-Za-z0-9_-]+_WP$/u.test(value); });
    if (exact) return exact;
    var known = {
      theisland: 'TheIsland_WP', scorchedearth: 'ScorchedEarth_WP', thecenter: 'TheCenter_WP',
      aberration: 'Aberration_WP', extinction: 'Extinction_WP', ragnarok: 'Ragnarok_WP',
      valguero: 'Valguero_WP'
    };
    for (var candidate of candidates) {
      var match = known[candidate.toLowerCase().replace(/[^a-z0-9]/gu, '')];
      if (match) return match;
    }
    return '';
  }

  async function scanProfileHostKey(card, button) {
    var host = settingControl(card, 'profile.host').value.trim();
    var port = settingNumber(card, 'profile.port');
    if (!host || !port) return toast('Enter the SFTP host and port first.', 'warn');
    setBusy(button, true, 'Scanning...');
    try {
      var result = await api('/admin/api/settings/sftp-host-key', {
        method: 'POST', csrf: true, body: { host: host, port: port }
      });
      if (!result || !/^[a-f0-9]{64}$/iu.test(result.fingerprint || '')) {
        throw new ApiError('The SFTP server returned an invalid host key.', 502, 'INVALID_HOST_KEY_RESPONSE');
      }
      settingControl(card, 'profile.hostKeySha256').value = result.openssh || result.fingerprint;
      updateSettingsDirtyState();
      toast('Host key scanned. Compare it with your host provider if possible, then apply the settings.', 'good', 10_000);
    } catch (error) {
      toast(errorMessage(error), 'bad', 10_000);
    } finally {
      setBusy(button, false);
    }
  }

  function updateProfileFieldState(card) {
    var toggle = $('[data-setting-field="profile.enabled"]', card);
    var fields = $('.settings-profile-fields', card);
    if (!toggle || !fields) return;
    var enabled = toggle.checked;
    var clearPassword = settingControl(card, 'profile.clearPassword');
    if (clearPassword) {
      clearPassword.setCustomValidity(clearPassword.checked && enabled
        ? 'Disable profile import before deleting its stored password.' : '');
    }
    fields.hidden = !enabled;
    $all('input, textarea', fields).forEach(function (input) {
      input.disabled = !enabled;
      if (input.dataset.profileRequired === 'true') input.required = enabled;
      if (input.classList.contains('settings-secret-input')) {
        var id = settingControl(card, 'id');
        var identityChanged = Boolean(card.dataset.originalId && id && id.value.trim() !== card.dataset.originalId);
        input.required = enabled && (input.dataset.configured !== 'true' || identityChanged);
        if (!enabled && input.value) {
          input.value = '';
          resetPasswordToggle(input);
        }
      }
    });
  }

  function updateServerCardPresentation(card) {
    var enabled = $('[data-setting-field="enabled"]', card);
    var name = $('[data-setting-field="name"]', card);
    var id = $('[data-setting-field="id"]', card);
    var title = $('.settings-server-name', card);
    var detail = $('.settings-server-detail', card);
    var badge = $('.settings-server-state', card);
    card.classList.toggle('disabled', enabled && !enabled.checked);
    if (title) title.textContent = safeString(name && name.value.trim() || 'New map', 100);
    if (detail) detail.textContent = safeString(id && id.value.trim() || 'Map ID required', 80);
    if (badge) {
      badge.textContent = enabled && enabled.checked ? 'Enabled' : 'Disabled';
      badge.className = 'state-badge settings-server-state ' + (enabled && enabled.checked ? 'good' : '');
    }
    var password = settingControl(card, 'password');
    var identityChanged = Boolean(card.dataset.originalId && id && id.value.trim() !== card.dataset.originalId);
    if (password) password.required = password.dataset.configured !== 'true' || identityChanged;
    updateProfileFieldState(card);
  }

  function buildSettingsServerCard(server) {
    var card = element('article', 'settings-server-card' + (server.enabled ? '' : ' disabled'));
    card.dataset.settingsServer = 'true';
    card.dataset.originalId = safeString(server.id, 32);
    var heading = element('header', 'settings-server-heading');
    var identity = element('div', 'settings-server-title');
    var copy = document.createElement('div');
    copy.append(element('h4', 'settings-server-name', server.name || 'New map'), element('p', 'settings-server-detail', server.id || 'Map ID required'));
    identity.append(element('span', 'state-badge settings-server-state ' + (server.enabled ? 'good' : ''), server.enabled ? 'Enabled' : 'Disabled'), copy);
    var actions = element('div', 'row-actions');
    var enabled = settingSwitch('Map enabled', 'enabled', server.enabled);
    var remove = element('button', 'danger-quiet-button settings-remove-server', 'Remove');
    remove.type = 'button';
    remove.addEventListener('click', function () {
      var mapName = safeString($('[data-setting-field="name"]', card).value || 'this map', 100);
      if (!window.confirm('Remove ' + mapName + ' from the cluster configuration?')) return;
      $all('.settings-secret-input', card).forEach(function (input) { input.value = ''; });
      card.remove();
      if (!$('[data-settings-server]', $('#settings-server-list'))) {
        $('#settings-server-list').append(element('div', 'settings-server-empty empty-copy', 'No maps configured. Add a map when you are ready to activate the bridge.'));
      }
      updateSettingsDirtyState();
    });
    actions.append(enabled, remove);
    heading.append(identity, actions);

    var body = element('div', 'settings-server-body');
    var rcon = settingSubsection('RCON connection', server.passwordConfigured ? 'Credential configured' : 'Credential required');
    var basicGrid = element('div', 'settings-field-grid');
    basicGrid.append(
      settingInput('Map ID', 'id', server.id, { required: true, maximum: 32, pattern: '[A-Za-z0-9_-]{1,32}', help: 'Stable identifier used for commands and saved records.' }),
      settingInput('Display name', 'name', server.name, { required: true, maximum: 96 }),
      settingInput('RCON host', 'host', server.host, {
        required: true, maximum: 255, help: 'Use a private or loopback IP literal. Public RCON endpoints are refused.'
      }),
      settingInput('RCON port', 'port', server.port, { type: 'number', required: true, minimum: 1, maximumNumber: 65_535, step: 1 }),
      settingInput('RCON password', 'password', '', {
        secret: true, full: true, required: !server.passwordConfigured, configured: server.passwordConfigured,
        minimumLength: 16, maximum: 256, placeholder: server.passwordConfigured ? 'Configured - enter a replacement' : 'Enter at least 16 characters'
      })
    );
    rcon.section.append(basicGrid);

    var advanced = element('details', 'settings-advanced');
    advanced.append(element('summary', '', 'Advanced RCON timing and retries'));
    var advancedGrid = element('div', 'settings-field-grid');
    advancedGrid.append(
      settingInput('Chat poll interval (ms)', 'pollIntervalMs', server.pollIntervalMs, { type: 'number', required: true, minimum: 250, maximumNumber: 3_600_000, step: 1 }),
      settingInput('Player refresh interval (ms)', 'playerRefreshIntervalMs', server.playerRefreshIntervalMs, { type: 'number', required: true, minimum: 500, maximumNumber: 3_600_000, step: 1 }),
      settingInput('Connect timeout (ms)', 'connectTimeoutMs', server.connectTimeoutMs, { type: 'number', required: true, minimum: 100, maximumNumber: 120_000, step: 1 }),
      settingInput('Command timeout (ms)', 'commandTimeoutMs', server.commandTimeoutMs, { type: 'number', required: true, minimum: 100, maximumNumber: 300_000, step: 1 }),
      settingInput('Fragment idle window (ms)', 'fragmentIdleMs', server.fragmentIdleMs, { type: 'number', required: true, minimum: 10, maximumNumber: 10_000, step: 1 }),
      settingInput('Retry attempts', 'retries', server.retries, { type: 'number', required: true, minimum: 0, maximumNumber: 10, step: 1 })
    );
    advanced.append(advancedGrid);
    rcon.section.append(advanced);

    var profile = server.profileImport;
    var sftp = settingSubsection('SFTP profile import', profile.enabled
      ? (profile.passwordConfigured ? 'Read-only credential configured' : 'Credential required')
      : 'Optional player-ID discovery');
    var profileSwitch = settingSwitch('Profile import enabled', 'profile.enabled', profile.enabled);
    var clearProfilePassword = settingSwitch('Delete saved password', 'profile.clearPassword', false);
    var clearProfileInput = $('[data-setting-field="profile.clearPassword"]', clearProfilePassword);
    clearProfilePassword.hidden = !profile.passwordConfigured;
    clearProfileInput.disabled = !profile.passwordConfigured;
    sftp.heading.append(profileSwitch, clearProfilePassword);
    var profileFields = element('div', 'settings-field-grid settings-profile-fields');
    var inheritedProfileHost = !profile.passwordConfigured && profile.host === '127.0.0.1'
      && server.host !== '127.0.0.1' ? server.host : (profile.host || server.host);
    var profileHost = settingInput('SFTP host', 'profile.host', inheritedProfileHost, {
      required: true, maximum: 255, help: 'Defaults to the RCON host until you enter a different address.'
    });
    var profilePort = settingInput('SFTP port', 'profile.port', profile.port, { type: 'number', required: true, minimum: 1, maximumNumber: 65_535, step: 1 });
    var profileUser = settingInput('Read-only username', 'profile.username', profile.username, { required: true, maximum: 128 });
    $('[data-setting-field]', profileHost).dataset.profileRequired = 'true';
    $('[data-setting-field]', profilePort).dataset.profileRequired = 'true';
    $('[data-setting-field]', profileUser).dataset.profileRequired = 'true';
    var fingerprintField = settingInput('Host-key SHA-256', 'profile.hostKeySha256', profile.hostKeySha256, {
      full: true, required: true, maximum: 64,
      pattern: '(?:[A-Fa-f0-9]{64}|SHA256:[A-Za-z0-9+/]{43}={0,1})',
      placeholder: 'SHA256:... or 64 hexadecimal characters',
      help: 'Pinning protects the SFTP password if another machine impersonates this server. You can scan the key, then compare it with your host provider if possible.'
    });
    var scanFingerprint = element('button', 'quiet-button settings-sftp-scan', 'Scan host key');
    scanFingerprint.type = 'button';
    scanFingerprint.addEventListener('click', function () { void scanProfileHostKey(card, scanFingerprint); });
    fingerprintField.append(scanFingerprint);
    var profileMap = settingInput('ASA map name', 'profile.mapName', profile.mapName || suggestedAsaMapName(server), {
      required: true, maximum: 64, pattern: '[A-Za-z0-9_-]{1,64}',
      help: 'Filled automatically for recognized official map names; edit it if your save-directory token differs.'
    });
    profileFields.append(
      profileHost,
      profilePort,
      profileUser,
      settingInput('SFTP password', 'profile.password', '', {
        secret: true, required: profile.enabled && !profile.passwordConfigured, configured: profile.passwordConfigured,
        minimumLength: 16, maximum: 512, placeholder: profile.passwordConfigured ? 'Configured - enter a replacement' : 'Enter at least 16 characters'
      }),
      fingerprintField,
      profileMap,
      settingTextarea('Profile directories', 'profile.directories', profile.directories, 'Optional. Leave blank to try the built-in ASA save paths, or enter one canonical absolute server path per line.'),
      settingInput('Connect timeout (ms)', 'profile.connectTimeoutMs', profile.connectTimeoutMs, { type: 'number', required: true, minimum: 100, maximumNumber: 120_000, step: 1 }),
      settingInput('Operation timeout (ms)', 'profile.operationTimeoutMs', profile.operationTimeoutMs, { type: 'number', required: true, minimum: 100, maximumNumber: 300_000, step: 1 }),
      settingInput('Retry interval (ms)', 'profile.retryIntervalMs', profile.retryIntervalMs, { type: 'number', required: true, minimum: 1_000, maximumNumber: 86_400_000, step: 1 }),
      settingInput('Revalidate interval (ms)', 'profile.revalidateIntervalMs', profile.revalidateIntervalMs, { type: 'number', required: true, minimum: 10_000, maximumNumber: 86_400_000, step: 1 }),
      settingInput('Maximum profile bytes', 'profile.maxFileBytes', profile.maxFileBytes, { type: 'number', required: true, minimum: 1_024, maximumNumber: 67_108_864, step: 1 })
    );
    sftp.section.append(profileFields);
    body.append(rcon.section, sftp.section);
    card.append(heading, body);
    var rconHostInput = settingControl(card, 'host');
    var profileHostInput = settingControl(card, 'profile.host');
    var profileMapInput = settingControl(card, 'profile.mapName');
    var previousRconHost = rconHostInput.value.trim();
    var previousSuggestion = suggestedAsaMapName(server);
    rconHostInput.addEventListener('input', function () {
      if (!profileHostInput.value.trim() || profileHostInput.value.trim() === previousRconHost) {
        profileHostInput.value = rconHostInput.value.trim();
      }
      previousRconHost = rconHostInput.value.trim();
    });
    for (var sourceField of [settingControl(card, 'id'), settingControl(card, 'name')]) {
      sourceField.addEventListener('input', function () {
        var nextSuggestion = suggestedAsaMapName({
          id: settingControl(card, 'id').value, name: settingControl(card, 'name').value
        });
        if (nextSuggestion && (!profileMapInput.value.trim() || profileMapInput.value.trim() === previousSuggestion)) {
          profileMapInput.value = nextSuggestion;
        }
        previousSuggestion = nextSuggestion;
      });
    }
    updateServerCardPresentation(card);
    return card;
  }

  function applyDiscordFieldState() {
    var enabled = $('#settings-discord-enabled').checked;
    var wrapper = $('#settings-discord-fields');
    wrapper.classList.toggle('disabled', !enabled);
    $all('input, textarea', wrapper).forEach(function (input) {
      input.disabled = !enabled;
    });
    var token = $('#settings-discord-token');
    var clearToken = $('#settings-discord-clear-token');
    token.required = enabled && token.dataset.configured !== 'true';
    clearToken.setCustomValidity(clearToken.checked && enabled
      ? 'Disable Discord before deleting its stored token.' : '');
    token.minLength = enabled ? 20 : 0;
    if (!enabled && token.value) {
      token.value = '';
      resetPasswordToggle(token);
    }
    for (var selector of ['#settings-discord-application', '#settings-discord-guild', '#settings-discord-chat-channel']) {
      $(selector).required = enabled;
    }
  }

  function applyTlsStagingState() {
    var names = $('#settings-tls-names');
    var staged = settingsSecurityStaged('#settings-regenerate-tls');
    names.disabled = !staged;
    names.setCustomValidity('');
  }

  function announcementTemplateMaximum() {
    return boundedInteger(state.capabilities && state.capabilities.announcementMaxLength, 400, 1, 2_000);
  }

  function buildSettingsTemplateRow(name, message) {
    var row = element('div', 'settings-template-row');
    row.dataset.settingsTemplate = 'true';
    var nameLabel = element('label', 'settings-field');
    nameLabel.append(element('span', '', 'Template name'));
    var nameInput = document.createElement('input');
    nameInput.type = 'text'; nameInput.required = true; nameInput.maxLength = 40;
    nameInput.pattern = '[A-Za-z0-9][A-Za-z0-9 _-]{0,39}';
    nameInput.autocomplete = 'off'; nameInput.dataset.templateField = 'name'; nameInput.value = name || '';
    nameLabel.append(nameInput, element('small', '', 'Letters, numbers, spaces, underscores, or hyphens.'));
    var messageLabel = element('label', 'settings-field');
    messageLabel.append(element('span', '', 'Broadcast message'));
    var messageInput = document.createElement('textarea');
    messageInput.required = true; messageInput.rows = 2; messageInput.dataset.templateField = 'message';
    messageInput.value = message || '';
    configureCodePointMaximum(messageInput, announcementTemplateMaximum());
    messageLabel.append(messageInput, element('small', '', 'Sent exactly as written after staff review and confirmation.'));
    var remove = element('button', 'danger-quiet-button settings-template-remove', 'Delete');
    remove.type = 'button';
    remove.addEventListener('click', function () {
      row.remove(); renderSettingsTemplateEmpty(); updateSettingsDirtyState();
    });
    row.append(nameLabel, messageLabel, remove);
    return row;
  }

  function renderSettingsTemplateEmpty() {
    var list = $('#settings-template-list');
    var empty = $('.settings-template-empty', list);
    var hasRows = Boolean($('[data-settings-template]', list));
    if (hasRows && empty) empty.remove();
    else if (!hasRows && !empty) list.append(element('div', 'settings-template-empty empty-copy', 'No templates configured. Add one or restore the starter set.'));
  }

  function renderSettingsTemplates(templateMap) {
    var rows = Object.keys(templateMap || {}).map(function (name) {
      return buildSettingsTemplateRow(name, templateMap[name]);
    });
    $('#settings-template-list').replaceChildren.apply($('#settings-template-list'), rows);
    renderSettingsTemplateEmpty();
  }

  function addSettingsTemplate(name, message) {
    var list = $('#settings-template-list');
    if ($all('[data-settings-template]', list).length >= 32) {
      toast('Broadcast templates are limited to 32 entries.', 'warn'); return null;
    }
    var empty = $('.settings-template-empty', list); if (empty) empty.remove();
    var row = buildSettingsTemplateRow(name || '', message || ''); list.append(row);
    updateSettingsDirtyState();
    return row;
  }

  function addStarterAnnouncementTemplates() {
    var existing = new Set($all('[data-template-field="name"]', $('#settings-template-list')).map(function (input) {
      return input.value.trim().toLowerCase();
    }));
    var added = 0;
    Object.keys(STARTER_ANNOUNCEMENT_TEMPLATES).forEach(function (name) {
      if (!existing.has(name.toLowerCase()) && addSettingsTemplate(name, STARTER_ANNOUNCEMENT_TEMPLATES[name])) added += 1;
    });
    toast(added ? plural(added, 'starter template') + ' added. Review and apply to save.' : 'All starter templates are already present.', added ? 'good' : 'warn');
  }

  function readSettingsTemplates() {
    var output = {};
    $all('[data-settings-template]', $('#settings-template-list')).forEach(function (row) {
      var name = $('[data-template-field="name"]', row).value.trim();
      var message = $('[data-template-field="message"]', row).value.trim();
      if (name) output[name] = message;
    });
    return output;
  }

  function renderSettingsProjection(projection) {
    state.settingsProjection = settingsProjectionFromPayload(projection);
    var current = state.settingsProjection;
    var recoveryDisposition = '';
    if (state.automationTokenRecoveryReceipt && state.automationTokenRecoveryNeedsReconciliation) {
      if (state.automationTokenRecoveryInstanceId
        && state.automationTokenRecoveryInstanceId === current.instance.instanceId) {
        recoveryDisposition = automationTokenAckDisposition(
          current.instance.automationToken,
          state.automationTokenRecoveryReceipt,
        );
      } else recoveryDisposition = 'instance-changed';
      clearAutomationTokenRecovery();
    }
    $('#settings-cluster-name').value = current.settings.clusterName;
    var mapCards = current.settings.servers.map(buildSettingsServerCard);
    if (mapCards.length) $('#settings-server-list').replaceChildren.apply($('#settings-server-list'), mapCards);
    else $('#settings-server-list').replaceChildren(element('div', 'settings-server-empty empty-copy', 'No maps configured. Add a map when you are ready to activate the bridge.'));
    var discord = current.settings.discord;
    $('#settings-discord-enabled').checked = discord.enabled;
    $('#settings-discord-token').value = '';
    $('#settings-discord-token').dataset.configured = discord.tokenConfigured ? 'true' : 'false';
    $('#settings-discord-token').placeholder = discord.tokenConfigured ? 'Configured - enter a replacement' : 'Enter the Discord bot token';
    $('#settings-discord-token-help').textContent = discord.tokenConfigured
      ? 'Configured. Enter a new value to replace it.'
      : 'Not configured. Enter the bot token before enabling Discord.';
    $('#settings-discord-application').value = discord.applicationId;
    $('#settings-discord-guild').value = discord.guildId;
    $('#settings-discord-chat-channel').value = discord.chatChannelId;
    $('#settings-discord-audit-channel').value = discord.auditChannelId;
    $('#settings-discord-admin-roles').value = discord.adminRoleIds.join('\n');
    $('#settings-discord-moderator-roles').value = discord.moderatorRoleIds.join('\n');
    $('#settings-discord-relay-roles').value = discord.relayRoleIds.join('\n');
    $('#settings-discord-unlinked').checked = discord.allowUnlinkedChat;
    $('#settings-discord-register').checked = discord.registerCommands;
    $('#settings-discord-clear-token').checked = false;
    $('#settings-discord-clear-token').disabled = !discord.tokenConfigured;
    $('#settings-analytics-enabled').checked = current.settings.analytics.enabled;
    applyDiscordFieldState();
    var moderation = current.settings.moderation;
    renderSettingsTemplates(moderation.announcementTemplates);
    $('#settings-raw-rcon-enabled').checked = moderation.allowRawRcon;
    $('#settings-rcon-allowlist').value = moderation.rawRconAllowlist.join('\n');
    $('#settings-rotate-token').setAttribute('aria-pressed', 'false');
    $('#settings-regenerate-tls').setAttribute('aria-pressed', 'false');
    $('#settings-tls-names').value = current.instance.tls.rotationRequiresExplicitNames
      ? '' : current.instance.tls.additionalSubjectAltNames.join('\n');
    applyTlsStagingState();
    showFormError($('#settings-error'), '');
    showFormError($('#settings-review-error'), '');

    var instance = current.instance;
    var tls = instance.tls;
    var managed = current.managed;
    $('#settings-instance-status').textContent = managed ? 'Protected' : 'Needs attention';
    $('#settings-keystore-status').textContent = keystoreLabel(instance.keystore);
    $('#settings-instance-id').textContent = instance.instanceId || 'Unavailable';
    $('#settings-keystore').textContent = keystoreLabel(instance.keystore);
    $('#settings-managed-badge').textContent = managed ? 'Managed' : 'Unavailable';
    $('#settings-managed-badge').className = 'state-badge ' + (managed ? 'good' : 'bad');
    $('#settings-tls-mode').textContent = tls.mode || 'Managed HTTPS';
    var tlsDetails = [];
    if (tls.fingerprint) tlsDetails.push('Fingerprint ' + tls.fingerprint);
    if (tls.expiresAt) tlsDetails.push('Expires ' + formatDate(tls.expiresAt));
    if (tls.subjectAltNames.length) tlsDetails.push(plural(tls.subjectAltNames.length, 'trusted name'));
    if (!tls.expiryKnown) tlsDetails.push('Leaf expiry unavailable; regenerate to use a fully managed identity');
    if (tls.rotationRequiresExplicitNames) {
      tlsDetails.push('Imported names require explicit DNS/IP replacements before any regeneration');
    }
    $('#settings-tls-detail').textContent = tlsDetails.join(' - ') || 'Certificate details unavailable';
    $('#settings-token-status').textContent = instance.automationToken.deliveryPending
      ? 'Awaiting acknowledgment'
      : instance.automationToken.activationPending
        ? 'Ready for restart'
        : instance.automationToken.configured ? 'Configured' : 'Not configured';

    var maps = current.settings.servers;
    var rconReady = maps.filter(function (server) { return server.passwordConfigured; }).length;
    var profileNeeded = maps.filter(function (server) {
      return server.profileImport.enabled && !server.profileImport.passwordConfigured;
    }).length;
    $('#settings-map-status').textContent = plural(maps.length, 'map');
    $('#settings-map-detail').textContent = rconReady + '/' + maps.length + ' RCON credentials configured'
      + (profileNeeded ? '; ' + plural(profileNeeded, 'profile credential') + ' needed' : '');
    $('#settings-discord-status').textContent = discord.enabled ? (discord.tokenConfigured ? 'Enabled' : 'Needs token') : 'Disabled';
    $('#settings-discord-detail').textContent = discord.enabled ? (discord.guildId ? 'Guild configured' : 'Guild setup needed') : 'Relay integration is off';
    $('#settings-revision-status').textContent = 'Revision ' + String(current.revision);
    $('#settings-restart-copy').textContent = instance.automationToken.deliveryPending
      ? 'An automation-token replacement is staged but has not been acknowledged. The known active token is unchanged. If the displayed replacement was not saved, rotate again. After saving it, select “I saved it” to promote it; only then update automation clients and restart.'
        + (tls.trustUpdateRequired ? ' A replacement HTTPS CA is also staged; trust it on every administrator device before any restart.' : '')
      : instance.automationToken.activationPending
        ? 'The saved and acknowledged automation token is ready to activate. Update every authorized automation client with it before restarting.'
          + (tls.trustUpdateRequired ? ' Trust the replacement HTTPS CA on every administrator device before that restart.' : '')
        : tls.trustUpdateRequired
          ? 'A replacement HTTPS CA is staged. Before restarting, download the current or staged CA below, install it on every administrator device, and retain the old CA until the new listener is verified.'
          : 'Select Restart now to activate the saved configuration. With Docker Compose, the container returns automatically.';
    $('#settings-restart-now').disabled = instance.automationToken.deliveryPending;
    setHidden($('#settings-restart-banner'), !(restartRequired(current.restartRequired)
      || instance.automationToken.deliveryPending || instance.automationToken.activationPending));
    if (recoveryDisposition === 'confirmed') {
      toast(instance.automationToken.activationPending
        ? 'The earlier token acknowledgment is confirmed. Update automation clients before restarting.'
        : 'The earlier token acknowledgment is confirmed and the saved replacement is active.', 'good', 12_000);
    } else if (recoveryDisposition === 'pending') {
      toast('The earlier token acknowledgment did not commit. Its browser copy was cleared when the session ended; rotate again before restarting.', 'warn', 12_000);
    } else if (recoveryDisposition) {
      toast('The earlier token acknowledgment could not be matched to this instance. The browser receipt was cleared; verify Settings before restarting.', 'warn', 12_000);
    }
    state.settingsBaseline = JSON.stringify(readSettingsForm(false));
    updateSettingsDirtyState();
  }

  function splitSettingsList(value) {
    return safeString(value, 8_192).split(/[\s,]+/u).map(function (entry) { return entry.trim(); }).filter(Boolean);
  }

  function splitSettingsLines(value) {
    return safeString(value, 8_192).split(/\r?\n/u).map(function (entry) { return entry.trim(); }).filter(Boolean);
  }

  function settingControl(card, field) {
    return $('[data-setting-field="' + field + '"]', card);
  }

  function settingNumber(card, field) {
    var input = settingControl(card, field);
    if (!input || input.value === '') return null;
    var number = Number(input.value);
    return Number.isFinite(number) ? Math.floor(number) : null;
  }

  function readSettingsServer(card, includeSecrets) {
    var profileEnabled = settingControl(card, 'profile.enabled').checked;
    var profile = {
      enabled: profileEnabled,
      host: settingControl(card, 'profile.host').value.trim(),
      port: settingNumber(card, 'profile.port'),
      username: settingControl(card, 'profile.username').value.trim(),
      hostKeySha256: settingControl(card, 'profile.hostKeySha256').value.trim(),
      mapName: settingControl(card, 'profile.mapName').value.trim(),
      directories: splitSettingsLines(settingControl(card, 'profile.directories').value),
      connectTimeoutMs: settingNumber(card, 'profile.connectTimeoutMs'),
      operationTimeoutMs: settingNumber(card, 'profile.operationTimeoutMs'),
      retryIntervalMs: settingNumber(card, 'profile.retryIntervalMs'),
      revalidateIntervalMs: settingNumber(card, 'profile.revalidateIntervalMs'),
      maxFileBytes: settingNumber(card, 'profile.maxFileBytes'),
      clearPassword: settingControl(card, 'profile.clearPassword').checked
    };
    var server = {
      id: settingControl(card, 'id').value.trim(),
      name: settingControl(card, 'name').value.trim(),
      host: settingControl(card, 'host').value.trim(),
      port: settingNumber(card, 'port'),
      enabled: settingControl(card, 'enabled').checked,
      pollIntervalMs: settingNumber(card, 'pollIntervalMs'),
      playerRefreshIntervalMs: settingNumber(card, 'playerRefreshIntervalMs'),
      connectTimeoutMs: settingNumber(card, 'connectTimeoutMs'),
      commandTimeoutMs: settingNumber(card, 'commandTimeoutMs'),
      fragmentIdleMs: settingNumber(card, 'fragmentIdleMs'),
      retries: settingNumber(card, 'retries'),
      profileImport: profile
    };
    if (includeSecrets) {
      var rconPassword = settingControl(card, 'password').value;
      var sftpPassword = settingControl(card, 'profile.password').value;
      if (rconPassword) server.password = rconPassword;
      if (sftpPassword) profile.password = sftpPassword;
    }
    return server;
  }

  function readSettingsForm(includeSecrets) {
    var discord = {
      enabled: $('#settings-discord-enabled').checked,
      applicationId: $('#settings-discord-application').value.trim(),
      guildId: $('#settings-discord-guild').value.trim(),
      chatChannelId: $('#settings-discord-chat-channel').value.trim(),
      auditChannelId: $('#settings-discord-audit-channel').value.trim(),
      adminRoleIds: splitSettingsList($('#settings-discord-admin-roles').value),
      moderatorRoleIds: splitSettingsList($('#settings-discord-moderator-roles').value),
      relayRoleIds: splitSettingsList($('#settings-discord-relay-roles').value),
      allowUnlinkedChat: $('#settings-discord-unlinked').checked,
      registerCommands: $('#settings-discord-register').checked,
      clearToken: $('#settings-discord-clear-token').checked
    };
    if (includeSecrets && $('#settings-discord-token').value) discord.token = $('#settings-discord-token').value;
    return {
      clusterName: $('#settings-cluster-name').value.trim(),
      servers: $all('[data-settings-server]', $('#settings-server-list')).map(function (card) {
        return readSettingsServer(card, includeSecrets);
      }),
      discord: discord,
      analytics: { enabled: $('#settings-analytics-enabled').checked },
      moderation: {
        allowRawRcon: $('#settings-raw-rcon-enabled').checked,
        rawRconAllowlist: splitSettingsLines($('#settings-rcon-allowlist').value),
        announcementTemplates: readSettingsTemplates()
      }
    };
  }

  function settingsSecurityStaged(selector) {
    var button = $(selector);
    return Boolean(button && button.getAttribute('aria-pressed') === 'true');
  }

  function settingsChangeSummary() {
    if (!state.settingsProjection || !state.settingsBaseline) return [];
    var baseline;
    try { baseline = JSON.parse(state.settingsBaseline); }
    catch (_) {
      // The baseline is generated locally; malformed state fails closed with no reviewable changes.
      return [];
    }
    var current = readSettingsForm(false);
    var changes = [];
    if (baseline.clusterName !== current.clusterName) changes.push('General: Update cluster name');
    var oldMaps = new Map(baseline.servers.map(function (server) { return [server.id, server]; }));
    var newMaps = new Map(current.servers.map(function (server) { return [server.id, server]; }));
    oldMaps.forEach(function (server, id) {
      if (!newMaps.has(id)) changes.push('Map servers: Remove ' + safeString(server.name || id || 'map', 100));
    });
    newMaps.forEach(function (server, id) {
      var previous = oldMaps.get(id);
      if (!previous) {
        changes.push('Map servers: Add ' + safeString(server.name || id || 'new map', 100));
        return;
      }
      var previousRcon = Object.assign({}, previous); delete previousRcon.profileImport;
      var currentRcon = Object.assign({}, server); delete currentRcon.profileImport;
      if (JSON.stringify(previousRcon) !== JSON.stringify(currentRcon)) {
        changes.push(safeString(server.name || id, 100) + ': Update RCON and map settings');
      }
      if (JSON.stringify(previous.profileImport) !== JSON.stringify(server.profileImport)) {
        changes.push(safeString(server.name || id, 100) + ': Update profile import settings');
      }
    });
    $all('[data-settings-server]', $('#settings-server-list')).forEach(function (card) {
      var name = safeString(settingControl(card, 'name').value || settingControl(card, 'id').value || 'Map', 100);
      if (settingControl(card, 'password').value) changes.push(name + ': Replace RCON password');
      if (settingControl(card, 'profile.password').value) changes.push(name + ': Replace SFTP password');
      if (settingControl(card, 'profile.clearPassword').checked) changes.push(name + ': Delete stored SFTP password');
    });
    if (JSON.stringify(baseline.discord) !== JSON.stringify(current.discord)) changes.push('Discord: Update integration settings');
    if ($('#settings-discord-token').value) changes.push('Discord: Replace bot token');
    if ($('#settings-discord-clear-token').checked) changes.push('Discord: Delete stored bot token');
    if (baseline.analytics.enabled !== current.analytics.enabled) {
      changes.push('Analytics: ' + (current.analytics.enabled ? 'Enable optional product analytics' : 'Disable product analytics'));
    }
    if (JSON.stringify(baseline.moderation.announcementTemplates) !== JSON.stringify(current.moderation.announcementTemplates)) {
      changes.push('Broadcast templates: Update reusable announcements');
    }
    if (baseline.moderation.allowRawRcon !== current.moderation.allowRawRcon
      || JSON.stringify(baseline.moderation.rawRconAllowlist) !== JSON.stringify(current.moderation.rawRconAllowlist)) {
      changes.push('Security: Update advanced console policy');
    }
    if (settingsSecurityStaged('#settings-rotate-token')) changes.push('Security: Rotate automation token');
    if (settingsSecurityStaged('#settings-regenerate-tls')) {
      changes.push('Security: Regenerate HTTPS identity for '
        + plural(splitSettingsLines($('#settings-tls-names').value).length, 'additional endpoint'));
    }
    if (!changes.length && JSON.stringify(current) !== state.settingsBaseline) changes.push('Configuration: Update settings');
    return Array.from(new Set(changes));
  }

  function settingsHasChanges() {
    return settingsChangeSummary().length > 0;
  }

  function updateSettingsDirtyState() {
    if (!state.settingsProjection) return;
    var changes = settingsChangeSummary();
    var dirty = changes.length > 0;
    setHidden($('#settings-change-bar'), !dirty);
    $('#settings-change-status').textContent = dirty ? plural(changes.length, 'change') : 'None';
    $('#settings-change-count').textContent = dirty ? plural(changes.length, 'unsaved change') : 'Unsaved changes';
  }

  function addSettingsServer() {
    if (!state.settingsProjection) return;
    var cards = $all('[data-settings-server]', $('#settings-server-list'));
    if (cards.length >= 64) return toast('Map configuration is limited to 64 servers.', 'warn');
    var used = new Set(cards.map(function (card) { return settingControl(card, 'id').value.toLowerCase(); }));
    var number = cards.length + 1;
    while (used.has('map' + String(number))) number += 1;
    var server = {
      id: 'map' + String(number), name: 'New map ' + String(number), host: '127.0.0.1', port: Math.min(65_535, 27019 + number),
      enabled: true, pollIntervalMs: 1_000, playerRefreshIntervalMs: 15_000, connectTimeoutMs: 3_000,
      commandTimeoutMs: 5_000, fragmentIdleMs: 100, retries: 2, passwordConfigured: false,
      profileImport: {
        enabled: false, host: '127.0.0.1', port: 22, username: '', passwordConfigured: false,
        hostKeySha256: '', mapName: '', directories: [], connectTimeoutMs: 5_000, operationTimeoutMs: 15_000,
        retryIntervalMs: 60_000, revalidateIntervalMs: 300_000, maxFileBytes: 16 * 1024 * 1024
      }
    };
    var card = buildSettingsServerCard(server);
    var empty = $('.settings-server-empty', $('#settings-server-list'));
    if (empty) empty.remove();
    $('#settings-server-list').append(card);
    updateSettingsDirtyState();
    var name = settingControl(card, 'name');
    name.focus(); name.select();
  }

  function discardSettingsChanges(options) {
    if (state.settingsProjection) renderSettingsProjection(state.settingsProjection);
    clearSettingSecretInputs();
    if ($('#settings-review-dialog').open) $('#settings-review-dialog').close();
    if (!options || !options.quiet) toast('Unsaved settings were discarded.', 'good');
  }

  async function loadSettings(options) {
    if (!state.session || !isAdministrator()) return;
    var config = options || {};
    if (state.settingsController) state.settingsController.abort();
    var controller = new AbortController();
    state.settingsController = controller;
    var button = $('#reload-settings');
    if (!config.quiet) setBusy(button, true, 'Refreshing...');
    showFormError($('#settings-error'), '');
    try {
      var result = await api('/admin/api/settings', { signal: controller.signal });
      if (state.settingsController !== controller || !isAdministrator()) return;
      if (!completeManagedSettingsProjection(result)) {
        throw new ApiError('The Settings response was incomplete and was not rendered.', 200, 'INVALID_RESPONSE');
      }
      renderSettingsProjection(result);
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      showFormError($('#settings-error'), errorMessage(error, 'Settings could not be loaded.'));
      $('#settings-instance-status').textContent = 'Unavailable';
      if (!config.quiet) toast(errorMessage(error), 'bad');
    } finally {
      if (state.settingsController === controller) state.settingsController = null;
      if (!config.quiet) setBusy(button, false);
    }
  }

  function validateSettingsForm() {
    var form = $('#settings-form');
    var cards = $all('[data-settings-server]', $('#settings-server-list'));
    showFormError($('#settings-error'), '');
    $all('[data-setting-field="id"]', $('#settings-server-list')).forEach(function (input) {
      input.setCustomValidity('');
    });
    $all('[data-setting-field="profile.directories"]', $('#settings-server-list')).forEach(function (input) {
      input.setCustomValidity('');
    });
    var ids = new Set();
    for (var card of cards) {
      var idInput = settingControl(card, 'id');
      var id = idInput.value.trim().toLowerCase();
      if (ids.has(id)) {
        idInput.setCustomValidity('Each map ID must be unique.');
        idInput.reportValidity();
        return false;
      }
      ids.add(id);
      var directoryInput = settingControl(card, 'profile.directories');
      if (splitSettingsLines(directoryInput.value).length > 16) {
        directoryInput.setCustomValidity('Profile directories are limited to 16 paths.');
        directoryInput.reportValidity();
        return false;
      }
    }
    var templateNames = new Set();
    var templateRows = $all('[data-settings-template]', $('#settings-template-list'));
    if (templateRows.length > 32) {
      showFormError($('#settings-error'), 'Broadcast templates are limited to 32 entries.'); return false;
    }
    for (var templateRow of templateRows) {
      var templateNameInput = $('[data-template-field="name"]', templateRow);
      var templateMessageInput = $('[data-template-field="message"]', templateRow);
      templateNameInput.setCustomValidity(''); templateMessageInput.setCustomValidity('');
      var templateName = templateNameInput.value.trim().toLowerCase();
      if (templateNames.has(templateName)) {
        templateNameInput.setCustomValidity('Template names must be unique.');
        templateNameInput.reportValidity(); return false;
      }
      templateNames.add(templateName);
      if (!validateCodePointMaximum(templateMessageInput)) {
        templateMessageInput.reportValidity(); return false;
      }
    }
    for (var roleSelector of ['#settings-discord-admin-roles', '#settings-discord-moderator-roles', '#settings-discord-relay-roles']) {
      var roleInput = $(roleSelector);
      roleInput.setCustomValidity('');
      var roles = splitSettingsList(roleInput.value);
      if (roles.length > 64 || roles.some(function (role) { return !/^\d{17,20}$/u.test(role); })) {
        roleInput.setCustomValidity('Enter at most 64 Discord role IDs, each containing 17-20 digits.');
        roleInput.reportValidity();
        return false;
      }
    }
    var consoleAllowlist = $('#settings-rcon-allowlist');
    consoleAllowlist.setCustomValidity('');
    var consoleVerbs = splitSettingsLines(consoleAllowlist.value);
    if (consoleVerbs.length > 64 || consoleVerbs.some(function (verb) { return !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/u.test(verb); })
      || ($('#settings-raw-rcon-enabled').checked && consoleVerbs.length === 0)) {
      consoleAllowlist.setCustomValidity('Enter 1-64 single command verbs when the advanced console is enabled.');
      consoleAllowlist.reportValidity();
      return false;
    }
    var tlsNamesInput = $('#settings-tls-names');
    tlsNamesInput.setCustomValidity('');
    if (settingsSecurityStaged('#settings-regenerate-tls')) {
      var tlsNames = splitSettingsLines(tlsNamesInput.value);
      if (state.settingsProjection?.instance?.tls?.rotationRequiresExplicitNames && tlsNames.length === 0) {
        tlsNamesInput.setCustomValidity('Enter the complete replacement DNS/IP name set for this imported HTTPS identity.');
        tlsNamesInput.reportValidity();
        return false;
      }
      var validTlsName = function (name) {
        var normalized = name.toLowerCase();
        if (normalized.includes('%') || /[\u0000-\u0020\u007f]/u.test(normalized)) return false;
        if (/^\d{1,3}(?:\.\d{1,3}){3}$/u.test(normalized)) {
          return normalized.split('.').every(function (part) { return Number(part) >= 0 && Number(part) <= 255; });
        }
        if (normalized.includes(':')) {
          try { return new URL('https://[' + normalized.replace(/^\[|\]$/gu, '') + ']/').hostname.length > 0; }
          catch (_) {
            // URL construction is syntax validation here; a parse failure means the address is invalid.
            return false;
          }
        }
        return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/u.test(normalized);
      };
      if (tlsNames.length > 16 || tlsNames.some(function (name) { return !validTlsName(name); })) {
        tlsNamesInput.setCustomValidity('Enter at most 16 valid DNS names or IP addresses, one per line.');
        tlsNamesInput.reportValidity();
        return false;
      }
    }
    var valid = form.reportValidity();
    if (!valid) showFormError($('#settings-error'), 'Review the highlighted configuration fields.');
    return valid;
  }

  function reviewSettings(event) {
    event.preventDefault();
    if (!validateSettingsForm()) return;
    var changes = settingsChangeSummary();
    if (!changes.length) return toast('There are no settings changes to apply.', 'warn');
    $('#settings-review-list').replaceChildren.apply($('#settings-review-list'), changes.map(function (change) {
      return element('li', '', change);
    }));
    $('#settings-review-impact').textContent = settingsSecurityStaged('#settings-regenerate-tls')
      ? 'Saving stages a new HTTPS CA. After Apply and before restart, download and install the staged CA on every administrator device. Keep the old CA until the restarted listener is verified.'
      : 'Restart the service to activate these changes.';
    showFormError($('#settings-review-error'), '');
    showFormError($('#settings-reauthentication-error'), '');
    updateSettingsReauthenticationState();
    $('#settings-review-dialog').showModal();
    window.setTimeout(function () {
      if (!$('#settings-reauthentication-form').hidden) $('#settings-current-password').focus();
      else ($('#settings-apply-restart').disabled ? $('#settings-apply') : $('#settings-apply-restart')).focus();
    }, 0);
  }

  function hasRecentAuthentication() {
    var expiresAt = timestamp(state.session && state.session.recentAuthenticationExpiresAt);
    // Leave a small margin so authentication cannot expire while the settings
    // request is being assembled and transmitted.
    return expiresAt !== null && expiresAt > Date.now() + 5_000;
  }

  function updateSettingsReauthenticationState(forceRequired) {
    var required = Boolean(forceRequired || !hasRecentAuthentication());
    setHidden($('#settings-reauthentication-form'), !required);
    $('#settings-apply').disabled = required;
    $('#settings-apply-restart').disabled = required
      || settingsSecurityStaged('#settings-regenerate-tls')
      || settingsSecurityStaged('#settings-rotate-token');
    return required;
  }

  async function handleSettingsReauthentication(event) {
    event.preventDefault();
    var form = event.currentTarget;
    if (!form.reportValidity() || !state.session || !isAdministrator()) return;
    var input = $('#settings-current-password');
    var button = $('#settings-reauthenticate');
    var password = input.value;
    setBusy(button, true, 'Confirming...');
    showFormError($('#settings-reauthentication-error'), '');
    var confirmation = api('/admin/api/session/reauthenticate', {
      method: 'POST', csrf: true, body: { currentPassword: password }
    });
    password = '';
    input.value = '';
    try {
      var result = await confirmation;
      var expiresAt = timestamp(result && result.recentAuthenticationExpiresAt);
      if (!result || result.ok !== true || expiresAt === null || expiresAt <= Date.now()) {
        throw incompleteMutationResponse('The password confirmation response was incomplete.');
      }
      state.session.recentAuthenticationExpiresAt = expiresAt;
      updateSettingsReauthenticationState();
      toast('Password confirmed. You can apply these settings now.', 'good');
      ($('#settings-apply-restart').disabled ? $('#settings-apply') : $('#settings-apply-restart')).focus();
    } catch (error) {
      showFormError($('#settings-reauthentication-error'), errorMessage(error));
      updateSettingsReauthenticationState(true);
      input.focus();
    } finally {
      setBusy(button, false);
    }
  }

  function scrubSettingsRequest(requestBody) {
    if (!requestBody || !requestBody.settings) return;
    if (requestBody.settings.discord && requestBody.settings.discord.token) requestBody.settings.discord.token = '';
    (requestBody.settings.servers || []).forEach(function (server) {
      if (server.password) server.password = '';
      if (server.profileImport && server.profileImport.password) server.profileImport.password = '';
    });
  }

  function showAutomationToken(value, deliveryId) {
    var token = safeString(value, 256);
    var receipt = safeString(deliveryId, 64);
    if (!token || !/^[A-Za-z0-9_-]{43}$/u.test(receipt)) return;
    // Keep the one-time value on screen until the administrator explicitly
    // acknowledges saving it; background refreshes must not erase the dialog.
    // Pause network work without disabling the independent session-expiry
    // watchdog, which must still clear this value if the session expires.
    stopNetworkActivity();
    clearAutomationTokenRecovery();
    var input = $('#settings-automation-token');
    state.pendingAutomationTokenDeliveryId = receipt;
    input.value = token;
    input.type = 'password';
    var toggle = $('[data-password-target="settings-automation-token"]');
    toggle.textContent = 'Show';
    toggle.setAttribute('aria-pressed', 'false');
    toggle.setAttribute('aria-label', 'Show automation token');
    $('#settings-token-dialog').showModal();
    window.setTimeout(function () { input.focus(); input.select(); }, 0);
    token = ''; receipt = '';
  }

  async function acknowledgeAutomationToken() {
    var button = $('#settings-close-token');
    var expectedRevision = state.settingsProjection && state.settingsProjection.revision;
    var deliveryId = state.pendingAutomationTokenDeliveryId;
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1) {
      toast('Refresh Settings before acknowledging this token.', 'bad');
      return;
    }
    state.automationTokenRecoveryReceipt = deliveryId;
    state.automationTokenRecoveryInstanceId = safeString(state.settingsProjection?.instance?.instanceId, 128);
    state.automationTokenRecoveryNeedsReconciliation = false;
    setBusy(button, true, 'Saving...');
    try {
      var result = await api('/admin/api/settings/automation-token/ack', {
        method: 'POST', csrf: true, body: { expectedRevision: expectedRevision, deliveryId: deliveryId }
      });
      if (!completeManagedSettingsProjection(result) || result.revision <= expectedRevision
        || result.instance.automationToken.deliveryPending !== false
        || result.instance.automationToken.activationReceipt !== deliveryId) {
        throw incompleteMutationResponse('The token-acknowledgment response was incomplete.');
      }
      clearAutomationTokenRecovery();
      renderSettingsProjection(result);
      clearOneTimeAutomationToken();
      $('#settings-token-dialog').close();
      startPolling();
      await refreshBootstrap({ force: true, quiet: true });
      toast('Automation token saved and staged for activation on restart.', 'good');
    } catch (error) {
      if (error && error.mutationCommitted) {
        var tlsTrustUpdateRequired = Boolean(state.settingsProjection?.instance?.tls?.trustUpdateRequired);
        clearOneTimeAutomationToken();
        clearAutomationTokenRecovery();
        $('#settings-token-dialog').close();
        startPolling();
        $('#settings-restart-copy').textContent = 'The saved token was promoted, but its audit confirmation failed. Repair audit log storage and update automation clients with the saved token.'
          + (tlsTrustUpdateRequired ? ' Before restarting, download and trust the staged HTTPS CA on every administrator device and retain the old CA until the new listener is verified.' : '')
          + ' Restart the service before making another change.';
        setHidden($('#settings-restart-banner'), false);
        toast('Token acknowledgment was committed; repair audit logging before restart.', 'warn', 12_000);
        return;
      }
      if (error && error.code === 'token_delivery_replaced') {
        clearOneTimeAutomationToken();
        clearAutomationTokenRecovery();
        $('#settings-token-dialog').close();
        startPolling();
        await loadSettings({ quiet: true });
        toast('Another token rotation replaced the displayed value. Rotate again and save the new token; the obsolete value was cleared.', 'warn', 12_000);
        return;
      }
      if (mutationOutcomeUnknown(error) || (error && error.code === 'token_delivery_not_pending')) {
        await loadSettings({ quiet: true });
        // A 401 during reconciliation has already locked the console, cleared
        // the bearer from the DOM, and retained only its non-secret receipt.
        // Preserve that receipt for the next in-page sign-in and Settings load.
        if (!state.session || !state.settingsProjection) return;
        var tokenState = state.settingsProjection?.instance?.automationToken;
        var pending = Boolean(tokenState?.deliveryPending);
        var receiptMatches = Boolean(deliveryId && tokenState?.activationReceipt === deliveryId);
        if (receiptMatches) {
          clearOneTimeAutomationToken();
          clearAutomationTokenRecovery();
          $('#settings-token-dialog').close();
          startPolling();
          toast('Token acknowledgment was confirmed by refreshed Settings.', 'good');
        } else if (pending) {
          toast('Acknowledgment was not confirmed. The token remains displayed; save it and try “I saved it” again before restarting.', 'warn', 12_000);
        } else {
          clearOneTimeAutomationToken();
          clearAutomationTokenRecovery();
          $('#settings-token-dialog').close();
          startPolling();
          toast('The displayed token could not be proven as the promoted replacement. It was cleared; rotate again before changing automation clients or restarting.', 'warn', 12_000);
        }
        return;
      }
      toast(errorMessage(error), 'bad');
    } finally {
      expectedRevision = 0;
      deliveryId = '';
      setBusy(button, false);
    }
  }

  async function restartApplication() {
    await api('/admin/api/settings/restart', { method: 'POST', csrf: true, body: {} });
    toast('Restart accepted. Reconnect in a few seconds.', 'good', 10_000);
  }

  async function restartNow() {
    var button = $('#settings-restart-now');
    setBusy(button, true, 'Restarting...');
    try { await restartApplication(); }
    catch (error) { toast(errorMessage(error), 'bad', 10_000); setBusy(button, false); }
  }

  async function applySettings(event) {
    if (!state.settingsProjection || !isAdministrator()) return;
    if (updateSettingsReauthenticationState()) {
      showFormError($('#settings-review-error'), 'Confirm your current password before applying these settings.');
      $('#settings-current-password').focus();
      return;
    }
    var restartAfterApply = event && event.currentTarget && event.currentTarget.id === 'settings-apply-restart';
    var form = $('#settings-form');
    if (!validateSettingsForm()) {
      $('#settings-review-dialog').close();
      var invalid = $(':invalid', form);
      if (invalid) invalid.focus();
      return;
    }
    var secretLabels = $all('.settings-secret-input').filter(function (input) { return Boolean(input.value); })
      .map(function (input) { return safeString(input.dataset.secretLabel, 80); });
    var expectedSettingsRevision = state.settingsProjection.revision;
    var requestBody = {
      expectedRevision: expectedSettingsRevision,
      settings: readSettingsForm(true)
    };
    var automationTokenRotationRequested = settingsSecurityStaged('#settings-rotate-token');
    if (automationTokenRotationRequested) requestBody.rotateAutomationToken = true;
    var tlsRegenerationRequested = settingsSecurityStaged('#settings-regenerate-tls');
    if (tlsRegenerationRequested) {
      requestBody.regenerateTls = true;
      requestBody.tlsSubjectAltNames = splitSettingsLines($('#settings-tls-names').value);
    }
    var button = event && event.currentTarget ? event.currentTarget : $('#settings-apply');
    setBusy(button, true, 'Applying...');
    showFormError($('#settings-review-error'), '');
    var saveRequest = api('/admin/api/settings', { method: 'PUT', csrf: true, body: requestBody });
    clearSettingSecretInputs();
    scrubSettingsRequest(requestBody);
    requestBody = null;
    updateSettingsDirtyState();
    try {
      var result = await saveRequest;
      if (!isAdministrator()) return;
      if (!completeManagedSettingsProjection(result)
        || result.revision !== expectedSettingsRevision + 1
        || (automationTokenRotationRequested && (!/^[A-Za-z0-9_-]{64}$/u.test(result.automationToken || '')
          || !/^[A-Za-z0-9_-]{43}$/u.test(result.automationTokenDeliveryId || '')
          || result.instance.automationToken.deliveryPending !== true))
        || (tlsRegenerationRequested && result.instance.tls?.trustUpdateRequired !== true)) {
        throw new ApiError('The Settings response was incomplete; the outcome must be verified.', 200, 'INVALID_SETTINGS_RESPONSE');
      }
      var oneTimeToken = safeString(result && result.automationToken, 256);
      var analyticsContact = result && jsonRecord(result.analyticsContact) ? result.analyticsContact : null;
      renderSettingsProjection(result);
      $('#settings-review-dialog').close();
      if (analyticsContact && analyticsContact.attempted === true) {
        toast(analyticsContact.delivered === true
          ? 'Analytics enabled and the initial contact was sent.'
          : analyticsContact.reasonCode === 'collector_browser_challenge'
            ? 'Analytics was enabled, but Cloudflare blocked the collector request with a browser challenge.'
            : 'Analytics was enabled, but the initial contact could not be sent.',
        analyticsContact.delivered === true ? 'good' : 'warn', analyticsContact.delivered === true ? 5_000 : 12_000);
      } else toast('Settings saved successfully.', 'good');
      if (oneTimeToken) showAutomationToken(oneTimeToken, result.automationTokenDeliveryId);
      oneTimeToken = '';
      if (restartAfterApply && !$('#settings-token-dialog').open) {
        try { await restartApplication(); }
        catch (restartError) {
          setHidden($('#settings-restart-banner'), false);
          toast('Settings were saved, but restart failed: ' + errorMessage(restartError), 'warn', 12_000);
        }
        return;
      }
      if (!$('#settings-token-dialog').open) await refreshBootstrap({ force: true, quiet: true });
    } catch (error) {
      if (error && error.settingsCommitted) {
        $('#settings-review-dialog').close();
        for (var stageSelector of ['#settings-rotate-token', '#settings-regenerate-tls']) {
          $(stageSelector).setAttribute('aria-pressed', 'false');
        }
        applyTlsStagingState();
        state.settingsBaseline = JSON.stringify(readSettingsForm(false));
        updateSettingsDirtyState();
        var trustUpdateRequired = Boolean(error.tlsTrustUpdateRequired || tlsRegenerationRequested);
        var tokenDeliveryFailed = Boolean(error.automationTokenDeliveryFailed || automationTokenRotationRequested);
        $('#settings-restart-copy').textContent = tokenDeliveryFailed
          ? 'Settings were committed, but the staged replacement automation token could not be safely delivered because audit confirmation failed. The known active token was preserved.'
            + (trustUpdateRequired ? ' Before the first restart, download and trust the current or staged CA below, and retain the old CA until the new listener is verified.' : '')
            + ' Repair audit logging, restart, sign in, rotate again, save the displayed token, select “I saved it,” update automation clients, and then restart once more to activate it.'
          : trustUpdateRequired
            ? 'Settings were committed, but audit confirmation failed. Before restarting, download the current or staged CA below, install it on every administrator device, and retain the old CA until the new listener is verified.'
            : 'Settings were committed, but audit confirmation failed. Restart the application before making another change.';
        setHidden($('#settings-restart-banner'), false);
        showFormError($('#settings-error'), errorMessage(error));
        toast(tokenDeliveryFailed
          ? 'The committed automation token was not delivered; review the two-restart recovery warning.'
          : 'Settings were committed; review the restart warning.', 'warn');
        return;
      }
      var networkOutcomeUnknown = mutationOutcomeUnknown(error);
      if (networkOutcomeUnknown) {
        $('#settings-review-dialog').close();
        for (var uncertainStageSelector of ['#settings-rotate-token', '#settings-regenerate-tls']) {
          $(uncertainStageSelector).setAttribute('aria-pressed', 'false');
        }
        applyTlsStagingState();
        updateSettingsDirtyState();
        var rotationRecovery = automationTokenRotationRequested
          ? ' If the revision advanced, the known active token remains in use while the undelivered replacement is staged. Rotate again, save the displayed token, acknowledge it, update clients, and only then restart.'
          : '';
        var tlsRecovery = tlsRegenerationRequested
          ? ' If the revision advanced, download and trust the current or staged CA before any intentional restart.'
          : '';
        $('#settings-restart-copy').textContent = 'The connection or Settings response was lost or incomplete after the change may have been committed. Do not retry or intentionally restart yet. Reconnect and refresh Settings first to determine whether its revision advanced. If refresh reports audit logging unavailable, assume the security change committed: repair logging and trust the current or staged CA before restart if TLS was requested. An undelivered automation-token replacement remains staged separately, so the known active token is preserved until a displayed replacement is explicitly acknowledged.'
          + tlsRecovery + rotationRecovery;
        setHidden($('#settings-restart-banner'), false);
        showFormError($('#settings-error'), 'The Settings outcome is unknown. Refresh before making another change. Entered secret values were cleared.');
        toast('Settings outcome unknown; reconnect and refresh before retrying or restarting.', 'warn');
        return;
      }
      var suffix = secretLabels.length ? ' Entered secret values were cleared; re-enter them before retrying.' : '';
      if (error && error.code === 'reauthentication_required') {
        if (state.session) state.session.recentAuthenticationExpiresAt = 0;
        updateSettingsReauthenticationState(true);
        $('#settings-current-password').focus();
      }
      showFormError($('#settings-review-error'), errorMessage(error) + suffix);
      showFormError($('#settings-error'), errorMessage(error) + suffix);
    } finally {
      secretLabels = [];
      expectedSettingsRevision = 0;
      automationTokenRotationRequested = false;
      tlsRegenerationRequested = false;
      restartAfterApply = false;
      setBusy(button, false);
    }
  }

  async function handlePasswordChange(event) {
    event.preventDefault();
    var form = event.currentTarget;
    if (!form.reportValidity()) return;
    var currentInput = $('#current-password');
    var newInput = $('#new-password');
    var confirmationInput = $('#new-password-confirmation');
    if (newInput.value !== confirmationInput.value) {
      confirmationInput.setCustomValidity('Passwords do not match.');
      confirmationInput.reportValidity();
      return;
    }
    confirmationInput.setCustomValidity('');
    var currentPassword = currentInput.value;
    var newPassword = newInput.value;
    var passwordConfirmation = confirmationInput.value;
    currentInput.value = ''; newInput.value = ''; confirmationInput.value = '';
    var button = $('#save-password-button');
    showFormError($('#change-password-error'), '');
    setBusy(button, true, 'Changing...');
    try {
      var result = await api('/admin/api/session/password', {
        method: 'POST', csrf: true,
        body: { currentPassword: currentPassword, newPassword: newPassword, passwordConfirmation: passwordConfirmation }
      });
      if (!result || result.ok !== true) throw incompleteMutationResponse('The password-change response was incomplete.');
      currentPassword = ''; newPassword = ''; passwordConfirmation = '';
      state.passwordChangeRequired = false;
      $('#change-password-dialog').dataset.forced = 'false';
      $('#change-password-dialog').close();
      form.reset();
      await refreshBootstrap({ force: true, quiet: true });
      toast('Password changed. Other sessions were signed out.', 'good');
    } catch (error) {
      currentPassword = ''; newPassword = ''; passwordConfirmation = '';
      if (error && error.mutationCommitted) {
        lockConsole('Your new password was saved, but audit confirmation failed and all sessions were revoked. Repair audit log storage, restart the service, then sign in with the new password. Do not submit the password change again.');
        return;
      }
      if (mutationOutcomeUnknown(error)) {
        lockConsole('The password-change response was lost or incomplete. Sign in with the new password first; if it is rejected, try the previous credential once. Do not resubmit the change blindly.');
        return;
      }
      showFormError($('#change-password-error'), errorMessage(error));
      currentInput.focus();
    } finally {
      setBusy(button, false);
      currentInput.value = ''; newInput.value = ''; confirmationInput.value = '';
    }
  }

  function actionDefinitions() {
    var defaultMute = numeric(state.capabilities.defaultMuteMinutes, 15);
    var maxMute = numeric(state.capabilities.maxMuteMinutes, 43_200);
    var announcementMaxLength = Math.max(1, numeric(state.capabilities.announcementMaxLength, 400));
    var restartReasonMaxLength = Math.max(1, numeric(state.capabilities.restartReasonMaxLength, 160));
    return {
      'announce': {
        title: 'Send server broadcast',
        description: 'Send an ASA broadcast to one map or the cluster.',
        fields: [
          { name: 'message', label: 'Broadcast message', type: 'textarea', required: true, codePointMaxLength: announcementMaxLength, full: true, placeholder: 'Maintenance begins in 15 minutes.' },
          { name: 'server', label: 'Map target', type: 'server', cluster: true }
        ]
      },
      'announce-template': {
        title: 'Send broadcast template',
        description: 'Choose and send a saved broadcast.',
        fields: [
          { name: 'template', label: 'Template', type: 'template', required: true },
          { name: 'server', label: 'Map target', type: 'server', cluster: true }
        ]
      },
      'save-world': {
        title: 'Save world',
        description: 'Request a world save on one map or the whole cluster.',
        fields: [{ name: 'server', label: 'Map target', type: 'server', cluster: true }]
      },
      'restart': {
        title: 'Schedule restart window',
        description: 'Broadcast visible countdown warnings and save the selected map at the deadline.',
        fields: [
          { name: 'minutes', label: 'Minutes from now', type: 'number', required: true, min: 1, max: 10_080, value: 15 },
          { name: 'server', label: 'Map target', type: 'server', cluster: true },
          { name: 'reason', label: 'Reason', type: 'text', codePointMaxLength: restartReasonMaxLength, full: true, placeholder: 'Scheduled maintenance' }
        ]
      },
      'cancel-restart': {
        title: 'Cancel restart window',
        description: 'Remove an active countdown from one map or the whole cluster.',
        fields: [{ name: 'server', label: 'Map target', type: 'server', cluster: true }]
      },
      'give-item': {
        title: 'Give catalog item',
        description: 'Give an item to a connected player.',
        fields: [
          { name: 'player', label: 'Connected player', type: 'player', required: true, full: true },
          { name: 'item', label: 'Catalog item', type: 'item', required: true, full: true, placeholder: 'Search item name, GFI, or item number' },
          { name: 'quantity', label: 'Quantity', type: 'number', min: 1, max: 10_000, value: 1 },
          { name: 'quality', label: 'Quality', type: 'number', min: 0, max: 100, step: 'any', value: 0 },
          { name: 'blueprint', label: 'Give as blueprint', type: 'checkbox', full: true }
        ]
      },
      'give-xp': {
        title: 'Give experience',
        description: 'Grant bounded XP to a verified connected survivor.',
        fields: [
          { name: 'player', label: 'Connected player', type: 'player', required: true, full: true },
          { name: 'amount', label: 'XP amount', type: 'number', min: 1, max: 1_000_000_000, required: true, value: 500, full: true },
          { name: 'from-tribe', label: 'Treat as tribe share', type: 'checkbox' },
          { name: 'share-with-tribe', label: 'Share with tribe members', type: 'checkbox' }
        ]
      },
      'refresh-player-id': {
        title: 'Verify player targeting',
        description: 'Read profile metadata and refresh the private numeric mapping. No RCON mutation is sent.',
        fields: [{ name: 'player', label: 'Connected player', type: 'player', required: true, full: true }]
      },
      'player': {
        title: 'View player staff record',
        description: 'View status, playtime, targeting, and staff notes.',
        fields: [{ name: 'player', label: 'Connected player', type: 'player', required: true, full: true }]
      },
      'warn': {
        title: 'Warn player',
        description: 'Send a private staff warning to the selected connected player.',
        fields: [
          { name: 'player', label: 'Connected player', type: 'player', required: true, full: true },
          { name: 'message', label: 'Warning message', type: 'textarea', required: true, maxLength: 500, full: true }
        ]
      },
      'note': {
        title: 'Add staff note',
        description: 'Save a private moderation note for the selected player.',
        fields: [
          { name: 'player', label: 'Connected player', type: 'player', required: true, full: true },
          { name: 'type', label: 'Category', type: 'select', value: 'note', options: [
            ['note', 'General note'], ['incident', 'Incident / tribe dispute'], ['positive', 'Positive note'], ['warning', 'Warning record']
          ], required: true, full: true },
          { name: 'note', label: 'Staff note', type: 'textarea', required: true, maxLength: 1_000, full: true }
        ]
      },
      'mute-player': {
        title: 'Mute player relay',
        description: 'Temporarily prevent the selected player from using Cluster Chat.',
        fields: [
          { name: 'player', label: 'Connected player', type: 'player', required: true, full: true },
          { name: 'minutes', label: 'Mute duration (minutes)', type: 'number', required: true, min: 1, max: maxMute, value: defaultMute },
          { name: 'reason', label: 'Reason', type: 'text', maxLength: 500 }
        ]
      },
      'unmute-player': {
        title: 'Unmute player relay',
        description: 'Restore Cluster Chat access for the selected player.',
        fields: [{ name: 'player', label: 'Connected player', type: 'player', required: true, full: true }]
      },
      'kick': {
        title: 'Kick player',
        description: 'Remove the selected connected player from their current map.',
        fields: [
          { name: 'player', label: 'Connected player', type: 'player', required: true, full: true },
          { name: 'reason', label: 'Audit reason', type: 'text', maxLength: 500, full: true }
        ]
      },
      'ban': {
        title: 'Ban player',
        description: 'Ban the selected connected account from its current map.',
        fields: [
          { name: 'player', label: 'Connected player', type: 'player', required: true, full: true },
          { name: 'reason', label: 'Audit reason', type: 'text', maxLength: 500, full: true }
        ]
      },
      'whitelist': {
        title: 'Add to no-check list',
        description: 'Allow the selected connected account through the map no-check join list.',
        fields: [{ name: 'player', label: 'Connected player', type: 'player', required: true, full: true }]
      },
      'unwhitelist': {
        title: 'Remove from no-check list',
        description: 'Remove the selected connected account from the map no-check join list.',
        fields: [{ name: 'player', label: 'Connected player', type: 'player', required: true, full: true }]
      },
      'destroy-wild-dinos': {
        title: 'Destroy wild dinosaurs',
        description: 'Remove every untamed creature on one map. Respawning takes time.',
        fields: [{ name: 'server', label: 'Map server', type: 'server', required: true }]
      },
      'rcon': {
        title: 'Run allowlisted RCON command',
        description: 'Execute one configured verb. The raw response remains suppressed.',
        fields: [
          { name: 'server', label: 'Map server', type: 'server', required: true },
          { name: 'command', label: 'Allowlisted command', type: 'text', required: true, maxLength: 1_000, full: true }
        ]
      }
    };
  }

  function makeLabel(field) {
    var label = element('label', field.full ? 'full' : '');
    var title = element('span', '', field.label);
    label.append(title);
    if (field.help) label.append(element('span', 'field-help', field.help));
    return label;
  }

  function setCommonFieldAttributes(input, field) {
    input.dataset.option = field.name;
    if (field.required) input.required = true;
    if (field.maxLength) input.maxLength = field.maxLength;
    if (field.codePointMaxLength) configureCodePointMaximum(input, field.codePointMaxLength);
    if (field.placeholder) input.placeholder = field.placeholder;
    if (field.min !== undefined) input.min = String(field.min);
    if (field.max !== undefined) input.max = String(field.max);
    if (field.step !== undefined) input.step = String(field.step);
    input.autocomplete = 'off';
  }

  function validateCodePointMaximum(input) {
    var maximum = Math.max(0, Math.floor(numeric(input && input.dataset && input.dataset.codePointMaxLength, 0)));
    if (!input || maximum < 1) return true;
    var valid = Array.from(input.value || '').length <= maximum;
    input.setCustomValidity(valid ? '' : 'Use no more than ' + String(maximum) + ' characters.');
    return valid;
  }

  function configureCodePointMaximum(input, maximum) {
    var normalized = Math.max(1, Math.floor(numeric(maximum, 1)));
    input.dataset.codePointMaxLength = String(normalized);
    // HTML maxlength counts UTF-16 code units. Two units per allowed code
    // point keeps the native input bounded without rejecting valid emoji.
    input.maxLength = normalized * 2;
    input.addEventListener('input', function () { validateCodePointMaximum(input); });
    validateCodePointMaximum(input);
  }

  function validateCodePointFields(form) {
    return $all('[data-code-point-max-length]', form).every(validateCodePointMaximum);
  }

  function fieldNode(field) {
    var label = makeLabel(field);
    var input;
    if (field.type === 'textarea') {
      input = document.createElement('textarea');
      setCommonFieldAttributes(input, field);
    } else if (field.type === 'server') {
      input = document.createElement('select');
      input.dataset.fieldType = 'server';
      input.dataset.cluster = field.cluster ? 'true' : 'false';
      setCommonFieldAttributes(input, field);
      populateServerSelect(input, {
        required: Boolean(field.required),
        cluster: Boolean(field.cluster),
        defaultValue: state.actionDefaults.server
      });
    } else if (field.type === 'player') {
      input = document.createElement('select');
      input.dataset.fieldType = 'player';
      setCommonFieldAttributes(input, field);
      label.append(input);
      refreshPlayerSelects();
      return label;
    } else if (field.type === 'template') {
      input = document.createElement('select');
      setCommonFieldAttributes(input, field);
      var options = [new Option('Choose a configured template', '')].concat(templates().map(function (entry) {
        return new Option(entry.label, entry.value);
      }));
      input.replaceChildren.apply(input, options);
    } else if (field.type === 'select') {
      input = document.createElement('select');
      setCommonFieldAttributes(input, field);
      var choices = Array.isArray(field.options) ? field.options.map(function (choice) {
        return new Option(safeString(choice[1], 100), safeString(choice[0], 64));
      }) : [];
      input.replaceChildren.apply(input, choices);
    } else if (field.type === 'checkbox') {
      label.className = 'checkbox-field' + (field.full ? ' full' : '');
      input = document.createElement('input');
      input.type = 'checkbox';
      input.dataset.option = field.name;
      var checkboxText = label.firstElementChild;
      label.replaceChildren(input, checkboxText);
      if (state.actionDefaults[field.name] === true || field.value === true) input.checked = true;
      return label;
    } else if (field.type === 'item') {
      return itemFieldNode(field, label);
    } else {
      input = document.createElement('input');
      input.type = field.type === 'number' ? 'number' : 'text';
      setCommonFieldAttributes(input, field);
    }
    var defaultValue = state.actionDefaults[field.name] !== undefined ? state.actionDefaults[field.name] : field.value;
    if (defaultValue !== undefined && defaultValue !== null) input.value = String(defaultValue);
    label.append(input);
    return label;
  }

  function itemFieldNode(field, label) {
    var search = document.createElement('input');
    search.type = 'search';
    search.placeholder = field.placeholder || 'Search catalog';
    search.autocomplete = 'off';
    search.spellcheck = false;
    search.setAttribute('role', 'combobox');
    search.setAttribute('aria-autocomplete', 'list');
    search.setAttribute('aria-expanded', 'false');
    search.setAttribute('aria-controls', 'item-combobox-results');
    if (field.required) search.required = true;
    var hidden = document.createElement('input');
    hidden.type = 'hidden';
    hidden.dataset.option = field.name;
    var results = element('div', 'combobox-results');
    results.id = 'item-combobox-results';
    results.setAttribute('role', 'listbox');
    results.hidden = true;
    label.append(search, hidden, results);
    search.addEventListener('input', function () {
      hidden.value = '';
      search.setCustomValidity('Choose an item from the trusted catalog results.');
      window.clearTimeout(state.itemSearchTimer);
      state.itemSearchTimer = window.setTimeout(function () { loadItems(search.value, search, hidden, results); }, 180);
    });
    search.addEventListener('focus', function () {
      if (!hidden.value) loadItems(search.value, search, hidden, results);
    });
    search.addEventListener('keydown', function (event) { handleItemKeys(event, search, hidden, results); });
    search.addEventListener('blur', function () {
      window.setTimeout(function () {
        if (!label.contains(document.activeElement)) closeItemResults(search, results);
      }, 100);
    });
    return label;
  }

  async function loadItems(query, search, hidden, results) {
    if (state.itemController) state.itemController.abort();
    var controller = new AbortController();
    state.itemController = controller;
    try {
      var params = new URLSearchParams();
      if (query.trim()) params.set('q', query.trim().slice(0, 120));
      var response = await api('/admin/api/items?' + params.toString(), { signal: controller.signal });
      if (state.itemController !== controller || !search.isConnected) return;
      renderItemResults(Array.isArray(response.items) ? response.items : [], search, hidden, results);
    } catch (error) {
      if (error && error.name === 'AbortError') return;
      closeItemResults(search, results);
    } finally {
      if (state.itemController === controller) state.itemController = null;
    }
  }

  function renderItemResults(items, search, hidden, results) {
    var nodes = items.slice(0, 25).filter(function (item) { return item && item.key && item.name; }).map(function (item) {
      var option = element('button', 'combobox-option');
      option.type = 'button';
      option.setAttribute('role', 'option');
      option.dataset.itemKey = safeString(item.key, 100);
      option.append(
        element('strong', '', item.name),
        element('span', '', [item.category, item.gfi ? 'GFI ' + item.gfi : '', item.itemNumber === undefined || item.itemNumber === null ? '' : '#' + item.itemNumber].filter(Boolean).join(' - '))
      );
      if (item.blueprintPath) {
        var blueprint = element('code', 'item-blueprint', safeString(item.blueprintPath, 400));
        blueprint.title = safeString(item.blueprintPath, 400);
        option.append(blueprint);
      }
      option.addEventListener('mousedown', function (event) { event.preventDefault(); });
      option.addEventListener('click', function () { chooseItem(item, search, hidden, results); });
      return option;
    });
    if (!nodes.length) {
      var empty = element('div', 'empty-copy', 'No matching catalog items.');
      results.replaceChildren(empty);
    } else {
      results.replaceChildren.apply(results, nodes);
    }
    results.hidden = false;
    search.setAttribute('aria-expanded', 'true');
  }

  function chooseItem(item, search, hidden, results) {
    search.value = safeString(item.name, 160);
    hidden.value = safeString(item.key, 100);
    search.setCustomValidity('');
    closeItemResults(search, results);
    search.focus();
  }

  function closeItemResults(search, results) {
    results.hidden = true;
    search.setAttribute('aria-expanded', 'false');
    $all('.combobox-option', results).forEach(function (option) { option.classList.remove('active'); });
  }

  function handleItemKeys(event, search, hidden, results) {
    if (results.hidden && ['ArrowDown', 'ArrowUp'].includes(event.key)) {
      loadItems(search.value, search, hidden, results);
      return;
    }
    var options = $all('.combobox-option', results);
    if (!options.length) return;
    var current = options.findIndex(function (option) { return option.classList.contains('active'); });
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      var direction = event.key === 'ArrowDown' ? 1 : -1;
      var next = current < 0 ? (direction > 0 ? 0 : options.length - 1) : (current + direction + options.length) % options.length;
      options.forEach(function (option, index) {
        option.classList.toggle('active', index === next);
        option.setAttribute('aria-selected', index === next ? 'true' : 'false');
      });
      options[next].scrollIntoView({ block: 'nearest' });
    } else if (event.key === 'Enter' && current >= 0) {
      event.preventDefault();
      options[current].click();
    } else if (event.key === 'Escape') {
      event.preventDefault();
      closeItemResults(search, results);
    }
  }

  function openAction(name, defaults, trigger) {
    if (!actionAvailable(name) || (name === 'rcon' && !rawRconEnabled())) {
      toast('This operation is not available to the current operator.', 'warn');
      return;
    }
    var definitions = actionDefinitions();
    var definition = definitions[name];
    if (!definition) {
      toast('This operation does not have a guided dashboard workflow.', 'warn');
      return;
    }
    var suppliedDefaults = Object.assign({}, defaults || {});
    var playerContext = suppliedDefaults.player
      ? state.players.find(function (player) { return player.selection === suppliedDefaults.player; })
        || (state.selectedPlayer && state.selectedPlayer.selection === suppliedDefaults.player ? state.selectedPlayer : null)
      : null;
    state.currentAction = name;
    state.actionPlayers = [];
    state.actionDefaults = Object.assign({}, suppliedDefaults, { player: '' });
    state.pendingAction = null;
    state.lastDialogTrigger = trigger || document.activeElement;
    $('#action-dialog-title').textContent = definition.title;
    $('#action-dialog').querySelector('.dialog-header p:last-child').textContent = definition.description;
    $('#preview-button').textContent = name === 'player' ? 'Open staff record' : 'Review operation';
    showFormError($('#action-dialog').querySelector('.form-error'), '');
    var fields = definition.fields.map(fieldNode);
    $('#action-dialog').querySelector('.form-grid').replaceChildren.apply($('#action-dialog').querySelector('.form-grid'), fields);
    if ($('#player-dialog').open) {
      clearPlayerIdentifierDisclosure();
      $('#player-dialog').close();
    }
    $('#action-dialog').showModal();
    var first = $('#action-dialog').querySelector('input:not([type="hidden"]), select, textarea');
    if (first) first.focus();
    if (definition.fields.some(function (field) { return field.type === 'player'; })) loadActionPlayers(name, playerContext);
    if (definition.fields.some(function (field) { return field.type === 'item'; })) {
      var search = $('#action-dialog input[role="combobox"]');
      if (search) loadItems('', search, $('[data-option="item"]', $('#action-dialog')), $('.combobox-results', $('#action-dialog')));
    }
  }

  function collectActionOptions(form) {
    var options = {};
    $all('[data-option]', form).forEach(function (field) {
      var name = field.dataset.option;
      if (!name) return;
      if (field.type === 'checkbox') {
        options[name] = Boolean(field.checked);
      } else if (field.type === 'number') {
        if (field.value !== '') options[name] = Number(field.value);
      } else {
        var value = field.value.trim();
        if (value !== '') options[name] = value;
      }
    });
    return options;
  }

  async function submitActionForm(event) {
    event.preventDefault();
    var form = event.currentTarget;
    validateCodePointFields(form);
    if (!form.reportValidity()) return;
    var options = collectActionOptions(form);
    if (state.currentAction === 'player') {
      var player = state.actionPlayers.find(function (candidate) { return candidate.selection === options.player; });
      if (!player) {
        showFormError($('#action-dialog').querySelector('.form-error'), 'That player selection expired. Choose a connected player again.');
        return;
      }
      await showStaffRecord(player, state.lastDialogTrigger);
      return;
    }
    await previewAction(state.currentAction, options, { sourceDialog: $('#action-dialog') });
  }

  function summaryText(summary) {
    if (typeof summary === 'string') return safeString(summary, 1_500);
    if (Array.isArray(summary)) return summary.slice(0, 20).map(function (item) { return safeString(item, 200); }).join('\n');
    if (summary && typeof summary === 'object') {
      var lines = [];
      ['title', 'message', 'detail'].forEach(function (key) {
        if (typeof summary[key] === 'string') lines.push(safeString(summary[key], 500));
      });
      if (Array.isArray(summary.details)) {
        summary.details.slice(0, 15).forEach(function (item) { lines.push(safeString(item, 200)); });
      }
      if (lines.length) return lines.join('\n');
    }
    return 'Review the selected operation before it is sent.';
  }

  function riskInfo(value) {
    var risk = safeString(value || 'medium', 20).toLowerCase();
    if (!['low', 'medium', 'high', 'critical'].includes(risk)) risk = 'medium';
    return { value: risk, label: risk.charAt(0).toUpperCase() + risk.slice(1) + ' risk' };
  }

  function configureChallenge(challenge) {
    var wrapper = $('#confirm-dialog').querySelector('.challenge-field');
    var input = $('#confirm-dialog').querySelector('input');
    input.value = '';
    input.required = false;
    if (!challenge) {
      wrapper.hidden = true;
      return;
    }
    var prompt = '';
    if (typeof challenge === 'string') prompt = 'Type \"' + safeString(challenge, 100) + '\" to confirm';
    else if (challenge && typeof challenge === 'object') {
      var phrase = safeString(challenge.phrase || challenge.value, 100);
      prompt = safeString(challenge.prompt || challenge.label, 200) || (phrase ? 'Type \"' + phrase + '\" to confirm' : 'Enter the confirmation response');
    }
    $('#confirm-dialog').querySelector('.challenge-field > span').textContent = prompt || 'Enter the confirmation response';
    wrapper.hidden = false;
    input.required = true;
  }

  async function previewAction(action, options, settings) {
    var sourceDialog = settings && settings.sourceDialog;
    var button = sourceDialog ? $('.dialog-footer button[type="submit"]', sourceDialog) : $('#console-form button[type="submit"]');
    showFormError(sourceDialog ? $('.form-error', sourceDialog) : null, '');
    setBusy(button, true, 'Preparing...');
    try {
      var result = await api('/admin/api/actions/preview', {
        method: 'POST',
        csrf: true,
        body: { action: action, options: options }
      });
      if (!result.confirmationToken) throw new ApiError('The server did not return a confirmation token.', 500, 'NO_CONFIRMATION');
      state.pendingAction = {
        action: action,
        options: options,
        confirmationToken: result.confirmationToken,
        expiresAt: result.expiresAt,
        source: settings && settings.source || ''
      };
      var risk = riskInfo(result.risk);
      $('#confirm-dialog').querySelector('.eyebrow').textContent = risk.label;
      $('#confirm-dialog').querySelector('.eyebrow').className = 'eyebrow risk-badge ' + risk.value;
      $('#confirm-dialog').querySelector('.operation-summary').textContent = summaryText(result.summary);
      configureChallenge(result.challenge);
      showFormError($('#confirm-dialog').querySelector('.form-error'), '');
      var execute = $('#confirm-dialog .danger-button');
      execute.textContent = risk.value === 'low' ? 'Run operation' : 'Confirm operation';
      execute.disabled = false;
      if (sourceDialog && sourceDialog.open) sourceDialog.close();
      $('#confirm-dialog').showModal();
      var challengeInput = $('#confirm-dialog').querySelector('input');
      if (!$('#confirm-dialog').querySelector('.challenge-field').hidden) challengeInput.focus();
      else execute.focus();
    } catch (error) {
      if (sourceDialog) showFormError($('.form-error', sourceDialog), errorMessage(error));
      else toast(errorMessage(error), 'bad');
    } finally {
      setBusy(button, false);
    }
  }

  function idempotencyKey() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') return window.crypto.randomUUID();
    var bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes).map(function (byte) { return byte.toString(16).padStart(2, '0'); }).join('');
  }

  function invalidatePlayerSelections() {
    clearPlayerIdentifierDisclosure();
    state.players = [];
    state.actionPlayers = [];
    state.visiblePlayers = [];
    state.selectedPlayer = null;
    state.lastPlayerRefreshAt = 0;
    renderPlayers();
  }

  async function executePendingAction(event) {
    event.preventDefault();
    if (!state.pendingAction) {
      showFormError($('#confirm-dialog').querySelector('.form-error'), 'The confirmation expired. Preview the operation again.');
      return;
    }
    var input = $('#confirm-dialog').querySelector('input');
    if (!$('#confirm-dialog').querySelector('.challenge-field').hidden && !input.reportValidity()) return;
    var pending = state.pendingAction;
    var button = $('#confirm-dialog .danger-button');
    var operationKey = idempotencyKey();
    setBusy(button, true, 'Executing...');
    showFormError($('#confirm-dialog').querySelector('.form-error'), '');
    try {
      var result = await api('/admin/api/actions/execute', {
        method: 'POST',
        csrf: true,
        headers: { 'Idempotency-Key': operationKey },
        body: {
          action: pending.action,
          options: pending.options,
          confirmationToken: pending.confirmationToken,
          challengeResponse: input.value
        }
      });
      if (!result || result.ok !== true || result.outcome !== 'succeeded'
        || typeof result.operationId !== 'string' || !result.operationId) {
        throw incompleteMutationResponse('The operation response was incomplete.');
      }
      var message = safeString(result.message || 'Operation completed.', 500);
      toast(message, result.ok === false ? 'warn' : 'good', 8_000);
      if (pending.action === 'rcon') {
        state.consoleActivity.unshift({
          at: Date.now(),
          actor: 'Current operator',
          action: 'RCON ' + safeString((pending.options.command || '').split(/\s+/, 1)[0], 50),
          server: pending.options.server,
          status: result.ok === false ? 'ambiguous' : 'succeeded',
          operationId: result.operationId,
          message: result.ok === false ? 'Outcome requires verification' : 'Raw response suppressed'
        });
      }
      invalidatePlayerSelections();
      state.pendingAction = null;
      state.currentAction = null;
      state.actionDefaults = {};
      input.value = '';
      $('#confirm-dialog').close();
      renderActivity();
      refreshBootstrap({ force: true, quiet: true });
      loadActivity({ quiet: true });
      if (state.currentTab === 'players') loadPlayers({ quiet: true, purpose: 'player' });
    } catch (error) {
      var networkAmbiguous = mutationOutcomeUnknown(error);
      var serverAmbiguous = error && (error.status >= 500 || safeString(error.outcome).toLowerCase() === 'uncertain');
      var message = networkAmbiguous
        ? 'Connection was lost. The operation may have been applied. Verify server state before considering another attempt.'
        : serverAmbiguous
          ? errorMessage(error) + ' The outcome may be uncertain; verify server state before considering another attempt.'
          : errorMessage(error);
      showFormError($('#confirm-dialog').querySelector('.form-error'), message);
      invalidatePlayerSelections();
      state.pendingAction = null;
      state.currentAction = null;
      state.actionDefaults = {};
      button.disabled = true;
      if (networkAmbiguous || serverAmbiguous) toast(message, 'warn', 12_000);
      else toast(message + ' Preview the action again before another attempt.', 'bad', 10_000);
    } finally {
      setBusy(button, false);
      if (!state.pendingAction) button.disabled = true;
      if (state.currentTab === 'players' && !state.playerController) loadPlayers({ quiet: true, purpose: 'player' });
    }
  }

  function closeDialog(dialog) {
    if (!dialog || !dialog.open) return;
    if (dialog === $('#change-password-dialog') && dialog.dataset.forced === 'true') {
      toast('Change the temporary password or sign out to continue.', 'warn');
      return;
    }
    if (dialog === $('#temporary-password-dialog')) {
      toast('Save the temporary password, then select “I saved it”.', 'warn');
      return;
    }
    if (dialog === $('#settings-token-dialog')) {
      toast('Save the automation token, then select “I saved it”.', 'warn');
      return;
    }
    dialog.close();
    if (dialog === $('#player-dialog')) {
      clearPlayerIdentifierDisclosure();
      state.selectedPlayer = null;
    }
    if (dialog === $('#confirm-dialog')) state.pendingAction = null;
    if (dialog === $('#action-dialog')) {
      state.currentAction = null;
      state.actionDefaults = {};
    }
    if (dialog === $('#result-dialog')) {
      clearStaffRecord();
      state.selectedPlayer = null;
    }
    if (dialog === $('#create-operator-dialog')) {
      $('#create-operator-form').reset();
      showFormError($('#create-operator-error'), '');
    }
    if (dialog === $('#operator-permissions-dialog')) {
      state.permissionOperator = null;
      $('#operator-permissions-form').reset();
      $('#operator-permission-options').replaceChildren();
      showFormError($('#operator-permissions-error'), '');
    }
    if (dialog === $('#change-password-dialog')) {
      $('#change-password-form').reset();
      showFormError($('#change-password-error'), '');
    }
    if (dialog === $('#settings-review-dialog')) {
      $('#settings-reauthentication-form').reset();
      showFormError($('#settings-reauthentication-error'), '');
      showFormError($('#settings-review-error'), '');
    }
    if (state.lastDialogTrigger && state.lastDialogTrigger.isConnected) state.lastDialogTrigger.focus();
    if ((dialog === $('#player-dialog') || dialog === $('#result-dialog')) && state.currentTab === 'players') {
      window.setTimeout(function () { loadPlayers({ quiet: true, purpose: 'player' }); }, 0);
    }
  }

  async function submitConsole(event) {
    event.preventDefault();
    if (!event.currentTarget.reportValidity()) return;
    var command = $('#console-command').value.trim();
    if (/[\u0000-\u001F\u007F;|&]/u.test(command)) {
      toast('The command contains a prohibited separator or control character.', 'bad');
      return;
    }
    await previewAction('rcon', { server: $('#console-server').value, command: command }, { source: 'console' });
  }

  function bindEvents() {
    ['pointerdown', 'keydown', 'touchstart'].forEach(function (name) {
      document.addEventListener(name, function (event) {
        if (event.isTrusted && state.session) state.lastOperatorActivityAt = Date.now();
      }, { passive: name !== 'keydown' });
    });
    $('#login-form').addEventListener('submit', handleLogin);
    $('#setup-form').addEventListener('submit', handleSetup);
    $all('.password-toggle').forEach(function (button) { button.addEventListener('click', function () {
      var input = $('#' + button.dataset.passwordTarget);
      if (!input) return;
      var showing = input.type === 'text';
      input.type = showing ? 'password' : 'text';
      this.textContent = showing ? 'Show' : 'Hide';
      this.setAttribute('aria-pressed', showing ? 'false' : 'true');
      this.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
    }); });
    $('#setup-password-confirmation').addEventListener('input', function () { this.setCustomValidity(''); });
    $('#new-password-confirmation').addEventListener('input', function () { this.setCustomValidity(''); });
    $('#logout-button').addEventListener('click', logout);
    $('#forced-password-logout').addEventListener('click', logout);
    $('#change-password-button').addEventListener('click', function () {
      state.lastDialogTrigger = this;
      openPasswordDialog(false);
    });
    $('#change-password-form').addEventListener('submit', handlePasswordChange);
    $('#create-operator-button').addEventListener('click', function () {
      state.lastDialogTrigger = this;
      $('#create-operator-form').reset();
      showFormError($('#create-operator-error'), '');
      $('#create-operator-dialog').showModal();
      window.setTimeout(function () { $('#operator-username').focus(); }, 0);
    });
    $('#create-operator-form').addEventListener('submit', handleCreateOperator);
    $('#operator-permissions-form').addEventListener('submit', handleOperatorPermissions);
    $('#copy-temporary-password').addEventListener('click', async function () {
      var input = $('#temporary-password');
      try {
        if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') throw new Error('Clipboard unavailable');
        await navigator.clipboard.writeText(input.value);
        toast('Temporary password copied.', 'good');
      } catch (_) {
        input.focus(); input.select();
        toast('Copy is unavailable. The password is selected for manual copying.', 'warn');
      }
    });
    $('#close-temporary-password').addEventListener('click', function () {
      var dialog = $('#temporary-password-dialog');
      $('#temporary-password').value = '';
      $('#temporary-password').type = 'password';
      dialog.close();
      if (state.lastDialogTrigger && state.lastDialogTrigger.isConnected) state.lastDialogTrigger.focus();
      else if ($('#create-operator-button') && !$('#create-operator-button').hidden) $('#create-operator-button').focus();
    });
    $('#settings-form').addEventListener('submit', reviewSettings);
    $('#settings-reauthentication-form').addEventListener('submit', handleSettingsReauthentication);
    $('#settings-form').addEventListener('input', function (event) {
      if (event.target.dataset && event.target.dataset.settingField === 'id') event.target.setCustomValidity('');
      var card = event.target.closest('[data-settings-server]');
      if (card) updateServerCardPresentation(card);
      updateSettingsDirtyState();
    });
    $('#settings-form').addEventListener('change', function (event) {
      var card = event.target.closest('[data-settings-server]');
      if (card) {
        if (event.target.dataset.settingField === 'profile.enabled') updateProfileFieldState(card);
        updateServerCardPresentation(card);
      }
      if (event.target === $('#settings-discord-enabled') || event.target === $('#settings-discord-clear-token')) {
        applyDiscordFieldState();
      }
      updateSettingsDirtyState();
    });
    $('#reload-settings').addEventListener('click', function () {
      if (settingsHasChanges() && !window.confirm('Discard unsaved changes and reload settings from the server?')) return;
      clearSettingSecretInputs();
      loadSettings({ quiet: false });
    });
    $('#settings-add-server').addEventListener('click', addSettingsServer);
    $('#settings-add-template').addEventListener('click', function () {
      var row = addSettingsTemplate('', '');
      if (row) $('[data-template-field="name"]', row).focus();
    });
    $('#settings-add-starter-templates').addEventListener('click', addStarterAnnouncementTemplates);
    $('#settings-discard').addEventListener('click', function () { discardSettingsChanges(); });
    $('#settings-review').addEventListener('click', function () { showFormError($('#settings-error'), ''); });
    $('#settings-apply').addEventListener('click', applySettings);
    $('#settings-apply-restart').addEventListener('click', applySettings);
    $('#settings-restart-now').addEventListener('click', restartNow);
    for (var stageSelector of ['#settings-rotate-token', '#settings-regenerate-tls']) {
      $(stageSelector).addEventListener('click', function () {
        var staged = this.getAttribute('aria-pressed') === 'true';
        this.setAttribute('aria-pressed', staged ? 'false' : 'true');
        if (this === $('#settings-regenerate-tls')) {
          applyTlsStagingState();
          if (!staged) $('#settings-tls-names').focus();
        }
        updateSettingsDirtyState();
      });
    }
    $all('[data-settings-jump]').forEach(function (button) {
      button.addEventListener('click', function () {
        var destination = document.getElementById(button.dataset.settingsJump);
        if (destination) destination.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    });
    $('#settings-copy-token').addEventListener('click', async function () {
      var input = $('#settings-automation-token');
      try {
        if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') throw new Error('Clipboard unavailable');
        await navigator.clipboard.writeText(input.value);
        toast('Automation token copied.', 'good');
      } catch (_) {
        input.focus(); input.select();
        toast('Copy is unavailable. The token is selected for manual copying.', 'warn');
      }
    });
    $('#settings-close-token').addEventListener('click', acknowledgeAutomationToken);
    $('#refresh-button').addEventListener('click', function () { refreshBootstrap({ force: true, quiet: false }); });
    $('#menu-button').addEventListener('click', function () {
      if ($('#sidebar').classList.contains('open')) closeMobileNavigation();
      else openMobileNavigation();
    });
    $('#sidebar-scrim').addEventListener('click', closeMobileNavigation);
    $all('[data-tab]').forEach(function (button) {
      button.addEventListener('click', function () { activateTab(button.dataset.tab); });
    });
    $('#server-scope').addEventListener('change', function () {
      renderStatus();
      renderPlayers();
    });
    $('#reload-players').addEventListener('click', function () { loadPlayers({ quiet: false }); });
    $('#player-search').addEventListener('input', function () {
      window.clearTimeout(state.playerSearchTimer);
      state.playerSearchTimer = window.setTimeout(function () { loadPlayers({ quiet: true }); }, 220);
    });
    $('#player-state-filter').addEventListener('change', renderPlayers);
    $('#reveal-player-identifiers').addEventListener('click', revealPlayerIdentifiers);
    $('#hide-player-identifiers').addEventListener('click', function () {
      clearPlayerIdentifierDisclosure('Identifiers hidden.');
      $('#reveal-player-identifiers').focus();
    });
    $('#back-to-player').addEventListener('click', async function () {
      var button = this;
      var playerContext = state.selectedPlayer;
      var trigger = state.lastDialogTrigger;
      setBusy(button, true, 'Refreshing...');
      clearStaffRecord();
      $('#result-dialog').close();
      var refreshed = await loadPlayers({ quiet: true, purpose: 'player' });
      var matches = refreshed && playerContext
        ? state.players.filter(function (candidate) { return sameVisiblePlayer(candidate, playerContext); })
        : [];
      if (matches.length === 1) {
        showPlayerDialog(matches[0]);
        state.lastDialogTrigger = trigger;
      } else {
        toast(refreshed
          ? 'That player disconnected or changed maps. The player list has been refreshed.'
          : 'The player list could not be refreshed. Try again from Players.', 'warn');
      }
      setBusy(button, false);
      if (matches.length !== 1 && trigger && trigger.isConnected) {
        trigger.focus();
      }
    });
    $('#player-rows').addEventListener('click', function (event) {
      var button = event.target.closest('[data-player-index]');
      if (!button) return;
      showPlayerDialog(state.visiblePlayers[numeric(button.dataset.playerIndex)]);
    });
    $('#reload-activity').addEventListener('click', function () { loadActivity({ quiet: false }); });
    $('#activity-search').addEventListener('input', renderActivity);
    $('#activity-state-filter').addEventListener('change', renderActivity);
    $('#reload-diagnostics').addEventListener('click', function () { loadDiagnostics({ quiet: false }); });
    $('#diagnostic-search').addEventListener('input', scheduleDiagnosticLoad);
    $('#diagnostic-channel').addEventListener('change', function () { loadDiagnostics({ quiet: true }); });
    $('#diagnostic-level').addEventListener('change', function () { loadDiagnostics({ quiet: true }); });
    $('#action-form').addEventListener('submit', submitActionForm);
    $('#confirm-dialog form').addEventListener('submit', executePendingAction);
    $('#console-form').addEventListener('submit', submitConsole);

    document.addEventListener('click', function (event) {
      var staffRecordButton = event.target.closest('[data-open-staff-record]');
      if (staffRecordButton && !staffRecordButton.disabled) {
        var selection = staffRecordButton.dataset.player || '';
        var player = state.players.find(function (candidate) { return candidate.selection === selection; })
          || (state.selectedPlayer && state.selectedPlayer.selection === selection ? state.selectedPlayer : null);
        showStaffRecord(player, staffRecordButton);
      }
      var actionButton = event.target.closest('[data-open-action]');
      if (actionButton && !actionButton.disabled) {
        openAction(actionButton.dataset.openAction, {
          player: actionButton.dataset.player || '',
          server: actionButton.dataset.server || ''
        }, actionButton);
      }
      var closeButton = event.target.closest('.close-button, .close-dialog');
      if (closeButton) closeDialog(closeButton.closest('dialog'));
    });

    $all('dialog').forEach(function (dialog) {
      dialog.addEventListener('click', function (event) {
        if (event.target === dialog) closeDialog(dialog);
      });
      dialog.addEventListener('cancel', function (event) {
        event.preventDefault();
        closeDialog(dialog);
      });
    });

    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && $('#sidebar').classList.contains('open')) closeMobileNavigation();
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k' && state.session) {
        event.preventDefault();
        activateTab(rawRconEnabled() && actionAvailable('rcon') ? 'console' : 'operations');
      }
    });

    document.addEventListener('visibilitychange', function () {
      if (document.hidden) {
        clearStaffRecord();
        if ($('#result-dialog').open) $('#result-dialog').close();
        state.selectedPlayer = null;
        window.clearTimeout(state.pollTimer);
        if (state.bootstrapController) state.bootstrapController.abort();
      } else if (state.session) {
        refreshBootstrap({ force: true, quiet: true });
      }
    });
    window.addEventListener('hashchange', function () { activateTab(tabFromHash(), { updateHash: false }); });
    window.addEventListener('beforeunload', function (event) {
      if (!settingsHasChanges() && !oneTimeCredentialVisible()) return;
      event.preventDefault();
      event.returnValue = '';
    });
    window.addEventListener('pagehide', function () {
      stopPolling();
      clearSensitiveClientState();
    });
  }

  async function initialize() {
    bindEvents();
    activateTab(tabFromHash(), { updateHash: false });
    await initAuthentication();
  }

  initialize();
}());
