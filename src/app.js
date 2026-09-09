import { pathToFileURL } from 'node:url';
import { Logger } from './logger.js';
import { Metrics } from './core/metrics.js';
import { configuredRedactionSecrets } from './core/redaction.js';
import { ClusterBridge } from './core/bridge.js';
import { ArkServer } from './adapters/rcon/ark-server.js';
import { SftpProfileSource } from './adapters/profiles/sftp-profile-source.js';
import { DiscordAdapter } from './adapters/discord/discord-adapter.js';
import { createStateStore } from './adapters/state/create-state-store.js';
import { HttpService } from './http/server.js';
import { openRuntimeContext } from './managed-instance.js';
import { ManagedSettingsService } from './core/managed-settings.js';
import { acquireManagedRuntimeLock } from './security/managed-keystore.js';
import { AnalyticsClient } from './core/analytics.js';

function defaultProfileDirectories(profileImport) {
  if (profileImport.directory || profileImport.directories?.length) {
    return [profileImport.directory, ...(profileImport.directories ?? [])].filter(Boolean);
  }
  const suffix = `ShooterGame/Saved/SavedArks/${profileImport.mapName}`;
  return [`/${suffix}`, `/2430930/${suffix}`, `/ark-sa/2430930/${suffix}`];
}

export function createProfileSources(config) {
  return new Map(config.servers
    .filter((server) => server.profileImport?.enabled)
    .map((server) => [server.id, new SftpProfileSource({
      ...server.profileImport,
      serverId: server.id,
      directories: defaultProfileDirectories(server.profileImport),
    })]));
}

export function createApplication(config, dependencies = {}) {
  const configuredSecrets = configuredRedactionSecrets(config);
  const logger = dependencies.logger ?? new Logger({ ...config.logging, secrets: configuredSecrets });
  const metrics = dependencies.metrics ?? new Metrics();
  const state = dependencies.state ?? createStateStore({ ...config.persistence });
  const servers = dependencies.servers ?? config.servers.map((server) => new ArkServer({ ...server, gameMaxLength: config.chat.gameMaxLength }, { logger, metrics }));
  const profileSources = dependencies.profileSources ?? createProfileSources(config);
  const discordConfig = {
    ...config.discord,
    redactionSecrets: configuredSecrets,
    maxMessageLength: config.chat.discordMaxLength,
    maxMuteMinutes: config.moderation.maxMuteMinutes,
    gameMaxLength: config.chat.gameMaxLength,
  };
  const discord = dependencies.discord ?? new DiscordAdapter(discordConfig, { logger });
  const analytics = dependencies.analytics ?? new AnalyticsClient(config.analytics, { logger });
  const bridge = dependencies.bridge ?? new ClusterBridge({ config, servers, discord, state, profileSources, metrics, logger });
  const http = dependencies.http ?? new HttpService({
    config: { ...config.http, managedInstance: config.managedInstance, redactionSecrets: configuredSecrets }, bridge, state, metrics, logger,
    settingsService: dependencies.settingsService ?? null,
    onOwnerSetupCompleted: dependencies.onOwnerSetupCompleted ?? null,
  });
  const managedRecoveryMode = Boolean(config.managedInstance?.enabled);
  const instanceLockFile = dependencies.instanceLockFile ?? '';
  const acquireRuntimeLock = dependencies.acquireRuntimeLock ?? acquireManagedRuntimeLock;
  let started = false; let loggerStarted = false; let startPromise = null; let stopPromise = null;
  let cleanupPromise = null; let resourcesClosed = false; let stopRequested = false;
  let runtimeLock = dependencies.runtimeLock ?? null; let dataPlaneAvailable = false;

  const closeResources = () => {
    if (cleanupPromise) return cleanupPromise;
    if (resourcesClosed) return Promise.resolve();
    cleanupPromise = (async () => {
      const failures = [];
      try { await bridge.stop(); } catch (error) { failures.push(error); }
      try { await analytics.stop(); } catch (error) { failures.push(error); }
      try { await http.stop(); } catch (error) { failures.push(error); }
      try { await state.close?.(); } catch (error) { failures.push(error); }
      started = false; dataPlaneAvailable = false;
      const failure = failures.length === 1 ? failures[0]
        : failures.length > 1 ? new AggregateError(failures, 'Application shutdown failed') : null;
      if (loggerStarted) {
        if (failure) logger.security?.('system.stop_failed', {
          component: 'application', outcome: 'failed', reasonCode: failure?.code ?? failure?.name ?? 'shutdown_failed',
        }, 'error');
        else logger.info?.('BLCKSNAKE Command stopped', { event: 'system.stopped' });
        try { await Promise.resolve(logger.close?.()); } catch (error) { failures.push(error); }
        loggerStarted = false;
      }
      try { await runtimeLock?.release?.(); } catch (error) { failures.push(error); }
      runtimeLock = null; resourcesClosed = true;
      if (failures.length === 1) throw failures[0];
      if (failures.length > 1) throw new AggregateError(failures, 'Application shutdown failed');
    })();
    return cleanupPromise;
  };

  const assertStartContinues = () => {
    if (stopRequested) {
      const error = new Error('Application startup was cancelled by shutdown');
      error.code = 'APPLICATION_START_CANCELLED';
      throw error;
    }
  };

  return {
    config, logger, metrics, state, servers, profileSources, discord, bridge, http, analytics,
    start() {
      if (started) return Promise.resolve();
      if (startPromise) return startPromise;
      if (resourcesClosed) return Promise.reject(new Error('Application instance is closed'));
      stopRequested = false;
      startPromise = (async () => {
        try {
          if (instanceLockFile && !runtimeLock) runtimeLock = await acquireRuntimeLock(instanceLockFile);
          assertStartContinues();
          await Promise.resolve(logger.start?.()); loggerStarted = true;
        logger.security?.('logging.initialized', { component: 'logging', outcome: 'succeeded' }, 'info');
        logger.security?.('system.starting', { component: 'application' }, 'info');
        try {
          await state.load();
          logger.info?.('Encrypted state opened', { event: 'state.opened', component: 'state', driver: config.persistence.driver, outcome: 'succeeded' });
        } catch (error) {
          logger.security?.('state.integrity_failed', {
            component: 'state', outcome: 'failed', reasonCode: error?.code ?? error?.name ?? 'open_failed',
          }, 'error');
          throw error;
        }
        if (config.managedInstance?.initializedThisStart) {
          logger.security?.(config.managedInstance.importedLegacyConfiguration
            ? 'managed_instance.legacy_imported' : 'managed_instance.initialized', {
            component: 'managed-instance', outcome: 'succeeded', revision: config.managedInstance.revision,
            configured: Boolean(config.managedInstance.configured),
          }, 'info');
        }
        assertStartContinues();
        bridge.controlPlaneOnly = true;
        await http.start();
        assertStartContinues();
        try {
          await bridge.start();
          dataPlaneAvailable = true;
          bridge.controlPlaneOnly = false;
        } catch (error) {
          if (!managedRecoveryMode) throw error;
          dataPlaneAvailable = false;
          bridge.controlPlaneOnly = true;
          logger.security?.('data_plane.start_failed', {
            component: 'application', outcome: 'failed', reasonCode: error?.code ?? error?.name ?? 'start_failed',
            controlPlaneAvailable: true,
          }, 'error');
        }
        assertStartContinues();
        started = true;
        analytics.start({
          serverCount: servers.length, discordEnabled: config.discord.enabled,
          managed: Boolean(config.managedInstance?.enabled),
        });
        logger.info?.('BLCKSNAKE Command started', {
          event: 'system.started', cluster: config.clusterName, servers: servers.length,
          http: http.address(), dataPlaneAvailable,
        });
        } catch (error) {
          if (loggerStarted && error?.code !== 'APPLICATION_START_CANCELLED') {
            logger.security?.('system.start_failed', {
              component: 'application', outcome: 'failed', reasonCode: error?.code ?? error?.name ?? 'start_failed',
            }, 'error');
          }
          let cleanupError = null;
          try { await closeResources(); } catch (failure) { cleanupError = failure; }
          if (error?.code === 'APPLICATION_START_CANCELLED' && !cleanupError) return;
          if (cleanupError) throw new AggregateError([error, cleanupError], 'Application startup and cleanup failed');
          throw error;
        }
      })().finally(() => { startPromise = null; });
      return startPromise;
    },
    stop() {
      if (stopPromise) return stopPromise;
      stopRequested = true;
      const pendingStart = startPromise;
      stopPromise = (async () => {
        await pendingStart?.catch(() => undefined);
        await closeResources();
      })();
      return stopPromise;
    },
    get started() { return started; },
    get dataPlaneAvailable() { return dataPlaneAvailable; },
  };
}

export async function main() {
  const runtime = await openRuntimeContext();
  let app = null;
  try {
    const { config } = runtime;
    const settingsService = runtime.managed
      ? new ManagedSettingsService({ context: runtime, state: runtime.state, paths: runtime.paths })
      : null;
    app = createApplication(config, {
      ...(runtime.state ? { state: runtime.state } : {}),
      ...(runtime.runtimeLock ? { runtimeLock: runtime.runtimeLock } : {}),
      settingsService,
      onOwnerSetupCompleted: runtime.ownerSetupCompleted?.bind(runtime) ?? null,
    });
    settingsService?.setAnalyticsConsentHandler((enabled) => app.analytics.setConsent(enabled, {
      serverCount: app.servers.length, discordEnabled: config.discord.enabled,
      managed: Boolean(config.managedInstance?.enabled),
    }));
    let stopping = false;
    const shutdown = async (signal) => {
      if (stopping) return; stopping = true;
      app.logger.info('Shutdown requested', { event: 'system.stop_requested', signal });
      try { await app.stop(); process.exitCode = 0; }
      catch { process.exitCode = 1; }
    };
    process.once('SIGINT', () => { void shutdown('SIGINT'); });
    process.once('SIGTERM', () => { void shutdown('SIGTERM'); });
    process.on('uncaughtException', (error) => { app.logger.error('Uncaught exception', { error: error.message, stack: error.stack }); void shutdown('uncaughtException'); });
    process.on('unhandledRejection', (error) => { app.logger.error('Unhandled rejection', { error: error?.message ?? String(error) }); void shutdown('unhandledRejection'); });
    await app.start();
    return app;
  } catch (error) {
    // Managed startup acquires its OS-level singleton before any initialization.
    // If construction fails before the application owns that handle, release the
    // context explicitly so a configuration error cannot strand the process.
    if (app) await app.stop().catch(() => undefined);
    else await runtime.close?.().catch(() => undefined);
    throw error;
  }
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) main().catch(() => {
  console.error('BLCKSNAKE Command could not start. Run the sanitized configuration and security checks for details.');
  process.exitCode = 1;
});
