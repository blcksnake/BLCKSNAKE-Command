import { EventEmitter } from 'node:events';
import { buildApplicationCommands } from './commands.js';
import { DiscordGateway } from './gateway.js';
import { DiscordRest } from './rest.js';

export class DiscordAdapter extends EventEmitter {
  constructor(config, { rest, gateway, logger = null } = {}) {
    super(); this.config = config; this.logger = logger;
    this.rest = rest ?? new DiscordRest({ ...config, maxMessageLength: config.maxMessageLength }, { logger });
    this.gateway = gateway ?? new DiscordGateway(config, { logger });
    this.started = false;
    this.onGatewayMessage = (message) => this.emit('messageCreate', message);
    this.onGatewayInteraction = (interaction) => this.emit('interactionCreate', interaction);
    this.onGatewayFatal = (error) => this.emit('fatal', error);
  }

  async start() {
    if (!this.config.enabled || this.started) return;
    this.gateway.on('messageCreate', this.onGatewayMessage);
    this.gateway.on('interactionCreate', this.onGatewayInteraction);
    this.gateway.on('fatal', this.onGatewayFatal);
    try {
      if (this.config.registerCommands) await this.rest.registerGuildCommands(buildApplicationCommands({
        maxMuteMinutes: this.config.maxMuteMinutes,
        gameMaxLength: this.config.gameMaxLength,
      }));
      await this.gateway.start(); this.started = true;
    } catch (error) { this.stop(); throw error; }
  }

  stop() {
    this.gateway.off('messageCreate', this.onGatewayMessage);
    this.gateway.off('interactionCreate', this.onGatewayInteraction);
    this.gateway.off('fatal', this.onGatewayFatal);
    this.gateway.stop(); this.started = false;
  }

  snapshot() { return { ...this.gateway.snapshot(), enabled: this.config.enabled, started: this.started }; }
  sendChat(content) { return this.rest.sendMessage(this.config.chatChannelId, content); }
  sendAudit(content) { return this.config.auditChannelId ? this.rest.sendMessage(this.config.auditChannelId, content) : Promise.resolve([]); }
  deferInteraction(interaction, options) { return this.rest.deferInteraction(interaction, options); }
  autocompleteInteraction(interaction, choices) { return this.rest.autocompleteInteraction(interaction, choices); }
  editInteraction(interaction, content) { return this.rest.editInteraction(interaction, content); }
}
