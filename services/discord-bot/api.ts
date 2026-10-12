import express from 'express';
import { Client } from 'discord.js';
import { ShardConfig } from './k8s-sharding';

export function createDiscordBotRouter(client: Client, shardConfig: ShardConfig): express.Router {
  const router = express.Router();
  router.use(express.json());

  // Kubernetes Probes
  router.get('/healthz', (_req, res) => {
    res.status(200).json({ status: 'ok', service: 'discord-bot' });
  });

  router.get('/readyz', (_req, res) => {
    if (client.isReady()) {
      res.status(200).json({
        status: 'ready',
        service: 'discord-bot',
        shardId: shardConfig.shardId,
        shardCount: shardConfig.shardCount,
        ping: client.ws.ping,
      });
    } else {
      res.status(503).json({
        status: 'not-ready',
        service: 'discord-bot',
        message: 'Discord Gateway client not yet ready',
      });
    }
  });

  // Telemetry and Status
  router.get('/api/discord/status', (_req, res) => {
    const isReady = client.isReady();
    res.json({
      status: isReady ? 'online' : 'connecting',
      ready: isReady,
      user: client.user ? {
        id: client.user.id,
        tag: client.user.tag,
        username: client.user.username,
        avatar: client.user.avatarURL(),
      } : null,
      shard: {
        id: shardConfig.shardId,
        count: shardConfig.shardCount,
        isSharded: shardConfig.isSharded,
        source: shardConfig.source,
      },
      guildsCount: client.guilds?.cache?.size || 0,
      usersCount: client.users?.cache?.size || 0,
      ping: client.ws?.ping ?? -1,
      uptime: client.uptime || 0,
    });
  });

  // Get cached guilds on this shard
  router.get('/api/discord/guilds', (_req, res) => {
    if (!client.isReady()) {
      return res.status(503).json({ error: 'Client not ready' });
    }
    const guilds = client.guilds.cache.map((g) => ({
      id: g.id,
      name: g.name,
      memberCount: g.memberCount,
      iconUrl: g.iconURL(),
      shardId: shardConfig.shardId,
    }));
    res.json({ guilds, count: guilds.length, shardId: shardConfig.shardId });
  });

  // Fetch Discord user via client cache/API
  router.get('/api/discord/user/:id', async (req, res) => {
    const userId = req.params.id;
    if (!userId) return res.status(400).json({ error: 'User ID is required' });

    try {
      const user = await client.users.fetch(userId);
      res.json({
        id: user.id,
        tag: user.tag,
        username: user.username,
        displayName: user.displayName,
        avatarUrl: user.avatarURL({ size: 256 }) || user.defaultAvatarURL,
        bot: user.bot,
      });
    } catch (e: any) {
      res.status(404).json({ error: 'Discord user not found', details: e?.message });
    }
  });

  return router;
}
