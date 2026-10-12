import express from 'express';
import { connectDB, disconnectDB } from '../shared/db';
import { config } from '../shared/config';
import { getShardConfiguration } from './k8s-sharding';
import { createDiscordBot } from './bot';
import { createDiscordBotRouter } from './api';

async function main() {
  const shardConfig = getShardConfiguration();
  console.log(`[Discord Bot Service] Starting...`);
  console.log(`[Discord Bot Service] Shard Configuration: Shard ${shardConfig.shardId} of ${shardConfig.shardCount} (Mode: ${shardConfig.source})`);

  if (!config.discordToken) {
    console.warn('[Discord Bot Service] Warning: DISCORD_TOKEN is not configured.');
  }

  // Connect to DB
  await connectDB();

  // Create Discord Client
  const client = await createDiscordBot(shardConfig);

  // Create internal HTTP server for Kubernetes probes & telemetry
  const app = express();
  app.use(express.json());
  app.use(createDiscordBotRouter(client, shardConfig));

  const server = app.listen(config.discordBotPort, '0.0.0.0', () => {
    console.log(`[Discord Bot Service] Internal HTTP API listening on http://0.0.0.0:${config.discordBotPort}`);
  });

  // Login to Discord Gateway
  if (config.discordToken) {
    client.login(config.discordToken).catch((err) => {
      console.error('[Discord Bot Service] Failed to login to Discord Gateway:', err?.message || err);
    });
  }

  // Graceful shutdown
  const shutdown = async (signal: string) => {
    console.log(`[Discord Bot Service] Received ${signal}. Shutting down gracefully...`);
    client.destroy();
    server.close(async () => {
      await disconnectDB();
      console.log('[Discord Bot Service] Clean shutdown complete.');
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  console.error('[Discord Bot Service] Fatal error:', err);
  process.exit(1);
});
