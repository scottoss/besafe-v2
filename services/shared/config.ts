import 'dotenv/config';

export const config = {
  serviceName: (process.env.SERVICE_NAME || 'all').toLowerCase(),
  nodeEnv: process.env.NODE_ENV || 'development',
  isProduction: process.env.NODE_ENV === 'production',

  // Ports
  port: parseInt(process.env.PORT || '3000', 10),
  vrchatBotPort: parseInt(process.env.VRCHAT_BOT_PORT || '3001', 10),
  discordBotPort: parseInt(process.env.DISCORD_BOT_PORT || '3002', 10),

  // Inter-service discovery URLs
  appUrl: process.env.APP_URL || 'http://localhost:3000',
  vrchatServiceUrl: process.env.VRCHAT_SERVICE_URL || `http://localhost:${process.env.VRCHAT_BOT_PORT || '3001'}`,
  discordServiceUrl: process.env.DISCORD_SERVICE_URL || `http://localhost:${process.env.DISCORD_BOT_PORT || '3002'}`,

  // Database
  mongoUri: process.env.MONGO_URI || process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/besafe',

  // Discord Credentials & Sharding
  discordToken: process.env.DISCORD_TOKEN || '',
  discordClientId: process.env.DISCORD_CLIENT_ID || '',
  discordShardingMode: process.env.DISCORD_SHARDING_MODE || 'stateful', // 'stateful' | 'manager' | 'single'
  shardId: process.env.SHARD_ID ? parseInt(process.env.SHARD_ID, 10) : undefined,
  shardCount: process.env.SHARD_COUNT || process.env.TOTAL_SHARDS
    ? parseInt((process.env.SHARD_COUNT || process.env.TOTAL_SHARDS)!, 10)
    : undefined,

  // VRChat Bot Partitioning / Sharding
  vrcInstanceId: parseInt(process.env.VRC_INSTANCE_ID || '0', 10),
  vrcTotalInstances: parseInt(process.env.VRC_TOTAL_INSTANCES || '1', 10),

  // Security & Auth
  jwtSecret: process.env.JWT_SECRET || 'besafe-jwt-super-secret-key-change-in-prod',
  apiKeySalt: process.env.API_KEY_SALT || 'besafe-key-salt-production',

  // Email
  smtpHost: process.env.SMTP_HOST,
  smtpPort: parseInt(process.env.SMTP_PORT || '587', 10),
  smtpUser: process.env.SMTP_USER,
  smtpPass: process.env.SMTP_PASS,
  smtpFrom: process.env.SMTP_FROM || '"BeSafe Network" <noreply@besafe.network>',
};
