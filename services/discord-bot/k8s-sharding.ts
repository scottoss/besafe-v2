import os from 'os';
import { config } from '../shared/config';

export interface ShardConfig {
  shardId: number;
  shardCount: number;
  isSharded: boolean;
  source: 'env' | 'k8s_hostname' | 'default';
}

/**
 * Determines Shard ID and Shard Count from environment or Kubernetes StatefulSet hostname.
 * In a Kubernetes StatefulSet named `discord-bot`, pods are named `discord-bot-0`, `discord-bot-1`, etc.
 * This extracts the ordinal index from the hostname automatically!
 */
export function getShardConfiguration(): ShardConfig {
  // 1. Check explicit environment variables
  if (config.shardId !== undefined && config.shardCount !== undefined) {
    return {
      shardId: config.shardId,
      shardCount: config.shardCount,
      isSharded: config.shardCount > 1,
      source: 'env',
    };
  }

  // 2. Check Kubernetes Pod Hostname or POD_NAME env (e.g., discord-bot-2)
  const hostname = process.env.POD_NAME || process.env.HOSTNAME || os.hostname();
  const match = hostname.match(/-(\d+)$/);
  if (match) {
    const ordinalId = parseInt(match[1], 10);
    const totalShards = config.shardCount || 1;
    console.log(`[Discord Sharding] Detected Kubernetes StatefulSet pod ordinal from hostname "${hostname}": Shard ${ordinalId} of ${totalShards}`);
    return {
      shardId: ordinalId,
      shardCount: totalShards,
      isSharded: totalShards > 1,
      source: 'k8s_hostname',
    };
  }

  // 3. Fallback to single shard / standalone mode
  const defaultShardId = config.shardId || 0;
  const defaultShardCount = config.shardCount || 1;
  return {
    shardId: defaultShardId,
    shardCount: defaultShardCount,
    isSharded: defaultShardCount > 1,
    source: 'default',
  };
}
