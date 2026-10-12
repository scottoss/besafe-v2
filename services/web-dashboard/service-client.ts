import { config } from '../shared/config';
import { fetchDiscordUserViaREST } from '../shared/discord-rest';

export class ServiceClient {
  private vrchatUrl: string;
  private discordUrl: string;

  constructor() {
    this.vrchatUrl = config.vrchatServiceUrl.replace(/\/+$/, '');
    this.discordUrl = config.discordServiceUrl.replace(/\/+$/, '');
  }

  // --- VRChat Service RPCs ---
  async getVRChatStatus(): Promise<any> {
    try {
      const res = await fetch(`${this.vrchatUrl}/api/vrchat/status`, { signal: AbortSignal.timeout(3000) });
      if (res.ok) return await res.json();
      return { status: 'offline', error: `HTTP ${res.status}` };
    } catch (e: any) {
      return { status: 'offline', error: e.message };
    }
  }

  async triggerVRChatScan(): Promise<boolean> {
    try {
      const res = await fetch(`${this.vrchatUrl}/api/vrchat/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(5000),
      });
      return res.ok;
    } catch (e) {
      return false;
    }
  }

  async triggerVRChatSync(): Promise<boolean> {
    try {
      const res = await fetch(`${this.vrchatUrl}/api/vrchat/sync`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(8000),
      });
      return res.ok;
    } catch (e) {
      return false;
    }
  }

  async banVRChatUser(vrchatUserId: string, reason: string, isCustomList = false, customListId?: string): Promise<boolean> {
    try {
      const res = await fetch(`${this.vrchatUrl}/api/vrchat/ban`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vrchatUserId, reason, isCustomList, customListId }),
        signal: AbortSignal.timeout(10000),
      });
      if (res.ok) {
        const data: any = await res.json();
        return data.success ?? true;
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  async unbanVRChatUser(vrchatUserId: string): Promise<boolean> {
    try {
      const res = await fetch(`${this.vrchatUrl}/api/vrchat/unban`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vrchatUserId }),
        signal: AbortSignal.timeout(10000),
      });
      if (res.ok) {
        const data: any = await res.json();
        return data.success ?? true;
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  // --- Discord Service RPCs ---
  async getDiscordStatus(): Promise<any> {
    try {
      const res = await fetch(`${this.discordUrl}/api/discord/status`, { signal: AbortSignal.timeout(3000) });
      if (res.ok) return await res.json();
      return { status: 'offline', error: `HTTP ${res.status}` };
    } catch (e: any) {
      return { status: 'offline', error: e.message };
    }
  }

  async fetchDiscordUser(userId: string): Promise<any> {
    try {
      // 1. Try Discord bot internal HTTP API first
      const res = await fetch(`${this.discordUrl}/api/discord/user/${userId}`, { signal: AbortSignal.timeout(3000) });
      if (res.ok) {
        return await res.json();
      }
    } catch (e) {}

    // 2. Fallback to direct Discord REST API
    return await fetchDiscordUserViaREST(userId);
  }

  async fetchDiscordGuilds(): Promise<any[]> {
    try {
      const res = await fetch(`${this.discordUrl}/api/discord/guilds`, { signal: AbortSignal.timeout(4000) });
      if (res.ok) {
        const data: any = await res.json();
        return data.guilds || [];
      }
      return [];
    } catch (e) {
      return [];
    }
  }
}

export const serviceClient = new ServiceClient();
