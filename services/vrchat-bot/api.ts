import express from 'express';
import { SystemConfig, UserVRChatGroup, Guild, VRChatAnnouncementHistory } from '../shared/models';
import {
  getVRChatBots,
  syncAllVRChatBots,
  banUserFromVRChatGroup,
  unbanUserFromVRChatGroup,
  getBotForGroup,
  getVRChatAuthHeadersForBot,
} from './vrchat-client';
import { scanAndBanBlacklistedUsers } from './worker';
import { config as appConfig } from '../shared/config';

export function createVRChatRouter(): express.Router {
  const router = express.Router();
  router.use(express.json());

  // Kubernetes Probes
  router.get('/healthz', (_req, res) => {
    res.status(200).json({ status: 'ok', service: 'vrchat-bot' });
  });

  router.get('/readyz', async (_req, res) => {
    try {
      const config = await SystemConfig.findOne({ id: 'main' });
      res.status(200).json({
        status: 'ready',
        service: 'vrchat-bot',
        enabled: config?.vrchatBotEnabled || false,
        instanceId: appConfig.vrcInstanceId,
        totalInstances: appConfig.vrcTotalInstances,
      });
    } catch (e: any) {
      res.status(500).json({ status: 'not-ready', error: e?.message });
    }
  });

  // Telemetry and Status
  router.get('/api/vrchat/status', async (_req, res) => {
    try {
      const config = await SystemConfig.findOne({ id: 'main' });
      if (!config) {
        return res.json({ enabled: false, bots: [] });
      }

      const bots = getVRChatBots(config);
      const activeGroups = await UserVRChatGroup.countDocuments({ status: 'active' });

      res.json({
        enabled: config.vrchatBotEnabled,
        status: config.vrchatBotStatus,
        lastCheckedAt: config.vrchatBotLastCheckedAt,
        error: config.vrchatBotError,
        botCount: bots.length,
        bots: bots.map((b) => ({
          id: b.id,
          username: b.vrchatUsername,
          groupCount: b.groupCount,
          status: b.status,
          error: b.error,
        })),
        activeGroups,
        sharding: {
          instanceId: appConfig.vrcInstanceId,
          totalInstances: appConfig.vrcTotalInstances,
        },
      });
    } catch (e: any) {
      res.status(500).json({ error: e?.message });
    }
  });

  // Trigger Immediate Blacklist Scan
  router.post('/api/vrchat/scan', async (_req, res) => {
    try {
      // Run scan in background
      scanAndBanBlacklistedUsers().catch((err) =>
        console.error('[VRChat API] Scan trigger error:', err)
      );
      res.json({ success: true, message: 'VRChat blacklist scan initiated.' });
    } catch (e: any) {
      res.status(500).json({ error: e?.message });
    }
  });

  // Trigger Immediate Session Sync
  router.post('/api/vrchat/sync', async (_req, res) => {
    try {
      const config = await SystemConfig.findOne({ id: 'main' });
      if (!config) {
        return res.status(400).json({ error: 'Config not found' });
      }
      await syncAllVRChatBots(config);
      const updated = await SystemConfig.findOne({ id: 'main' });
      res.json({ success: true, config: updated });
    } catch (e: any) {
      res.status(500).json({ error: e?.message });
    }
  });

  // Trigger User Ban
  router.post('/api/vrchat/ban', async (req, res) => {
    try {
      const { vrchatUserId, reason, isCustomList, customListId } = req.body;
      if (!vrchatUserId) {
        return res.status(400).json({ error: 'vrchatUserId is required' });
      }

      const success = await banUserFromVRChatGroup(
        vrchatUserId,
        reason || 'Manual ban requested',
        isCustomList || false,
        customListId
      );

      res.json({ success, vrchatUserId });
    } catch (e: any) {
      res.status(500).json({ error: e?.message });
    }
  });

  // Trigger User Unban
  router.post('/api/vrchat/unban', async (req, res) => {
    try {
      const { vrchatUserId } = req.body;
      if (!vrchatUserId) {
        return res.status(400).json({ error: 'vrchatUserId is required' });
      }

      const success = await unbanUserFromVRChatGroup(vrchatUserId);
      res.json({ success, vrchatUserId });
    } catch (e: any) {
      res.status(500).json({ error: e?.message });
    }
  });

  // List Managed Groups
  router.get('/api/vrchat/groups', async (_req, res) => {
    try {
      const groups = await UserVRChatGroup.find();
      const config = await SystemConfig.findOne({ id: 'main' });
      const bots = config ? getVRChatBots(config) : [];
      res.json({ groups, bots: bots.map((b) => ({ id: b.id, username: b.vrchatUsername, groups: b.groups })) });
    } catch (e: any) {
      res.status(500).json({ error: e?.message });
    }
  });

  // Announcement broadcast
  router.post('/api/vrchat/announcements/broadcast', async (req, res) => {
    try {
      const { title, text, imageId, sendNotification, visibility, sentBy } = req.body;
      if (!title || !text) {
        return res.status(400).json({ error: 'Title and text are required' });
      }

      const config = await SystemConfig.findOne({ id: 'main' });
      if (!config) return res.status(400).json({ error: 'System config not found' });

      const allGroups = await UserVRChatGroup.find({ status: 'active' });
      const groupResults: any[] = [];
      let successCount = 0;
      let failedCount = 0;

      for (const g of allGroups) {
        try {
          const bot = await getBotForGroup(config, g.groupId);
          const { headers, apiKey } = await getVRChatAuthHeadersForBot(bot, config);

          const postRes = await fetch(`https://api.vrchat.cloud/api/1/groups/${g.groupId}/posts?apiKey=${apiKey}`, {
            method: 'POST',
            headers,
            body: JSON.stringify({
              title,
              text,
              imageId: imageId || undefined,
              sendNotification: sendNotification !== false,
              visibility: visibility || 'group',
            }),
          });

          if (postRes.ok) {
            const data: any = await postRes.json();
            successCount++;
            groupResults.push({ groupId: g.groupId, groupName: g.groupName, success: true, postId: data.id });
          } else {
            failedCount++;
            const err = await postRes.text();
            groupResults.push({ groupId: g.groupId, groupName: g.groupName, success: false, error: err });
          }
        } catch (postErr: any) {
          failedCount++;
          groupResults.push({ groupId: g.groupId, groupName: g.groupName, success: false, error: postErr.message });
        }
      }

      const historyDoc = new VRChatAnnouncementHistory({
        title,
        text,
        imageId,
        sendNotification: sendNotification !== false,
        visibility: visibility || 'group',
        sentBy: sentBy || 'Admin',
        totalTargeted: allGroups.length,
        successCount,
        failedCount,
        groupResults,
      });
      await historyDoc.save();

      res.json({ success: true, announcement: historyDoc });
    } catch (e: any) {
      res.status(500).json({ error: e?.message });
    }
  });

  return router;
}
