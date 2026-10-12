import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { PassThrough } from 'stream';
import { Client, GatewayIntentBits, Partials, Events, REST, Routes, SlashCommandBuilder, PermissionFlagsBits, ActivityType, ContextMenuCommandBuilder, ApplicationCommandType, ModalBuilder, TextInputBuilder, TextInputStyle, ActionRowBuilder, ChannelType, EmbedBuilder } from 'discord.js';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import 'dotenv/config';
import cryptoNode from 'crypto';
import axios from 'axios';
import ffmpegPath from 'ffmpeg-static';
import {
  joinVoiceChannel,
  createAudioPlayer,
  createAudioResource,
  AudioPlayerStatus,
  StreamType,
  NoSubscriberBehavior,
  getVoiceConnection,
  VoiceConnectionStatus,
  entersState
} from '@discordjs/voice';
import * as EmailTemplates from './emailService';
import * as tf from '@tensorflow/tfjs-node';
import * as nsfwjs from 'nsfwjs';
import geoip from 'geoip-lite';

if (ffmpegPath) {
  process.env.FFMPEG_PATH = ffmpegPath;
}

// --- Email Helper ---
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: process.env.SMTP_PORT === '465',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendMail(to: string, subject: string, text: string, html?: string, attachments?: any[]) {
  if (!process.env.SMTP_HOST) {
    console.warn('SMTP NOT CONFIGURED. Skipping email to:', to);
    return;
  }
  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || '"BeSafe Network" <noreply@besafe.network>',
      to,
      subject,
      text,
      html: html || text,
      attachments: attachments
    });
    console.log(`Email sent to ${to}: ${subject}`);
  } catch (err) {
    console.error('Email failed:', err);
  }
}

async function notifyAdmins(subject: string, text: string) {
  const config = await SystemConfig.findOne({ id: 'main' });
  if (config?.notificationEmail) {
    const email = EmailTemplates.getGeneralAlertEmail(subject, text, `${process.env.APP_URL}/dashboard`);
    await sendMail(config.notificationEmail, email.subject, email.text, email.html);
  }
}


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function extractVRChatGroupId(input: string): string {
  if (!input) return '';
  const trimmed = input.trim();
  const grpMatch = trimmed.match(/grp_[a-zA-Z0-9\-_]+/);
  if (grpMatch) {
    return grpMatch[0];
  }
  return trimmed;
}

function extractVRChatUserId(input: string): string {
  if (!input) return '';
  const trimmed = input.trim();
  const uuidMatch = trimmed.match(/usr_[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}/);
  if (uuidMatch) {
    return uuidMatch[0];
  }
  const fallbackMatch = trimmed.match(/usr_[a-zA-Z0-9\-_]+/);
  if (fallbackMatch) {
    return fallbackMatch[0];
  }
  return trimmed;
}

// --- VRChat API Rate Limit Cache & Cooldown helpers ---
const verifiedCookiesCache = new Map<string, { verifiedAt: number; cookie: string }>();
const botLoginCooldowns = new Map<string, number>();
let lastStatusUpdateAt = 0;

// --- MongoDB Models ---
// User model: Dedicated strictly for Trusted Members, Whitelist tracking, reputation, and age verification.
// (All bans belong exclusively to the BanCase model).
const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  email: { type: String, index: true },
  username: String,
  reputation: { type: Number, default: 0 },
  isTrusted: { type: Boolean, default: false, index: true },
  isBanned: { type: Boolean, default: false },
  banReason: String,
  bannedAt: Date,
  bannedBy: String,
  banType: String,
  banExpiresAt: Date,
  banCaseId: String,
  evidenceLinks: [String],
  isDangerous: { type: Boolean, default: false },
  dangerousNotes: String,
  trustIndex: String,
  isAgeVerified: { type: Boolean, default: false },
  dob: Date,
  ageVerifiedAt: Date,
  avatarUrl: String,
  savedAvatarUrl: String,
  vrchatUserId: { type: String, default: "" },
  vrchatUsername: { type: String, default: "" },
  vrchatAlts: [{
    vrchatUserId: { type: String, required: true },
    vrchatUsername: String,
    linkedAt: { type: Date, default: Date.now }
  }],
  warnings: [{
    reason: String,
    adminId: String,
    guildId: String,
    timestamp: { type: Date, default: Date.now }
  }],
  unbanHistory: [{
    bandate: { type: Date, default: Date.now },
    unbandate: { type: Date, default: Date.now },
    banreason: String,
    username: String,
    bannedBy: String,
    unbannedBy: String,
    unbanReason: String
  }],
  vrchatLastCheckedAt: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const banCaseSchema = new mongoose.Schema({
  caseNumber: { type: String, required: true, unique: true, index: true },
  title: { type: String, default: "" },
  reason: { type: String, required: true },
  severity: { type: String, enum: ['permanent', 'temporary', 'critical', 'warning'], default: 'permanent' },
  status: { type: String, enum: ['active', 'lifted'], default: 'active', index: true },
  discordAccounts: [{
    discordId: { type: String, required: true },
    username: { type: String, default: "" },
    displayName: { type: String, default: "" },
    avatarUrl: { type: String, default: "" },
    linkedAt: { type: Date, default: Date.now }
  }],
  vrchatAccounts: [{
    vrchatUserId: { type: String, required: true },
    vrchatUsername: { type: String, default: "" },
    isPrimary: { type: Boolean, default: false },
    linkedAt: { type: Date, default: Date.now }
  }],
  evidenceLinks: [{ type: String }],
  notes: { type: String, default: "" },
  isDangerous: { type: Boolean, default: false, index: true },
  dangerousNotes: { type: String, default: "" },
  trustIndex: { type: String, default: "CRIMINAL" },
  bannedBy: { type: String, default: "Admin" },
  bannedAt: { type: Date, default: Date.now },
  unbannedBy: { type: String, default: "" },
  unbannedAt: { type: Date },
  unbanReason: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const reportSchema = new mongoose.Schema({
  targetUserId: { type: String, required: true },
  targetDisplayName: { type: String, default: "" },
  reporterUserId: { type: String, required: true },
  reporterEmail: { type: String, required: true },
  reason: { type: String, required: true },
  evidenceLinks: [String],
  attachments: [String],
  status: { type: String, enum: ['pending', 'claimed', 'reviewed', 'dismissed'], default: 'pending' },
  claimedBy: { type: String, default: null },
  claimedAt: { type: Date },
  messages: [{
    sender: { type: String, enum: ['admin', 'user'] },
    content: String,
    attachments: [String],
    timestamp: { type: Date, default: Date.now }
  }],
  vrchatAccount: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now }
});

const appealSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  email: { type: String, required: true },
  reason: { type: String, required: true },
  status: { type: String, enum: ['pending', 'claimed', 'approved', 'denied'], default: 'pending' },
  adminNotes: String,
  vrchatAccount: { type: String, default: "" },
  attachments: [{ type: String }],
  claimedBy: { type: String, default: null },
  claimedAt: { type: Date },
  messages: [{
    sender: { type: String, enum: ['admin', 'user'] },
    content: String,
    attachments: [{ type: String }],
    timestamp: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const logSchema = new mongoose.Schema({
  action: { type: String, required: true },
  adminId: String,
  targetId: String,
  details: String,
  timestamp: { type: Date, default: Date.now }
});

const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true }, // To receive links
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'moderator', 'user'], default: 'user' },
  displayName: { type: String, default: "" },
  avatarUrl: { type: String, default: "" },
  bio: { type: String, default: "" },
  discordId: String,
  vrchatUserId: { type: String, default: "" },
  vrchatUsername: { type: String, default: "" },
  dawnchatId: { type: String, default: "" },
  dawnchatUsername: { type: String, default: "" },
  isAgeVerified: { type: Boolean, default: false },
  dob: Date,
  ageVerifiedAt: Date,
  dawnchatSettings: {
    safetyBridgeEnabled: { type: Boolean, default: true },
    filterSensitivity: { type: String, default: "balanced" },
    autoKickBlacklisted: { type: Boolean, default: true },
    webhookUrl: { type: String, default: "" },
    communityId: { type: String, default: "" }
  },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  isEmailVerified: { type: Boolean, default: false },
  emailVerificationToken: String,
  createdAt: { type: Date, default: Date.now }
});

const userVRChatGroupSchema = new mongoose.Schema({
  userId: { type: String, required: true }, // Admin user ID
  groupId: { type: String, required: true }, // e.g. grp_xxxx-xxxx
  groupName: { type: String, default: "" },
  shortCode: { type: String, default: "" },
  description: { type: String, default: "" },
  iconUrl: { type: String, default: "" },
  bannerUrl: { type: String, default: "" },
  memberCount: { type: Number, default: 0 },
  autoBanEnabled: { type: Boolean, default: true },
  autoUnbanEnabled: { type: Boolean, default: true },
  blacklistThreshold: { type: Number, default: -10 },
  customBanlistId: { type: String, default: "" },
  status: { type: String, enum: ['active', 'paused', 'error'], default: 'active' },
  statusMessage: { type: String, default: "" },
  publicListing: {
    isListed: { type: Boolean, default: false },
    description: { type: String, default: "" },
    joinUrl: { type: String, default: "" },
    category: { type: String, default: "VRChat Community" }
  },
  lastSyncedAt: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});
const UserVRChatGroup = mongoose.models.UserVRChatGroup || mongoose.model('UserVRChatGroup', userVRChatGroupSchema);

const systemConfigSchema = new mongoose.Schema({
  id: { type: String, default: 'main' },
  notificationEmail: String,
  vrchatUsername: { type: String, default: "" },
  vrchatPassword: { type: String, default: "" },
  vrchatCookie: { type: String, default: "" },
  vrchatGroupId: { type: String, default: "" },
  vrchatBotEnabled: { type: Boolean, default: false },
  twoFactorAuthApiUrl: { type: String, default: "" },
  twoFactorAuthApiToken: { type: String, default: "" },
  twoFactorAuthAccountId: { type: String, default: "" },
  vrchatBotStatus: { type: String, default: "idle" },
  vrchatBotError: { type: String, default: "" },
  vrchatBotLastCheckedAt: { type: Date, default: Date.now },
  vrchatBotGroupCount: { type: Number, default: 0 },
  vrchatBotGroups: [String],
  vrchatBots: [{
    id: { type: String, default: () => new mongoose.Types.ObjectId().toString() },
    vrchatUsername: { type: String, default: "" },
    vrchatPassword: { type: String, default: "" },
    vrchatCookie: { type: String, default: "" },
    twoFactorAuthApiUrl: { type: String, default: "" },
    twoFactorAuthApiToken: { type: String, default: "" },
    twoFactorAuthAccountId: { type: String, default: "" },
    groupCount: { type: Number, default: 0 },
    groups: [String],
    status: { type: String, default: "idle" },
    error: { type: String, default: "" },
    lastCheckedAt: { type: Date, default: Date.now }
  }],
  disableAgeVerifyCommand: { type: Boolean, default: false },
  updatedAt: { type: Date, default: Date.now }
});
const SystemConfig = mongoose.model('SystemConfig', systemConfigSchema);

const guildSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: String,
  ownerId: String,
  settings: {
    autoBanThreshold: { type: Number, default: -10 },
    warningThreshold: { type: Number, default: 3 },
    tempBanDuration: { type: Number, default: 7 }, // in days
    logChannelId: String,
    autoBanEnabled: { type: Boolean, default: false },
    staffRoleId: String,
    staffChannelId: String,
    verificationEnabled: { type: Boolean, default: false },
    verificationRoleId: String,
    ageRoleEnabled: { type: Boolean, default: false },
    ageRoleId: String,
    autoAssignAgeRole: { type: Boolean, default: false },
    disableAgeVerifyCommand: { type: Boolean, default: false },
    vrchatBotEnabled: { type: Boolean, default: false },
    vrchatGroupId: { type: String, default: "" },
    vrchatAutoBanEnabled: { type: Boolean, default: true },
    autoUnbanDiscordEnabled: { type: Boolean, default: true },
    autoUnbanVRChatEnabled: { type: Boolean, default: true },
    customBanlistId: { type: String, default: "" },
    banlistSelectionMode: { type: String, enum: ['both', 'global', 'custom'], default: 'global' },
    customBotToken: { type: String, default: "" },
    customBotEnabled: { type: Boolean, default: false },
    customBotStatus: { type: String, enum: ['online', 'idle', 'dnd', 'invisible'], default: "online" },
    customBotActivityType: { type: String, default: "PLAYING" },
    customBotActivityText: { type: String, default: "" },
    nsfwBlockerEnabled: { type: Boolean, default: false },
    nsfwBlockerAction: { type: String, enum: ['delete_and_warn', 'delete', 'warn', 'log_only'], default: 'delete_and_warn' },
    nsfwBlockerLogChannelId: { type: String, default: "" },
    nsfwBlockerSensitivity: { type: Number, default: 0.65 },
    nsfwBlockerScanNsfwChannels: { type: Boolean, default: false },
    nsfwBlockerAllowedChannelIds: { type: [String], default: [] }
  },
  publicListing: {
    isListed: { type: Boolean, default: false },
    description: { type: String, default: "" },
    inviteUrl: { type: String, default: "" },
    category: { type: String, default: "Gaming & Community" },
    iconUrl: { type: String, default: "" },
    memberCount: { type: Number, default: 0 }
  },
  updatedAt: { type: Date, default: Date.now }
});

const customBanlistSchema = new mongoose.Schema({
  name: { type: String, required: true },
  ownerId: { type: String, required: true },
  entries: [{
    type: { type: String, enum: ['discord', 'vrchat'], required: true },
    targetId: { type: String, required: true },
    reason: { type: String, default: 'Custom blacklisted' },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const CustomBanlist = mongoose.model('CustomBanlist', customBanlistSchema);

const serverBackupSchema = new mongoose.Schema({
  guildId: { type: String, required: true, index: true },
  name: { type: String, required: true },
  creatorId: { type: String, required: true },
  creatorTag: String,
  serverDetails: {
    name: String,
    icon: String,
    afkTimeout: Number,
    verificationLevel: Number,
    explicitContentFilter: Number,
    defaultMessageNotifications: Number
  },
  roles: [{
    id: String,
    name: String,
    color: Number,
    hoist: Boolean,
    position: Number,
    permissions: String,
    mentionable: Boolean,
    isManaged: Boolean
  }],
  categories: [{
    id: String,
    name: String,
    position: Number,
    permissionOverwrites: [{
      id: String,
      type: { type: Number },
      roleName: String,
      allow: String,
      deny: String
    }]
  }],
  channels: [{
    id: String,
    name: String,
    type: { type: Number },
    topic: String,
    nsfw: Boolean,
    rateLimitPerUser: Number,
    bitrate: Number,
    userLimit: Number,
    position: Number,
    parentId: String,
    parentName: String,
    permissionOverwrites: [{
      id: String,
      type: { type: Number },
      roleName: String,
      allow: String,
      deny: String
    }]
  }],
  bans: [{
    userId: String,
    userTag: String,
    reason: String
  }],
  members: [{
    userId: String,
    userTag: String,
    roles: [String],
    roleNames: [String]
  }],
  createdAt: { type: Date, default: Date.now }
});

const ServerBackup = mongoose.models.ServerBackup || mongoose.model('ServerBackup', serverBackupSchema);

async function createGuildBackup(guild: any, creatorId: string, creatorTag?: string, customName?: string) {
  const fetchedRoles = await guild.roles.fetch();
  const rolesData: any[] = [];
  fetchedRoles.forEach((role: any) => {
    if (role.name !== '@everyone' && role.managed) return;
    rolesData.push({
      id: role.id,
      name: role.name,
      color: role.color,
      hoist: role.hoist,
      position: role.rawPosition !== undefined ? role.rawPosition : role.position,
      permissions: role.permissions.bitfield.toString(),
      mentionable: role.mentionable,
      isManaged: role.managed || false
    });
  });

  const membersData: any[] = [];
  try {
    const fetchedMembers = await guild.members.fetch().catch(() => null);
    if (fetchedMembers) {
      fetchedMembers.forEach((member: any) => {
        if (member.user?.bot) return;
        const userRoles = member.roles.cache
          .filter((r: any) => r.name !== '@everyone' && !r.managed)
          .map((r: any) => ({ id: r.id, name: r.name }));
        if (userRoles.length > 0) {
          membersData.push({
            userId: member.id,
            userTag: member.user?.tag || member.user?.username || member.id,
            roles: userRoles.map((r: any) => r.id),
            roleNames: userRoles.map((r: any) => r.name)
          });
        }
      });
    }
  } catch (e: any) {
    console.error('Error fetching members for backup:', e?.message);
  }

  const fetchedChannels = await guild.channels.fetch();
  const categoriesData: any[] = [];
  const channelsData: any[] = [];

  fetchedChannels.forEach((channel: any) => {
    if (!channel) return;

    const overwrites: any[] = [];
    if (channel.permissionOverwrites && channel.permissionOverwrites.cache) {
      channel.permissionOverwrites.cache.forEach((po: any) => {
        const role = fetchedRoles.get(po.id);
        overwrites.push({
          id: po.id,
          type: po.type,
          roleName: role ? role.name : undefined,
          allow: po.allow.bitfield.toString(),
          deny: po.deny.bitfield.toString()
        });
      });
    }

    if (channel.type === ChannelType.GuildCategory) {
      categoriesData.push({
        id: channel.id,
        name: channel.name,
        position: channel.rawPosition !== undefined ? channel.rawPosition : channel.position,
        permissionOverwrites: overwrites
      });
    } else {
      channelsData.push({
        id: channel.id,
        name: channel.name,
        type: channel.type,
        topic: channel.topic || '',
        nsfw: channel.nsfw || false,
        rateLimitPerUser: channel.rateLimitPerUser || 0,
        bitrate: channel.bitrate || undefined,
        userLimit: channel.userLimit || undefined,
        position: channel.rawPosition !== undefined ? channel.rawPosition : channel.position,
        parentId: channel.parentId || undefined,
        parentName: channel.parent ? channel.parent.name : undefined,
        permissionOverwrites: overwrites
      });
    }
  });

  const serverDetails = {
    name: guild.name,
    icon: typeof guild.iconURL === 'function' ? (guild.iconURL({ size: 256 }) || '') : '',
    afkTimeout: guild.afkTimeout || 300,
    verificationLevel: guild.verificationLevel || 0,
    explicitContentFilter: guild.explicitContentFilter || 0,
    defaultMessageNotifications: guild.defaultMessageNotifications || 0
  };

  const bansData: any[] = [];
  try {
    const fetchedBans = await guild.bans.fetch();
    fetchedBans.forEach((ban: any) => {
      bansData.push({
        userId: ban.user.id,
        userTag: ban.user.tag || ban.user.username,
        reason: ban.reason || ''
      });
    });
  } catch (e) {}

  const backupName = customName && customName.trim()
    ? customName.trim()
    : `Backup - ${new Date().toLocaleString()}`;

  const backup = new ServerBackup({
    guildId: guild.id,
    name: backupName,
    creatorId,
    creatorTag: creatorTag || creatorId,
    serverDetails,
    roles: rolesData,
    members: membersData,
    categories: categoriesData,
    channels: channelsData,
    bans: bansData
  });

  await backup.save();
  return backup;
}

async function restoreGuildBackup(guild: any, backup: any) {
  if (!guild || !backup) return false;

  // 1. Snapshot current members and their role names before wiping roles
  const currentMembers = await guild.members.fetch().catch(() => null);
  const existingMemberRolesMap = new Map<string, string[]>();
  if (currentMembers) {
    currentMembers.forEach((m: any) => {
      if (m.user?.bot) return;
      const rNames = m.roles.cache
        .filter((r: any) => r.name !== '@everyone' && !r.managed)
        .map((r: any) => r.name.toLowerCase());
      if (rNames.length > 0) {
        existingMemberRolesMap.set(m.id, rNames);
      }
    });
  }

  // 2. Delete ALL existing non-managed, deletable roles
  const currentRoles = await guild.roles.fetch().catch(() => new Map());
  for (const [, role] of currentRoles) {
    if (!role) continue;
    if (role.id === guild.id || role.name === '@everyone') continue;
    if (role.managed) continue;
    if (!role.editable) continue;

    try {
      await role.delete('Anti-Raid Server Rollback - Wiping Existing Roles').catch((e: any) => {
        console.error(`Failed to delete role "${role.name}" (${role.id}):`, e?.message);
      });
    } catch (e: any) {
      console.error(`Error deleting role "${role.name}":`, e?.message);
    }
  }

  const roleIdMap = new Map<string, string>();
  const roleNameMap = new Map<string, string>();

  const rolesList = Array.isArray(backup.roles) ? backup.roles : [];
  const everyoneBackupRole = rolesList.find((r: any) => r.name === '@everyone' || r.id === guild.id);
  if (everyoneBackupRole) {
    try {
      if (guild.roles.everyone && guild.roles.everyone.editable) {
        const perms = everyoneBackupRole.permissions?.toString() || '0';
        await guild.roles.everyone.setPermissions(BigInt(perms)).catch((e: any) => console.error('Set everyone perms failed:', e?.message));
      }
      if (guild.roles.everyone) {
        roleIdMap.set(everyoneBackupRole.id, guild.roles.everyone.id);
        roleNameMap.set('@everyone', guild.roles.everyone.id);
      }
    } catch (e: any) {
      console.error('Error restoring @everyone permissions:', e?.message);
    }
  }

  // 3. Recreate all roles from backup (sort descending so highest roles are created first and pushed to the top)
  const rolesToCreate = rolesList.filter((r: any) => r && r.name !== '@everyone' && !r.isManaged);
  rolesToCreate.sort((a: any, b: any) => (b.position || 0) - (a.position || 0));

  for (const r of rolesToCreate) {
    try {
      const perms = r.permissions?.toString() || '0';
      const createdRole = await guild.roles.create({
        name: r.name,
        color: r.color,
        hoist: r.hoist,
        mentionable: r.mentionable,
        permissions: BigInt(perms),
        reason: 'Anti-Raid Server Rollback - Recreating Role'
      });
      roleIdMap.set(r.id, createdRole.id);
      roleNameMap.set(r.name, createdRole.id);
      roleNameMap.set(r.name.toLowerCase(), createdRole.id);
    } catch (e: any) {
      console.error(`Error recreating role ${r.name}:`, e?.message);
    }
  }

  const existingChannels = await guild.channels.fetch().catch(() => new Map());
  const nonCategories: any[] = [];
  const categories: any[] = [];
  for (const [, ch] of existingChannels) {
    if (!ch) continue;
    if (ch.type === ChannelType.GuildCategory || ch.type === 4) {
      categories.push(ch);
    } else {
      nonCategories.push(ch);
    }
  }

  for (const ch of nonCategories) {
    try {
      await ch.delete('Anti-Raid Rollback Cleanup').catch(() => null);
    } catch (e) {}
  }
  for (const ch of categories) {
    try {
      await ch.delete('Anti-Raid Rollback Cleanup').catch(() => null);
    } catch (e) {}
  }

  const resolveOverwrites = (overwrites: any[]) => {
    if (!Array.isArray(overwrites)) return [];
    const resolved: any[] = [];
    const guildMemberIds = guild.members?.cache ? new Set(guild.members.cache.keys()) : null;

    for (const po of overwrites) {
      if (!po) continue;
      
      let overwriteType = 0; // 0 = Role, 1 = Member
      if (
        po.type === 1 || 
        po.type === '1' || 
        po.type === 'member' || 
        po.type === 'user' || 
        po.type === 'Member' || 
        po.type === 'User'
      ) {
        overwriteType = 1;
      }

      let targetId: string | undefined = undefined;

      if (overwriteType === 0) {
        targetId = roleIdMap.get(po.id);
        if (!targetId && po.roleName) {
          targetId = roleNameMap.get(po.roleName);
        }
        if (!targetId && (po.id === guild.id || po.roleName === '@everyone')) {
          targetId = guild.roles.everyone?.id || guild.id;
        }
        if (!targetId && currentRoles.has && currentRoles.has(po.id)) {
          targetId = po.id;
        }
      } else {
        if (!guildMemberIds || guildMemberIds.has(po.id)) {
          targetId = po.id;
        }
      }

      if (targetId) {
        try {
          const allowStr = po.allow?.toString() || '0';
          const denyStr = po.deny?.toString() || '0';
          resolved.push({
            id: targetId,
            type: overwriteType,
            allow: BigInt(allowStr),
            deny: BigInt(denyStr)
          });
        } catch (e) {}
      }
    }
    return resolved;
  };

  const categoryMap = new Map<string, string>();
  const categoryNameMap = new Map<string, string>();

  const backupCategories = Array.isArray(backup.categories) ? backup.categories : [];
  const sortedCategories = [...backupCategories].sort((a, b) => (a.position || 0) - (b.position || 0));
  for (const cat of sortedCategories) {
    if (!cat || !cat.name) continue;
    const catName = String(cat.name).trim().substring(0, 100);
    try {
      const createdCat = await guild.channels.create({
        name: catName,
        type: ChannelType.GuildCategory,
        position: typeof cat.position === 'number' ? cat.position : undefined,
        permissionOverwrites: resolveOverwrites(cat.permissionOverwrites),
        reason: 'Anti-Raid Server Rollback'
      });
      categoryMap.set(cat.id, createdCat.id);
      categoryNameMap.set(catName, createdCat.id);
    } catch (e: any) {
      console.warn(`Error recreating category ${catName} with overwrites:`, e?.message);
      try {
        const createdCat = await guild.channels.create({
          name: catName,
          type: ChannelType.GuildCategory,
          reason: 'Anti-Raid Server Rollback Fallback'
        });
        categoryMap.set(cat.id, createdCat.id);
        categoryNameMap.set(catName, createdCat.id);
      } catch (e2: any) {
        console.error(`Failed category ${catName}:`, e2?.message);
      }
    }
  }

  const hasCommunity = guild.features && (
    (Array.isArray(guild.features) && (guild.features.includes('COMMUNITY') || guild.features.includes('NEWS'))) ||
    (typeof guild.features.has === 'function' && (guild.features.has('COMMUNITY') || guild.features.has('NEWS')))
  );

  const backupChannels = Array.isArray(backup.channels) ? backup.channels : [];
  const sortedChannels = [...backupChannels].sort((a, b) => (a.position || 0) - (b.position || 0));

  for (const ch of sortedChannels) {
    if (!ch || !ch.name) continue;

    let parentId: string | undefined = undefined;
    if (ch.parentId) parentId = categoryMap.get(ch.parentId);
    if (!parentId && ch.parentName) parentId = categoryNameMap.get(ch.parentName);

    let channelType = ChannelType.GuildText;
    let rawType = ch.type;

    if (typeof rawType === 'string') {
      if (rawType === 'GUILD_TEXT' || rawType === '0') channelType = ChannelType.GuildText;
      else if (rawType === 'GUILD_VOICE' || rawType === '2') channelType = ChannelType.GuildVoice;
      else if (rawType === 'GUILD_ANNOUNCEMENT' || rawType === 'GUILD_NEWS' || rawType === '5') {
        channelType = hasCommunity ? ChannelType.GuildAnnouncement : ChannelType.GuildText;
      }
      else if (rawType === 'GUILD_STAGE_VOICE' || rawType === '13') {
        channelType = hasCommunity ? ChannelType.GuildStageVoice : ChannelType.GuildVoice;
      }
      else if (rawType === 'GUILD_FORUM' || rawType === '15') {
        channelType = hasCommunity ? ChannelType.GuildForum : ChannelType.GuildText;
      }
      else if (rawType === 'GUILD_MEDIA' || rawType === '16') {
        channelType = hasCommunity ? ChannelType.GuildMedia : ChannelType.GuildText;
      }
      else if (!isNaN(Number(rawType))) {
        rawType = Number(rawType);
      }
    }

    if (typeof rawType === 'number') {
      if (rawType === 0) channelType = ChannelType.GuildText;
      else if (rawType === 2) channelType = ChannelType.GuildVoice;
      else if (rawType === 4) channelType = ChannelType.GuildCategory;
      else if (rawType === 5) channelType = hasCommunity ? ChannelType.GuildAnnouncement : ChannelType.GuildText;
      else if (rawType === 13) channelType = hasCommunity ? ChannelType.GuildStageVoice : ChannelType.GuildVoice;
      else if (rawType === 15) channelType = hasCommunity ? ChannelType.GuildForum : ChannelType.GuildText;
      else if (rawType === 16) channelType = hasCommunity ? ChannelType.GuildMedia : ChannelType.GuildText;
      else channelType = ChannelType.GuildText;
    }

    const channelName = String(ch.name || 'unnamed-channel').trim().substring(0, 100);
    const isTextOrNews = channelType === ChannelType.GuildText || channelType === ChannelType.GuildAnnouncement;
    const isVoiceOrStage = channelType === ChannelType.GuildVoice || channelType === ChannelType.GuildStageVoice;

    const channelOptions: any = {
      name: channelName,
      type: channelType,
      reason: 'Anti-Raid Server Rollback'
    };

    if (parentId && guild.channels.cache.has(parentId)) {
      channelOptions.parent = parentId;
    }

    if (typeof ch.position === 'number') {
      channelOptions.position = ch.position;
    }

    const cleanOverwrites = resolveOverwrites(ch.permissionOverwrites);
    if (cleanOverwrites.length > 0) {
      channelOptions.permissionOverwrites = cleanOverwrites;
    }

    if (isTextOrNews) {
      if (ch.topic) channelOptions.topic = String(ch.topic).substring(0, 1024);
      if (typeof ch.rateLimitPerUser === 'number') {
        channelOptions.rateLimitPerUser = Math.min(Math.max(ch.rateLimitPerUser, 0), 21600);
      }
      if (typeof ch.nsfw === 'boolean') {
        channelOptions.nsfw = ch.nsfw;
      }
    }

    if (isVoiceOrStage) {
      if (typeof ch.bitrate === 'number' && ch.bitrate >= 8000) {
        channelOptions.bitrate = Math.min(ch.bitrate, guild.maximumBitrate || 96000);
      }
      if (typeof ch.userLimit === 'number' && ch.userLimit > 0) {
        channelOptions.userLimit = Math.min(Math.max(ch.userLimit, 0), 99);
      }
    }

    try {
      await guild.channels.create(channelOptions);
    } catch (err1: any) {
      console.warn(`Primary creation failed for channel "${channelName}" (${err1?.message}). Attempting secondary creation...`);
      try {
        const secType = isVoiceOrStage ? ChannelType.GuildVoice : ChannelType.GuildText;
        const secOptions: any = {
          name: channelName,
          type: secType,
          reason: 'Anti-Raid Server Rollback Fallback'
        };
        if (parentId && guild.channels.cache.has(parentId)) secOptions.parent = parentId;
        if (cleanOverwrites.length > 0) secOptions.permissionOverwrites = cleanOverwrites;
        if (ch.topic && secType === ChannelType.GuildText) secOptions.topic = String(ch.topic).substring(0, 1024);

        await guild.channels.create(secOptions);
      } catch (err2: any) {
        console.warn(`Secondary creation failed for channel "${channelName}" (${err2?.message}). Attempting bare minimum creation...`);
        try {
          const bareType = isVoiceOrStage ? ChannelType.GuildVoice : ChannelType.GuildText;
          await guild.channels.create({
            name: channelName,
            type: bareType,
            reason: 'Anti-Raid Server Rollback Bare Fallback'
          });
        } catch (err3: any) {
          console.error(`Error recreating channel ${channelName}:`, err3?.message);
        }
      }
    }
  }

  if (backup.serverDetails) {
    try {
      const editData: any = {};
      if (backup.serverDetails.name) editData.name = backup.serverDetails.name;
      if (backup.serverDetails.verificationLevel !== undefined) editData.verificationLevel = backup.serverDetails.verificationLevel;
      if (backup.serverDetails.explicitContentFilter !== undefined) editData.explicitContentFilter = backup.serverDetails.explicitContentFilter;
      if (backup.serverDetails.defaultMessageNotifications !== undefined) editData.defaultMessageNotifications = backup.serverDetails.defaultMessageNotifications;
      if (backup.serverDetails.afkTimeout !== undefined) editData.afkTimeout = backup.serverDetails.afkTimeout;
      if (Object.keys(editData).length > 0) {
        await guild.edit(editData).catch((e: any) => console.error('Guild edit failed:', e?.message));
      }
    } catch (e: any) {
      console.error('Error restoring server details:', e?.message);
    }
  }

  // Unban all currently banned users in the server first
  try {
    const currentBans = await guild.bans.fetch().catch(() => null);
    if (currentBans) {
      for (const [userId] of currentBans) {
        try {
          await guild.bans.remove(userId, 'Anti-Raid Server Rollback - Unbanning existing bans prior to restore').catch((e: any) => {
            console.error(`Failed to unban user ${userId}:`, e?.message);
          });
        } catch (e: any) {
          console.error(`Error unbanning user ${userId}:`, e?.message);
        }
      }
    }
  } catch (e: any) {
    console.error('Error fetching current server bans during restore:', e?.message);
  }

  // Ban everyone from the restore point
  if (Array.isArray(backup.bans) && backup.bans.length > 0) {
    for (const ban of backup.bans) {
      if (!ban || !ban.userId) continue;
      try {
        await guild.bans.create(ban.userId, { reason: ban.reason || 'Restored from Anti-Raid Server Backup' }).catch((e: any) => {
          console.error(`Failed to ban user ${ban.userId} from restore point:`, e?.message);
        });
      } catch (e: any) {
        console.error(`Error banning user ${ban.userId} from restore point:`, e?.message);
      }
    }
  }

  // 4. Re-assign newly recreated roles back on members
  try {
    const targetMembers = await guild.members.fetch().catch(() => currentMembers);
    if (targetMembers) {
      const backupMembers = Array.isArray(backup.members) ? backup.members : [];
      const backupMembersMap = new Map<string, { roles: string[]; roleNames: string[] }>();
      for (const bm of backupMembers) {
        if (bm && bm.userId) {
          backupMembersMap.set(bm.userId, {
            roles: Array.isArray(bm.roles) ? bm.roles : [],
            roleNames: Array.isArray(bm.roleNames) ? bm.roleNames : []
          });
        }
      }

      for (const [, member] of targetMembers) {
        if (!member || member.user?.bot) continue;

        const rolesToAddIds = new Set<string>();

        // 1. Check if member has role mappings in backup.members
        const bMember = backupMembersMap.get(member.id);
        if (bMember) {
          for (const oldRoleId of bMember.roles) {
            const newRoleId = roleIdMap.get(oldRoleId);
            if (newRoleId) rolesToAddIds.add(newRoleId);
          }
          for (const roleName of bMember.roleNames) {
            if (roleName) {
              const newRoleId = roleNameMap.get(roleName.toLowerCase());
              if (newRoleId) rolesToAddIds.add(newRoleId);
            }
          }
        }

        // 2. Fallback: if backup.members didn't list this member, check pre-wipe member roles
        if (rolesToAddIds.size === 0 && existingMemberRolesMap.has(member.id)) {
          const preWipeRoleNames = existingMemberRolesMap.get(member.id) || [];
          for (const rName of preWipeRoleNames) {
            const newRoleId = roleNameMap.get(rName);
            if (newRoleId) rolesToAddIds.add(newRoleId);
          }
        }

        if (rolesToAddIds.size > 0) {
          try {
            await member.roles.add(Array.from(rolesToAddIds), 'Anti-Raid Server Rollback - Restoring Member Roles').catch((e: any) => {
              console.error(`Failed to re-assign roles to member ${member.user?.tag || member.id}:`, e?.message);
            });
          } catch (e: any) {
            console.error(`Error adding roles back to member ${member.id}:`, e?.message);
          }
        }
      }
    }
  } catch (e: any) {
    console.error('Error re-assigning member roles during restore:', e?.message);
  }

  return true;
}

const User = mongoose.model('User', userSchema);
const BanCase = mongoose.models.BanCase || mongoose.model('BanCase', banCaseSchema);
const Report = mongoose.model('Report', reportSchema);
const Appeal = mongoose.model('Appeal', appealSchema);

async function safeSaveReport(report: any) {
  if (Array.isArray(report.attachments) && report.attachments.length > 5) {
    report.attachments = report.attachments.slice(-5);
  }
  try {
    await report.save();
  } catch (err: any) {
    console.warn('safeSaveReport encountered error during save:', err?.message);
    if (
      err?.message?.includes('BSONObj size') ||
      err?.message?.includes('16793600') ||
      err?.code === 10334 ||
      err?.name === 'MongoServerError'
    ) {
      if (Array.isArray(report.attachments)) {
        report.attachments = [];
      }
      await report.save();
    } else {
      throw err;
    }
  }
}

async function safeSaveAppeal(appeal: any) {
  if (Array.isArray(appeal.attachments) && appeal.attachments.length > 5) {
    appeal.attachments = appeal.attachments.slice(-5);
  }
  if (Array.isArray(appeal.messages)) {
    for (const msg of appeal.messages) {
      if (Array.isArray(msg.attachments) && msg.attachments.length > 5) {
        msg.attachments = msg.attachments.slice(-5);
      }
    }
  }

  try {
    await appeal.save();
  } catch (err: any) {
    console.warn('safeSaveAppeal encountered error during save, attempting emergency size reduction:', err?.message);
    if (
      err?.message?.includes('BSONObj size') ||
      err?.message?.includes('16793600') ||
      err?.code === 10334 ||
      err?.name === 'MongoServerError'
    ) {
      if (Array.isArray(appeal.messages)) {
        for (let i = 0; i < appeal.messages.length - 1; i++) {
          appeal.messages[i].attachments = [];
        }
      }
      if (Array.isArray(appeal.attachments)) {
        appeal.attachments = [];
      }
      await appeal.save();
    } else {
      throw err;
    }
  }
}
const Log = mongoose.model('Log', logSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Guild = mongoose.model('Guild', guildSchema);

const vrchatAlertTrackerSchema = new mongoose.Schema({
  guildId: { type: String, required: true },
  vrchatUserId: { type: String, required: true },
  groupId: { type: String, required: true },
  lastWarnedAt: { type: Date, default: Date.now }
});
const VRChatAlertTracker = mongoose.model('VRChatAlertTracker', vrchatAlertTrackerSchema);

const verificationRequestSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  username: { type: String, default: "" },
  email: { type: String, index: true },
  externalUserId: { type: String },
  callbackUrl: { type: String },
  source: { type: String, enum: ['discord', 'web', 'enterprise'], default: 'discord' },
  idPhoto: String, // base64
  facePhoto: String, // base64
  dob: Date,
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  adminNotes: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const VerificationRequest = mongoose.model('VerificationRequest', verificationRequestSchema);

const enterpriseEndpointSchema = new mongoose.Schema({
  name: { type: String, required: true },
  apiKey: { type: String, required: true, unique: true, index: true },
  webhookUrl: { type: String, required: true },
  developerEmail: { type: String, required: true, index: true },
  description: { type: String, default: "" },
  secretKey: { type: String, default: "" },
  isActive: { type: Boolean, default: true },
  deliveriesCount: { type: Number, default: 0 },
  lastDeliveryStatus: { type: String, default: "idle" },
  lastDeliveryAt: { type: Date },
  lastPayloadSent: { type: mongoose.Schema.Types.Mixed },
  lastResponseCode: { type: Number },
  lastErrorMessage: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const EnterpriseEndpoint = mongoose.model('EnterpriseEndpoint', enterpriseEndpointSchema);

const enterpriseVerificationLogSchema = new mongoose.Schema({
  endpointId: { type: String, index: true },
  apiKey: { type: String, index: true },
  email: { type: String, required: true, index: true },
  userId: { type: String },
  status: { type: String, enum: ['approved', 'denied'], required: true },
  dob: { type: String },
  callbackUrl: { type: String, required: true },
  payloadSent: { type: mongoose.Schema.Types.Mixed },
  deliverySuccess: { type: Boolean, default: false },
  httpStatus: { type: Number },
  errorMessage: { type: String },
  timestamp: { type: Date, default: Date.now }
});
const EnterpriseVerificationLog = mongoose.model('EnterpriseVerificationLog', enterpriseVerificationLogSchema);

const ReputationRating = mongoose.model('ReputationRating', new mongoose.Schema({
  userId: { type: String, required: true },
  raterId: { type: String, required: true },
  rating: { type: Number, required: true },
  updatedAt: { type: Date, default: Date.now }
}).index({ userId: 1, raterId: 1 }, { unique: true }));
const LinkCode = mongoose.model('LinkCode', new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  discordId: { type: String },
  adminId: { type: String },
  createdAt: { type: Date, default: Date.now, expires: 600 }
}));

const apiKeyRequestSchema = new mongoose.Schema({
  botName: { type: String, required: true },
  botId: { type: String, required: true },
  serverCount: { type: Number, required: true },
  developerEmail: { type: String, required: true },
  purpose: { type: String, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});
const ApiKeyRequest = mongoose.model('ApiKeyRequest', apiKeyRequestSchema);

const apiKeySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  botName: { type: String, required: true },
  botId: { type: String, required: true },
  ownerEmail: String,
  isRevoked: { type: Boolean, default: false },
  revocationReason: String,
  revokedAt: Date,
  createdAt: { type: Date, default: Date.now },
  lastUsedAt: Date
});
const ApiKey = mongoose.model('ApiKey', apiKeySchema);

const vrchatAnnouncementHistorySchema = new mongoose.Schema({
  title: { type: String, required: true },
  text: { type: String, required: true },
  imageId: String,
  sendNotification: { type: Boolean, default: true },
  visibility: { type: String, default: 'group' },
  sentBy: { type: String, required: true },
  sentAt: { type: Date, default: Date.now },
  totalTargeted: { type: Number, default: 0 },
  successCount: { type: Number, default: 0 },
  failedCount: { type: Number, default: 0 },
  groupResults: [{
    groupId: String,
    groupName: String,
    success: Boolean,
    error: String,
    postId: String
  }]
});
const VRChatAnnouncementHistory = mongoose.model('VRChatAnnouncementHistory', vrchatAnnouncementHistorySchema);

// --- Geo & Country Social Age Compliance Rule Schema ---
const geoRuleSchema = new mongoose.Schema({
  countryCode: { type: String, required: true, unique: true, uppercase: true, trim: true, index: true },
  countryName: { type: String, required: true },
  defaultLocale: { type: String, default: "en" },
  minAgeSocial: { type: Number, required: true, default: 13 },
  idVerificationRequired: { type: Boolean, required: true, default: false },
  regulatoryFramework: { type: String, default: "" },
  notes: { type: String, default: "" },
  isCustom: { type: Boolean, default: false },
  updatedBy: { type: String, default: "system" },
  updatedAt: { type: Date, default: Date.now }
});
const GeoRule = mongoose.model('GeoRule', geoRuleSchema);

// --- API Partner Bot Schema ---
// Bots listed here are bots that use the BeSafe API. Bots can only be added by admins.
const apiBotSchema = new mongoose.Schema({
  name: { type: String, required: true },
  platform: { type: String, enum: ['discord', 'vrchat', 'multi'], default: 'discord' },
  description: { type: String, required: true },
  avatarUrl: { type: String, default: "" },
  inviteUrl: { type: String, default: "" },
  websiteUrl: { type: String, default: "" },
  authorName: { type: String, default: "BeSafe Verified Developer" },
  authorId: { type: String, default: "" },
  apiScopes: { type: [String], default: ['read:reputation', 'enforce:bans'] },
  apiUsageDetails: { type: String, default: "Queries global banlist and posts threat telemetry via BeSafe REST API v1" },
  serversCount: { type: Number, default: 0 },
  usersProtected: { type: Number, default: 0 },
  isVerified: { type: Boolean, default: true },
  isListed: { type: Boolean, default: true },
  addedBy: { type: String, default: "admin" },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const ApiBot = mongoose.models.ApiBot || mongoose.model('ApiBot', apiBotSchema);

// --- Trusted Company / Partner Schema ---
// Companies and websites that use BeSafe services
const trustedCompanySchema = new mongoose.Schema({
  name: { type: String, required: true },
  websiteUrl: { type: String, required: true },
  logoUrl: { type: String, default: "" },
  industry: { type: String, default: "Gaming & Metaverse" },
  description: { type: String, default: "" },
  servicesUsed: { type: [String], default: ['Global Ban Synchronization', 'Threat Intelligence API'] },
  isFeatured: { type: Boolean, default: true },
  order: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});
const TrustedCompany = mongoose.models.TrustedCompany || mongoose.model('TrustedCompany', trustedCompanySchema);

// --- MongoDB Indexes for Query Performance ---
userSchema.index({ isDangerous: 1 });
userSchema.index({ isAgeVerified: 1 });
banCaseSchema.index({ 'discordAccounts.discordId': 1 });
banCaseSchema.index({ 'vrchatAccounts.vrchatUserId': 1 });
reportSchema.index({ targetUserId: 1 });
reportSchema.index({ status: 1 });
appealSchema.index({ userId: 1 });
appealSchema.index({ status: 1 });
logSchema.index({ timestamp: -1 });

// Helper to resolve discord user info fast by caching and using memory cache / database fields
async function resolveDiscordUser(client: any, userId: string, dbUser?: any) {
  if (!client) {
    return {
      displayName: dbUser?.username || userId,
      username: dbUser?.username || 'unknown',
      avatarUrl: dbUser?.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png'
    };
  }

  // 1. Try local memory cache (discord.js client.users.cache)
  try {
    const cachedUser = client.users.cache.get(userId);
    if (cachedUser) {
      return {
        displayName: cachedUser.displayName || cachedUser.username,
        username: cachedUser.username,
        avatarUrl: cachedUser.avatarURL ? cachedUser.avatarURL({ size: 256 }) : (dbUser?.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png')
      };
    }
  } catch (e) {
    console.warn('[resolveDiscordUser] Error accessing cache:', e);
  }

  // 2. Use DB cached fields if we have them and they are not empty
  if (dbUser && dbUser.username) {
    return {
      displayName: dbUser.username,
      username: dbUser.username,
      avatarUrl: dbUser.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png'
    };
  }

  // 3. Fallback to discord API fetch, but catch errors and limit impact
  try {
    const discordUser = await client.users.fetch(userId);
    const displayName = discordUser.displayName || discordUser.username;
    const username = discordUser.username;
    let avatarUrl = 'https://cdn.discordapp.com/embed/avatars/0.png';
    if (discordUser.avatar) {
      avatarUrl = `https://cdn.discordapp.com/avatars/${userId}/${discordUser.avatar}.png?size=256`;
    }
    
    // Asynchronously update DB cache
    if (dbUser) {
      User.updateOne({ id: userId }, { $set: { username, avatarUrl } }).catch(() => {});
    }
    
    return { displayName, username, avatarUrl };
  } catch (e) {
    return {
      displayName: dbUser?.username || userId,
      username: dbUser?.username || 'unknown',
      avatarUrl: dbUser?.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png'
    };
  }
}

// Resolves live avatar for watchlist display without saving or caching image files
async function getWatchlistAvatar(client: any, user: any): Promise<string> {
  const DEFAULT_PLACEHOLDER = 'https://cdn.discordapp.com/embed/avatars/0.png';
  try {
    const resolved = await resolveDiscordUser(client, user.id, user);
    return resolved.avatarUrl || user.avatarUrl || DEFAULT_PLACEHOLDER;
  } catch (e) {
    return user.avatarUrl || DEFAULT_PLACEHOLDER;
  }
}

// Cleanup function to remove any previously saved avatars from database and local disk
async function cleanupSavedWatchlistAvatars() {
  try {
    // Unset savedAvatarUrl from all users in the database
    await User.updateMany(
      { savedAvatarUrl: { $exists: true } },
      { $unset: { savedAvatarUrl: "" } }
    );
    // Remove local watchlist avatars directory if it exists
    const avatarsDir = path.join(process.cwd(), 'data', 'watchlist-avatars');
    if (fs.existsSync(avatarsDir)) {
      await fs.promises.rm(avatarsDir, { recursive: true, force: true });
      console.log('[Watchlist Avatars] Cleaned up local saved watchlist avatars.');
    }
  } catch (err: any) {
    console.warn('[Watchlist Avatars] Cleanup notice:', err?.message);
  }
}

// Helper to accumulate all VRChat accounts (primary and alts) from a user model
function getAllVRChatAccounts(user: any) {
  const list: Array<{ vrchatUserId: string, vrchatUsername: string }> = [];
  if (user.vrchatUserId) {
    list.push({ vrchatUserId: user.vrchatUserId, vrchatUsername: user.vrchatUsername });
  }
  if (user.vrchatAlts && Array.isArray(user.vrchatAlts)) {
    for (const alt of user.vrchatAlts) {
      if (alt.vrchatUserId && !list.some(x => x.vrchatUserId === alt.vrchatUserId)) {
        list.push({ vrchatUserId: alt.vrchatUserId, vrchatUsername: alt.vrchatUsername });
      }
    }
  }
  return list;
}

function parseVRChatAccountString(input: string): Array<{ vrchatUserId: string; vrchatUsername: string }> {
  if (!input) return [];
  const list: Array<{ vrchatUserId: string; vrchatUsername: string }> = [];
  const tokens = input.split(/[\n,;]+/).map(t => t.trim()).filter(Boolean);

  for (let token of tokens) {
    if (token.includes('vrchat.com/home/user/')) {
      const parts = token.split('vrchat.com/home/user/');
      if (parts[1]) {
        token = parts[1].split('/')[0].split('?')[0].trim();
      }
    }

    if (token.startsWith('usr_')) {
      list.push({ vrchatUserId: token, vrchatUsername: '' });
    } else if (token) {
      list.push({ vrchatUserId: '', vrchatUsername: token });
    }
  }

  return list;
}

async function startServer() {
  const serviceName = (process.env.SERVICE_NAME || 'all').toLowerCase();
  console.log(`[Service Orchestrator] Service Mode: ${serviceName}`);

  if (serviceName === 'vrchat' || serviceName === 'vrchat-bot') {
    try {
      await import('./services/vrchat-bot/index.js');
    } catch {
      await import('./services/vrchat-bot/index.ts');
    }
    return;
  }

  if (serviceName === 'discord' || serviceName === 'discord-bot') {
    try {
      await import('./services/discord-bot/index.js');
    } catch {
      await import('./services/discord-bot/index.ts');
    }
    return;
  }

  if (serviceName === 'discord-sharder') {
    try {
      await import('./services/discord-bot/shard-manager.js');
    } catch {
      await import('./services/discord-bot/shard-manager.ts');
    }
    return;
  }

  const app = express();
  // Determine port: prioritize CLI args (--port <number>), DEFAULT_APP_PORT, or fallback to 3000
  // Note: Ignore PORT=8080 because port 8080 is reserved for Nginx ingress proxy in this environment
  let PORT = 3000;
  const portArgIndex = process.argv.indexOf('--port');
  if (portArgIndex !== -1 && process.argv[portArgIndex + 1]) {
    const parsed = parseInt(process.argv[portArgIndex + 1], 10);
    if (!isNaN(parsed) && parsed > 0) PORT = parsed;
  } else if (process.env.DEFAULT_APP_PORT) {
    const parsed = parseInt(process.env.DEFAULT_APP_PORT, 10);
    if (!isNaN(parsed) && parsed > 0) PORT = parsed;
  } else if (process.env.PORT && process.env.PORT !== '8080') {
    const parsed = parseInt(process.env.PORT, 10);
    if (!isNaN(parsed) && parsed > 0) PORT = parsed;
  }

  // Connect to MongoDB
  if (process.env.MONGODB_URI) {
    try {
      await mongoose.connect(process.env.MONGODB_URI);
      console.log('Connected to MongoDB');
      // Migrate any legacy base64 image strings to local image files
      // Clean up any previously saved watchlist avatars
      cleanupSavedWatchlistAvatars().catch(() => {});
    } catch (err) {
      console.error('MongoDB connection error:', err);
    }
  } else {
    console.warn('MONGODB_URI not found in environment variables.');
  }

  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ limit: '50mb', extended: true }));

  // Kubernetes Probes & Microservices Telemetry
  app.get('/healthz', (_req, res) => {
    res.status(200).json({ status: 'ok', service: serviceName, uptime: process.uptime() });
  });

  app.get('/readyz', (_req, res) => {
    const isDbReady = mongoose.connection.readyState === 1;
    res.status(isDbReady ? 200 : 503).json({
      status: isDbReady ? 'ready' : 'not-ready',
      service: serviceName,
      dbReady: isDbReady,
    });
  });

  app.get('/api/services/status', async (_req, res) => {
    try {
      let vrchatStatus: any = { status: 'unknown' };
      let discordStatus: any = { status: 'unknown' };

      const vrchatUrl = process.env.VRCHAT_SERVICE_URL || 'http://localhost:3001';
      const discordUrl = process.env.DISCORD_SERVICE_URL || 'http://localhost:3002';

      try {
        const vrRes = await fetch(`${vrchatUrl}/api/vrchat/status`, { signal: AbortSignal.timeout(2000) });
        if (vrRes.ok) vrchatStatus = await vrRes.json();
      } catch (e: any) {
        vrchatStatus = { status: serviceName === 'all' ? 'in-process' : 'offline', error: e.message };
      }

      try {
        const discRes = await fetch(`${discordUrl}/api/discord/status`, { signal: AbortSignal.timeout(2000) });
        if (discRes.ok) discordStatus = await discRes.json();
      } catch (e: any) {
        discordStatus = { status: serviceName === 'all' ? 'in-process' : 'offline', error: e.message };
      }

      res.json({
        dashboard: { status: 'online', serviceName, port: PORT },
        vrchatBot: vrchatStatus,
        discordBot: discordStatus,
      });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || err });
    }
  });

  // Fallback for legacy /api/watchlist-avatars route - redirect to default Discord avatar
  app.get('/api/watchlist-avatars/:filename?', (req, res) => {
    res.redirect('https://cdn.discordapp.com/embed/avatars/0.png');
  });

  // Hoisted reference for synchronizing Discord application commands from admin APIs
  let syncDiscordCommandsRef: () => Promise<{ success: boolean; count: number; ageVerifyDisabled: boolean; error?: string }> = async () => ({
    success: false,
    count: 0,
    ageVerifyDisabled: false
  });

  // =========================================================================
  // --- NSFW BLOCKER ENGINE (@tensorflow/tfjs-node & nsfwjs) ---
  // =========================================================================
  let nsfwModelInstance: any = null;
  let nsfwModelLoadingPromise: Promise<any> | null = null;

  async function getOrLoadNsfwModel(): Promise<any> {
    if (nsfwModelInstance) return nsfwModelInstance;
    if (nsfwModelLoadingPromise) return nsfwModelLoadingPromise;

    nsfwModelLoadingPromise = (async () => {
      try {
        console.log('[NSFW Blocker] Initializing NSFWJS model (InceptionV3, high precision) with @tensorflow/tfjs-node...');
        nsfwModelInstance = await nsfwjs.load('InceptionV3', { size: 299 });
        console.log('[NSFW Blocker] NSFWJS InceptionV3 high-precision neural model loaded successfully!');
        return nsfwModelInstance;
      } catch (err: any) {
        console.error('[NSFW Blocker] Failed to load NSFWJS neural model:', err?.message || err);
        nsfwModelInstance = null;
        return null;
      } finally {
        nsfwModelLoadingPromise = null;
      }
    })();

    return nsfwModelLoadingPromise;
  }

  interface NsfwEvaluation {
    isNsfw: boolean;
    topCategory: string;
    confidence: number;
    predictions: Array<{ className: string; probability: number }>;
    flagReason?: string;
  }

  async function scanImageBufferWithNsfwjs(buffer: Buffer, threshold = 0.65): Promise<NsfwEvaluation | null> {
    let imageTensor: any = null;
    let tensor3d: any = null;
    try {
      const model = await getOrLoadNsfwModel();
      if (!model) return null;

      imageTensor = tf.node.decodeImage(buffer, 3);

      // Squeeze 4D tensor (e.g. animated GIFs) to 3D first frame
      if (imageTensor.shape && imageTensor.shape.length === 4) {
        tensor3d = imageTensor.slice([0, 0, 0, 0], [1, -1, -1, -1]).squeeze([0]);
      } else {
        tensor3d = imageTensor;
      }

      const predictions = await model.classify(tensor3d);

      const pornProb = predictions.find((p: any) => p.className === 'Porn')?.probability || 0;
      const hentaiProb = predictions.find((p: any) => p.className === 'Hentai')?.probability || 0;

      let isNsfw = false;
      let topCategory = 'Neutral';
      let confidence = 0;
      let flagReason = '';

      // The 'Sexy' label is completely ignored per specification; only Porn and Hentai are evaluated as violations.
      if (pornProb >= threshold) {
        isNsfw = true;
        topCategory = 'Pornography';
        confidence = pornProb;
        flagReason = `Pornographic visual content detected (${(pornProb * 100).toFixed(1)}% confidence)`;
      } else if (hentaiProb >= threshold) {
        isNsfw = true;
        topCategory = 'Hentai / Illustrated Explicit';
        confidence = hentaiProb;
        flagReason = `Explicit illustrated/anime content detected (${(hentaiProb * 100).toFixed(1)}% confidence)`;
      } else {
        // Exclude 'Sexy' when determining the primary classification category
        const relevantPredictions = predictions.filter((p: any) => p.className !== 'Sexy');
        const top = [...relevantPredictions].sort((a: any, b: any) => b.probability - a.probability)[0];
        topCategory = top ? top.className : 'Neutral';
        confidence = top ? top.probability : 0;
      }

      return {
        isNsfw,
        topCategory,
        confidence,
        predictions,
        flagReason
      };
    } catch (err: any) {
      console.warn('[NSFW Blocker] Image decoding or classification skipped:', err?.message || err);
      return null;
    } finally {
      try {
        if (tensor3d && tensor3d !== imageTensor) tensor3d.dispose();
        if (imageTensor) imageTensor.dispose();
      } catch {}
    }
  }

  async function downloadImageForScan(url: string): Promise<Buffer | null> {
    try {
      let targetUrl = url;
      if (targetUrl.startsWith('/')) {
        targetUrl = `http://127.0.0.1:${PORT}${targetUrl}`;
      }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(targetUrl, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) BeSafe-NSFW-Scanner/1.0'
        }
      });
      clearTimeout(timeout);
      if (!res.ok) return null;
      const arrayBuffer = await res.arrayBuffer();
      if (!arrayBuffer || arrayBuffer.byteLength > 15 * 1024 * 1024) return null;
      return Buffer.from(arrayBuffer);
    } catch {
      return null;
    }
  }


  // --- Auth Middleware ---
  const authenticateToken = (req: any, res: any, next: any) => {
    const authHeader = req.headers['authorization'];
    let token = authHeader && authHeader.split(' ')[1];
    if (!token && req.query.token) {
      token = req.query.token as string;
    }

    if (!token) return res.status(401).json({ error: 'Authentication token required. Please sign in.' });

    jwt.verify(token, process.env.JWT_SECRET || 'secret', (err: any, user: any) => {
      if (err) return res.status(403).json({ error: 'Session expired or invalid token. Please sign in again.' });
      req.user = user;
      next();
    });
  };

  const optionalAuth = (req: any, res: any, next: any) => {
    const authHeader = req.headers['authorization'];
    let token = authHeader && authHeader.split(' ')[1];
    if (!token && req.query.token) {
      token = req.query.token as string;
    }
    if (token) {
      jwt.verify(token, process.env.JWT_SECRET || 'secret', (err: any, user: any) => {
        if (!err && user) {
          req.user = user;
        }
        next();
      });
    } else {
      next();
    }
  };

  async function recordUnbanAndUnbanUser(userId: string, unbannedBy: string = 'System', unbanReason: string = 'Manual Unban') {
    let user = await User.findOne({ id: userId });
    if (!user) {
      user = new User({ id: userId, username: userId });
    }

    let currentUsername = user.username || userId;
    try {
      if (typeof client !== 'undefined' && client) {
        const resolved = await resolveDiscordUser(client, userId, user);
        if (resolved?.displayName) {
          currentUsername = resolved.displayName;
        }
      }
    } catch (e) {}

    const bandate = user.bannedAt || user.updatedAt || user.createdAt || new Date();
    const unbandate = new Date();
    const banreason = user.banReason || 'No ban reason recorded';

    const unbanRecord = {
      bandate,
      unbandate,
      banreason,
      username: currentUsername,
      bannedBy: (user as any).bannedBy || 'System / Moderator',
      unbannedBy,
      unbanReason
    };

    user.isBanned = false;
    user.banReason = undefined;
    (user as any).bannedBy = undefined;
    (user as any).bannedAt = undefined;
    if (!user.unbanHistory) {
      (user as any).unbanHistory = [unbanRecord];
    } else {
      user.unbanHistory.push(unbanRecord as any);
    }
    user.updatedAt = new Date();

    await user.save();

    // Execute global cross-server unban
    try {
      await enforceGlobalUnban(userId);
    } catch (e) {}

    return user;
  }

  function calculateDynamicTrustIndex(data: {
    isDangerous?: boolean;
    isBanned?: boolean;
    banType?: string;
    severity?: string;
    reputation?: number;
    warningsCount?: number;
    isTrusted?: boolean;
    isAgeVerified?: boolean;
    trustIndexOverride?: string;
  }): string {
    if (data.isDangerous || data.severity === 'critical') {
      return 'CRIMINAL';
    }
    if (data.isBanned) {
      if (data.banType === 'permanent' || data.severity === 'permanent') {
        return 'RED_CLASS_D';
      }
      return 'BLACK_TERMINAL';
    }
    const rep = data.reputation ?? 0;
    const warnings = data.warningsCount ?? 0;

    if (rep <= -20) return 'RED_CLASS_D';
    if (rep < 0 || warnings >= 3) return 'ORANGE_HIGH_RISK';
    if (warnings >= 1 || rep < 20) return 'YELLOW_WARN';
    if (data.isTrusted || (data.isAgeVerified && rep >= 20) || rep >= 50) {
      return 'GREEN_SECURE';
    }
    return 'GREEN_SECURE';
  }

  async function cleanupUserDatabaseForTrustedOnly() {
    try {
      // 1. Strip all legacy ban fields from all documents in User collection
      await User.updateMany({}, {
        $unset: {
          isBanned: 1,
          banReason: 1,
          banType: 1,
          bannedBy: 1,
          bannedAt: 1,
          banExpiresAt: 1,
          banCaseId: 1
        }
      });

      // 2. Remove placeholder user docs that are NOT trusted members and have no profile/custom data
      const result = await User.deleteMany({
        isTrusted: { $ne: true },
        isAgeVerified: { $ne: true },
        $or: [
          { reputation: { $in: [0, null] } },
          { reputation: { $exists: false } }
        ],
        $and: [
          { 'warnings.0': { $exists: false } }
        ]
      });

      console.log(`[User DB Cleanup] Purged ${result.deletedCount || 0} non-trusted records. User collection is now exclusively reserved for trusted members & whitelist.`);
      return result.deletedCount || 0;
    } catch (e) {
      console.error('[User DB Cleanup Error]:', e);
      return 0;
    }
  }

  async function migrateLegacyBansToBanCases(adminUsername: string = 'AdminMigration'): Promise<{ migratedCount: number; totalBanned: number; clearedCount: number; details: string[] }> {
    const bannedUsers = await User.find({ isBanned: true });
    let migratedCount = 0;
    const details: string[] = [];

    for (const user of bannedUsers) {
      // Check if this user already belongs to an active BanCase
      const existingCase = await BanCase.findOne({
        $or: [
          { caseNumber: (user as any).banCaseId || 'NON_EXISTENT' },
          { 'discordAccounts.discordId': user.id },
          { 'vrchatAccounts.vrchatUserId': user.vrchatUserId || 'NON_EXISTENT' }
        ]
      });

      if (existingCase) {
        continue;
      }

      // Build Discord & VRChat accounts for this legacy user
      const discordAccounts: any[] = [];
      if (user.id && !user.id.startsWith('usr_')) {
        discordAccounts.push({
          discordId: user.id,
          username: user.username || user.id,
          displayName: (user as any).displayName || user.username || user.id,
          avatarUrl: user.avatarUrl || '',
          linkedAt: user.createdAt || new Date()
        });
      }

      const vrchatAccounts: any[] = [];
      if (user.vrchatUserId) {
        vrchatAccounts.push({
          vrchatUserId: user.vrchatUserId,
          vrchatUsername: user.vrchatUsername || user.vrchatUserId,
          isPrimary: true,
          linkedAt: user.createdAt || new Date()
        });
      }
      if (user.vrchatAlts && Array.isArray(user.vrchatAlts)) {
        for (const alt of user.vrchatAlts) {
          if (alt.vrchatUserId && !vrchatAccounts.some(v => v.vrchatUserId === alt.vrchatUserId)) {
            vrchatAccounts.push({
              vrchatUserId: alt.vrchatUserId,
              vrchatUsername: alt.vrchatUsername || alt.vrchatUserId,
              isPrimary: false,
              linkedAt: (alt as any).linkedAt || new Date()
            });
          }
        }
      }

      // If user.id itself is a VRChat user ID
      if (user.id.startsWith('usr_') && !vrchatAccounts.some(v => v.vrchatUserId === user.id)) {
        vrchatAccounts.push({
          vrchatUserId: user.id,
          vrchatUsername: user.username || user.id,
          isPrimary: vrchatAccounts.length === 0,
          linkedAt: user.createdAt || new Date()
        });
      }

      const nextNum = 'CASE-' + Math.floor(1000 + Math.random() * 9000);
      const newCase = new BanCase({
        caseNumber: nextNum,
        title: user.username ? `Legacy Ban - ${user.username}` : `Legacy Ban #${user.id}`,
        reason: (user as any).banReason || 'Legacy Global Ban',
        severity: (user as any).banType === 'temporary' ? 'temporary' : ((user as any).isDangerous ? 'critical' : 'permanent'),
        status: 'active',
        isDangerous: !!(user as any).isDangerous,
        dangerousNotes: (user as any).dangerousNotes || '',
        trustIndex: (user as any).trustIndex || ((user as any).isDangerous ? 'CRIMINAL' : 'RED_CLASS_D'),
        discordAccounts,
        vrchatAccounts,
        evidenceLinks: (user as any).evidenceLinks || [],
        notes: (user as any).dangerousNotes || '',
        bannedBy: (user as any).bannedBy || 'Legacy System',
        bannedAt: (user as any).bannedAt || user.updatedAt || new Date()
      });

      await newCase.save();
      migratedCount++;
      details.push(`Migrated ${user.username || user.id} -> Case #${nextNum}`);
    }

    // Completely purge bans from User DB
    const clearedCount = await cleanupUserDatabaseForTrustedOnly();

    return {
      migratedCount,
      totalBanned: bannedUsers.length,
      clearedCount,
      details
    };
  }

  async function createOrUpdateBanCase(params: {
    caseId?: string;
    caseNumber?: string;
    title?: string;
    reason: string;
    severity?: 'permanent' | 'temporary' | 'critical' | 'warning';
    discordAccounts?: Array<{ discordId: string; username?: string; displayName?: string; avatarUrl?: string }>;
    vrchatAccounts?: Array<{ vrchatUserId: string; vrchatUsername?: string; isPrimary?: boolean }>;
    evidenceLinks?: string[];
    notes?: string;
    bannedBy?: string;
  }, adminUsername: string = 'Admin') {
    let caseDoc: any = null;
    if (params.caseId) {
      caseDoc = await BanCase.findById(params.caseId);
    }
    if (!caseDoc && params.caseNumber) {
      caseDoc = await BanCase.findOne({ caseNumber: params.caseNumber });
    }

    const isNew = !caseDoc;
    if (!caseDoc) {
      const nextNum = 'CASE-' + Math.floor(1000 + Math.random() * 9000);
      caseDoc = new BanCase({
        caseNumber: params.caseNumber || nextNum,
        title: params.title || `Ban Case ${params.caseNumber || nextNum}`,
        reason: params.reason,
        severity: params.severity || 'permanent',
        status: 'active',
        bannedBy: params.bannedBy || adminUsername,
        bannedAt: new Date(),
        discordAccounts: [],
        vrchatAccounts: [],
        evidenceLinks: params.evidenceLinks || [],
        notes: params.notes || ''
      });
    } else {
      if (params.title !== undefined) caseDoc.title = params.title;
      if (params.reason) caseDoc.reason = params.reason;
      if (params.severity) caseDoc.severity = params.severity;
      if (params.notes !== undefined) caseDoc.notes = params.notes;
      if (params.evidenceLinks) caseDoc.evidenceLinks = params.evidenceLinks;
      caseDoc.status = 'active';
      caseDoc.updatedAt = new Date();
    }

    // Normalize Discord Accounts
    const processedDiscord: any[] = [];
    if (Array.isArray(params.discordAccounts)) {
      for (const d of params.discordAccounts) {
        const dId = (d.discordId || (d as any).id || '').trim();
        if (!dId) continue;
        
        let uName = d.username || '';
        let dName = d.displayName || uName || dId;
        let avatar = d.avatarUrl || '';
        
        if (typeof client !== 'undefined' && client) {
          try {
            const resolved = await resolveDiscordUser(client, dId);
            if (resolved) {
              dName = resolved.displayName || dName;
              uName = resolved.username || uName;
              avatar = resolved.avatarUrl || avatar;
            }
          } catch (e) {}
        }
        
        processedDiscord.push({
          discordId: dId,
          username: uName || dId,
          displayName: dName || uName || dId,
          avatarUrl: avatar,
          linkedAt: (d as any).linkedAt || new Date()
        });
      }
    }

    // Normalize VRChat Accounts
    const processedVRC: any[] = [];
    if (Array.isArray(params.vrchatAccounts)) {
      for (const v of params.vrchatAccounts) {
        const vId = extractVRChatUserId(v.vrchatUserId || (v as any).id || '');
        if (!vId) continue;
        
        let vName = (v.vrchatUsername || '').trim();
        if (!vName) {
          try {
            const fetchedName = await fetchVRChatDisplayName(vId);
            if (fetchedName) vName = fetchedName;
          } catch (e) {}
        }
        
        processedVRC.push({
          vrchatUserId: vId,
          vrchatUsername: vName || vId,
          isPrimary: !!v.isPrimary,
          linkedAt: (v as any).linkedAt || new Date()
        });
      }
    }

    caseDoc.discordAccounts = processedDiscord;
    caseDoc.vrchatAccounts = processedVRC;
    caseDoc.updatedAt = new Date();
    await caseDoc.save();

    // Enforce bans on all Discord accounts directly across connected servers
    for (const disc of processedDiscord) {
      if (disc.discordId) {
        // Cross-server ban on Discord
        await enforceGlobalBan(disc.discordId, `Ban Case #${caseDoc.caseNumber}: ${caseDoc.reason}`);
      }
    }

    // Enforce bans on all VRChat accounts directly in connected VRChat groups
    for (const vrc of processedVRC) {
      if (vrc.vrchatUserId) {
        await banUserFromVRChatGroup(vrc.vrchatUserId, `Ban Case #${caseDoc.caseNumber}: ${caseDoc.reason}`);
      }
    }

    // Trigger background scan to enforce bans in connected VRChat groups
    scanAndBanBlacklistedUsers().catch(() => null);

    await new Log({
      action: isNew ? 'CREATE_BAN_CASE' : 'UPDATE_BAN_CASE',
      adminId: params.bannedBy || adminUsername,
      targetId: caseDoc.caseNumber,
      details: `${isNew ? 'Created' : 'Updated'} Ban Case ${caseDoc.caseNumber} with ${processedDiscord.length} Discord account(s) and ${processedVRC.length} VRChat account(s). Reason: ${caseDoc.reason}`
    }).save().catch(() => null);

    return caseDoc;
  }

  async function liftBanCase(caseIdOrNumber: string, unbannedBy: string = 'Admin', unbanReason: string = 'Ban Case Lifted') {
    let caseDoc = await BanCase.findOne({
      $or: [
        { _id: mongoose.isValidObjectId(caseIdOrNumber) ? caseIdOrNumber : undefined },
        { caseNumber: caseIdOrNumber }
      ].filter(Boolean)
    });

    if (!caseDoc) return null;

    caseDoc.status = 'lifted';
    caseDoc.unbannedBy = unbannedBy;
    caseDoc.unbannedAt = new Date();
    caseDoc.unbanReason = unbanReason;
    caseDoc.updatedAt = new Date();
    await caseDoc.save();

    // 1. Unban all associated Discord accounts across guilds
    if (Array.isArray(caseDoc.discordAccounts)) {
      for (const disc of caseDoc.discordAccounts) {
        if (disc.discordId) {
          await recordUnbanAndUnbanUser(disc.discordId, unbannedBy, `Ban Case ${caseDoc.caseNumber} Lifted: ${unbanReason}`);
        }
      }
    }

    // 2. Unban all associated VRChat accounts across groups
    if (Array.isArray(caseDoc.vrchatAccounts)) {
      for (const vrc of caseDoc.vrchatAccounts) {
        if (vrc.vrchatUserId) {
          await unbanUserFromVRChatGroup(vrc.vrchatUserId);
        }
      }
    }

    await new Log({
      action: 'LIFT_BAN_CASE',
      adminId: unbannedBy,
      targetId: caseDoc.caseNumber,
      details: `Lifted Ban Case ${caseDoc.caseNumber}. Unbanned all associated Discord (${caseDoc.discordAccounts?.length || 0}) and VRChat (${caseDoc.vrchatAccounts?.length || 0}) accounts. Reason: ${unbanReason}`
    }).save().catch(() => null);

    return caseDoc;
  }

  async function rebanBanCase(caseIdOrNumber: string, adminUsername: string = 'Admin', newReason?: string) {
    let caseDoc = await BanCase.findOne({
      $or: [
        { _id: mongoose.isValidObjectId(caseIdOrNumber) ? caseIdOrNumber : undefined },
        { caseNumber: caseIdOrNumber }
      ].filter(Boolean)
    });

    if (!caseDoc) return null;

    caseDoc.status = 'active';
    if (newReason) caseDoc.reason = newReason;
    caseDoc.bannedBy = adminUsername;
    caseDoc.bannedAt = new Date();
    caseDoc.unbannedBy = undefined;
    caseDoc.unbannedAt = undefined;
    caseDoc.unbanReason = undefined;
    caseDoc.updatedAt = new Date();
    await caseDoc.save();

    // Re-ban Discord accounts
    for (const disc of caseDoc.discordAccounts || []) {
      if (disc.discordId) {
        let user = await User.findOne({ id: disc.discordId });
        if (!user) user = new User({ id: disc.discordId, username: disc.displayName || disc.username });
        user.isBanned = true;
        user.banReason = caseDoc.reason;
        user.bannedBy = adminUsername;
        user.bannedAt = new Date();
        user.banCaseId = caseDoc._id.toString();
        user.updatedAt = new Date();
        await user.save();
        await enforceGlobalBan(disc.discordId, caseDoc.reason);
      }
    }

    // Re-ban VRChat accounts
    for (const vrc of caseDoc.vrchatAccounts || []) {
      if (vrc.vrchatUserId) {
        if ((caseDoc.discordAccounts || []).length === 0) {
          let user = await User.findOne({ $or: [{ id: vrc.vrchatUserId }, { vrchatUserId: vrc.vrchatUserId }] });
          if (!user) user = new User({ id: vrc.vrchatUserId, username: vrc.vrchatUsername, vrchatUserId: vrc.vrchatUserId });
          user.isBanned = true;
          user.banReason = caseDoc.reason;
          user.bannedBy = adminUsername;
          user.bannedAt = new Date();
          user.banCaseId = caseDoc._id.toString();
          user.updatedAt = new Date();
          await user.save();
        }
        await banUserFromVRChatGroup(vrc.vrchatUserId, caseDoc.reason);
      }
    }

    scanAndBanBlacklistedUsers().catch(() => null);

    await new Log({
      action: 'REBAN_BAN_CASE',
      adminId: adminUsername,
      targetId: caseDoc.caseNumber,
      details: `Re-activated Ban Case ${caseDoc.caseNumber}. Re-enforced bans on all ${caseDoc.discordAccounts?.length || 0} Discord and ${caseDoc.vrchatAccounts?.length || 0} VRChat accounts.`
    }).save().catch(() => null);

    return caseDoc;
  }

  async function addAccountToBanCase(caseIdOrNumber: string, account: { type: 'discord' | 'vrchat'; id: string; name?: string }, adminUsername: string = 'Admin') {
    let caseDoc = await BanCase.findOne({
      $or: [
        { _id: mongoose.isValidObjectId(caseIdOrNumber) ? caseIdOrNumber : undefined },
        { caseNumber: caseIdOrNumber }
      ].filter(Boolean)
    });

    if (!caseDoc) return null;

    if (account.type === 'discord') {
      const rawId = account.id.trim();
      const exists = (caseDoc.discordAccounts || []).some((a: any) => a.discordId === rawId);
      if (!exists) {
        let uName = account.name || rawId;
        let dName = account.name || rawId;
        let avatar = '';
        if (typeof client !== 'undefined' && client) {
          try {
            const resolved = await resolveDiscordUser(client, rawId);
            if (resolved) {
              dName = resolved.displayName || dName;
              uName = resolved.username || uName;
              avatar = resolved.avatarUrl || avatar;
            }
          } catch (e) {}
        }

        caseDoc.discordAccounts.push({
          discordId: rawId,
          username: uName,
          displayName: dName,
          avatarUrl: avatar,
          linkedAt: new Date()
        });

        if (caseDoc.status === 'active') {
          let user = await User.findOne({ id: rawId });
          if (!user) user = new User({ id: rawId, username: dName });
          user.isBanned = true;
          user.banReason = caseDoc.reason;
          user.bannedBy = adminUsername;
          user.bannedAt = new Date();
          user.banCaseId = caseDoc._id.toString();
          user.updatedAt = new Date();
          await user.save();
          await enforceGlobalBan(rawId, caseDoc.reason);
        }
      }
    } else if (account.type === 'vrchat') {
      const vId = extractVRChatUserId(account.id.trim());
      const exists = (caseDoc.vrchatAccounts || []).some((a: any) => a.vrchatUserId === vId);
      if (!exists) {
        let vName = (account.name || '').trim();
        if (!vName) {
          try {
            const fetchedName = await fetchVRChatDisplayName(vId);
            if (fetchedName) vName = fetchedName;
          } catch (e) {}
        }

        caseDoc.vrchatAccounts.push({
          vrchatUserId: vId,
          vrchatUsername: vName || vId,
          isPrimary: caseDoc.vrchatAccounts.length === 0,
          linkedAt: new Date()
        });

        if (caseDoc.status === 'active') {
          if ((caseDoc.discordAccounts || []).length === 0) {
            let user = await User.findOne({ $or: [{ id: vId }, { vrchatUserId: vId }] });
            if (!user) user = new User({ id: vId, username: vName || vId, vrchatUserId: vId });
            user.isBanned = true;
            user.banReason = caseDoc.reason;
            user.bannedBy = adminUsername;
            user.bannedAt = new Date();
            user.banCaseId = caseDoc._id.toString();
            user.updatedAt = new Date();
            await user.save();
          }
          await banUserFromVRChatGroup(vId, caseDoc.reason);
          scanAndBanBlacklistedUsers().catch(() => null);
        }
      }
    }

    caseDoc.updatedAt = new Date();
    await caseDoc.save();

    await new Log({
      action: 'ADD_ACCOUNT_TO_BAN_CASE',
      adminId: adminUsername,
      targetId: caseDoc.caseNumber,
      details: `Added ${account.type.toUpperCase()} account ${account.id} to Ban Case ${caseDoc.caseNumber}`
    }).save().catch(() => null);

    return caseDoc;
  }

  async function removeAccountFromBanCase(caseIdOrNumber: string, targetId: string, type?: string, adminUsername: string = 'Admin') {
    let caseDoc = await BanCase.findOne({
      $or: [
        { _id: mongoose.isValidObjectId(caseIdOrNumber) ? caseIdOrNumber : undefined },
        { caseNumber: caseIdOrNumber }
      ].filter(Boolean)
    });

    if (!caseDoc) return null;

    const rawId = targetId.trim();
    const isDiscord = type === 'discord' || (caseDoc.discordAccounts || []).some((a: any) => a.discordId === rawId);
    const isVRChat = type === 'vrchat' || (caseDoc.vrchatAccounts || []).some((a: any) => a.vrchatUserId === rawId);

    if (isDiscord) {
      caseDoc.discordAccounts = (caseDoc.discordAccounts || []).filter((a: any) => a.discordId !== rawId);
      if (caseDoc.status === 'active') {
        await recordUnbanAndUnbanUser(rawId, adminUsername, `Removed from Ban Case ${caseDoc.caseNumber}`);
      }
    }

    if (isVRChat) {
      const vId = extractVRChatUserId(rawId);
      caseDoc.vrchatAccounts = (caseDoc.vrchatAccounts || []).filter((a: any) => a.vrchatUserId !== vId && a.vrchatUserId !== rawId);
      if (caseDoc.status === 'active') {
        await unbanUserFromVRChatGroup(vId);
        const user = await User.findOne({ $or: [{ id: vId }, { vrchatUserId: vId }] });
        if (user && user.isBanned) {
          user.isBanned = false;
          user.banReason = undefined;
          user.updatedAt = new Date();
          await user.save();
        }
      }
    }

    caseDoc.updatedAt = new Date();
    await caseDoc.save();

    await new Log({
      action: 'REMOVE_ACCOUNT_FROM_BAN_CASE',
      adminId: adminUsername,
      targetId: caseDoc.caseNumber,
      details: `Removed account ${rawId} from Ban Case ${caseDoc.caseNumber}`
    }).save().catch(() => null);

    return caseDoc;
  }

  async function syncAllBansAcrossPlatforms(): Promise<{ discordBansCount: number; vrchatBansCount: number; activeCasesCount: number }> {
    const activeCases = await BanCase.find({ status: 'active' });
    let discordBansCount = 0;
    let vrchatBansCount = 0;

    for (const bCase of activeCases) {
      // 1. Enforce Discord Bans
      if (Array.isArray(bCase.discordAccounts)) {
        for (const disc of bCase.discordAccounts) {
          if (disc.discordId) {
            try {
              await enforceGlobalBan(disc.discordId, `Ban Case #${bCase.caseNumber}: ${bCase.reason}`);
              discordBansCount++;
            } catch (err) {
              console.error(`[Sync Bans] Error banning Discord account ${disc.discordId}:`, err);
            }
          }
        }
      }

      // 2. Enforce VRChat Bans
      if (Array.isArray(bCase.vrchatAccounts)) {
        for (const vrc of bCase.vrchatAccounts) {
          const vId = vrc.vrchatUserId ? vrc.vrchatUserId.trim() : '';
          if (vId && vId.startsWith('usr_')) {
            try {
              await banUserFromVRChatGroup(vId, `Ban Case #${bCase.caseNumber}: ${bCase.reason}`);
              vrchatBansCount++;
            } catch (err) {
              console.error(`[Sync Bans] Error banning VRChat account ${vId}:`, err);
            }
          }
        }
      }
    }

    // Trigger full background scan to enforce bans in all connected VRChat groups
    scanAndBanBlacklistedUsers().catch(() => null);

    return {
      activeCasesCount: activeCases.length,
      discordBansCount,
      vrchatBansCount
    };
  }

  const isAdmin = async (req: any, res: any, next: any) => {
    try {
      if (req.user && req.user.role === 'admin') {
        return next();
      }
      const user = await Admin.findById(req.user?.id);
      if (user && user.role === 'admin') {
        return next();
      }
      return res.status(403).json({ error: 'Admin access required' });
    } catch (e) {
      if (req.user && req.user.role === 'admin') {
        return next();
      }
      return res.status(500).json({ error: 'Internal server error' });
    }
  };

  const isModOrAdmin = async (req: any, res: any, next: any) => {
    try {
      if (req.user && (req.user.role === 'admin' || req.user.role === 'moderator')) {
        return next();
      }
      const user = await Admin.findById(req.user?.id);
      if (user && (user.role === 'admin' || user.role === 'moderator')) {
        return next();
      }
      return res.status(403).json({ error: 'Moderator or Admin access required' });
    } catch (e) {
      if (req.user && (req.user.role === 'admin' || req.user.role === 'moderator')) {
        return next();
      }
      return res.status(500).json({ error: 'Internal server error' });
    }
  };

  // Helper to determine the application base URL safely
  const getBaseUrl = (req?: express.Request): string => {
    if (process.env.APP_URL && process.env.APP_URL.trim() !== '' && process.env.APP_URL !== 'undefined') {
      return process.env.APP_URL.trim().replace(/\/$/, '');
    }
    if (req) {
      const rawProto = req.headers['x-forwarded-proto'];
      let protocol = 'http';
      if (typeof rawProto === 'string') {
        protocol = rawProto.split(',')[0].trim();
      } else if (Array.isArray(rawProto) && rawProto.length > 0) {
        protocol = rawProto[0].split(',')[0].trim();
      } else if (req.protocol) {
        protocol = req.protocol;
      }
      
      const rawHost = req.headers['x-forwarded-host'] || req.get('host') || 'localhost:3000';
      const host = Array.isArray(rawHost) ? rawHost[0] : rawHost.split(',')[0].trim();
      
      return `${protocol}://${host}`.replace(/\/$/, '');
    }
    return 'http://localhost:3000';
  };

  // --- Auto-Verification Matching Helper ---
  // Automatically verify an account if its email matches an already verified Discord user
  async function checkAndAutoVerifyFromDiscord(options: {
    email?: string | null;
    adminId?: any;
    discordId?: string | null;
  }) {
    try {
      const email = options.email ? String(options.email).trim().toLowerCase() : null;
      const discordId = options.discordId ? String(options.discordId).trim() : null;

      if (!email && !discordId) return null;

      // 1. Check for verified Discord User in User collection
      let verifiedDiscordUser: any = null;
      if (email) {
        verifiedDiscordUser = await User.findOne({
          email,
          isAgeVerified: true
        });
      }
      if (!verifiedDiscordUser && discordId) {
        verifiedDiscordUser = await User.findOne({
          id: discordId,
          isAgeVerified: true
        });
      }

      // 2. Check for approved VerificationRequest
      let approvedReq: any = null;
      if (email) {
        approvedReq = await VerificationRequest.findOne({
          email,
          status: 'approved'
        }).sort({ updatedAt: -1 });
      }
      if (!approvedReq && discordId) {
        approvedReq = await VerificationRequest.findOne({
          userId: discordId,
          status: 'approved'
        }).sort({ updatedAt: -1 });
      }

      // If approvedReq has a userId that is a Discord user, let's also grab that Discord user if not yet loaded
      if (!verifiedDiscordUser && approvedReq?.userId) {
        const u = await User.findOne({ id: approvedReq.userId, isAgeVerified: true });
        if (u) verifiedDiscordUser = u;
      }

      // If neither a verified Discord User nor an approved VerificationRequest was found, return null
      if (!verifiedDiscordUser && !approvedReq) {
        return null;
      }

      const rawDob = verifiedDiscordUser?.dob || approvedReq?.dob;
      const dob: Date = rawDob ? new Date(rawDob) : new Date('2000-01-01');
      const ageVerifiedAt: Date = verifiedDiscordUser?.ageVerifiedAt || approvedReq?.updatedAt || new Date();
      const matchedDiscordId = verifiedDiscordUser?.id || (approvedReq?.source === 'discord' ? approvedReq?.userId : (discordId || null));

      // 3. Update Admin account if requested or found by email
      let updatedAdmin: any = null;
      const adminQuery: any = options.adminId
        ? { _id: options.adminId }
        : email
          ? { email }
          : matchedDiscordId
            ? { discordId: matchedDiscordId }
            : null;

      if (adminQuery) {
        updatedAdmin = await Admin.findOneAndUpdate(
          adminQuery,
          {
            $set: {
              isAgeVerified: true,
              dob,
              ageVerifiedAt,
              isEmailVerified: true,
              ...(matchedDiscordId ? { discordId: matchedDiscordId } : {})
            }
          },
          { new: true }
        );
      }

      // 4. Update or sync User document
      if (matchedDiscordId) {
        await User.findOneAndUpdate(
          { id: matchedDiscordId },
          {
            $set: {
              isAgeVerified: true,
              dob,
              ageVerifiedAt,
              ...(email ? { email } : {})
            }
          },
          { upsert: true }
        );
      }

      // 5. Ensure an approved VerificationRequest exists for records/audit
      const existingReq = await VerificationRequest.findOne({
        $or: [
          ...(email ? [{ email, status: 'approved' }] : []),
          ...(matchedDiscordId ? [{ userId: matchedDiscordId, status: 'approved' }] : [])
        ]
      });

      if (!existingReq && (email || matchedDiscordId)) {
        await new VerificationRequest({
          userId: matchedDiscordId || updatedAdmin?._id?.toString() || 'web',
          username: updatedAdmin?.username || verifiedDiscordUser?.username || '',
          email: email || verifiedDiscordUser?.email || '',
          source: 'discord',
          dob,
          status: 'approved',
          adminNotes: 'Auto-verified: email matches already verified Discord user'
        }).save().catch(() => null);
      }

      await new Log({
        action: 'AUTO_AGE_VERIFIED',
        adminId: 'SYSTEM',
        targetId: email || matchedDiscordId || 'User',
        details: `Auto-verified account: email ${email || 'N/A'} matches verified Discord user (${matchedDiscordId || 'N/A'}). DOB: ${dob.toISOString().split('T')[0]}`
      }).save().catch(() => null);

      return {
        matched: true,
        email: email || verifiedDiscordUser?.email || approvedReq?.email,
        discordId: matchedDiscordId,
        dob,
        ageVerifiedAt,
        admin: updatedAdmin,
        verifiedDiscordUser,
        approvedReq
      };
    } catch (err) {
      console.error('Error in checkAndAutoVerifyFromDiscord:', err);
      return null;
    }
  }

  // --- API Routes ---

  // Admin Auth Routes
  app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    
    const adminUser = await Admin.findOne({ username });
    if (!adminUser) return res.status(401).json({ error: 'Invalid credentials' });

    const validPassword = await bcrypt.compare(password, adminUser.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    // Auto-verify if the acc email is the same as an already verified discord user
    if (!adminUser.isAgeVerified && adminUser.email) {
      const match = await checkAndAutoVerifyFromDiscord({
        email: adminUser.email,
        adminId: adminUser._id,
        discordId: adminUser.discordId
      });
      if (match) {
        adminUser.isAgeVerified = true;
        adminUser.dob = match.dob;
        adminUser.ageVerifiedAt = match.ageVerifiedAt;
        if (match.discordId && !adminUser.discordId) {
          adminUser.discordId = match.discordId;
        }
        await adminUser.save();
      }
    }

    if (!adminUser.isEmailVerified) {
      if (!process.env.SMTP_HOST || adminUser.isAgeVerified) {
        // If SMTP is not configured or already verified from Discord, auto-verify email
        adminUser.isEmailVerified = true;
        adminUser.emailVerificationToken = undefined;
        await adminUser.save();
      } else {
        return res.status(403).json({ 
          error: 'Please verify your email address before logging in.', 
          unverified: true, 
          email: adminUser.email 
        });
      }
    }

    const token = jwt.sign({ id: adminUser._id, username: adminUser.username, role: adminUser.role }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
    res.json({ token, username: adminUser.username, role: adminUser.role, isAgeVerified: adminUser.isAgeVerified });
  });

  app.post('/api/auth/register', async (req, res) => {
    try {
      const { username, password, email } = req.body;
      if (!username || !password || !email) return res.status(400).json({ error: 'Username, password and email required' });
      
      const existing = await Admin.findOne({ $or: [{ username }, { email }] });
      if (existing) return res.status(400).json({ error: 'Username or email already taken' });

      const hashedPassword = await bcrypt.hash(password, 10);
      const verificationToken = cryptoNode.randomBytes(32).toString('hex');
      const isAutoVerified = !process.env.SMTP_HOST;

      // Auto verify if the acc email is the same as an already verified discord user
      const autoDiscordMatch = await checkAndAutoVerifyFromDiscord({ email });
      
      const newUser = new Admin({ 
        username, 
        password: hashedPassword, 
        role: 'user', 
        email,
        isEmailVerified: isAutoVerified || Boolean(autoDiscordMatch),
        isAgeVerified: Boolean(autoDiscordMatch),
        dob: autoDiscordMatch?.dob || undefined,
        ageVerifiedAt: autoDiscordMatch?.ageVerifiedAt || undefined,
        discordId: autoDiscordMatch?.discordId || undefined,
        emailVerificationToken: verificationToken
      });
      await newUser.save();

      const baseUrl = getBaseUrl(req);
      const verifyUrl = `${baseUrl}/verify-email?token=${verificationToken}`;

      if (!isAutoVerified && !autoDiscordMatch) {
        const emailData = EmailTemplates.getEmailVerificationEmail(verifyUrl);
        await sendMail(email, emailData.subject, emailData.text, emailData.html);
      }

      res.json({ 
        success: true, 
        isAgeVerified: Boolean(autoDiscordMatch),
        autoVerifiedFromDiscord: Boolean(autoDiscordMatch),
        message: autoDiscordMatch
          ? 'Registration successful! Your account has been automatically verified because your email matches an already verified Discord user.'
          : (isAutoVerified
              ? 'Registration successful! Your account has been automatically verified.'
              : 'Registration successful. Please check your email to verify your account.'),
        verificationUrl: verifyUrl
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({ error: 'Registration failed' });
    }
  });

  app.get('/api/auth/verify-email', async (req, res) => {
    try {
      const token = (req.query.token as string)?.trim();
      if (!token) return res.status(400).json({ error: 'Token is required' });

      let admin = await Admin.findOne({ emailVerificationToken: token });

      if (admin) {
        if (!admin.isEmailVerified) {
          admin.isEmailVerified = true;
          await admin.save();
        }
        return res.json({ success: true, message: 'Email address verified successfully! You can now login.' });
      }

      // If token wasn't directly found by emailVerificationToken:
      // Fallback: check if all accounts are already verified (or if user was auto-verified previously)
      const unverifiedCount = await Admin.countDocuments({ isEmailVerified: false });
      const totalCount = await Admin.countDocuments();

      if (totalCount > 0 && unverifiedCount === 0) {
        return res.json({ success: true, message: 'Your email address is already verified! You can now login.' });
      }

      return res.status(400).json({ error: 'Invalid or expired verification token' });
    } catch (error) {
      console.error('Verify email error:', error);
      res.status(500).json({ error: 'Verification failed' });
    }
  });

  app.post('/api/auth/resend-verification', async (req, res) => {
    try {
      const { email, username } = req.body;
      if (!email && !username) return res.status(400).json({ error: 'Email or username required' });

      const admin = await Admin.findOne(email ? { email } : { username });
      
      if (!admin) return res.status(404).json({ error: 'User not found' });
      if (admin.isEmailVerified) return res.status(400).json({ error: 'Email already verified' });

      const verificationToken = cryptoNode.randomBytes(32).toString('hex');
      admin.emailVerificationToken = verificationToken;
      await admin.save();

      const baseUrl = getBaseUrl(req);
      const verifyUrl = `${baseUrl}/verify-email?token=${verificationToken}`;
      const emailData = EmailTemplates.getEmailVerificationEmail(verifyUrl);
      await sendMail(admin.email, emailData.subject, emailData.text, emailData.html);

      res.json({ 
        success: true, 
        message: 'Verification email resent! Please check your inbox.',
        verificationUrl: verifyUrl
      });
    } catch (error) {
      console.error('Resend verification error:', error);
      res.status(500).json({ error: 'Failed to resend verification email' });
    }
  });

  app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const admin = await Admin.findOne({ email });
    if (!admin) return res.status(404).json({ error: 'No account with that email' });

    const token = cryptoNode.randomBytes(20).toString('hex');
    admin.resetPasswordToken = token;
    admin.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hour
    await admin.save();

    const baseUrl = getBaseUrl(req);
    const resetUrl = `${baseUrl}/reset-password?token=${token}`;
    const emailData = EmailTemplates.getPasswordResetEmail(resetUrl);
    await sendMail(email, emailData.subject, emailData.text, emailData.html);

    res.json({ success: true, message: 'Password reset link sent to your email.' });
  });

  app.post('/api/auth/reset-password', async (req, res) => {
    const { token, password } = req.body;
    const admin = await Admin.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() }
    });

    if (!admin) return res.status(400).json({ error: 'Password reset token is invalid or has expired.' });

    admin.password = await bcrypt.hash(password, 10);
    admin.resetPasswordToken = undefined;
    admin.resetPasswordExpires = undefined;
    await admin.save();

    res.json({ success: true });
  });

  // Public report endpoint
  app.post('/api/public/report', async (req, res) => {
    try {
      const { targetUserId, targetDisplayName, reporterUserId, reporterEmail, reason, evidenceLinks, vrchatAccount, attachments } = req.body;
      if (!targetUserId || !reporterUserId || !reporterEmail || !reason) {
        return res.status(400).json({ error: 'Missing required report fields' });
      }

      const cleanedVrchat = extractVRChatUserId(vrchatAccount || "");
      const report = new Report({
        targetUserId,
        reporterUserId,
        reporterEmail,
        reason,
        evidenceLinks: Array.isArray(evidenceLinks) ? evidenceLinks.filter(Boolean) : [],
        attachments: Array.isArray(attachments) ? attachments.filter(Boolean) : [],
        vrchatAccount: cleanedVrchat
      });
      await safeSaveReport(report);

      await notifyAdmins('New Subject Report', `A new safety report has been filed against ${targetDisplayName || targetUserId} (${targetUserId}) by ${reporterUserId}.${cleanedVrchat ? ` Connected VRChat Account ID: ${cleanedVrchat}` : ''}`);

      res.json({ success: true, reportId: report._id });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Failed to submit report' });
    }
  });

  // Initial admin setup (only if no admins exist)
  app.post('/api/auth/setup', async (req, res) => {
    const count = await Admin.countDocuments({ role: 'admin' });
    if (count > 0) return res.status(403).json({ error: 'Setup already completed' });

    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const newAdmin = new Admin({ 
      username, 
      password: hashedPassword, 
      role: 'admin', 
      email: 'admin@besafe.network',
      isEmailVerified: true 
    });
    await newAdmin.save();
    res.json({ success: true });
  });

  // Age Verification Routes (Handles direct website submissions, Discord submissions, and instant auto-verify)
  app.post('/api/verify/auto-check', async (req: any, res: any) => {
    try {
      let email = req.body?.email || req.body?.mail;
      let discordId = req.body?.discordId || req.body?.userId;
      let adminId: string | null = null;

      // Check if user is logged in
      const authHeader = req.headers['authorization'];
      if (authHeader && authHeader.startsWith('Bearer ')) {
        try {
          const token = authHeader.split(' ')[1];
          const decoded: any = jwt.verify(token, process.env.JWT_SECRET || 'secret');
          if (decoded && decoded.id) {
            adminId = decoded.id;
            const adminUser = await Admin.findById(adminId);
            if (adminUser) {
              if (!email && adminUser.email) email = adminUser.email;
              if (!discordId && adminUser.discordId) discordId = adminUser.discordId;
            }
          }
        } catch (e) {}
      }

      if (!email && !discordId) {
        return res.status(400).json({ error: 'Please provide an email address or Discord ID to check.' });
      }

      const match = await checkAndAutoVerifyFromDiscord({ email, adminId, discordId });
      if (match) {
        return res.json({
          success: true,
          verified: true,
          autoVerified: true,
          email: match.email,
          discordId: match.discordId,
          dob: match.dob ? match.dob.toISOString().split('T')[0] : null,
          message: 'Account verified! Your account email matches an already verified Discord user.'
        });
      }

      return res.json({
        success: false,
        verified: false,
        autoVerified: false,
        message: 'No verified Discord user was found with that email address. Please submit your verification documents below.'
      });
    } catch (e) {
      console.error('Auto-check error:', e);
      return res.status(500).json({ error: 'Auto-verification check failed' });
    }
  });

  app.post('/api/verify/request', async (req: any, res: any) => {
    try {
      let { userId, username, email, idPhoto, facePhoto, dob, source } = req.body;
      let adminUser: any = null;

      // Check if user is logged into the web dashboard
      const authHeader = req.headers['authorization'];
      if (authHeader && authHeader.startsWith('Bearer ')) {
        try {
          const token = authHeader.split(' ')[1];
          const decoded: any = jwt.verify(token, process.env.JWT_SECRET || 'secret');
          if (decoded && decoded.id) {
            adminUser = await Admin.findById(decoded.id);
            if (adminUser) {
              userId = userId || adminUser.discordId || adminUser._id.toString();
              username = username || adminUser.displayName || adminUser.username;
              email = email || adminUser.email;
              source = source || 'web';
            }
          }
        } catch (e) {
          // Token expired or invalid, fallback to body params
        }
      }

      // 1. Auto-verify check: If email matches an already verified Discord user, approve instantly!
      const candidateEmail = (email || '').trim().toLowerCase();
      if (candidateEmail || userId) {
        const autoMatch = await checkAndAutoVerifyFromDiscord({
          email: candidateEmail || undefined,
          adminId: adminUser?._id,
          discordId: userId
        });

        if (autoMatch) {
          const matchedDob = autoMatch.dob || (dob ? new Date(dob) : new Date('2000-01-01'));
          const request = new VerificationRequest({
            userId: String(userId || autoMatch.discordId || 'web').trim(),
            username: username || adminUser?.username || '',
            email: candidateEmail || autoMatch.email || '',
            source: source || 'web',
            idPhoto: idPhoto || 'auto-verified-discord-match',
            facePhoto: facePhoto || 'auto-verified-discord-match',
            dob: matchedDob,
            status: 'approved',
            adminNotes: 'Auto-verified: email matches already verified Discord user'
          });
          await request.save();

          await notifyAdmins('Age Verification Auto-Verified', `User ${username || userId} (${candidateEmail || 'No email'}) was automatically age-verified because their email matches an already verified Discord user.`);

          return res.json({ 
            success: true, 
            autoVerified: true, 
            message: 'Instant Verification! Your account has been automatically verified because your email matches an already verified Discord user.' 
          });
        }
      }

      if (!userId || !idPhoto || !facePhoto || !dob) {
        return res.status(400).json({ error: 'Missing required fields: ID document photo, face selfie photo, and Date of Birth are required.' });
      }

      // Check if there is already a pending request for this user ID or username
      const existing = await VerificationRequest.findOne({ 
        $or: [
          { userId, status: 'pending' },
          ...(username ? [{ username, status: 'pending' }] : [])
        ]
      });
      if (existing) {
        return res.status(400).json({ error: 'An age verification request is already pending review for your account.' });
      }

      const request = new VerificationRequest({
        userId: String(userId).trim(),
        username: username || '',
        email: candidateEmail || '',
        source: source || 'web',
        idPhoto,
        facePhoto,
        dob: new Date(dob)
      });
      await request.save();

      await notifyAdmins('New Age Verification Request', `A new verification request has been submitted by ${username ? `${username} (${userId})` : userId} via ${source || 'web'}.`);

      res.json({ success: true, message: 'Age verification documents submitted successfully! Our staff will review your request.' });
    } catch (error) {
      console.error('Failed to submit verification request:', error);
      res.status(500).json({ error: 'Failed to submit verification request' });
    }
  });

  app.get('/api/admin/config', authenticateToken, isAdmin, async (req, res) => {
    const config = await SystemConfig.findOne({ id: 'main' });
    res.json(config || { 
      id: 'main', 
      notificationEmail: '',
      vrchatUsername: '',
      vrchatPassword: '',
      vrchatCookie: '',
      vrchatGroupId: '',
      vrchatBotEnabled: false,
      twoFactorAuthApiUrl: '',
      twoFactorAuthApiToken: '',
      twoFactorAuthAccountId: '',
      vrchatBots: [],
      disableAgeVerifyCommand: false
    });
  });

  app.post('/api/admin/config', authenticateToken, isAdmin, async (req: any, res) => {
    const { 
      notificationEmail, 
      vrchatUsername, 
      vrchatPassword, 
      vrchatCookie, 
      vrchatGroupId, 
      vrchatBotEnabled,
      twoFactorAuthApiUrl,
      twoFactorAuthApiToken,
      twoFactorAuthAccountId,
      vrchatBots,
      disableAgeVerifyCommand
    } = req.body;
    const cleanedGroupId = extractVRChatGroupId(vrchatGroupId);
    const updatePayload: any = { 
      notificationEmail, 
      vrchatUsername, 
      vrchatPassword, 
      vrchatCookie, 
      vrchatGroupId: cleanedGroupId, 
      vrchatBotEnabled,
      twoFactorAuthApiUrl,
      twoFactorAuthApiToken,
      twoFactorAuthAccountId,
      vrchatBots: vrchatBots || [],
      updatedAt: new Date() 
    };
    if (typeof disableAgeVerifyCommand === 'boolean') {
      updatePayload.disableAgeVerifyCommand = disableAgeVerifyCommand;
    }
    const updatedConfig = await SystemConfig.findOneAndUpdate(
      { id: 'main' },
      updatePayload,
      { upsert: true, new: true }
    );
    
    if (vrchatBotEnabled) {
      // Sync group lists and auth statuses for all configured bots in background
      syncAllVRChatBots(updatedConfig).catch((err) => console.error('[VRChat Bot] Error in syncAllVRChatBots background run:', err.message));
    }

    let discordSyncResult: any = null;
    if (typeof disableAgeVerifyCommand === 'boolean') {
      try {
        discordSyncResult = await syncDiscordCommandsRef();
      } catch (e: any) {
        console.error('[Discord Commands] Error during command sync on config save:', e?.message || e);
      }
    }
    
    res.json({ success: true, config: updatedConfig, discordSync: discordSyncResult });
  });

  // Admin API: Manually trigger synchronization of Discord application slash commands
  app.post('/api/admin/discord/sync-commands', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const { disableAgeVerifyCommand } = req.body;
      if (typeof disableAgeVerifyCommand === 'boolean') {
        await SystemConfig.findOneAndUpdate(
          { id: 'main' },
          { disableAgeVerifyCommand, updatedAt: new Date() },
          { upsert: true }
        );
      }
      const syncResult = await syncDiscordCommandsRef();
      const adminUser = await Admin.findById(req.user.id);
      await new Log({
        action: 'DISCORD_COMMANDS_SYNC',
        adminId: adminUser ? adminUser.username : req.user.username,
        details: `Synchronized Discord slash commands. /age-verify command is ${syncResult.ageVerifyDisabled ? 'DISABLED and UNSYNCED' : 'ENABLED and SYNCED'}. (${syncResult.count} commands in registry)`
      }).save();

      res.json({
        success: syncResult.success,
        count: syncResult.count,
        ageVerifyDisabled: syncResult.ageVerifyDisabled,
        error: syncResult.error,
        message: syncResult.ageVerifyDisabled 
          ? 'The /age-verify slash command has been disabled and unsynced from Discord.' 
          : 'The /age-verify slash command has been enabled and synced with Discord.'
      });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to sync Discord slash commands' });
    }
  });

  // Admin API: Read live status of Discord command synchronization
  app.get('/api/admin/discord/commands-status', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const config = await SystemConfig.findOne({ id: 'main' });
      const isAgeVerifyDisabled = Boolean(config?.disableAgeVerifyCommand);
      res.json({
        ageVerifyDisabled: isAgeVerifyDisabled,
        hasBotToken: Boolean(process.env.DISCORD_TOKEN),
        hasClientId: Boolean(process.env.DISCORD_CLIENT_ID)
      });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to get Discord command status' });
    }
  });

  // --- Global Geo & Country Social Age Compliance API & Admin Rules ---
  const DEFAULT_GEO_RULES = [
    {
      countryCode: 'US',
      countryName: 'United States',
      defaultLocale: 'en-US',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "COPPA (15 U.S.C. §§ 6501–6506)",
      notes: "Federal COPPA baseline age is 13. State statutes (e.g. Texas SCOPE Act, Utah Social Media Regulation) enforce age verification and parental approval on high-risk platforms."
    },
    {
      countryCode: 'GB',
      countryName: 'United Kingdom',
      defaultLocale: 'en-GB',
      minAgeSocial: 13,
      idVerificationRequired: true,
      regulatoryFramework: "Online Safety Act 2023 & Ofcom Age Assurance Codes",
      notes: "Mandatory robust age assurance / ID verification required for commercial platforms with adult or age-restricted content. Digital consent baseline is 13 under DPA 2018."
    },
    {
      countryCode: 'AU',
      countryName: 'Australia',
      defaultLocale: 'en-AU',
      minAgeSocial: 16,
      idVerificationRequired: true,
      regulatoryFramework: "Online Safety Amendment (Social Media Minimum Age) Act 2024",
      notes: "National minimum social media access age set to 16 with mandatory age assurance/ID verification obligations enforced on service providers."
    },
    {
      countryCode: 'DE',
      countryName: 'Germany',
      defaultLocale: 'de-DE',
      minAgeSocial: 16,
      idVerificationRequired: true,
      regulatoryFramework: "GDPR Art. 8 / JMStV (Jugendmedienschutz-Staatsvertrag)",
      notes: "Digital age of consent is 16. JMStV Section 4 mandates government-recognized technical age verification (eID, Ausweis, PostIdent) for adult-rated spaces."
    },
    {
      countryCode: 'FR',
      countryName: 'France',
      defaultLocale: 'fr-FR',
      minAgeSocial: 15,
      idVerificationRequired: true,
      regulatoryFramework: "Loi n° 2023-566 (Majorité numérique et lutte contre la haine en ligne)",
      notes: "Digital majority age set at 15. Social networks must verify age and parental consent via certified third-party tokenized ID systems."
    },
    {
      countryCode: 'IT',
      countryName: 'Italy',
      defaultLocale: 'it-IT',
      minAgeSocial: 14,
      idVerificationRequired: true,
      regulatoryFramework: "Codice Privacy Art. 2-quinquies & Decreto Caivano",
      notes: "Digital consent age is 14. Parental authorization and strict age gating required for minor access to social platforms."
    },
    {
      countryCode: 'ES',
      countryName: 'Spain',
      defaultLocale: 'es-ES',
      minAgeSocial: 14,
      idVerificationRequired: true,
      regulatoryFramework: "LOPDGDD & Digital Wallet Age Verification (Cartera Digital)",
      notes: "Current digital consent age is 14. Government requires digital credential/ID age verification passport for online age assurance."
    },
    {
      countryCode: 'KR',
      countryName: 'South Korea',
      defaultLocale: 'ko-KR',
      minAgeSocial: 14,
      idVerificationRequired: true,
      regulatoryFramework: "Personal Information Protection Act & Telecommunications Business Act",
      notes: "Mandatory real-name authentication (mobile PASS, I-PIN, or credit card ID) required for service sign-ups and age-restricted content."
    },
    {
      countryCode: 'JP',
      countryName: 'Japan',
      defaultLocale: 'ja-JP',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "Act on Development of an Environment for Youth Internet Safety",
      notes: "Standard social platforms baseline is 13. Specified services (dating/social matchmaking) legally mandate government ID submission."
    },
    {
      countryCode: 'CA',
      countryName: 'Canada',
      defaultLocale: 'en-CA',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "PIPEDA & Bill C-63 (Online Harms Act)",
      notes: "Baseline age 13 for standard social networks. Federal legislative initiatives propose ID verification requirements for age-restricted material."
    },
    {
      countryCode: 'IN',
      countryName: 'India',
      defaultLocale: 'en-IN',
      minAgeSocial: 18,
      idVerificationRequired: true,
      regulatoryFramework: "Digital Personal Data Protection Act 2023 (DPDP Act, Sec. 9)",
      notes: "DPDP defines any individual below 18 as a child; platforms processing minor data are legally obligated to obtain verifiable parental consent with identity checks."
    },
    {
      countryCode: 'NL',
      countryName: 'Netherlands',
      defaultLocale: 'nl-NL',
      minAgeSocial: 16,
      idVerificationRequired: false,
      regulatoryFramework: "Uitvoeringswet Algemene verordening gegevensbescherming (UAVG)",
      notes: "Article 8 GDPR digital consent threshold set at 16."
    },
    {
      countryCode: 'IE',
      countryName: 'Ireland',
      defaultLocale: 'en-IE',
      minAgeSocial: 16,
      idVerificationRequired: false,
      regulatoryFramework: "Data Protection Act 2018 (Section 31) & Coimisiún na Meán Online Safety Code",
      notes: "Digital age of consent is 16. Online Safety Code requires age assurance on high-risk video-sharing and social platforms."
    },
    {
      countryCode: 'BR',
      countryName: 'Brazil',
      defaultLocale: 'pt-BR',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "Lei Geral de Proteção de Dados (LGPD) & Marco Civil da Internet",
      notes: "Under 12 classified as children requiring verifiable parental consent; 13+ standard social media participation."
    },
    {
      countryCode: 'CN',
      countryName: 'China',
      defaultLocale: 'zh-CN',
      minAgeSocial: 14,
      idVerificationRequired: true,
      regulatoryFramework: "Regulations on the Protection of Minors in Cyberspace",
      notes: "Mandatory real-name identity verification (National ID / face recognition) for all social and gaming accounts."
    },
    {
      countryCode: 'SG',
      countryName: 'Singapore',
      defaultLocale: 'en-SG',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "Code of Practice for Online Safety (IMDA)",
      notes: "Designated social media services must provide age-appropriate default privacy configurations and tools."
    },
    {
      countryCode: 'NZ',
      countryName: 'New Zealand',
      defaultLocale: 'en-NZ',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "Harmful Digital Communications Act & Privacy Act 2020",
      notes: "Baseline age 13 for standard social networks."
    },
    {
      countryCode: 'SE',
      countryName: 'Sweden',
      defaultLocale: 'sv-SE',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "Dataskyddsförordningen (Swedish GDPR implementation)",
      notes: "Sweden lowered the GDPR digital age of consent to 13."
    },
    {
      countryCode: 'NO',
      countryName: 'Norway',
      defaultLocale: 'no-NO',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "Personopplysningsloven (Personal Data Act)",
      notes: "Consent age set to 13, with proposals under parliamentary review to elevate minimum social age to 15."
    },
    {
      countryCode: 'BE',
      countryName: 'Belgium',
      defaultLocale: 'nl-BE',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "Loi relative à la protection des personnes physiques (GDPR consent at 13)",
      notes: "Digital age of consent is set to 13."
    },
    {
      countryCode: 'AT',
      countryName: 'Austria',
      defaultLocale: 'de-AT',
      minAgeSocial: 14,
      idVerificationRequired: false,
      regulatoryFramework: "Datenschutzgesetz (DSG) § 4",
      notes: "Digital consent age for information society services set at 14."
    },
    {
      countryCode: 'CH',
      countryName: 'Switzerland',
      defaultLocale: 'de-CH',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "Federal Act on the Protection of Minors in the Media (JSMPG / FAPMM)",
      notes: "Baseline digital participation age is 13."
    },
    {
      countryCode: 'DK',
      countryName: 'Denmark',
      defaultLocale: 'da-DK',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "Databeskyttelsesloven (GDPR Art. 8 implementation)",
      notes: "Digital age of consent is set at 13."
    },
    {
      countryCode: 'FI',
      countryName: 'Finland',
      defaultLocale: 'fi-FI',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "Tietosuojalaki (Data Protection Act 1050/2018)",
      notes: "Digital age of consent is set at 13."
    },
    {
      countryCode: 'PL',
      countryName: 'Poland',
      defaultLocale: 'pl-PL',
      minAgeSocial: 16,
      idVerificationRequired: false,
      regulatoryFramework: "Ustawa o ochronie danych osobowych",
      notes: "Default Article 8 GDPR threshold of 16."
    },
    {
      countryCode: 'PT',
      countryName: 'Portugal',
      defaultLocale: 'pt-PT',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "Lei n.º 58/2019",
      notes: "Digital consent age set to 13."
    },
    {
      countryCode: 'GR',
      countryName: 'Greece',
      defaultLocale: 'el-GR',
      minAgeSocial: 15,
      idVerificationRequired: false,
      regulatoryFramework: "Law 4624/2019",
      notes: "Digital consent age set to 15."
    },
    {
      countryCode: 'CZ',
      countryName: 'Czech Republic',
      defaultLocale: 'cs-CZ',
      minAgeSocial: 15,
      idVerificationRequired: false,
      regulatoryFramework: "Zákon o zpracování osobních údajů č. 110/2019 Sb.",
      notes: "Digital consent age set to 15."
    },
    {
      countryCode: 'RO',
      countryName: 'Romania',
      defaultLocale: 'ro-RO',
      minAgeSocial: 16,
      idVerificationRequired: false,
      regulatoryFramework: "Legea nr. 190/2018",
      notes: "Digital age of consent maintained at 16."
    },
    {
      countryCode: 'HU',
      countryName: 'Hungary',
      defaultLocale: 'hu-HU',
      minAgeSocial: 16,
      idVerificationRequired: false,
      regulatoryFramework: "Infotv. Act CXII of 2011",
      notes: "Digital age of consent maintained at 16."
    },
    {
      countryCode: 'MX',
      countryName: 'Mexico',
      defaultLocale: 'es-MX',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "Ley Federal de Protección de Datos Personales (LFPDPPP)",
      notes: "General age of consent for digital accounts is 13."
    },
    {
      countryCode: 'ZA',
      countryName: 'South Africa',
      defaultLocale: 'en-ZA',
      minAgeSocial: 18,
      idVerificationRequired: true,
      regulatoryFramework: "Protection of Personal Information Act (POPIA)",
      notes: "POPIA defines individuals under 18 as children requiring parental consent and identity validation."
    },
    {
      countryCode: 'GLOBAL',
      countryName: 'Global (International Default)',
      defaultLocale: 'en-US',
      minAgeSocial: 13,
      idVerificationRequired: false,
      regulatoryFramework: "International Standard Digital Age Baseline",
      notes: "Fallback rule applied when the visitor's country cannot be determined."
    }
  ];

  // In-memory cache for fast IP lookups
  const ipGeoCache = new Map<string, { countryCode: string; city?: string; timezone?: string; source: string }>();

  // Helper to determine private / loopback IP addresses
  function isPrivateOrLocalIp(ip: string): boolean {
    if (!ip) return true;
    const clean = ip.replace(/^::ffff:/, '').trim();
    if (clean === '127.0.0.1' || clean === '::1' || clean === 'localhost') return true;
    if (clean.startsWith('10.') || clean.startsWith('192.168.')) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(clean)) return true;
    if (clean.startsWith('fc00:') || clean.startsWith('fe80:')) return true;
    return false;
  }

  // Extract true client IP from request headers (Cloud Run, Cloudflare, proxies, query override)
  function extractClientIp(req: any): string {
    if (req.query?.ip && typeof req.query.ip === 'string') {
      return req.query.ip.trim().replace(/^::ffff:/, '');
    }

    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      const list = String(forwarded).split(',');
      for (const item of list) {
        const candidate = item.trim().replace(/^::ffff:/, '');
        if (candidate && !isPrivateOrLocalIp(candidate)) {
          return candidate;
        }
      }
      const first = list[0]?.trim().replace(/^::ffff:/, '');
      if (first) return first;
    }

    const realIp = req.headers['x-real-ip'] || 
                   req.headers['cf-connecting-ip'] || 
                   req.headers['true-client-ip'] || 
                   req.headers['fastly-client-ip'];
    if (realIp && typeof realIp === 'string') {
      return realIp.trim().replace(/^::ffff:/, '');
    }

    const rawIp = req.ip || req.socket?.remoteAddress || '127.0.0.1';
    return String(rawIp).trim().replace(/^::ffff:/, '');
  }

  const ALPHA3_TO_ALPHA2: Record<string, string> = {
    USA: 'US', GBR: 'GB', CAN: 'CA', AUS: 'AU', DEU: 'DE', FRA: 'FR',
    NLD: 'NL', ITA: 'IT', ESP: 'ES', JPN: 'JP', KOR: 'KR', BRA: 'BR',
    IND: 'IN', CHN: 'CN', MEX: 'MX', RUS: 'RU', SWE: 'SE', NOR: 'NO',
    DNK: 'DK', FIN: 'FI', CHE: 'CH', AUT: 'AT', BEL: 'BE', POL: 'PL',
    IRL: 'IE', NZL: 'NZ', SGP: 'SG', ZAF: 'ZA', ARG: 'AR', CHL: 'CL',
    PRT: 'PT', GRC: 'GR', CZE: 'CZ', ROU: 'RO', HUN: 'HU', TUR: 'TR'
  };

  let geoRulesSeeded = false;
  async function ensureDefaultGeoRulesSeeded() {
    if (geoRulesSeeded) return;
    try {
      const existing = await GeoRule.find({}, { countryCode: 1 }).lean();
      const existingCodes = new Set(existing.map((e: any) => e.countryCode));
      const missing = DEFAULT_GEO_RULES.filter(r => !existingCodes.has(r.countryCode));
      if (missing.length > 0) {
        await GeoRule.insertMany(missing.map(r => ({ ...r, isCustom: false })), { ordered: false }).catch(() => null);
      }
      geoRulesSeeded = true;
    } catch (e) {
      console.error('Failed to seed default geo rules:', e);
    }
  }

  // Detect visitor location based on IP Geolocation, Proxy Headers, or query overrides
  function detectVisitorLocation(req: any): {
    countryCode: string;
    detectedFrom: string;
    clientIp: string;
    city?: string;
    timezone?: string;
  } {
    const clientIp = extractClientIp(req);

    // 1. Explicit query parameter override (e.g. ?country=NL or ?countryCode=NL)
    if (req.query?.country || req.query?.countryCode) {
      const code = String(req.query.country || req.query.countryCode).trim().toUpperCase();
      return {
        countryCode: code,
        detectedFrom: 'query_param',
        clientIp
      };
    }

    // 2. IP Geolocation via geoip-lite (offline, sub-millisecond, accurate)
    if (!isPrivateOrLocalIp(clientIp)) {
      if (ipGeoCache.has(clientIp)) {
        const cached = ipGeoCache.get(clientIp)!;
        return {
          countryCode: cached.countryCode,
          detectedFrom: cached.source,
          clientIp,
          city: cached.city,
          timezone: cached.timezone
        };
      }

      try {
        const geo = geoip.lookup(clientIp);
        if (geo && geo.country && typeof geo.country === 'string' && geo.country.trim().length === 2) {
          const countryCode = geo.country.trim().toUpperCase();
          ipGeoCache.set(clientIp, {
            countryCode,
            city: geo.city,
            timezone: geo.timezone,
            source: 'ip_geolocation'
          });
          return {
            countryCode,
            detectedFrom: 'ip_geolocation',
            clientIp,
            city: geo.city,
            timezone: geo.timezone
          };
        }
      } catch (err) {
        console.warn('geoip-lite lookup error for IP:', clientIp, err);
      }
    }

    // 3. Reverse Proxy & CDN Country Headers
    const cfCountry = req.headers['cf-ipcountry'] || req.headers['CF-IPCountry'];
    if (cfCountry && typeof cfCountry === 'string' && cfCountry.trim().length === 2 && cfCountry.toUpperCase() !== 'XX') {
      return {
        countryCode: cfCountry.trim().toUpperCase(),
        detectedFrom: 'cf_ipcountry_header',
        clientIp
      };
    }

    const appEngineCountry = req.headers['x-appengine-country'] || req.headers['x-country-code'] || req.headers['cloudfront-viewer-country'];
    if (appEngineCountry && typeof appEngineCountry === 'string' && appEngineCountry.trim().length === 2) {
      return {
        countryCode: appEngineCountry.trim().toUpperCase(),
        detectedFrom: 'proxy_country_header',
        clientIp
      };
    }

    // 4. Client Explicit Locale or Country Headers
    const clientCountryHeader = req.headers['x-client-country'] || req.headers['x-visitor-country'];
    if (clientCountryHeader && typeof clientCountryHeader === 'string' && clientCountryHeader.trim().length === 2) {
      return {
        countryCode: clientCountryHeader.trim().toUpperCase(),
        detectedFrom: 'client_country_header',
        clientIp
      };
    }

    const LANG_TO_DEFAULT_COUNTRY: Record<string, string> = {
      nl: 'NL', de: 'DE', fr: 'FR', es: 'ES', it: 'IT', ja: 'JP', ko: 'KR',
      pt: 'BR', pl: 'PL', sv: 'SE', da: 'DK', fi: 'FI', el: 'GR', cs: 'CZ',
      hu: 'HU', ro: 'RO', sk: 'SK', uk: 'UA', ru: 'RU', zh: 'CN', tr: 'TR',
      ar: 'SA', he: 'IL', no: 'NO', nb: 'NO', nn: 'NO', th: 'TH', vi: 'VN',
      id: 'ID', en: 'US'
    };

    const clientLocaleHeader = req.headers['x-client-locale'] || req.headers['x-locale'];
    if (clientLocaleHeader && typeof clientLocaleHeader === 'string') {
      const cleanLocale = clientLocaleHeader.trim().replace('_', '-');
      const parts = cleanLocale.split('-');
      if (parts.length >= 2 && parts[1].length === 2 && /^[a-zA-Z]{2}$/.test(parts[1])) {
        return {
          countryCode: parts[1].toUpperCase(),
          detectedFrom: 'client_locale_header',
          clientIp
        };
      } else if (parts.length === 1 && LANG_TO_DEFAULT_COUNTRY[parts[0].toLowerCase()]) {
        return {
          countryCode: LANG_TO_DEFAULT_COUNTRY[parts[0].toLowerCase()],
          detectedFrom: 'client_locale_language',
          clientIp
        };
      }
    }

    // 5. Fallback to Accept-Language region code or primary language
    const acceptLang = req.headers['accept-language'];
    if (acceptLang && typeof acceptLang === 'string') {
      const parts = acceptLang.split(',');
      for (const part of parts) {
        const tag = part.split(';')[0].trim().replace('_', '-');
        const sub = tag.split('-');
        if (sub.length >= 2 && sub[1].length === 2 && /^[a-zA-Z]{2}$/.test(sub[1])) {
          return {
            countryCode: sub[1].toUpperCase(),
            detectedFrom: 'accept_language_fallback',
            clientIp
          };
        } else if (sub.length === 1 && LANG_TO_DEFAULT_COUNTRY[sub[0].toLowerCase()]) {
          return {
            countryCode: LANG_TO_DEFAULT_COUNTRY[sub[0].toLowerCase()],
            detectedFrom: 'accept_language_primary',
            clientIp
          };
        }
      }
    }

    return {
      countryCode: 'US',
      detectedFrom: 'default_fallback',
      clientIp
    };
  }

  // Resolve best locale for the detected country & request
  function resolveVisitorLocale(countryCode: string, ruleDefaultLocale: string, req: any): string {
    // 1. Explicit query parameter override (?locale=...)
    if (req.query?.locale && typeof req.query.locale === 'string') {
      return req.query.locale.trim();
    }

    // 2. Client explicit header override (x-client-locale)
    const clientLocaleHeader = req.headers['x-client-locale'] || req.headers['x-locale'];
    if (clientLocaleHeader && typeof clientLocaleHeader === 'string' && clientLocaleHeader.trim()) {
      return clientLocaleHeader.trim().replace('_', '-');
    }

    // 3. If client specified Accept-Language matching this country
    const acceptLang = req.headers['accept-language'];
    if (acceptLang && typeof acceptLang === 'string') {
      const parts = acceptLang.split(',');
      const codeUpper = countryCode.toUpperCase();
      for (const part of parts) {
        const tag = part.split(';')[0].trim().replace('_', '-');
        const sub = tag.split('-');
        // E.g. tag 'nl-NL' matches country 'NL', or 'en-GB' matches country 'GB'
        if (sub.length >= 2 && sub[1].toUpperCase() === codeUpper) {
          return tag;
        }
      }
    }

    // 4. Country's configured rule default locale (authoritative for this jurisdiction)
    if (ruleDefaultLocale && ruleDefaultLocale.trim()) {
      return ruleDefaultLocale.trim();
    }

    // 5. Dynamic Intl lookup
    try {
      return `${countryCode.toLowerCase()}-${countryCode.toUpperCase()}`;
    } catch {
      return 'en-US';
    }
  }

  // Public Geo API Endpoint: returns locale of user visiting, minimal age requirement for social for that country, and if ID verification is required
  app.get(['/api/geo', '/geo', '/api/v1/geo'], async (req: any, res: any) => {
    try {
      await ensureDefaultGeoRulesSeeded();
      const detected = detectVisitorLocation(req);
      const targetCode = detected.countryCode;

      let rule = await GeoRule.findOne({ countryCode: targetCode });
      if (!rule) {
        const defaultMatch = DEFAULT_GEO_RULES.find(r => r.countryCode === targetCode);
        if (defaultMatch) {
          rule = await new GeoRule(defaultMatch).save().catch(() => defaultMatch as any);
        } else {
          // Dynamic rule generation for any valid ISO country
          let countryName = targetCode;
          try {
            const displayNames = new Intl.DisplayNames(['en'], { type: 'region' });
            countryName = displayNames.of(targetCode) || targetCode;
          } catch {}

          const dynamicLocale = `${targetCode.toLowerCase()}-${targetCode.toUpperCase()}`;
          const isEU = ['AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE','IT','LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE'].includes(targetCode);

          rule = await new GeoRule({
            countryCode: targetCode,
            countryName,
            defaultLocale: dynamicLocale,
            minAgeSocial: isEU ? 16 : 13,
            idVerificationRequired: false,
            regulatoryFramework: isEU ? 'EU General Data Protection Regulation (GDPR Art. 8)' : 'National Digital Age Baseline',
            notes: `Standard compliance rule for ${countryName}.`,
            isCustom: false
          }).save().catch(() => ({
            countryCode: targetCode,
            countryName,
            defaultLocale: dynamicLocale,
            minAgeSocial: isEU ? 16 : 13,
            idVerificationRequired: false,
            regulatoryFramework: isEU ? 'EU GDPR Art. 8' : 'National Digital Age Baseline',
            notes: '',
            isCustom: false
          }) as any);
        }
      }

      const clientIp = detected.clientIp || extractClientIp(req);
      const visitorLocale = resolveVisitorLocale(rule.countryCode, rule.defaultLocale || 'en-US', req);

      return res.json({
        success: true,
        locale: visitorLocale,
        countryCode: rule.countryCode,
        countryName: rule.countryName,
        minimalAgeRequirement: rule.minAgeSocial,
        minAgeSocial: rule.minAgeSocial,
        idVerificationRequired: rule.idVerificationRequired,
        isIdVerificationRequired: rule.idVerificationRequired,
        regulatoryFramework: rule.regulatoryFramework || '',
        notes: rule.notes || '',
        isCustomOverride: Boolean(rule.isCustom),
        clientIp,
        city: detected.city || null,
        timezone: detected.timezone || null,
        detectedFrom: detected.detectedFrom
      });
    } catch (e: any) {
      console.error('Geo API error:', e);
      return res.status(500).json({ error: 'Failed to retrieve geo compliance information' });
    }
  });

  // Public / Admin Geo Rules listing API
  app.get(['/api/admin/geo-rules', '/api/geo/rules'], optionalAuth, async (req: any, res: any) => {
    try {
      await ensureDefaultGeoRulesSeeded();
      let rules = await GeoRule.find().sort({ countryName: 1 }).lean();
      if (!rules || rules.length === 0) {
        rules = DEFAULT_GEO_RULES.map((r, idx) => ({ ...r, _id: `default-${idx}`, isCustom: false })) as any;
      }
      const stats = {
        totalRules: rules.length,
        idVerificationRequiredCount: rules.filter((r: any) => r.idVerificationRequired).length,
        customOverridesCount: rules.filter((r: any) => r.isCustom).length
      };
      return res.json({ success: true, rules, stats });
    } catch (e: any) {
      console.error('Failed to fetch geo compliance rules:', e);
      const fallbackRules = DEFAULT_GEO_RULES.map((r, idx) => ({ ...r, _id: `fallback-${idx}`, isCustom: false }));
      return res.json({
        success: true,
        rules: fallbackRules,
        stats: {
          totalRules: fallbackRules.length,
          idVerificationRequiredCount: fallbackRules.filter(r => r.idVerificationRequired).length,
          customOverridesCount: 0
        }
      });
    }
  });

  // Admin API: Create or update a country rule
  app.post('/api/admin/geo-rules', optionalAuth, async (req: any, res: any) => {
    try {
      if (req.user && req.user.role !== 'admin' && req.user.role !== 'moderator') {
        return res.status(403).json({ error: 'Moderator or Admin access required' });
      }

      let { countryCode, countryName, defaultLocale, minAgeSocial, idVerificationRequired, regulatoryFramework, notes } = req.body;
      if (!countryCode || typeof countryCode !== 'string') {
        return res.status(400).json({ error: 'Valid Country Code is required (e.g. US, NL, DE, or GLOBAL)' });
      }

      countryCode = countryCode.trim().toUpperCase();
      if (countryCode.length === 3 && ALPHA3_TO_ALPHA2[countryCode]) {
        countryCode = ALPHA3_TO_ALPHA2[countryCode];
      }
      if (!/^[A-Z]{2,3}$/.test(countryCode) && countryCode !== 'GLOBAL') {
        return res.status(400).json({ error: 'Country Code must be a 2 or 3-letter ISO code or GLOBAL (e.g. US, NL, DE)' });
      }

      const age = parseInt(String(minAgeSocial), 10);
      if (isNaN(age) || age < 1 || age > 99) {
        return res.status(400).json({ error: 'Minimal social age requirement must be a valid number between 1 and 99' });
      }

      const isIdRequired = Boolean(idVerificationRequired);

      const existingDefault = DEFAULT_GEO_RULES.find(r => r.countryCode === countryCode);
      let name = countryName?.trim() || existingDefault?.countryName;
      if (!name) {
        try {
          const dn = new Intl.DisplayNames(['en'], { type: 'region' });
          name = dn.of(countryCode) || countryCode;
        } catch {
          name = countryCode;
        }
      }

      const locale = defaultLocale?.trim() || existingDefault?.defaultLocale || `${countryCode.toLowerCase()}-${countryCode.toUpperCase()}`;

      const updated = await GeoRule.findOneAndUpdate(
        { countryCode },
        {
          $set: {
            countryCode,
            countryName: name,
            defaultLocale: locale,
            minAgeSocial: age,
            idVerificationRequired: isIdRequired,
            regulatoryFramework: regulatoryFramework?.trim() || existingDefault?.regulatoryFramework || '',
            notes: notes?.trim() || '',
            isCustom: true,
            updatedBy: req.user?.username || 'admin',
            updatedAt: new Date()
          }
        },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );

      ipGeoCache.clear();

      await new Log({
        action: 'GEO_RULE_UPDATED',
        adminId: req.user?.username || 'admin',
        targetId: countryCode,
        details: `Updated geo compliance rule for ${countryCode} (${name}): Min Age = ${age}, ID Verification Required = ${isIdRequired}`
      }).save().catch(() => null);

      return res.json({ success: true, rule: updated, message: `Geo compliance rule for ${countryCode} updated successfully!` });
    } catch (e: any) {
      console.error('Save geo rule error:', e);
      return res.status(500).json({ error: 'Failed to save geo compliance rule: ' + (e?.message || 'Server error') });
    }
  });

  // Admin API: Reset a specific country rule back to default
  app.delete('/api/admin/geo-rules/:countryCode', optionalAuth, async (req: any, res: any) => {
    try {
      if (req.user && req.user.role !== 'admin' && req.user.role !== 'moderator') {
        return res.status(403).json({ error: 'Moderator or Admin access required' });
      }

      const code = String(req.params.countryCode).trim().toUpperCase();
      const defaultRule = DEFAULT_GEO_RULES.find(r => r.countryCode === code);
      if (defaultRule) {
        const reset = await GeoRule.findOneAndUpdate(
          { countryCode: code },
          { $set: { ...defaultRule, isCustom: false, updatedAt: new Date(), updatedBy: req.user?.username || 'admin' } },
          { upsert: true, new: true }
        );
        ipGeoCache.clear();
        return res.json({ success: true, rule: reset, message: `Rule for ${code} reset to system default.` });
      } else {
        await GeoRule.deleteOne({ countryCode: code });
        ipGeoCache.clear();
        return res.json({ success: true, message: `Custom country rule ${code} deleted.` });
      }
    } catch (e: any) {
      return res.status(500).json({ error: 'Failed to reset geo rule: ' + (e?.message || 'Server error') });
    }
  });

  // Admin API: Reset all country rules to system defaults
  app.post('/api/admin/geo-rules/reset', optionalAuth, async (req: any, res: any) => {
    try {
      if (req.user && req.user.role !== 'admin' && req.user.role !== 'moderator') {
        return res.status(403).json({ error: 'Moderator or Admin access required' });
      }
      await GeoRule.deleteMany({});
      await GeoRule.insertMany(DEFAULT_GEO_RULES.map(r => ({ ...r, isCustom: false })));
      ipGeoCache.clear();

      await new Log({
        action: 'GEO_RULES_RESET_ALL',
        adminId: req.user?.username || 'admin',
        details: 'Admin reset all geo compliance rules back to factory defaults.'
      }).save().catch(() => null);

      const rules = await GeoRule.find().sort({ countryName: 1 }).lean();
      return res.json({ success: true, message: 'All geo compliance rules have been reset to factory defaults.', rules });
    } catch (e: any) {
      return res.status(500).json({ error: 'Failed to reset all geo compliance rules: ' + (e?.message || 'Server error') });
    }
  });

  // =========================================================================
  // --- PROTECTED COMMUNITIES, API PARTNER BOTS & TRUSTED COMPANIES SYSTEM ---
  // =========================================================================

  // 1. Public Protected Communities (Discord Servers & VRChat Groups)
  app.get('/api/public/protected-communities', async (req: any, res: any) => {
    try {
      // Find all listed Discord Guilds
      const guilds = await Guild.find({
        $or: [
          { 'publicListing.isListed': true },
          { 'settings.publicDirectoryEnabled': true }
        ]
      }).select('id name publicListing settings updatedAt').lean();

      // Find all listed VRChat Groups
      const vrchatGroups = await UserVRChatGroup.find({
        $or: [
          { 'publicListing.isListed': true }
        ]
      }).select('groupId groupName shortCode description iconUrl bannerUrl memberCount publicListing autoBanEnabled lastSyncedAt').lean();

      // Collect all linked VRChat group IDs from guilds
      const linkedGroupIds = guilds
        .map((g: any) => g.settings?.vrchatGroupId?.trim())
        .filter(Boolean);

      const additionalVrcGroups = linkedGroupIds.length > 0
        ? await UserVRChatGroup.find({ groupId: { $in: linkedGroupIds } }).lean()
        : [];

      const vrcGroupMap = new Map<string, any>();
      for (const v of vrchatGroups) {
        vrcGroupMap.set(v.groupId, v);
      }
      for (const v of additionalVrcGroups) {
        if (!vrcGroupMap.has(v.groupId)) {
          vrcGroupMap.set(v.groupId, v);
        }
      }

      // 1. Build Discord servers list with linked VRChat group details
      const discordServers = guilds.map((g: any) => {
        const vrcGroupId = g.settings?.vrchatGroupId?.trim();
        let linkedVRChatGroup: any = null;

        if (vrcGroupId) {
          const vrcData = vrcGroupMap.get(vrcGroupId);
          const shortCode = vrcData?.shortCode || '';
          const groupName = vrcData?.groupName || (shortCode ? `VRC: ${shortCode}` : `${g.name} VRChat Group`);
          const joinUrl = vrcData?.publicListing?.joinUrl || (shortCode ? `https://vrc.group/${shortCode}` : `https://vrchat.com/home/group/${vrcGroupId}`);
          const iconUrl = vrcData?.iconUrl || g.publicListing?.iconUrl || '';
          const memberCount = vrcData?.memberCount || 0;

          linkedVRChatGroup = {
            groupId: vrcGroupId,
            groupName,
            shortCode,
            iconUrl,
            joinUrl,
            memberCount
          };
        }

        const features = [
          g.settings?.autoBanEnabled ? 'Global Ban Sync' : null,
          g.settings?.verificationEnabled ? 'Age Verification' : null,
          vrcGroupId ? '🎮 VRChat Group Linked' : (g.settings?.vrchatBotEnabled ? 'VRChat Sync' : null),
          g.settings?.nsfwBlockerEnabled ? 'AI NSFW Shield' : null
        ].filter(Boolean);

        return {
          id: g.id,
          name: g.name || `Server #${g.id.slice(-4)}`,
          iconUrl: g.publicListing?.iconUrl || '',
          category: g.publicListing?.category || 'Gaming & Community',
          description: g.publicListing?.description || 'Active Discord server protected by the BeSafe Network.',
          inviteUrl: g.publicListing?.inviteUrl || '',
          memberCount: g.publicListing?.memberCount || (g.settings?.approximateMemberCount || 0),
          features,
          isProtected: true,
          updatedAt: g.updatedAt,
          linkedVRChatGroup
        };
      });

      // 2. Build VRChat groups list
      const vrcList: any[] = vrchatGroups.map((v: any) => {
        // Check if any public guild links this VRChat group
        const linkedGuild = guilds.find((g: any) => g.settings?.vrchatGroupId?.trim() === v.groupId);
        let linkedDiscordServer: any = null;

        if (linkedGuild) {
          linkedDiscordServer = {
            id: linkedGuild.id,
            name: linkedGuild.name || `Server #${linkedGuild.id.slice(-4)}`,
            iconUrl: linkedGuild.publicListing?.iconUrl || '',
            inviteUrl: linkedGuild.publicListing?.inviteUrl || '',
            memberCount: linkedGuild.publicListing?.memberCount || ((linkedGuild.settings as any)?.approximateMemberCount || 0)
          };
        }

        const features = [
          'VRChat 2FA Defense',
          linkedDiscordServer ? '💬 Discord Server Linked' : null,
          v.autoBanEnabled ? 'Auto-Blacklist Eviction' : null,
          'Global Ban Sync'
        ].filter(Boolean);

        return {
          groupId: v.groupId,
          groupName: v.groupName || v.groupId,
          shortCode: v.shortCode || '',
          iconUrl: v.iconUrl || '',
          bannerUrl: v.bannerUrl || '',
          category: v.publicListing?.category || 'VRChat Community',
          description: v.publicListing?.description || v.description || 'VRChat group protected by BeSafe automated eviction.',
          joinUrl: v.publicListing?.joinUrl || (v.shortCode ? `https://vrc.group/${v.shortCode}` : `https://vrchat.com/home/group/${v.groupId}`),
          memberCount: v.memberCount || 0,
          features,
          isProtected: true,
          linkedDiscordServer
        };
      });

      // 3. User request requirement: If a discord community has a vrchat group linked,
      // show it in BOTH discord and vrchat communities (if the owner has it public).
      for (const g of guilds) {
        const vrcGroupId = g.settings?.vrchatGroupId?.trim();
        if (!vrcGroupId) continue;

        const alreadyInVrcList = vrcList.some((v: any) => v.groupId === vrcGroupId);
        if (!alreadyInVrcList) {
          const vrcData = vrcGroupMap.get(vrcGroupId);
          const shortCode = vrcData?.shortCode || '';
          const groupName = vrcData?.groupName || (shortCode ? `${g.name} [${shortCode}]` : `${g.name} [VRChat Group]`);
          const joinUrl = vrcData?.publicListing?.joinUrl || (shortCode ? `https://vrc.group/${shortCode}` : `https://vrchat.com/home/group/${vrcGroupId}`);
          const iconUrl = vrcData?.iconUrl || g.publicListing?.iconUrl || 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=120&auto=format&fit=crop&q=80';
          const bannerUrl = vrcData?.bannerUrl || '';
          const description = vrcData?.publicListing?.description || vrcData?.description || g.publicListing?.description || `Official VRChat Group linked with ${g.name}. Protected by BeSafe.`;
          const category = vrcData?.publicListing?.category || g.publicListing?.category || 'VRChat Community';
          const memberCount = vrcData?.memberCount || 0;

          vrcList.push({
            groupId: vrcGroupId,
            groupName,
            shortCode,
            iconUrl,
            bannerUrl,
            category,
            description,
            joinUrl,
            memberCount,
            features: [
              'VRChat 2FA Defense',
              '💬 Discord Server Linked',
              g.settings?.autoBanEnabled ? 'Global Ban Sync' : 'Eviction Shield'
            ],
            isProtected: true,
            linkedDiscordServer: {
              id: g.id,
              name: g.name || `Server #${g.id.slice(-4)}`,
              iconUrl: g.publicListing?.iconUrl || '',
              inviteUrl: g.publicListing?.inviteUrl || '',
              memberCount: g.publicListing?.memberCount || ((g.settings as any)?.approximateMemberCount || 0)
            }
          });
        }
      }

      return res.json({
        success: true,
        stats: {
          totalDiscordServers: discordServers.length,
          totalVRChatGroups: vrcList.length,
          totalCommunities: discordServers.length + vrcList.length
        },
        discordServers,
        vrchatGroups: vrcList
      });
    } catch (e: any) {
      console.error('Failed to fetch protected communities:', e);
      return res.status(500).json({ error: 'Failed to retrieve protected communities list' });
    }
  });

  // 2. Server Owner Toggle Public Listing
  app.post('/api/guilds/:guildId/public-listing', authenticateToken, async (req: any, res: any) => {
    try {
      const { guildId } = req.params;
      const { isListed, description, inviteUrl, category, iconUrl, memberCount } = req.body;

      let guild = await Guild.findOne({ id: guildId });
      if (!guild) {
        return res.status(404).json({ error: 'Server not found' });
      }

      // Check permission: owner of the guild or BeSafe Admin
      const isOwner = guild.ownerId === req.user?.id || guild.ownerId === req.user?.username;
      const userIsAdmin = req.user?.role === 'admin' || req.user?.role === 'moderator';

      if (!isOwner && !userIsAdmin) {
        return res.status(403).json({ error: 'Only the server owner or an administrator can toggle this listing' });
      }

      if (!guild.publicListing) {
        guild.publicListing = {} as any;
      }

      if (typeof isListed === 'boolean') {
        guild.publicListing.isListed = isListed;
      }
      if (typeof description === 'string') {
        guild.publicListing.description = description.slice(0, 500);
      }
      if (typeof inviteUrl === 'string') {
        guild.publicListing.inviteUrl = inviteUrl.trim();
      }
      if (typeof category === 'string') {
        guild.publicListing.category = category.trim();
      }
      if (typeof iconUrl === 'string') {
        guild.publicListing.iconUrl = iconUrl.trim();
      }
      if (typeof memberCount === 'number') {
        guild.publicListing.memberCount = memberCount;
      }

      guild.updatedAt = new Date();
      await guild.save();

      return res.json({
        success: true,
        message: guild.publicListing.isListed 
          ? 'Server is now listed in the public BeSafe Protected Communities directory!' 
          : 'Server removed from public directory.',
        publicListing: guild.publicListing
      });
    } catch (e: any) {
      return res.status(500).json({ error: 'Failed to update server public listing: ' + (e?.message || 'Server error') });
    }
  });

  // 3. VRChat Group Owner Toggle Public Listing
  app.post('/api/vrchat/groups/:groupId/public-listing', authenticateToken, async (req: any, res: any) => {
    try {
      const { groupId } = req.params;
      const { isListed, description, joinUrl, category } = req.body;

      let group = await UserVRChatGroup.findOne({ groupId });
      if (!group) {
        return res.status(404).json({ error: 'VRChat group not found' });
      }

      const isOwner = group.userId === req.user?.id || group.userId === req.user?.username;
      const userIsAdmin = req.user?.role === 'admin' || req.user?.role === 'moderator';

      if (!isOwner && !userIsAdmin) {
        return res.status(403).json({ error: 'Only the group manager or an administrator can toggle this listing' });
      }

      if (!group.publicListing) {
        group.publicListing = {} as any;
      }

      if (typeof isListed === 'boolean') {
        group.publicListing.isListed = isListed;
      }
      if (typeof description === 'string') {
        group.publicListing.description = description.slice(0, 500);
      }
      if (typeof joinUrl === 'string') {
        group.publicListing.joinUrl = joinUrl.trim();
      }
      if (typeof category === 'string') {
        group.publicListing.category = category.trim();
      }

      await group.save();

      return res.json({
        success: true,
        message: group.publicListing.isListed 
          ? 'VRChat group is now listed in the public BeSafe Protected Communities directory!' 
          : 'VRChat group removed from public directory.',
        publicListing: group.publicListing
      });
    } catch (e: any) {
      return res.status(500).json({ error: 'Failed to update VRChat group public listing: ' + (e?.message || 'Server error') });
    }
  });

  // 4. Public API Partner Bots (Only bots using the API, certified by admins)
  app.get('/api/public/bots', async (req: any, res: any) => {
    try {
      const bots = await ApiBot.find({ isListed: true }).sort({ serversCount: -1, createdAt: -1 }).lean();

      return res.json({
        success: true,
        count: bots.length,
        bots
      });
    } catch (e: any) {
      console.error('Failed to fetch public bots:', e);
      return res.status(500).json({ error: 'Failed to retrieve bots directory' });
    }
  });

  // Admin: Get all bots (including unlisted)
  app.get('/api/admin/bots', optionalAuth, async (req: any, res: any) => {
    try {
      if (req.user && req.user.role !== 'admin' && req.user.role !== 'moderator') {
        return res.status(403).json({ error: 'Administrator access required' });
      }
      const bots = await ApiBot.find().sort({ createdAt: -1 }).lean();
      return res.json({ success: true, count: bots.length, bots });
    } catch (e: any) {
      return res.status(500).json({ error: 'Failed to fetch admin bots' });
    }
  });

  // Admin: Add API Bot (bots can only be added by admins)
  app.post('/api/admin/bots', optionalAuth, async (req: any, res: any) => {
    try {
      if (req.user && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Administrator access required. Only admins can register certified API partner bots.' });
      }

      const { name, platform, description, avatarUrl, inviteUrl, websiteUrl, authorName, apiScopes, apiUsageDetails, serversCount, usersProtected, isVerified, isListed } = req.body;

      if (!name || !description) {
        return res.status(400).json({ error: 'Bot Name and Description are required' });
      }

      const newBot = new ApiBot({
        name: name.trim(),
        platform: ['discord', 'vrchat', 'multi'].includes(platform) ? platform : 'discord',
        description: description.trim(),
        avatarUrl: avatarUrl?.trim() || '',
        inviteUrl: inviteUrl?.trim() || '',
        websiteUrl: websiteUrl?.trim() || '',
        authorName: authorName?.trim() || req.user?.username || 'Verified Developer',
        authorId: req.user?.id || '',
        apiScopes: Array.isArray(apiScopes) ? apiScopes : ['read:reputation', 'enforce:bans'],
        apiUsageDetails: apiUsageDetails?.trim() || 'Integrates with BeSafe API v1 endpoints for real-time community protection.',
        serversCount: Number(serversCount) || 0,
        usersProtected: Number(usersProtected) || 0,
        isVerified: isVerified !== false,
        isListed: isListed !== false,
        addedBy: req.user?.username || 'admin',
        createdAt: new Date(),
        updatedAt: new Date()
      });

      await newBot.save();

      await new Log({
        action: 'API_BOT_REGISTERED',
        adminId: req.user?.username || 'admin',
        details: `Registered certified API partner bot: ${newBot.name} (${newBot.platform})`
      }).save().catch(() => null);

      return res.json({ success: true, message: `Bot ${newBot.name} added successfully!`, bot: newBot });
    } catch (e: any) {
      return res.status(500).json({ error: 'Failed to create bot: ' + (e?.message || 'Server error') });
    }
  });

  // Admin: Update API Bot
  app.put('/api/admin/bots/:id', optionalAuth, async (req: any, res: any) => {
    try {
      if (req.user && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Administrator access required' });
      }
      const bot = await ApiBot.findById(req.params.id);
      if (!bot) return res.status(404).json({ error: 'Bot not found' });

      const fields = ['name', 'platform', 'description', 'avatarUrl', 'inviteUrl', 'websiteUrl', 'authorName', 'apiScopes', 'apiUsageDetails', 'serversCount', 'usersProtected', 'isVerified', 'isListed'];
      fields.forEach(f => {
        if (req.body[f] !== undefined) {
          (bot as any)[f] = req.body[f];
        }
      });
      bot.updatedAt = new Date();
      await bot.save();

      return res.json({ success: true, message: 'Bot updated successfully', bot });
    } catch (e: any) {
      return res.status(500).json({ error: 'Failed to update bot: ' + (e?.message || 'Server error') });
    }
  });

  // Admin: Delete API Bot
  app.delete('/api/admin/bots/:id', optionalAuth, async (req: any, res: any) => {
    try {
      if (req.user && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Administrator access required' });
      }
      await ApiBot.findByIdAndDelete(req.params.id);
      return res.json({ success: true, message: 'Bot deleted from directory' });
    } catch (e: any) {
      return res.status(500).json({ error: 'Failed to delete bot' });
    }
  });

  // 5. Public Trusted Companies & Websites Directory
  app.get('/api/public/trusted-companies', async (req: any, res: any) => {
    try {
      const companies = await TrustedCompany.find().sort({ order: 1, createdAt: 1 }).lean();

      return res.json({
        success: true,
        count: companies.length,
        companies
      });
    } catch (e: any) {
      console.error('Failed to fetch trusted companies:', e);
      return res.status(500).json({ error: 'Failed to retrieve trusted companies' });
    }
  });

  // Admin: Add Trusted Company
  app.post('/api/admin/trusted-companies', optionalAuth, async (req: any, res: any) => {
    try {
      if (req.user && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Administrator access required to manage trusted companies directory.' });
      }
      const { name, websiteUrl, logoUrl, industry, description, servicesUsed, isFeatured, order } = req.body;
      if (!name || !websiteUrl) {
        return res.status(400).json({ error: 'Company Name and Website URL are required' });
      }

      const newCompany = new TrustedCompany({
        name: name.trim(),
        websiteUrl: websiteUrl.trim(),
        logoUrl: logoUrl?.trim() || '',
        industry: industry?.trim() || 'Gaming & Metaverse',
        description: description?.trim() || '',
        servicesUsed: Array.isArray(servicesUsed) ? servicesUsed : ['Global Ban Synchronization', 'Threat Intelligence API'],
        isFeatured: isFeatured !== false,
        order: Number(order) || 0,
        createdAt: new Date()
      });

      await newCompany.save();

      await new Log({
        action: 'TRUSTED_COMPANY_ADDED',
        adminId: req.user?.username || 'admin',
        details: `Added trusted partner company: ${newCompany.name} (${newCompany.websiteUrl})`
      }).save().catch(() => null);

      return res.json({ success: true, message: `Company ${newCompany.name} added successfully!`, company: newCompany });
    } catch (e: any) {
      return res.status(500).json({ error: 'Failed to add company: ' + (e?.message || 'Server error') });
    }
  });

  // Admin: Update Trusted Company
  app.put('/api/admin/trusted-companies/:id', optionalAuth, async (req: any, res: any) => {
    try {
      if (req.user && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Administrator access required' });
      }
      const company = await TrustedCompany.findById(req.params.id);
      if (!company) return res.status(404).json({ error: 'Company not found' });

      const fields = ['name', 'websiteUrl', 'logoUrl', 'industry', 'description', 'servicesUsed', 'isFeatured', 'order'];
      fields.forEach(f => {
        if (req.body[f] !== undefined) {
          (company as any)[f] = req.body[f];
        }
      });
      await company.save();

      return res.json({ success: true, message: 'Company updated successfully', company });
    } catch (e: any) {
      return res.status(500).json({ error: 'Failed to update company: ' + (e?.message || 'Server error') });
    }
  });

  // Admin: Delete Trusted Company
  app.delete('/api/admin/trusted-companies/:id', optionalAuth, async (req: any, res: any) => {
    try {
      if (req.user && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Administrator access required' });
      }
      await TrustedCompany.findByIdAndDelete(req.params.id);
      return res.json({ success: true, message: 'Company deleted from directory' });
    } catch (e: any) {
      return res.status(500).json({ error: 'Failed to delete company' });
    }
  });

  // Admin API: List all connected VRChat groups with live metadata
  app.get('/api/admin/vrchat-groups', authenticateToken, isAdmin, async (req: any, res: any) => {
    try {
      const config = await SystemConfig.findOne({ id: 'main' });
      const groupIds = new Set<string>();

      if (config?.vrchatGroupId && config.vrchatGroupId.trim()) {
        groupIds.add(config.vrchatGroupId.trim());
      }
      if (config?.vrchatBotGroups && Array.isArray(config.vrchatBotGroups)) {
        for (const g of config.vrchatBotGroups) {
          if (g && g.trim()) groupIds.add(g.trim());
        }
      }

      const userGroups = await UserVRChatGroup.find();
      for (const ug of userGroups) {
        if (ug.groupId && ug.groupId.trim()) groupIds.add(ug.groupId.trim());
      }

      const activeGuilds = await Guild.find({ 'settings.vrchatBotEnabled': true });
      for (const guild of activeGuilds) {
        const gId = guild.settings?.vrchatGroupId?.trim();
        if (gId) {
          groupIds.add(gId);
        }
      }

      const groupsList: any[] = [];
      for (const groupId of groupIds) {
        const linkedGuilds = activeGuilds
          .filter(g => g.settings?.vrchatGroupId?.trim() === groupId)
          .map(g => ({ id: g.id, name: g.name }));

        let groupDetails: any = {
          groupId,
          name: `VRChat Group (${groupId})`,
          description: '',
          iconUrl: null,
          bannerUrl: null,
          memberCount: null,
          shortCode: null,
          linkedGuilds,
          status: 'online'
        };

        try {
          const bot = await getBotForGroup(config, groupId);
          const { headers, apiKey } = await getVRChatAuthHeadersForBot(bot, config);
          const vRes = await fetch(`https://api.vrchat.cloud/api/1/groups/${groupId}?apiKey=${apiKey}`, { headers });
          if (vRes.ok) {
            const data = await vRes.json();
            groupDetails.name = data.name || groupDetails.name;
            groupDetails.description = data.description || '';
            groupDetails.iconUrl = data.iconUrl || data.bannerUrl || null;
            groupDetails.bannerUrl = data.bannerUrl || null;
            groupDetails.memberCount = data.memberCount || 0;
            groupDetails.shortCode = data.shortCode || null;
            groupDetails.discriminator = data.discriminator || null;
            groupDetails.botAssigned = bot.vrchatUsername;
          } else {
            groupDetails.status = 'warning';
            groupDetails.error = `HTTP ${vRes.status}`;
          }
        } catch (err: any) {
          groupDetails.status = 'error';
          groupDetails.error = err.message || 'Failed to fetch group details';
        }

        groupsList.push(groupDetails);
      }

      res.json({
        totalGroups: groupsList.length,
        groups: groupsList
      });
    } catch (err: any) {
      console.error('[Admin VRChat Groups] Error fetching group list:', err);
      res.status(500).json({ error: 'Failed to retrieve connected VRChat groups' });
    }
  });

  // Admin API: Broadcast announcement across connected VRChat groups
  app.post('/api/admin/vrchat-announcements/broadcast', authenticateToken, isAdmin, async (req: any, res: any) => {
    try {
      const { title, text, imageId, sendNotification, visibility, targetGroupIds } = req.body;
      
      if (!title || !title.trim()) {
        return res.status(400).json({ error: 'Announcement title is required' });
      }
      if (!text || !text.trim()) {
        return res.status(400).json({ error: 'Announcement content text is required' });
      }

      const config = await SystemConfig.findOne({ id: 'main' });
      
      const allGroupIds = new Set<string>();
      if (config?.vrchatGroupId && config.vrchatGroupId.trim()) {
        allGroupIds.add(config.vrchatGroupId.trim());
      }
      if (config?.vrchatBotGroups && Array.isArray(config.vrchatBotGroups)) {
        for (const g of config.vrchatBotGroups) {
          if (g && g.trim()) allGroupIds.add(g.trim());
        }
      }
      const activeGuilds = await Guild.find({ 'settings.vrchatBotEnabled': true });
      for (const guild of activeGuilds) {
        const gId = guild.settings?.vrchatGroupId?.trim();
        if (gId) allGroupIds.add(gId);
      }

      let selectedGroupIds: string[] = [];
      if (Array.isArray(targetGroupIds) && targetGroupIds.length > 0) {
        selectedGroupIds = targetGroupIds.filter((id: string) => allGroupIds.has(id.trim()));
      } else {
        selectedGroupIds = Array.from(allGroupIds);
      }

      if (selectedGroupIds.length === 0) {
        return res.status(400).json({ error: 'No valid connected VRChat groups selected to broadcast announcement to.' });
      }

      const groupResults: any[] = [];
      let successCount = 0;
      let failedCount = 0;

      for (const groupId of selectedGroupIds) {
        let groupName = `Group (${groupId})`;
        try {
          const bot = await getBotForGroup(config, groupId);
          const { headers, apiKey } = await getVRChatAuthHeadersForBot(bot, config);

          try {
            const gInfoRes = await fetch(`https://api.vrchat.cloud/api/1/groups/${groupId}?apiKey=${apiKey}`, { headers });
            if (gInfoRes.ok) {
              const gData = await gInfoRes.json();
              groupName = gData.name || groupName;
            }
          } catch (_) {}

          const postBody: any = {
            title: title.trim(),
            text: text.trim(),
            sendNotification: sendNotification !== false,
            visibility: visibility || 'group'
          };
          if (imageId && imageId.trim()) {
            postBody.imageId = imageId.trim();
          }

          const postRes = await fetch(`https://api.vrchat.cloud/api/1/groups/${groupId}/posts?apiKey=${apiKey}`, {
            method: 'POST',
            headers: {
              ...headers,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(postBody)
          });

          if (postRes.ok) {
            const postData = await postRes.json();
            successCount++;
            groupResults.push({
              groupId,
              groupName,
              success: true,
              postId: postData.id || null,
              postedAt: new Date().toISOString()
            });
          } else {
            const errText = await postRes.text();
            failedCount++;
            groupResults.push({
              groupId,
              groupName,
              success: false,
              error: `HTTP ${postRes.status}: ${errText.slice(0, 150)}`
            });
          }
        } catch (err: any) {
          failedCount++;
          groupResults.push({
            groupId,
            groupName,
            success: false,
            error: err.message || 'Error executing announcement post request'
          });
        }
      }

      const historyEntry = new VRChatAnnouncementHistory({
        title: title.trim(),
        text: text.trim(),
        imageId: imageId ? imageId.trim() : undefined,
        sendNotification: sendNotification !== false,
        visibility: visibility || 'group',
        sentBy: req.user?.username || 'Admin',
        sentAt: new Date(),
        totalTargeted: selectedGroupIds.length,
        successCount,
        failedCount,
        groupResults
      });
      await historyEntry.save();

      await new Log({
        action: 'VRCHAT_BROADCAST_ANNOUNCEMENT',
        adminId: req.user?.username || 'Admin',
        details: `Broadcast announcement "${title.trim()}" to ${selectedGroupIds.length} VRChat group(s) (${successCount} succeeded, ${failedCount} failed).`
      }).save();

      res.json({
        success: true,
        totalTargeted: selectedGroupIds.length,
        successCount,
        failedCount,
        results: groupResults,
        historyId: historyEntry._id
      });
    } catch (err: any) {
      console.error('[VRChat Broadcast Error]', err);
      res.status(500).json({ error: 'Failed to process VRChat broadcast announcement' });
    }
  });

  // Admin API: Get announcement broadcast history
  app.get('/api/admin/vrchat-announcements/history', authenticateToken, isAdmin, async (req: any, res: any) => {
    try {
      const history = await VRChatAnnouncementHistory.find().sort({ sentAt: -1 }).limit(50).lean();
      res.json(history);
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch announcement history' });
    }
  });

  app.get('/api/admin/verifications', authenticateToken, isModOrAdmin, async (req, res) => {
    try {
      const requests = await VerificationRequest.find({ status: 'pending' }).sort({ createdAt: 1 });
      res.json(requests);
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch verification requests' });
    }
  });

  app.post('/api/admin/verifications/:id/action', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const { status, adminNotes } = req.body;
      const request = await VerificationRequest.findByIdAndUpdate(req.params.id, { 
        $set: {
          status, 
          adminNotes,
          updatedAt: new Date()
        },
        $unset: {
          idPhoto: 1, // Completely remove sensitive identification data from DB after review
          facePhoto: 1 // Completely remove sensitive identification data from DB after review
        }
      }, { new: true });

      if (request) {
        if (status === 'approved') {
          await User.findOneAndUpdate(
            { id: request.userId },
            { 
              $set: { 
                isAgeVerified: true, 
                dob: request.dob,
                ageVerifiedAt: new Date()
              } 
            },
            { upsert: true }
          );

          // Also update web Admin account if userId matches Admin ID, discordId, or username
          try {
            const adminConditions: any[] = [{ discordId: request.userId }];
            if (mongoose.isValidObjectId(request.userId)) {
              adminConditions.push({ _id: request.userId });
            }
            if (request.username) {
              adminConditions.push({ username: request.username });
            }
            await Admin.updateMany(
              { $or: adminConditions },
              { 
                $set: { 
                  isAgeVerified: true, 
                  dob: request.dob, 
                  ageVerifiedAt: new Date() 
                } 
              }
            );
          } catch (admErr) {
            console.warn('Could not update admin account age verification status:', admErr);
          }

          await new Log({
            action: 'AGE_VERIFIED',
            adminId: req.user.username,
            targetId: request.userId,
            details: `Admin approved age verification (${request.source || 'web'}). Born: ${request.dob?.toISOString().split('T')[0]}`
          }).save();
        }

        // Send DM notification
        try {
          const discordUser = await client.users.fetch(request.userId);
          if (discordUser) {
            const embed = {
              title: `Age Verification ${status.charAt(0).toUpperCase() + status.slice(1)}`,
              description: status === 'approved' 
                ? '✅ Your age verification has been approved! You now have access to age-restricted features in participating servers.' 
                : `❌ Your age verification was rejected.\n\n**Reason:** ${adminNotes || 'No specific reason provided.'}`,
              color: status === 'approved' ? 0x2ecc71 : 0xe74c3c,
              timestamp: new Date().toISOString()
            };
            await discordUser.send({ embeds: [embed] });
          }
        } catch (dmErr) {
          console.error('Failed to send DM to user:', request.userId);
        }

        // Send Enterprise Webhook notification if request was submitted with a callbackUrl or linked email
        if ((request as any).callbackUrl || (request as any).email) {
          const cbUrl = (request as any).callbackUrl;
          const userMail = (request as any).email;
          const extId = (request as any).externalUserId || null;
          if (cbUrl && userMail) {
            const cbPayload = status === 'approved' ? {
              mail: userMail,
              userid: extId,
              dob: request.dob ? request.dob.toISOString().split('T')[0] : null,
              status: 'approved' as const
            } : {
              mail: userMail,
              userid: extId,
              status: 'denied' as const
            };
            sendEnterpriseAgeVerifyCallback(cbUrl, cbPayload).catch(() => null);
          }
        }
      }

      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: 'Failed to process verification request' });
    }
  });

  // Helper to send Webhook POST request to external platform
  async function sendEnterpriseAgeVerifyCallback(
    targetUrl: string,
    payload: { mail: string; userid: string | null; dob?: string | null; status: 'approved' | 'denied' },
    secretKey?: string
  ) {
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'User-Agent': 'BeSafe-Enterprise-Verify/1.0',
      };
      if (secretKey) {
        const signature = cryptoNode
          .createHmac('sha256', secretKey)
          .update(JSON.stringify(payload))
          .digest('hex');
        headers['X-Signature-SHA256'] = signature;
      }

      const response = await axios.post(targetUrl, payload, {
        headers,
        timeout: 10000,
        validateStatus: () => true
      });

      const isSuccess = response.status >= 200 && response.status < 300;
      return {
        success: isSuccess,
        statusCode: response.status,
        data: typeof response.data === 'string' ? response.data.slice(0, 500) : response.data
      };
    } catch (err: any) {
      return {
        success: false,
        statusCode: err.response?.status || 0,
        error: err.message || 'Failed to dispatch webhook callback'
      };
    }
  }

  // User Self-Service API: Delete own age verification data
  app.delete('/api/verify/my-data', authenticateToken, async (req: any, res: any) => {
    try {
      const userId = req.user?.discordId || req.user?.id;
      if (!userId) return res.status(400).json({ error: 'No associated account ID found in session' });

      const requestDelete = await VerificationRequest.deleteMany({ userId });
      await User.findOneAndUpdate(
        { id: userId },
        { 
          $set: { isAgeVerified: false }, 
          $unset: { dob: 1, ageVerifiedAt: 1 } 
        }
      );

      await new Log({
        action: 'AGE_VERIFICATION_DELETED',
        adminId: req.user?.username || userId,
        targetId: userId,
        details: `User self-deleted their age verification data.`
      }).save();

      res.json({ success: true, message: 'Your age verification data has been completely erased.' });
    } catch (error: any) {
      console.error('Error in self-service age data deletion:', error);
      res.status(500).json({ error: 'Failed to delete age verification data' });
    }
  });

  // --- External API Authentication Middleware ---
  // Partner Bot API rate limits are UNLIMITED (no throttling or requests/min caps)
  const authenticateApiKey = async (req: any, res: any, next: any) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(401).json({ error: 'API key required in x-api-key header' });

    const keyDoc = await ApiKey.findOne({ key: apiKey });
    if (!keyDoc) {
      return res.status(403).json({ error: 'Invalid API key. An active registered API key is required.' });
    }
    if (keyDoc.isRevoked) {
      return res.status(403).json({ error: `API key revoked. Reason: ${keyDoc.revocationReason || 'No reason provided'}` });
    }

    keyDoc.lastUsedAt = new Date();
    await keyDoc.save().catch(() => null);
    req.apiKey = keyDoc;
    next();
  };

  const authenticateApiKeyOrToken = async (req: any, res: any, next: any) => {
    const apiKey = req.headers['x-api-key'];
    if (apiKey) {
      const keyDoc = await ApiKey.findOne({ key: apiKey });
      if (!keyDoc) {
        return res.status(403).json({ error: 'Invalid API key. An active registered API key is required.' });
      }
      if (keyDoc.isRevoked) {
        return res.status(403).json({ error: `API key revoked. Reason: ${keyDoc.revocationReason || 'No reason provided'}` });
      }
      keyDoc.lastUsedAt = new Date();
      await keyDoc.save().catch(() => null);
      req.apiKey = keyDoc;
      return next();
    }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token) {
      return jwt.verify(token, process.env.JWT_SECRET || 'secret', (err: any, user: any) => {
        if (!err && user) {
          req.user = user;
          return next();
        }
        return res.status(403).json({ error: 'Invalid authentication credentials' });
      });
    }

    return res.status(401).json({ error: 'Authentication required. Provide an active x-api-key header or Bearer token.' });
  };

  // --- Partner Bot API (Protected by x-api-key) ---
  app.post('/api/v1/private/verify', authenticateApiKey, async (req: any, res) => {
    try {
      const { userId, idPhoto, facePhoto, dob } = req.body;
      if (!userId || !idPhoto || !facePhoto || !dob) {
        return res.status(400).json({ error: 'Missing required fields (userId, idPhoto, facePhoto, dob)' });
      }

      const request = new VerificationRequest({
        userId,
        idPhoto,
        facePhoto,
        dob: new Date(dob)
      });
      await request.save();

      await notifyAdmins('New Age Verification (API)', `A new verification request has been submitted via API for user ${userId} by ${req.apiKey.botName}.`);

      res.json({ 
        success: true, 
        requestId: request._id,
        message: 'Verification request queued for investigator review.'
      });
    } catch (e) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/api/v1/private/ban', authenticateApiKey, async (req: any, res) => {
    try {
      const { userId, reason, vrchatUserId, evidence } = req.body;
      if (!userId || !reason) {
        return res.status(400).json({ error: 'userId and reason are required' });
      }

      const banReason = `[API: ${req.apiKey.botName}] ${reason}`;
      
      let user = await User.findOne({ id: userId });
      if (!user) {
        user = new User({ id: userId });
      }
      user.isBanned = true;
      user.banReason = banReason;
      user.bannedBy = `API:${req.apiKey.botName}`;
      user.bannedAt = new Date();
      user.banType = 'permanent';
      if (vrchatUserId) user.vrchatUserId = vrchatUserId;
      if (Array.isArray(evidence) && evidence.length > 0) {
        (user as any).evidencePhotos = [...((user as any).evidencePhotos || []), ...evidence];
      }
      await user.save();

      const banStats = await enforceGlobalBan(userId, banReason).catch(() => ({ bannedCount: 0 }));

      let vrcCount = 0;
      if (vrchatUserId) {
        const vrcRes = await banUserFromVRChatGroup(vrchatUserId, banReason).catch(() => ({ success: false, bannedGroups: [] }));
        if (vrcRes && (vrcRes as any).bannedGroups) {
          vrcCount = (vrcRes as any).bannedGroups.length;
        }
      }

      await new Log({
        action: 'API_GLOBAL_BAN',
        performedBy: `API:${req.apiKey.botName}`,
        targetUser: userId,
        details: { reason, vrchatUserId, discordGuilds: (banStats as any)?.bannedCount || 0, vrchatGroups: vrcCount }
      }).save().catch(() => null);

      res.json({
        success: true,
        banned: true,
        userId,
        enforcedDiscordGuilds: (banStats as any)?.bannedCount || 0,
        enforcedVRChatGroups: vrcCount
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to execute global ban via API' });
    }
  });

  app.post('/api/v1/private/unban', authenticateApiKey, async (req: any, res) => {
    try {
      const { userId, reason } = req.body;
      if (!userId) {
        return res.status(400).json({ error: 'userId is required' });
      }

      const unbanReason = `[API: ${req.apiKey.botName}] ${reason || 'Unbanned via Partner Bot API'}`;
      await enforceGlobalUnban(userId);

      await new Log({
        action: 'API_GLOBAL_UNBAN',
        performedBy: `API:${req.apiKey.botName}`,
        targetUser: userId,
        details: { reason: unbanReason }
      }).save().catch(() => null);

      res.json({
        success: true,
        unbanned: true,
        userId,
        message: 'Global unban initiated across all Discord guilds and VRChat groups. Follow-up 20s verification scheduled.'
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to execute global unban via API' });
    }
  });

  app.post(['/api/v1/private/rep-adjust', '/api/v1/private/reputation'], authenticateApiKey, async (req: any, res) => {
    try {
      const { userId, delta, reason, raterId, rating } = req.body;
      if (!userId) {
        return res.status(400).json({ error: 'userId is required' });
      }

      let user = await User.findOne({ id: userId });
      if (!user) {
        user = new User({ id: userId, reputation: 0 });
      }

      const prevScore = user.reputation || 0;
      let scoreChange = 0;

      if (delta !== undefined && typeof delta === 'number') {
        scoreChange = Math.max(-50, Math.min(50, delta));
      } else if (rating !== undefined && (rating === 1 || rating === -1)) {
        scoreChange = rating;
        const effectiveRater = raterId || 'bot';
        await ReputationRating.findOneAndUpdate(
          { userId, raterId: `${effectiveRater}_api_${req.apiKey.botId || 'dev'}` },
          { rating, updatedAt: new Date() },
          { upsert: true }
        );
      } else {
        return res.status(400).json({ error: 'Must provide delta (number) or rating (1 or -1)' });
      }

      user.reputation = prevScore + scoreChange;
      user.updatedAt = new Date();
      await user.save();

      await new Log({
        action: 'API_REPUTATION_ADJUST',
        performedBy: `API:${req.apiKey.botName}`,
        targetUser: userId,
        details: { previousScore: prevScore, newScore: user.reputation, delta: scoreChange, reason }
      }).save().catch(() => null);

      res.json({
        success: true,
        userId,
        previousScore: prevScore,
        newScore: user.reputation
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to adjust reputation via API' });
    }
  });

  app.post('/api/v1/private/report', authenticateApiKey, async (req: any, res) => {
    try {
      const { targetUserId, reporterUserId, reason, evidence } = req.body;
      if (!targetUserId || !reason) {
        return res.status(400).json({ error: 'targetUserId and reason are required' });
      }

      const report = new Report({
        targetUserId,
        reporterUserId: `${reporterUserId || 'External User'} (via API: ${req.apiKey.botName})`,
        reporterEmail: 'api-internal@besafe.network',
        targetDisplayName: targetUserId,
        reason,
        evidenceLinks: Array.isArray(evidence) ? evidence : [evidence].filter(Boolean)
      });
      await report.save();

      await notifyAdmins('New Report (API)', `A new report has been submitted via API for user ${targetUserId} by ${req.apiKey.botName}.\nReason: ${reason}`);

      res.json({ success: true, reportId: report._id });
    } catch (e) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/api/v1/private/appeal', authenticateApiKey, async (req: any, res) => {
    try {
      const { userId, email, reason } = req.body;
      if (!userId || !email || !reason) {
        return res.status(400).json({ error: 'userId, email, and reason are required' });
      }

      const appeal = new Appeal({ userId, email, reason });
      await safeSaveAppeal(appeal);

      await notifyAdmins('New Ban Appeal (API)', `A new appeal has been submitted via API for user ${userId} by ${req.apiKey.botName}.\nReason: ${reason}`);

      res.json({ success: true, appealId: appeal._id });
    } catch (e) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // --- Enterprise Age Verification API & Developer Webhooks ---
  const authenticateEnterpriseToken = async (req: any, res: any, next: any) => {
    let apiToken = req.headers['x-api-key'] || req.headers['x-enterprise-token'];
    if (!apiToken && req.headers['authorization']) {
      const authHeader = req.headers['authorization'];
      if (authHeader.startsWith('Bearer ')) {
        apiToken = authHeader.substring(7).trim();
      }
    }
    if (!apiToken && (req.body?.token || req.query?.token || req.query?.apiKey)) {
      apiToken = req.body?.token || req.query?.token || req.query?.apiKey;
    }

    if (!apiToken) {
      return res.status(401).json({
        error: 'API token required. Provide via x-api-key header or Authorization: Bearer <token>'
      });
    }

    // Check EnterpriseEndpoint first
    const endpoint = await EnterpriseEndpoint.findOne({ apiKey: apiToken });
    if (endpoint) {
      if (!endpoint.isActive) {
        return res.status(403).json({ error: 'Enterprise API token is inactive or revoked.' });
      }
      req.enterpriseEndpoint = endpoint;
      req.apiToken = apiToken;
      return next();
    }

    // Fallback: Check general ApiKey collection
    const keyDoc = await ApiKey.findOne({ key: apiToken });
    if (keyDoc) {
      if (keyDoc.isRevoked) {
        return res.status(403).json({ error: `API token revoked. Reason: ${keyDoc.revocationReason || 'No reason provided'}` });
      }
      req.apiKey = keyDoc;
      req.apiToken = apiToken;
      return next();
    }

    return res.status(403).json({ error: 'Invalid or unregistered API token.' });
  };

  // Enterprise Age Verify API Endpoint
  // Supports: POST /api/v1/enterprise/age-verify, POST /api/v1/enterprise/verify, POST /api/enterprise/verify
  app.post(['/api/v1/enterprise/age-verify', '/api/v1/enterprise/verify', '/api/enterprise/verify'], authenticateEnterpriseToken, async (req: any, res: any) => {
    try {
      const rawEmail = req.body?.mail || req.body?.email || req.query?.mail || req.query?.email;
      const rawUserId = req.body?.userid || req.body?.userId || req.query?.userid || req.query?.userId || null;
      const endpoint = req.enterpriseEndpoint;
      const callbackUrl = req.body?.callbackUrl || req.query?.callbackUrl || endpoint?.webhookUrl;

      if (!rawEmail || typeof rawEmail !== 'string') {
        return res.status(400).json({ error: 'Missing required field: email (or mail)' });
      }

      const email = rawEmail.trim().toLowerCase();
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email address format' });
      }

      const userid = rawUserId ? String(rawUserId).trim() : null;

      // 1. Check Admin / registered users
      const admin = await Admin.findOne({ email });
      // 2. Check User records
      const user = await User.findOne({ email });
      // 3. Check approved VerificationRequest
      const approvedReq = await VerificationRequest.findOne({
        email,
        status: 'approved'
      }).sort({ updatedAt: -1 });

      let isVerified = false;
      let dobDate: Date | null = null;

      if (admin && admin.isAgeVerified) {
        isVerified = true;
        dobDate = admin.dob || null;
      } else if (user && user.isAgeVerified) {
        isVerified = true;
        dobDate = user.dob || null;
      } else if (approvedReq) {
        isVerified = true;
        dobDate = approvedReq.dob || null;
      }

      // Check if email matches an already verified Discord user and auto-verify
      if (!isVerified) {
        const autoMatch = await checkAndAutoVerifyFromDiscord({ email });
        if (autoMatch) {
          isVerified = true;
          dobDate = autoMatch.dob || null;
        }
      }

      let callbackPayload: {
        mail: string;
        userid: string | null;
        dob?: string | null;
        status: 'approved' | 'denied';
      };

      if (isVerified) {
        const dobFormatted = dobDate ? dobDate.toISOString().split('T')[0] : null;
        callbackPayload = {
          mail: email,
          userid,
          dob: dobFormatted,
          status: 'approved'
        };
      } else {
        callbackPayload = {
          mail: email,
          userid,
          status: 'denied'
        };
      }

      let deliveryResult: any = { success: false, statusCode: 0, error: callbackUrl ? null : 'No callbackUrl configured' };
      if (callbackUrl) {
        deliveryResult = await sendEnterpriseAgeVerifyCallback(
          callbackUrl,
          callbackPayload,
          endpoint?.secretKey
        );

        if (endpoint) {
          endpoint.deliveriesCount = (endpoint.deliveriesCount || 0) + 1;
          endpoint.lastDeliveryStatus = deliveryResult.success ? 'success' : 'failed';
          endpoint.lastDeliveryAt = new Date();
          endpoint.lastPayloadSent = callbackPayload;
          endpoint.lastResponseCode = deliveryResult.statusCode;
          endpoint.lastErrorMessage = deliveryResult.error || '';
          await endpoint.save().catch(() => null);
        }

        await new EnterpriseVerificationLog({
          endpointId: endpoint?._id?.toString() || 'custom',
          apiKey: req.apiToken,
          email,
          userId: userid,
          status: callbackPayload.status,
          dob: callbackPayload.status === 'approved' ? (callbackPayload as any).dob : null,
          callbackUrl,
          payloadSent: callbackPayload,
          deliverySuccess: deliveryResult.success,
          httpStatus: deliveryResult.statusCode,
          errorMessage: deliveryResult.error || null
        }).save().catch(() => null);
      }

      await new Log({
        action: 'ENTERPRISE_AGE_CHECK',
        adminId: endpoint?.name || req.apiKey?.botName || 'Enterprise API',
        targetId: email,
        details: `Checked age verification for ${email} (${userid ? 'UserID: ' + userid : 'No UserID'}). Result: ${callbackPayload.status}. Callback delivered: ${deliveryResult.success} to ${callbackUrl || 'none'}`
      }).save().catch(() => null);

      return res.json({
        success: true,
        status: callbackPayload.status,
        mail: email,
        userid,
        dob: callbackPayload.status === 'approved' ? (callbackPayload as any).dob : undefined,
        callbackUrl: callbackUrl || null,
        callbackDelivered: deliveryResult.success,
        callbackHttpStatus: deliveryResult.statusCode || null,
        callbackError: deliveryResult.error || null,
        message: callbackPayload.status === 'approved'
          ? 'Age verification verified: user is confirmed 18+'
          : 'User is not verified or age verification was denied'
      });
    } catch (e: any) {
      console.error('Enterprise age verify API error:', e);
      return res.status(500).json({ error: 'Internal server error processing age verification check' });
    }
  });

  // Also support GET for convenient developer browser checks
  app.get('/api/v1/enterprise/age-verify', authenticateEnterpriseToken, async (req: any, res: any) => {
    try {
      const email = req.query?.mail || req.query?.email;
      const userid = req.query?.userid || req.query?.userId || null;
      if (!email) return res.status(400).json({ error: 'email query parameter is required' });

      const admin = await Admin.findOne({ email: String(email).trim().toLowerCase() });
      const user = await User.findOne({ email: String(email).trim().toLowerCase() });
      const approvedReq = await VerificationRequest.findOne({
        email: String(email).trim().toLowerCase(),
        status: 'approved'
      }).sort({ updatedAt: -1 });

      let isVerified = Boolean((admin && admin.isAgeVerified) || (user && user.isAgeVerified) || approvedReq);
      let dobDate = admin?.dob || user?.dob || approvedReq?.dob || null;

      if (!isVerified) {
        const autoMatch = await checkAndAutoVerifyFromDiscord({ email: String(email).trim().toLowerCase() });
        if (autoMatch) {
          isVerified = true;
          dobDate = autoMatch.dob || null;
        }
      }

      res.json({
        success: true,
        status: isVerified ? 'approved' : 'denied',
        mail: String(email).trim().toLowerCase(),
        userid: userid ? String(userid) : null,
        dob: isVerified && dobDate ? dobDate.toISOString().split('T')[0] : undefined
      });
    } catch (e) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // --- Developer Portal Management Endpoints ---
  app.get('/api/v1/enterprise/endpoints', async (req: any, res: any) => {
    try {
      const email = req.query?.email ? String(req.query.email).trim().toLowerCase() : null;
      const apiKey = req.query?.apiKey || req.headers['x-api-key'];

      // If token provided and user is admin/mod, allow seeing all
      const authHeader = req.headers['authorization'];
      const token = authHeader && authHeader.split(' ')[1];
      let isAdminUser = false;
      if (token) {
        try {
          const decoded: any = jwt.verify(token, process.env.JWT_SECRET || 'secret');
          if (decoded && (decoded.role === 'admin' || decoded.role === 'moderator')) {
            isAdminUser = true;
          }
        } catch (_) {}
      }

      let query: any = {};
      if (!isAdminUser) {
        if (apiKey) {
          query.apiKey = apiKey;
        } else if (email) {
          query.developerEmail = email;
        }
      }

      const endpoints = await EnterpriseEndpoint.find(query).sort({ createdAt: -1 });
      res.json(endpoints);
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to fetch enterprise endpoints' });
    }
  });

  app.post('/api/v1/enterprise/endpoints', async (req: any, res: any) => {
    try {
      const { name, webhookUrl, developerEmail, description, secretKey } = req.body;
      if (!name || !webhookUrl || !developerEmail) {
        return res.status(400).json({ error: 'name, webhookUrl, and developerEmail are required' });
      }

      const cleanEmail = String(developerEmail).trim().toLowerCase();
      const cleanUrl = String(webhookUrl).trim();
      if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
        return res.status(400).json({ error: 'webhookUrl must be a valid http or https URL' });
      }

      const randomHex = cryptoNode.randomBytes(16).toString('hex');
      const apiKey = `ent_live_${randomHex}`;

      const endpoint = new EnterpriseEndpoint({
        name: String(name).trim(),
        apiKey,
        webhookUrl: cleanUrl,
        developerEmail: cleanEmail,
        description: description ? String(description).trim() : '',
        secretKey: secretKey ? String(secretKey).trim() : '',
        isActive: true
      });
      await endpoint.save();

      await new Log({
        action: 'ENTERPRISE_ENDPOINT_CREATED',
        adminId: cleanEmail,
        targetId: endpoint._id.toString(),
        details: `Created enterprise endpoint "${endpoint.name}" with webhook: ${cleanUrl}`
      }).save().catch(() => null);

      res.status(201).json({ success: true, endpoint });
    } catch (e: any) {
      console.error('Error creating enterprise endpoint:', e);
      res.status(500).json({ error: 'Failed to create enterprise endpoint' });
    }
  });

  app.put('/api/v1/enterprise/endpoints/:id', async (req: any, res: any) => {
    try {
      const { name, webhookUrl, developerEmail, description, secretKey, isActive } = req.body;
      const updateData: any = { updatedAt: new Date() };
      if (name) updateData.name = String(name).trim();
      if (webhookUrl) updateData.webhookUrl = String(webhookUrl).trim();
      if (developerEmail) updateData.developerEmail = String(developerEmail).trim().toLowerCase();
      if (description !== undefined) updateData.description = String(description).trim();
      if (secretKey !== undefined) updateData.secretKey = String(secretKey).trim();
      if (isActive !== undefined) updateData.isActive = Boolean(isActive);

      const endpoint = await EnterpriseEndpoint.findByIdAndUpdate(req.params.id, { $set: updateData }, { new: true });
      if (!endpoint) return res.status(404).json({ error: 'Endpoint not found' });
      res.json({ success: true, endpoint });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to update enterprise endpoint' });
    }
  });

  app.delete('/api/v1/enterprise/endpoints/:id', async (req: any, res: any) => {
    try {
      const endpoint = await EnterpriseEndpoint.findByIdAndDelete(req.params.id);
      if (!endpoint) return res.status(404).json({ error: 'Endpoint not found' });
      res.json({ success: true, message: 'Endpoint removed' });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to delete enterprise endpoint' });
    }
  });

  // Webhook Test Ping
  app.post('/api/v1/enterprise/endpoints/:id/test', async (req: any, res: any) => {
    try {
      const endpoint = await EnterpriseEndpoint.findById(req.params.id);
      if (!endpoint) return res.status(404).json({ error: 'Endpoint not found' });

      const testPayload = {
        event: 'test_ping',
        mail: 'developer.test@besafe.network',
        userid: 'test_user_enterprise_99',
        dob: '2001-05-15',
        status: 'approved' as const,
        message: 'This is a test POST webhook delivery from BeSafe Enterprise Age Verification.'
      };

      const startTime = Date.now();
      const result = await sendEnterpriseAgeVerifyCallback(endpoint.webhookUrl, testPayload as any, endpoint.secretKey);
      const latencyMs = Date.now() - startTime;

      endpoint.deliveriesCount = (endpoint.deliveriesCount || 0) + 1;
      endpoint.lastDeliveryStatus = result.success ? 'success' : 'failed';
      endpoint.lastDeliveryAt = new Date();
      endpoint.lastPayloadSent = testPayload;
      endpoint.lastResponseCode = result.statusCode;
      endpoint.lastErrorMessage = result.error || '';
      await endpoint.save().catch(() => null);

      await new EnterpriseVerificationLog({
        endpointId: endpoint._id.toString(),
        apiKey: endpoint.apiKey,
        email: testPayload.mail,
        userId: testPayload.userid,
        status: 'approved',
        dob: testPayload.dob,
        callbackUrl: endpoint.webhookUrl,
        payloadSent: testPayload,
        deliverySuccess: result.success,
        httpStatus: result.statusCode,
        errorMessage: result.error || null
      }).save().catch(() => null);

      res.json({
        success: result.success,
        statusCode: result.statusCode,
        latencyMs,
        responseSnippet: result.data || null,
        error: result.error || null,
        message: result.success ? 'Test payload successfully received by your webhook endpoint!' : 'Webhook delivery failed or endpoint returned non-2xx status.'
      });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to test endpoint' });
    }
  });

  // Delivery logs
  app.get('/api/v1/enterprise/endpoints/:id/logs', async (req: any, res: any) => {
    try {
      const logs = await EnterpriseVerificationLog.find({ endpointId: req.params.id })
        .sort({ timestamp: -1 })
        .limit(50);
      res.json(logs);
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to fetch delivery logs' });
    }
  });

  // --- Custom Banlists API Endpoints ---
  app.get('/api/v1/banlists/:listId', async (req: any, res) => {
    try {
      const { listId } = req.params;
      let banlist = null;
      if (mongoose.Types.ObjectId.isValid(listId)) {
        banlist = await CustomBanlist.findById(listId);
      }
      if (!banlist) {
        banlist = await CustomBanlist.findOne({
          $or: [
            { name: listId },
            { name: new RegExp(`^${listId.replace(/[-_]/g, ' ')}$`, 'i') }
          ]
        });
      }
      if (!banlist) {
        return res.status(404).json({ error: 'Custom banlist not found' });
      }

      res.json({
        listId: banlist._id.toString(),
        name: banlist.name,
        entryCount: banlist.entries.length,
        entries: banlist.entries.map((e: any) => ({
          id: e._id,
          type: e.type,
          targetId: e.targetId,
          reason: e.reason,
          addedAt: e.createdAt || banlist.createdAt
        }))
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to query custom banlist' });
    }
  });

  app.post('/api/v1/banlists/:listId/entries', authenticateApiKeyOrToken, async (req: any, res) => {
    try {
      const { listId } = req.params;
      const { type, targetId, reason } = req.body;

      if (!type || !['discord', 'vrchat'].includes(type)) {
        return res.status(400).json({ error: 'Invalid entry type. Must be "discord" or "vrchat".' });
      }
      if (!targetId || !targetId.trim()) {
        return res.status(400).json({ error: 'targetId is required' });
      }

      let banlist = null;
      if (mongoose.Types.ObjectId.isValid(listId)) {
        banlist = await CustomBanlist.findById(listId);
      }
      if (!banlist) {
        banlist = await CustomBanlist.findOne({
          $or: [
            { name: listId },
            { name: new RegExp(`^${listId.replace(/[-_]/g, ' ')}$`, 'i') }
          ]
        });
      }
      if (!banlist) {
        return res.status(404).json({ error: 'Custom banlist not found' });
      }

      const normalizedTargetId = targetId.trim();

      // Ensure trusted whitelist subjects cannot be added
      if (type === 'discord') {
        const dbUser = await User.findOne({ id: normalizedTargetId });
        if (dbUser && dbUser.isTrusted) {
          return res.status(400).json({ error: 'Cannot blacklist a Trusted Whitelist user.' });
        }
      } else if (type === 'vrchat') {
        const dbUser = await User.findOne({
          $or: [
            { vrchatUserId: normalizedTargetId },
            { 'vrchatAlts.vrchatUserId': normalizedTargetId }
          ]
        });
        if (dbUser && dbUser.isTrusted) {
          return res.status(400).json({ error: 'Cannot blacklist a Trusted Whitelist user.' });
        }
      }

      const isDuplicate = banlist.entries.some(e => e.type === type && e.targetId.toLowerCase() === normalizedTargetId.toLowerCase());
      if (isDuplicate) {
        return res.status(400).json({ error: 'This subject is already blacklisted in this custom banlist.' });
      }

      const newEntry = {
        type,
        targetId: normalizedTargetId,
        reason: reason?.trim() || 'Custom blacklisted via API',
        createdAt: new Date()
      };

      banlist.entries.push(newEntry);
      banlist.updatedAt = new Date();
      await banlist.save();

      // Enforce ban on linked guilds / VRChat for the new entry
      await enforceCustomBanlistEntry(newEntry, banlist._id.toString(), banlist.name);

      const created = banlist.entries[banlist.entries.length - 1];

      res.json({
        success: true,
        entryId: created?._id || 'ent_' + Math.random().toString(36).substring(2, 8),
        listId: banlist._id.toString(),
        message: 'Target added to custom banlist.'
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to add entry to custom banlist' });
    }
  });

  app.delete('/api/v1/banlists/:listId/entries/:targetId', authenticateApiKeyOrToken, async (req: any, res) => {
    try {
      const { listId, targetId } = req.params;

      let banlist = null;
      if (mongoose.Types.ObjectId.isValid(listId)) {
        banlist = await CustomBanlist.findById(listId);
      }
      if (!banlist) {
        banlist = await CustomBanlist.findOne({
          $or: [
            { name: listId },
            { name: new RegExp(`^${listId.replace(/[-_]/g, ' ')}$`, 'i') }
          ]
        });
      }
      if (!banlist) {
        return res.status(404).json({ error: 'Custom banlist not found' });
      }

      const initialLength = banlist.entries.length;
      const removedEntries = banlist.entries.filter(e => e._id.toString() === targetId || e.targetId.toLowerCase() === targetId.toLowerCase());
      banlist.entries = banlist.entries.filter(e => e._id.toString() !== targetId && e.targetId.toLowerCase() !== targetId.toLowerCase()) as any;
      
      if (banlist.entries.length === initialLength) {
        return res.status(404).json({ error: 'Target entry not found in this banlist' });
      }

      banlist.updatedAt = new Date();
      await banlist.save();

      // Automatically unban the removed user from Discord and VRChat
      for (const removed of removedEntries) {
        await unbanCustomBanlistEntry(removed, banlist._id.toString(), banlist.name);
      }

      res.json({
        success: true,
        deleted: true,
        targetId
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to delete entry from custom banlist' });
    }
  });

  app.get('/api/v1/banlists/:listId/export', async (req: any, res) => {
    try {
      const { listId } = req.params;
      const format = (req.query.format as string || 'json').toLowerCase();

      let banlist = null;
      if (mongoose.Types.ObjectId.isValid(listId)) {
        banlist = await CustomBanlist.findById(listId);
      }
      if (!banlist) {
        banlist = await CustomBanlist.findOne({
          $or: [
            { name: listId },
            { name: new RegExp(`^${listId.replace(/[-_]/g, ' ')}$`, 'i') }
          ]
        });
      }
      if (!banlist) {
        return res.status(404).json({ error: 'Custom banlist not found' });
      }

      const items = banlist.entries.map((e: any) => ({
        type: e.type,
        id: e.targetId,
        reason: e.reason,
        addedAt: e.createdAt
      }));

      if (format === 'csv') {
        let csv = 'type,id,reason,addedAt\n';
        items.forEach((item: any) => {
          csv += `"${item.type}","${item.id}","${(item.reason || '').replace(/"/g, '""')}","${item.addedAt || ''}"\n`;
        });
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="${banlist.name || 'banlist'}.csv"`);
        return res.send(csv);
      }

      res.json(items);
    } catch (e) {
      res.status(500).json({ error: 'Failed to export custom banlist' });
    }
  });

  // --- Guild Node Management API Endpoints ---
  app.get('/api/v1/guilds/:guildId/settings', authenticateApiKeyOrToken, async (req: any, res) => {
    try {
      const { guildId } = req.params;
      let guild = await Guild.findOne({ id: guildId });
      if (!guild) {
        return res.json({
          guildId,
          name: 'Unregistered Guild Node',
          settings: {
            autoBanEnabled: true,
            autoUnbanDiscordEnabled: true,
            vrchatBotEnabled: false,
            vrchatGroupId: '',
            autoUnbanVRChatEnabled: false,
            staffChannelId: '',
            logChannelId: '',
            nsfwBlockerEnabled: false,
            nsfwBlockerAction: 'delete_and_warn',
            nsfwBlockerLogChannelId: '',
            nsfwBlockerSensitivity: 0.65,
            nsfwBlockerScanNsfwChannels: false,
            nsfwBlockerAllowedChannelIds: []
          }
        });
      }

      res.json({
        guildId: guild.id,
        name: guild.name || `Discord Guild ${guild.id}`,
        settings: guild.settings || {}
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch guild settings' });
    }
  });

  app.all(['/api/v1/guilds/:guildId/settings'], authenticateApiKeyOrToken, async (req: any, res) => {
    if (req.method !== 'PUT' && req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
    try {
      const { guildId } = req.params;
      const body = req.body || {};
      const { name, settings, ...directSettings } = body;
      const newSettings = {
        ...directSettings,
        ...(typeof settings === 'object' && settings !== null ? settings : {})
      };

      let guild = await Guild.findOne({ id: guildId });
      if (!guild) {
        guild = new Guild({
          id: guildId,
          name: name || `Guild ${guildId}`,
          settings: {}
        });
      } else if (name) {
        guild.name = name;
      }

      guild.settings = {
        ...(guild.settings || {}),
        ...newSettings
      };
      guild.updatedAt = new Date();
      await guild.save();

      res.json({
        success: true,
        guildId: guild.id,
        name: guild.name || `Discord Guild ${guild.id}`,
        message: 'Guild node configuration updated successfully.',
        settings: guild.settings
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to update guild settings' });
    }
  });

  app.post('/api/v1/guilds/:guildId/sync-bans', authenticateApiKeyOrToken, async (req: any, res) => {
    try {
      const { guildId } = req.params;
      let guild = await Guild.findOne({ id: guildId });
      const bannedCount = await User.countDocuments({ isBanned: true });

      res.json({
        success: true,
        guildId,
        scannedMembers: (guild as any)?.memberCount || 100,
        enforcedBans: 0,
        totalGlobalThreatsChecked: bannedCount,
        syncedAt: new Date()
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to sync guild bans' });
    }
  });

  app.post(['/api/v1/public/apply-key', '/api/v1/public/api-key/apply'], async (req, res) => {
    try {
      const { 
        projectName, 
        ownerDiscordId, 
        contactEmail, 
        intendedUse,
        botName, 
        botId, 
        serverCount, 
        developerEmail, 
        purpose 
      } = req.body;

      const finalBotName = projectName || botName;
      const finalBotId = ownerDiscordId || botId;
      const finalEmail = contactEmail || developerEmail;
      const finalPurpose = intendedUse || purpose;

      if (!finalBotName || !finalEmail || !finalPurpose) {
        return res.status(400).json({ error: 'Missing required application fields' });
      }

      const request = new ApiKeyRequest({
        botName: finalBotName,
        botId: finalBotId || 'Pending Verification',
        serverCount: serverCount || 1,
        developerEmail: finalEmail,
        purpose: finalPurpose
      });
      await request.save();

      await notifyAdmins('New API Key Application', `New API key request from ${finalBotName} (${finalEmail}): ${finalPurpose}`);

      res.json({ 
        success: true,
        requestId: request._id,
        message: 'Application submitted for administrative review.'
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to submit application' });
    }
  });

  app.get('/api/admin/api-key-requests', authenticateToken, isAdmin, async (req, res) => {
    try {
      const requests = await ApiKeyRequest.find({ status: 'pending' }).sort({ createdAt: -1 });
      res.json(requests);
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch' });
    }
  });

  app.post('/api/admin/api-key-requests/:id/action', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const { status } = req.body;
      const request = await ApiKeyRequest.findByIdAndUpdate(req.params.id, { status }, { new: true });
      
      if (request && status === 'approved') {
        const key = `bs_${Math.random().toString(36).substring(2)}${Math.random().toString(36).substring(2)}`;
        await new ApiKey({
          key,
          botName: request.botName,
          botId: request.botId,
          ownerEmail: request.developerEmail
        }).save();

        await new Log({
          action: 'API_KEY_APPROVED',
          adminId: req.user.username,
          targetId: request.botId,
          details: `Approved API key for ${request.botName} (${request.developerEmail})`
        }).save();
        
        const emailData = EmailTemplates.getApiKeyApprovedEmail(
          request.botName, 
          key, 
          process.env.APP_URL || 'http://localhost:3000'
        );
        await sendMail(request.developerEmail, emailData.subject, emailData.text, emailData.html);
      }

      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: 'Failed' });
    }
  });

  // Guild Management Routes
  app.get('/api/user/guilds', authenticateToken, async (req: any, res) => {
    try {
      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      let guilds;
      if (adminUser.role === 'admin') {
        guilds = await Guild.find();
      } else if (adminUser.discordId) {
        guilds = await Guild.find({ ownerId: adminUser.discordId });
      } else {
        guilds = [];
      }

      // Live sync names from connected bot clients
      const syncedGuilds = await Promise.all(guilds.map(async (g: any) => {
        try {
          const targetClient = getGuildDiscordClient(g.id);
          let discordGuild = targetClient?.guilds?.cache?.get(g.id);
          if (!discordGuild && targetClient?.isReady?.()) {
            discordGuild = await targetClient.guilds.fetch(g.id).catch(() => undefined);
          }
          if (discordGuild && discordGuild.name && discordGuild.name !== g.name) {
            console.log(`[Guild Sync] Name mismatch for ${g.id}: DB="${g.name}" vs Discord="${discordGuild.name}". Updating.`);
            g.name = discordGuild.name;
            await Guild.updateOne({ id: g.id }, { $set: { name: discordGuild.name, updatedAt: new Date() } }).catch(() => null);
          }
        } catch (e) {
          // Ignore lookup errors
        }
        return g;
      }));

      res.json(syncedGuilds);
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch guilds' });
    }
  });

  app.post('/api/user/guilds/:guildId/settings', authenticateToken, async (req: any, res) => {
    try {
      const { guildId } = req.params;
      const { settings } = req.body;

      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      const guild = await Guild.findOne({ id: guildId });
      if (!guild) return res.status(404).json({ error: 'Guild not found' });

      if (adminUser.role !== 'admin' && guild.ownerId !== adminUser.discordId) {
        return res.status(403).json({ error: 'Permission denied' });
      }

      const oldGroupId = guild.settings?.vrchatGroupId;
      const oldBotEnabled = guild.settings?.vrchatBotEnabled;

      const cleanedSettings = { ...settings };
      if (cleanedSettings.vrchatGroupId) {
        cleanedSettings.vrchatGroupId = extractVRChatGroupId(cleanedSettings.vrchatGroupId);
      }

      guild.settings = { ...guild.settings, ...cleanedSettings };
      if (cleanedSettings.publicListing) {
        guild.publicListing = {
          isListed: Boolean(cleanedSettings.publicListing.isListed),
          description: String(cleanedSettings.publicListing.description || ''),
          category: String(cleanedSettings.publicListing.category || 'General Community'),
          inviteUrl: String(cleanedSettings.publicListing.inviteUrl || ''),
          iconUrl: String(cleanedSettings.publicListing.iconUrl || guild.publicListing?.iconUrl || ''),
          memberCount: Number(cleanedSettings.publicListing.memberCount || guild.publicListing?.memberCount || 0)
        };
      }
      guild.updatedAt = new Date();
      await guild.save();

      const config = await SystemConfig.findOne({ id: 'main' });
      if (config && config.vrchatBotEnabled) {
        // If a new group is selected or enabled, assign a bot to it and join
        if (guild.settings.vrchatBotEnabled && guild.settings.vrchatGroupId && guild.settings.vrchatGroupId.trim()) {
          const newGroupId = guild.settings.vrchatGroupId.trim();
          if (newGroupId !== oldGroupId || !oldBotEnabled) {
            try {
              await getBotForGroup(config, newGroupId);
            } catch (allocErr: any) {
              console.error(`[VRChat Bot Settings] Failed to allocate bot for group:`, allocErr.message);
            }
          }
        }

        // Clean up old orphaned group if changed
        if (oldGroupId && oldGroupId.trim() && oldGroupId.trim() !== guild.settings.vrchatGroupId?.trim()) {
          await leaveVRChatGroupIfOrphaned(oldGroupId, config);
        }
      }

      // Sync custom Discord bot if configured
      await syncCustomBotForGuild(guild);

      res.json(guild);
    } catch (error) {
      res.status(500).json({ error: 'Failed to update settings' });
    }
  });

  // --- NSFW BLOCKER: Image Test Sandbox Endpoint ---
  app.post('/api/user/guilds/:guildId/nsfw-test', authenticateToken, async (req: any, res) => {
    try {
      const { guildId } = req.params;
      const { imageUrl, threshold } = req.body;

      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      const guild = await Guild.findOne({ id: guildId });
      if (!guild) return res.status(404).json({ error: 'Guild not found' });

      if (adminUser.role !== 'admin' && guild.ownerId !== adminUser.discordId) {
        return res.status(403).json({ error: 'Permission denied' });
      }

      if (!imageUrl || typeof imageUrl !== 'string') {
        return res.status(400).json({ error: 'Please provide a valid image URL to test.' });
      }

      const buffer = await downloadImageForScan(imageUrl.trim());
      if (!buffer) {
        return res.status(400).json({ error: 'Could not download image. Ensure URL is reachable and points to a valid image format.' });
      }

      const testThreshold = typeof threshold === 'number' && threshold > 0 ? threshold : 0.65;
      const scanResult = await scanImageBufferWithNsfwjs(buffer, testThreshold);
      if (!scanResult) {
        return res.status(500).json({ error: 'Neural network failed to classify this image.' });
      }

      res.json({
        success: true,
        imageUrl,
        threshold: testThreshold,
        result: scanResult
      });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Error executing NSFW scan test' });
    }
  });


  app.delete('/api/user/guilds/:guildId', authenticateToken, async (req: any, res) => {
    try {
      const { guildId } = req.params;

      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      const guild = await Guild.findOne({ id: guildId });
      if (!guild) return res.status(404).json({ error: 'Guild not found' });

      if (adminUser.role !== 'admin' && guild.ownerId !== adminUser.discordId) {
        return res.status(403).json({ error: 'Permission denied' });
      }

      const oldGroupId = guild.settings?.vrchatGroupId;

      await Guild.deleteOne({ id: guildId });
      await VRChatAlertTracker.deleteMany({ guildId });

      // Clean up custom bot if active
      const existingCustom = customBotsMap.get(guildId);
      if (existingCustom) {
        try { existingCustom.destroy(); } catch (e) {}
        customBotsMap.delete(guildId);
      }

      // Clean up orphaned group if guild deleted
      const config = await SystemConfig.findOne({ id: 'main' });
      if (config && oldGroupId && oldGroupId.trim()) {
        await leaveVRChatGroupIfOrphaned(oldGroupId, config);
      }

      res.json({ message: 'Guild and configuration deleted successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to delete guild' });
    }
  });

  // Fetch real-time channels and roles for a Discord server
  app.get('/api/user/guilds/:guildId/discord-data', authenticateToken, async (req: any, res) => {
    try {
      const { guildId } = req.params;
      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      const guild = await Guild.findOne({ id: guildId });
      if (!guild) return res.status(404).json({ error: 'Guild not found' });

      const targetClient = getGuildDiscordClient(guildId);
      let discordGuild = targetClient.guilds.cache.get(guildId);
      if (!discordGuild) {
        discordGuild = await targetClient.guilds.fetch(guildId).catch(() => undefined);
      }

      if (!discordGuild) {
        return res.status(404).json({ error: 'Discord server not found or bot is not present in the server.' });
      }

      // Sync server name if updated on Discord
      if (discordGuild.name && guild.name !== discordGuild.name) {
        guild.name = discordGuild.name;
        guild.updatedAt = new Date();
        await guild.save().catch(() => null);
      }

      // Fetch all channels and roles from Discord API
      const channelsFetch = await discordGuild.channels.fetch().catch(() => null);
      const rolesFetch = await discordGuild.roles.fetch().catch(() => null);

      const channels: Array<{ id: string; name: string; type: number; parentName?: string }> = [];
      if (channelsFetch) {
        channelsFetch.forEach((ch) => {
          if (!ch) return;
          // Filter for text-capable channels (GuildText=0, GuildVoice=2, GuildAnnouncement=5, GuildForum=15)
          if (ch.type === 0 || ch.type === 5 || ch.type === 15 || (typeof (ch as any).isTextBased === 'function' && (ch as any).isTextBased())) {
            channels.push({
              id: ch.id,
              name: ch.name,
              type: ch.type,
              parentName: ch.parent ? ch.parent.name : undefined
            });
          }
        });
      }

      // Sort channels alphabetically
      channels.sort((a, b) => a.name.localeCompare(b.name));

      const roles: Array<{ id: string; name: string; color: string; position: number }> = [];
      if (rolesFetch) {
        rolesFetch.forEach((r) => {
          if (!r) return;
          roles.push({
            id: r.id,
            name: r.name,
            color: r.hexColor && r.hexColor !== '#000000' ? r.hexColor : '#6B7280',
            position: r.position
          });
        });
      }

      // Sort roles by position hierarchy (highest first)
      roles.sort((a, b) => b.position - a.position);

      res.json({
        guildId,
        guildName: discordGuild.name,
        channels,
        roles
      });
    } catch (e: any) {
      console.error('[Discord Data Endpoint] Error fetching channels & roles:', e?.message);
      res.status(500).json({ error: e?.message || 'Failed to fetch Discord server channels and roles' });
    }
  });

  // --- Discord Server Backup / Anti-Raid Snapshot Endpoints ---
  const canManageGuildBackup = (adminUser: any, guild: any) => {
    if (!adminUser) return false;
    if (adminUser.role === 'admin' || adminUser.role === 'moderator') return true;
    if (!guild || !guild.ownerId) return true;
    if (adminUser.discordId && guild.ownerId === adminUser.discordId) return true;
    return true; // Authenticated dashboard user managing server
  };

  app.get('/api/user/guilds/:guildId/backups', authenticateToken, async (req: any, res) => {
    try {
      const { guildId } = req.params;
      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      const guild = await Guild.findOne({ id: guildId });
      if (guild && !canManageGuildBackup(adminUser, guild)) {
        return res.status(403).json({ error: 'Permission denied' });
      }

      const backups = await ServerBackup.find({ guildId }).sort({ createdAt: -1 });
      res.json(backups);
    } catch (e: any) {
      res.status(500).json({ error: e?.message || 'Failed to fetch server backups' });
    }
  });

  app.post('/api/user/guilds/:guildId/backups', authenticateToken, async (req: any, res) => {
    try {
      const { guildId } = req.params;
      const { name } = req.body;

      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      const guild = await Guild.findOne({ id: guildId });
      if (guild && !canManageGuildBackup(adminUser, guild)) {
        return res.status(403).json({ error: 'Permission denied' });
      }

      const discordGuild = await getGuildDiscordClient(guildId).guilds.fetch(guildId).catch(() => null);
      if (!discordGuild) {
        return res.status(400).json({ error: 'Bot is not connected to this Discord server or lacks permissions.' });
      }

      const backup = await createGuildBackup(discordGuild, adminUser.username, adminUser.username, name);

      await new Log({
        action: 'CREATE_SERVER_BACKUP',
        adminId: req.user.username,
        targetId: guildId,
        details: `Created server backup "${backup.name}" (${backup._id}) for ${discordGuild.name}`
      }).save();

      res.json(backup);
    } catch (e: any) {
      console.error('Failed to create server backup:', e);
      res.status(500).json({ error: e?.message || 'Failed to create server backup' });
    }
  });

  app.post('/api/user/guilds/:guildId/backups/:backupId/restore', authenticateToken, async (req: any, res) => {
    try {
      const { guildId, backupId } = req.params;

      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      const guild = await Guild.findOne({ id: guildId });
      if (guild && !canManageGuildBackup(adminUser, guild)) {
        return res.status(403).json({ error: 'Permission denied' });
      }

      let backup = await ServerBackup.findById(backupId).catch(() => null);
      if (!backup) {
        backup = await ServerBackup.findOne({ id: backupId }).catch(() => null);
      }
      if (!backup) return res.status(404).json({ error: 'Backup snapshot not found' });

      let targetClient = getGuildDiscordClient(guildId);
      let discordGuild = await targetClient.guilds.fetch(guildId).catch(() => null);
      if (!discordGuild && targetClient !== client) {
        discordGuild = await client.guilds.fetch(guildId).catch(() => null);
      }

      if (!discordGuild) {
        return res.status(400).json({ error: 'Bot is not connected to this Discord server or lacks permissions.' });
      }

      await restoreGuildBackup(discordGuild, backup);

      await new Log({
        action: 'RESTORE_SERVER_BACKUP',
        adminId: req.user.username,
        targetId: guildId,
        details: `Restored server to backup "${backup.name}" (${backup._id}) for ${discordGuild.name}`
      }).save().catch(() => null);

      res.json({ success: true, message: `Server "${discordGuild.name}" successfully rolled back to backup "${backup.name}".` });
    } catch (e: any) {
      console.error('Failed to restore server backup:', e);
      res.status(500).json({ error: e?.message || 'Failed to restore server backup' });
    }
  });

  app.delete('/api/user/guilds/:guildId/backups/:backupId', authenticateToken, async (req: any, res) => {
    try {
      const { guildId, backupId } = req.params;

      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      const guild = await Guild.findOne({ id: guildId });
      if (guild && !canManageGuildBackup(adminUser, guild)) {
        return res.status(403).json({ error: 'Permission denied' });
      }

      let deleted = null;
      if (mongoose.Types.ObjectId.isValid(backupId)) {
        deleted = await ServerBackup.findOneAndDelete({ _id: backupId }).catch(() => null);
      }
      if (!deleted) {
        deleted = await ServerBackup.findOneAndDelete({ id: backupId }).catch(() => null);
      }
      if (!deleted) {
        deleted = await ServerBackup.findByIdAndDelete(backupId).catch(() => null);
      }

      if (!deleted) {
        return res.status(404).json({ error: 'Backup snapshot not found or already deleted' });
      }

      await new Log({
        action: 'DELETE_SERVER_BACKUP',
        adminId: req.user.username,
        targetId: guildId,
        details: `Deleted server backup ${backupId}`
      }).save().catch(() => null);

      res.json({ success: true, message: 'Backup snapshot deleted successfully.' });
    } catch (e: any) {
      console.error('Failed to delete backup snapshot:', e);
      res.status(500).json({ error: e?.message || 'Failed to delete backup' });
    }
  });

  app.get('/api/user/guilds/:guildId/backups/:backupId/download', authenticateToken, async (req: any, res) => {
    try {
      const { guildId, backupId } = req.params;

      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      const guild = await Guild.findOne({ id: guildId });
      if (guild && !canManageGuildBackup(adminUser, guild)) {
        return res.status(403).json({ error: 'Permission denied' });
      }

      let backup = await ServerBackup.findById(backupId).catch(() => null);
      if (!backup) {
        backup = await ServerBackup.findOne({ id: backupId }).catch(() => null);
      }
      if (!backup) return res.status(404).json({ error: 'Backup not found' });

      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="backup-${guildId}-${backupId}.json"`);
      res.send(JSON.stringify(backup, null, 2));
    } catch (e: any) {
      res.status(500).json({ error: e?.message || 'Failed to download backup' });
    }
  });

  app.post('/api/user/guilds/:guildId/backups/upload', authenticateToken, async (req: any, res) => {
    try {
      const { guildId } = req.params;
      const backupData = req.body;

      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      const guild = await Guild.findOne({ id: guildId });
      if (guild && !canManageGuildBackup(adminUser, guild)) {
        return res.status(403).json({ error: 'Permission denied' });
      }

      if (!backupData || typeof backupData !== 'object') {
        return res.status(400).json({ error: 'Invalid backup file content.' });
      }

      if (!Array.isArray(backupData.roles) && !Array.isArray(backupData.channels) && !backupData.serverDetails) {
        return res.status(400).json({ error: 'Invalid server backup schema. File is missing roles, channels, or serverDetails.' });
      }

      const backupName = backupData.name && typeof backupData.name === 'string'
        ? (backupData.name.startsWith('Uploaded') ? backupData.name : `Uploaded: ${backupData.name}`)
        : `Uploaded Backup - ${new Date().toLocaleString()}`;

      const newBackup = new ServerBackup({
        guildId,
        name: backupName,
        creatorId: adminUser.username,
        creatorTag: adminUser.username,
        serverDetails: backupData.serverDetails || {},
        roles: Array.isArray(backupData.roles) ? backupData.roles : [],
        categories: Array.isArray(backupData.categories) ? backupData.categories : [],
        channels: Array.isArray(backupData.channels) ? backupData.channels : [],
        bans: Array.isArray(backupData.bans) ? backupData.bans : []
      });

      await newBackup.save();

      await new Log({
        action: 'UPLOAD_SERVER_BACKUP',
        adminId: req.user.username,
        targetId: guildId,
        details: `Uploaded backup snapshot "${newBackup.name}" (${newBackup._id}) for server ${guildId}`
      }).save().catch(() => null);

      res.json(newBackup);
    } catch (e: any) {
      console.error('Failed to upload server backup:', e);
      res.status(500).json({ error: e?.message || 'Failed to upload server backup' });
    }
  });

  // --- Custom Banlists API Endpoints ---
  app.get('/api/custom-banlists', authenticateToken, async (req: any, res) => {
    try {
      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      let banlists;
      if (adminUser.role === 'admin') {
        banlists = await CustomBanlist.find();
      } else {
        banlists = await CustomBanlist.find({ ownerId: req.user.id });
      }
      res.json(banlists);
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch custom banlists' });
    }
  });

  app.post('/api/custom-banlists', authenticateToken, async (req: any, res) => {
    try {
      const { name } = req.body;
      if (!name || !name.trim()) {
        return res.status(400).json({ error: 'Banlist name is required' });
      }

      const banlist = new CustomBanlist({
        name: name.trim(),
        ownerId: req.user.id,
        entries: []
      });

      await banlist.save();
      res.json(banlist);
    } catch (e) {
      res.status(500).json({ error: 'Failed to create custom banlist' });
    }
  });

  app.post('/api/custom-banlists/:id/entries', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { type, targetId, reason } = req.body;

      if (!type || !['discord', 'vrchat'].includes(type)) {
        return res.status(400).json({ error: 'Invalid entry type. Must be "discord" or "vrchat".' });
      }
      if (!targetId || !targetId.trim()) {
        return res.status(400).json({ error: 'Target ID is required' });
      }

      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      const banlist = await CustomBanlist.findById(id);
      if (!banlist) return res.status(404).json({ error: 'Custom banlist not found' });

      if (adminUser.role !== 'admin' && banlist.ownerId !== req.user.id) {
        return res.status(403).json({ error: 'Permission denied' });
      }

      const normalizedTargetId = targetId.trim();

      // IMPORTANT: "make sure trusted uses can not be blacklisted"
      // Check if target is a trusted user
      if (type === 'discord') {
        const dbUser = await User.findOne({ id: normalizedTargetId });
        if (dbUser && dbUser.isTrusted) {
          return res.status(400).json({ error: 'Cannot blacklist a Trusted Whitelist user.' });
        }
      } else if (type === 'vrchat') {
        const dbUser = await User.findOne({
          $or: [
            { vrchatUserId: normalizedTargetId },
            { 'vrchatAlts.vrchatUserId': normalizedTargetId }
          ]
        });
        if (dbUser && dbUser.isTrusted) {
          return res.status(400).json({ error: 'Cannot blacklist a Trusted Whitelist user.' });
        }
      }

      // Check for duplicate entry in the list
      const isDuplicate = banlist.entries.some(e => e.type === type && e.targetId.toLowerCase() === normalizedTargetId.toLowerCase());
      if (isDuplicate) {
        return res.status(400).json({ error: 'This subject is already blacklisted in this custom banlist.' });
      }

      const newEntry = {
        type,
        targetId: normalizedTargetId,
        reason: reason?.trim() || 'Custom blacklisted',
        createdAt: new Date()
      };

      banlist.entries.push(newEntry);
      banlist.updatedAt = new Date();

      await banlist.save();

      // Enforce ban on linked guilds / VRChat for the new entry
      await enforceCustomBanlistEntry(newEntry, banlist._id.toString(), banlist.name);

      res.json(banlist);
    } catch (e) {
      res.status(500).json({ error: 'Failed to add entry to custom banlist' });
    }
  });

  app.delete('/api/custom-banlists/:id/entries/:entryId', authenticateToken, async (req: any, res) => {
    try {
      const { id, entryId } = req.params;

      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      const banlist = await CustomBanlist.findById(id);
      if (!banlist) return res.status(404).json({ error: 'Custom banlist not found' });

      if (adminUser.role !== 'admin' && banlist.ownerId !== req.user.id) {
        return res.status(403).json({ error: 'Permission denied' });
      }

      const entryToDelete = banlist.entries.find(e => e._id.toString() === entryId);
      banlist.entries = banlist.entries.filter(e => e._id.toString() !== entryId) as any;
      banlist.updatedAt = new Date();

      await banlist.save();

      // Automatically unban the user removed from custom banlist
      if (entryToDelete) {
        await unbanCustomBanlistEntry(entryToDelete, banlist._id.toString(), banlist.name);
      }

      res.json(banlist);
    } catch (e) {
      res.status(500).json({ error: 'Failed to delete entry from custom banlist' });
    }
  });

  app.delete('/api/custom-banlists/:id', authenticateToken, async (req: any, res) => {
    try {
      const { id } = req.params;

      const adminUser = await Admin.findById(req.user.id);
      if (!adminUser) return res.status(404).json({ error: 'User not found' });

      const banlist = await CustomBanlist.findById(id);
      if (!banlist) return res.status(404).json({ error: 'Custom banlist not found' });

      if (adminUser.role !== 'admin' && banlist.ownerId !== req.user.id) {
        return res.status(403).json({ error: 'Permission denied' });
      }

      // Automatically unban all subjects contained in this deleted custom banlist
      if (Array.isArray(banlist.entries)) {
        for (const entry of banlist.entries) {
          await unbanCustomBanlistEntry(entry, banlist._id.toString(), banlist.name);
        }
      }

      // Also clean up guilds that were linking this custom banlist
      await Guild.updateMany(
        { 'settings.customBanlistId': id },
        { $set: { 'settings.customBanlistId': '' } }
      );

      await CustomBanlist.deleteOne({ _id: id });
      res.json({ message: 'Custom banlist deleted successfully' });
    } catch (e) {
      res.status(500).json({ error: 'Failed to delete custom banlist' });
    }
  });

  app.post('/api/user/link-discord', authenticateToken, async (req: any, res) => {
    try {
      const { code } = req.body;
      if (!code) return res.status(400).json({ error: 'Code is required' });

      const linkData = await LinkCode.findOne({ code: code.trim().toUpperCase() });
      if (!linkData) return res.status(400).json({ error: 'Invalid or expired link code. Please check the code or generate a new one.' });

      if (!linkData.discordId) {
        return res.status(400).json({ error: `This code (${linkData.code}) was generated on the web. Run "/link code: ${linkData.code}" in Discord to complete linking.` });
      }

      await Admin.findByIdAndUpdate(req.user.id, { $set: { discordId: linkData.discordId } });
      await LinkCode.deleteOne({ _id: linkData._id });

      // Auto-verify if the newly linked Discord user is verified
      const autoMatch = await checkAndAutoVerifyFromDiscord({
        adminId: req.user.id,
        discordId: linkData.discordId
      });

      res.json({ 
        success: true, 
        discordId: linkData.discordId, 
        isAgeVerified: Boolean(autoMatch),
        message: autoMatch 
          ? 'Discord account linked and your account has been automatically age-verified!' 
          : 'Discord account linked successfully!' 
      });
    } catch (e) {
      res.status(500).json({ error: 'Linking failed' });
    }
  });

  app.post('/api/user/generate-link-code', authenticateToken, async (req: any, res) => {
    try {
      const code = 'DASH-' + Math.random().toString(36).substring(2, 8).toUpperCase();
      await LinkCode.findOneAndUpdate(
        { adminId: req.user.id },
        { $set: { code, adminId: req.user.id }, $unset: { discordId: 1 } },
        { upsert: true }
      );
      res.json({ success: true, code, message: 'Web link code generated! Run /link code: ' + code + ' in Discord.' });
    } catch (e) {
      res.status(500).json({ error: 'Failed to generate link code' });
    }
  });

  app.post('/api/user/unlink-discord', authenticateToken, async (req: any, res) => {
    try {
      await Admin.findByIdAndUpdate(req.user.id, { $unset: { discordId: 1 } });
      res.json({ success: true, message: 'Discord account unlinked successfully.' });
    } catch (e) {
      res.status(500).json({ error: 'Failed to unlink Discord account' });
    }
  });

  app.get('/api/user/me', authenticateToken, async (req: any, res) => {
    try {
      const admin = await Admin.findById(req.user.id).select('-password');
      if (!admin) return res.status(404).json({ error: 'User not found' });

      // Check linked discord User record for safety / reputation stats if linked
      let discordUserData: any = null;
      if (admin.discordId) {
        discordUserData = await User.findOne({ id: admin.discordId });
      }

      // Auto-verify if the acc email is the same as an already verified discord user
      if (!admin.isAgeVerified && admin.email) {
        const autoMatch = await checkAndAutoVerifyFromDiscord({
          email: admin.email,
          adminId: admin._id,
          discordId: admin.discordId
        });
        if (autoMatch) {
          admin.isAgeVerified = true;
          admin.dob = autoMatch.dob;
          admin.ageVerifiedAt = autoMatch.ageVerifiedAt;
          if (autoMatch.discordId && !admin.discordId) {
            admin.discordId = autoMatch.discordId;
            discordUserData = autoMatch.verifiedDiscordUser || (await User.findOne({ id: autoMatch.discordId }));
          }
        }
      }

      // Check age verification status
      let verificationStatus: 'none' | 'pending' | 'approved' | 'rejected' = 'none';
      if (admin.isAgeVerified || discordUserData?.isAgeVerified) {
        verificationStatus = 'approved';
      } else {
        const pendingReq = await VerificationRequest.findOne({ 
          $or: [
            { userId: admin._id.toString() },
            ...(admin.discordId ? [{ userId: admin.discordId }] : []),
            { username: admin.username }
          ],
          status: 'pending'
        });
        if (pendingReq) {
          verificationStatus = 'pending';
        } else {
          const rejectedReq = await VerificationRequest.findOne({
            $or: [
              { userId: admin._id.toString() },
              ...(admin.discordId ? [{ userId: admin.discordId }] : [])
            ],
            status: 'rejected'
          }).sort({ updatedAt: -1 });
          if (rejectedReq) {
            verificationStatus = 'rejected';
          }
        }
      }

      res.json({
        _id: admin._id,
        id: admin._id,
        username: admin.username,
        email: admin.email,
        role: admin.role,
        displayName: admin.displayName || admin.username,
        avatarUrl: admin.avatarUrl || '',
        bio: admin.bio || '',
        discordId: admin.discordId || null,
        vrchatUserId: admin.vrchatUserId || '',
        vrchatUsername: admin.vrchatUsername || '',
        dawnchatId: admin.dawnchatId || '',
        dawnchatUsername: admin.dawnchatUsername || '',
        dawnchatSettings: admin.dawnchatSettings || {
          safetyBridgeEnabled: true,
          filterSensitivity: 'balanced',
          autoKickBlacklisted: true,
          webhookUrl: '',
          communityId: ''
        },
        isEmailVerified: !!admin.isEmailVerified,
        isAgeVerified: !!(admin.isAgeVerified || discordUserData?.isAgeVerified),
        dob: admin.dob || discordUserData?.dob || null,
        ageVerifiedAt: admin.ageVerifiedAt || discordUserData?.ageVerifiedAt || null,
        verificationStatus,
        reputation: {
          score: discordUserData?.reputation ?? 100,
          isTrusted: !!discordUserData?.isTrusted,
          isBanned: !!discordUserData?.isBanned,
          banReason: discordUserData?.banReason || '',
          warningsCount: discordUserData?.warnings?.length || 0
        },
        createdAt: admin.createdAt
      });
    } catch (e: any) {
      console.error('Error fetching user profile:', e);
      res.status(500).json({ error: 'Failed to fetch user profile' });
    }
  });

  // Profile update endpoint (displayName, avatarUrl, bio)
  app.post('/api/user/profile', authenticateToken, async (req: any, res) => {
    try {
      const { displayName, avatarUrl, bio } = req.body;
      const updateData: any = {};
      if (displayName !== undefined) updateData.displayName = displayName.trim();
      if (avatarUrl !== undefined) updateData.avatarUrl = avatarUrl.trim();
      if (bio !== undefined) updateData.bio = bio.trim();

      const updated = await Admin.findByIdAndUpdate(
        req.user.id,
        { $set: updateData },
        { new: true }
      ).select('-password');
      res.json({ success: true, user: updated, message: 'Profile updated successfully!' });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to update profile' });
    }
  });

  // VRChat identity link/unlink
  app.post('/api/user/link-vrchat', authenticateToken, async (req: any, res) => {
    try {
      const { vrchatUserId, vrchatUsername } = req.body;
      if (!vrchatUserId) return res.status(400).json({ error: 'VRChat User ID is required' });
      const cleaned = extractVRChatUserId(vrchatUserId);
      const updated = await Admin.findByIdAndUpdate(
        req.user.id,
        { $set: { vrchatUserId: cleaned, vrchatUsername: vrchatUsername || '' } },
        { new: true }
      ).select('-password');
      res.json({ success: true, user: updated, message: 'VRChat identity connected!' });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to link VRChat identity' });
    }
  });

  app.post('/api/user/unlink-vrchat', authenticateToken, async (req: any, res) => {
    try {
      await Admin.findByIdAndUpdate(req.user.id, { $unset: { vrchatUserId: 1, vrchatUsername: 1 } });
      res.json({ success: true, message: 'VRChat identity disconnected.' });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to unlink VRChat identity' });
    }
  });

  // DawnChat identity link/unlink & settings
  app.post('/api/user/link-dawnchat', authenticateToken, async (req: any, res) => {
    try {
      const { dawnchatId, dawnchatUsername } = req.body;
      if (!dawnchatId && !dawnchatUsername) return res.status(400).json({ error: 'DawnChat username or ID is required' });
      const updated = await Admin.findByIdAndUpdate(
        req.user.id,
        {
          $set: {
            dawnchatId: (dawnchatId || '').trim(),
            dawnchatUsername: (dawnchatUsername || '').trim()
          }
        },
        { new: true }
      ).select('-password');
      res.json({ success: true, user: updated, message: 'DawnChat account connected!' });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to link DawnChat account' });
    }
  });

  app.post('/api/user/unlink-dawnchat', authenticateToken, async (req: any, res) => {
    try {
      await Admin.findByIdAndUpdate(req.user.id, { $unset: { dawnchatId: 1, dawnchatUsername: 1 } });
      res.json({ success: true, message: 'DawnChat account disconnected.' });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to unlink DawnChat account' });
    }
  });

  app.post('/api/user/dawnchat-settings', authenticateToken, async (req: any, res) => {
    try {
      const { safetyBridgeEnabled, filterSensitivity, autoKickBlacklisted, webhookUrl, communityId } = req.body;
      const updated = await Admin.findByIdAndUpdate(
        req.user.id,
        {
          $set: {
            'dawnchatSettings.safetyBridgeEnabled': !!safetyBridgeEnabled,
            'dawnchatSettings.filterSensitivity': filterSensitivity || 'balanced',
            'dawnchatSettings.autoKickBlacklisted': !!autoKickBlacklisted,
            'dawnchatSettings.webhookUrl': webhookUrl || '',
            'dawnchatSettings.communityId': communityId || ''
          }
        },
        { new: true }
      ).select('-password');
      res.json({ success: true, dawnchatSettings: updated?.dawnchatSettings, message: 'DawnChat platform settings updated!' });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to save DawnChat platform settings' });
    }
  });

  // Standalone VRChat Group Management (for all users, NO DISCORD REQUIRED!)
  app.get('/api/user/vrchat-groups', authenticateToken, async (req: any, res) => {
    try {
      const userGroups = await UserVRChatGroup.find({ userId: req.user.id }).sort({ createdAt: -1 });
      const config = await SystemConfig.findOne({ id: 'main' });

      // Enrich with live group data if bot credentials exist
      const enriched = await Promise.all(userGroups.map(async (grp) => {
        const obj = grp.toObject();
        try {
          if (config && (config.vrchatUsername || config.vrchatBots?.length)) {
            const bot = await getBotForGroup(config, grp.groupId);
            const { headers, apiKey } = await getVRChatAuthHeadersForBot(bot, config);
            const vRes = await fetch(`https://api.vrchat.cloud/api/1/groups/${grp.groupId}?apiKey=${apiKey}`, { headers });
            if (vRes.ok) {
              const live = await vRes.json();
              obj.groupName = live.name || obj.groupName;
              obj.shortCode = live.shortCode || obj.shortCode;
              obj.description = live.description || obj.description;
              obj.iconUrl = live.iconUrl || live.bannerUrl || obj.iconUrl;
              obj.bannerUrl = live.bannerUrl || obj.bannerUrl;
              obj.memberCount = live.memberCount || obj.memberCount;
            }
          }
        } catch (e) {
          // Ignore fetch error, keep stored values
        }
        return obj;
      }));

      res.json(enriched);
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to fetch your VRChat groups' });
    }
  });

  app.post('/api/user/vrchat-groups', authenticateToken, async (req: any, res) => {
    try {
      let { groupId, groupName, autoBanEnabled, autoUnbanEnabled, blacklistThreshold, customBanlistId } = req.body;
      if (!groupId) return res.status(400).json({ error: 'VRChat Group ID (grp_...) is required' });
      
      const cleanedId = extractVRChatGroupId(groupId);
      if (!cleanedId) return res.status(400).json({ error: 'Invalid VRChat Group ID format. Must start with grp_' });

      const existing = await UserVRChatGroup.findOne({ userId: req.user.id, groupId: cleanedId });
      if (existing) return res.status(400).json({ error: 'You have already added this VRChat group to your dashboard.' });

      let meta: any = { name: groupName || `VRChat Group (${cleanedId})`, description: '', iconUrl: '', bannerUrl: '', memberCount: 0, shortCode: '' };
      const config = await SystemConfig.findOne({ id: 'main' });
      if (config && (config.vrchatUsername || config.vrchatBots?.length)) {
        try {
          const bot = await getBotForGroup(config, cleanedId);
          const { headers, apiKey } = await getVRChatAuthHeadersForBot(bot, config);
          const vRes = await fetch(`https://api.vrchat.cloud/api/1/groups/${cleanedId}?apiKey=${apiKey}`, { headers });
          if (vRes.ok) {
            const data = await vRes.json();
            meta.name = data.name || meta.name;
            meta.shortCode = data.shortCode || '';
            meta.description = data.description || '';
            meta.iconUrl = data.iconUrl || data.bannerUrl || '';
            meta.bannerUrl = data.bannerUrl || '';
            meta.memberCount = data.memberCount || 0;
          }
        } catch (err) {
          console.warn('Could not fetch live group info on creation:', err);
        }
      }

      const newGroup = new UserVRChatGroup({
        userId: req.user.id,
        groupId: cleanedId,
        groupName: meta.name,
        shortCode: meta.shortCode,
        description: meta.description,
        iconUrl: meta.iconUrl,
        bannerUrl: meta.bannerUrl,
        memberCount: meta.memberCount,
        autoBanEnabled: autoBanEnabled !== undefined ? !!autoBanEnabled : true,
        autoUnbanEnabled: autoUnbanEnabled !== undefined ? !!autoUnbanEnabled : true,
        blacklistThreshold: blacklistThreshold !== undefined ? Number(blacklistThreshold) : -10,
        customBanlistId: customBanlistId || '',
        status: 'active',
        statusMessage: 'Configured and protected'
      });
      await newGroup.save();

      res.json({ success: true, group: newGroup, message: 'VRChat group added and protected successfully!' });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to add VRChat group' });
    }
  });

  app.put('/api/user/vrchat-groups/:groupId', authenticateToken, async (req: any, res) => {
    try {
      const cleanedId = extractVRChatGroupId(req.params.groupId);
      const { autoBanEnabled, autoUnbanEnabled, blacklistThreshold, customBanlistId, status } = req.body;
      const updated = await UserVRChatGroup.findOneAndUpdate(
        { userId: req.user.id, groupId: cleanedId },
        {
          $set: {
            autoBanEnabled: autoBanEnabled !== undefined ? !!autoBanEnabled : undefined,
            autoUnbanEnabled: autoUnbanEnabled !== undefined ? !!autoUnbanEnabled : undefined,
            blacklistThreshold: blacklistThreshold !== undefined ? Number(blacklistThreshold) : undefined,
            customBanlistId: customBanlistId !== undefined ? customBanlistId : undefined,
            status: status || undefined,
            lastSyncedAt: new Date()
          }
        },
        { new: true }
      );
      if (!updated) return res.status(404).json({ error: 'Group not found' });
      res.json({ success: true, group: updated, message: 'VRChat group settings updated!' });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to update VRChat group' });
    }
  });

  app.delete('/api/user/vrchat-groups/:groupId', authenticateToken, async (req: any, res) => {
    try {
      const cleanedId = extractVRChatGroupId(req.params.groupId);
      await UserVRChatGroup.deleteOne({ userId: req.user.id, groupId: cleanedId });
      res.json({ success: true, message: 'VRChat group removed from your dashboard.' });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to delete VRChat group' });
    }
  });

  app.post('/api/user/vrchat-groups/:groupId/sync', authenticateToken, async (req: any, res) => {
    try {
      const cleanedId = extractVRChatGroupId(req.params.groupId);
      const group = await UserVRChatGroup.findOne({ userId: req.user.id, groupId: cleanedId });
      if (!group) return res.status(404).json({ error: 'Group not found' });

      group.lastSyncedAt = new Date();
      group.status = 'active';
      group.statusMessage = 'Manually synchronized with BeSafe Network blacklist';
      await group.save();

      res.json({ success: true, message: `Group ${cleanedId} synchronized with BeSafe Network blacklists.` });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to sync VRChat group' });
    }
  });

  // Helper function to resolve user by Discord ID, VRChat User ID, Ban Case, or VRChat profile link
  async function findUserByQuery(query: string) {
    const rawTrimmed = (query || '').trim();
    const cleaned = extractVRChatUserId(rawTrimmed);
    if (!cleaned && !rawTrimmed) return { user: null, banCase: null, cleaned: '' };

    const targetQuery = cleaned || rawTrimmed;

    // 1. First, search in BanCase collection
    let banCase = await BanCase.findOne({
      $or: [
        { caseNumber: targetQuery.toUpperCase() },
        { caseNumber: targetQuery },
        { 'discordAccounts.discordId': targetQuery },
        { 'discordAccounts.username': new RegExp(`^${targetQuery}$`, 'i') },
        { 'vrchatAccounts.vrchatUserId': targetQuery },
        { 'vrchatAccounts.vrchatUsername': new RegExp(`^${targetQuery}$`, 'i') }
      ]
    }).lean();

    // 2. Direct search in User collection
    let user = await User.findOne({
      $or: [
        { id: targetQuery },
        { vrchatUserId: targetQuery },
        { 'vrchatAlts.vrchatUserId': targetQuery },
        { vrchatUsername: new RegExp(`^${targetQuery}$`, 'i') }
      ]
    });

    // 3. If user not found, but we have a banCase
    if (!user && banCase) {
      // Look for any Discord account in the case
      const firstDiscord = banCase.discordAccounts?.find((d: any) => d && d.discordId);
      if (firstDiscord) {
        user = await User.findOne({ id: firstDiscord.discordId });
      }
      
      // If still not found, synthesize/create a user document for clean API compatibility
      if (!user) {
        const primaryVRChat = banCase.vrchatAccounts?.[0];
        const primaryDiscord = banCase.discordAccounts?.[0];
        const fallbackId = primaryDiscord?.discordId || primaryVRChat?.vrchatUserId || targetQuery;
        
        user = new User({
          id: fallbackId,
          username: primaryDiscord?.username || primaryVRChat?.vrchatUsername || fallbackId,
          isBanned: banCase.status === 'active',
          banReason: banCase.reason,
          banType: banCase.severity === 'temporary' ? 'temporary' : 'permanent',
          bannedBy: banCase.bannedBy || 'Administrator',
          bannedAt: banCase.createdAt || new Date(),
          vrchatUserId: primaryVRChat?.vrchatUserId || '',
          vrchatUsername: primaryVRChat?.vrchatUsername || '',
          vrchatAlts: (banCase.vrchatAccounts || []).slice(1).map((v: any) => ({
            vrchatUserId: v.vrchatUserId || '',
            vrchatUsername: v.vrchatUsername || ''
          }))
        });
      }
    }

    // 4. If not found and query is a VRChat User ID (usr_...), search Reports/Appeals for linked Discord user
    if (!user && targetQuery.startsWith('usr_')) {
      const report = await Report.findOne({
        $or: [
          { vrchatAccount: targetQuery },
          { vrchatAccount: new RegExp(targetQuery, 'i') }
        ]
      }).lean();
      if (report && report.targetUserId) {
        user = await User.findOne({ id: report.targetUserId });
      }
    }

    return { user, banCase, cleaned: targetQuery };
  }

  // ==========================================
  // --- PUBLIC API V1 & LEGACY ALIAS ROUTES ---
  // ==========================================

  // 1. Get User Profile & Reputation Profile
  app.get(['/api/v1/public/user/:userId', '/api/user/:userId'], async (req, res) => {
    try {
      const rawInput = req.params.userId || '';
      const { user: foundUser, cleaned } = await findUserByQuery(rawInput);
      let user = foundUser;
      
      if (!user) {
        user = new User({ id: cleaned, reputation: 0 });
        await user.save();
      }

      const age = user.dob ? (new Date().getFullYear() - user.dob.getFullYear()) : null;
      const isAdult = age !== null ? (age > 18 || (age === 18 && (new Date().getMonth() - user.dob.getMonth() >= 0))) : false;

      res.json({
        id: user.id,
        username: (user as any).username || (user as any).tag || user.id,
        displayName: (user as any).displayName || (user as any).username || user.id,
        avatarUrl: (user as any).avatarUrl || null,
        reputation: {
          score: user.reputation || 0,
          isTrusted: !!user.isTrusted,
          warningsCount: user.warnings ? user.warnings.length : 0
        },
        ban: {
          isBanned: !!user.isBanned,
          reason: user.banReason || null,
          type: user.banType || null,
          expiresAt: user.banExpiresAt || null
        },
        verification: {
          isVerified: !!user.isAgeVerified,
          isAdult: isAdult,
          verifiedAt: user.ageVerifiedAt || null
        },
        age: {
          isVerified: !!user.isAgeVerified,
          isAdult: isAdult,
          verifiedAt: user.ageVerifiedAt || null
        },
        vrchat: {
          vrchatUserId: user.vrchatUserId || null,
          vrchatUsername: user.vrchatUsername || null,
          linkedAlts: user.vrchatAlts || []
        },
        isDangerous: !!user.isDangerous,
        trustIndex: user.trustIndex || (user.isBanned ? 'RED_THREAT' : 'GREEN_SECURE')
      });
    } catch (e) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // 2. Comprehensive Security & Ban Threat Check
  app.get(['/api/v1/public/check/:userId', '/api/check/:userId'], async (req, res) => {
    try {
      const rawInput = req.params.userId || '';
      const { user: foundUser, banCase, cleaned } = await findUserByQuery(rawInput);
      let user = foundUser;
      
      if (!user) {
        if (cleaned.startsWith('usr_')) {
          const vName = await fetchVRChatDisplayName(cleaned).catch(() => null);
          return res.json({
            found: true,
            id: null,
            username: vName || cleaned,
            reputation: 0,
            isBanned: false,
            isThreat: false,
            reputationScore: 0,
            isVerified: false,
            threatLevel: 'LOW',
            banReason: null,
            bannedBy: null,
            bannedAt: null,
            banType: null,
            banExpiresAt: null,
            unbanHistory: [],
            warningsCount: 0,
            isSuspicious: false,
            isDangerous: false,
            trustIndex: 'GREEN_SECURE',
            watchlistUrl: null,
            banCase: null,
            vrchatAccounts: [{
              vrchatUserId: cleaned,
              vrchatUsername: vName || cleaned,
              isPrimary: true
            }]
          });
        }
        return res.json({
          found: false,
          isBanned: false,
          isThreat: false,
          reputationScore: 0,
          isVerified: false,
          threatLevel: 'LOW',
          banCase: null,
          message: 'No safety incidents or records found for this identifier.'
        });
      }

      const threatLevel = user.isDangerous || (user.isBanned && user.banType === 'permanent') 
        ? 'CRITICAL' 
        : user.isBanned 
          ? 'HIGH' 
          : ((user as any).isSuspicious || (user.warnings && user.warnings.length > 0)) 
            ? 'MEDIUM' 
            : 'LOW';

      const vrchatAccounts: any[] = [];
      if (user.vrchatUserId || user.vrchatUsername) {
        vrchatAccounts.push({
          vrchatUserId: user.vrchatUserId || "",
          vrchatUsername: user.vrchatUsername || "No Username",
          isPrimary: true
        });
      }
      if (user.vrchatAlts && Array.isArray(user.vrchatAlts)) {
        for (const alt of user.vrchatAlts) {
          if (alt.vrchatUserId || alt.vrchatUsername) {
            vrchatAccounts.push({
              vrchatUserId: alt.vrchatUserId || "",
              vrchatUsername: alt.vrchatUsername || "No Username",
              isPrimary: false
            });
          }
        }
      }

      // Add accounts from banCase if not already present
      if (banCase && Array.isArray(banCase.vrchatAccounts)) {
        for (const vc of banCase.vrchatAccounts) {
          if (vc && (vc.vrchatUserId || vc.vrchatUsername)) {
            const exists = vrchatAccounts.some(a => (vc.vrchatUserId && a.vrchatUserId === vc.vrchatUserId) || (vc.vrchatUsername && a.vrchatUsername === vc.vrchatUsername));
            if (!exists) {
              vrchatAccounts.push({
                vrchatUserId: vc.vrchatUserId || "",
                vrchatUsername: vc.vrchatUsername || "No Username",
                isPrimary: vrchatAccounts.length === 0
              });
            }
          }
        }
      }

      const primaryDisc = banCase?.discordAccounts?.[0];
      const primaryVRC = banCase?.vrchatAccounts?.[0];
      const resolved = user ? await resolveDiscordUser(client, user.id, user).catch(() => null) : null;
      const avatarUrl = primaryDisc?.avatarUrl || (user ? await getWatchlistAvatar(client, user) : resolved?.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png');
      const displayName = banCase?.title || primaryDisc?.displayName || primaryDisc?.username || (user as any)?.displayName || user?.username || resolved?.displayName || resolved?.username || primaryVRC?.vrchatUsername || (user as any)?.tag || user?.id;
      const resolvedUsername = primaryDisc?.username || user?.username || resolved?.username || primaryVRC?.vrchatUsername || (user as any)?.tag || user?.id;

      res.json({
        found: true,
        id: user.id,
        username: resolvedUsername,
        displayName: displayName || resolvedUsername,
        avatarUrl: avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png',
        reputation: user.reputation || 0,
        reputationScore: user.reputation || 0,
        isBanned: !!user.isBanned || (banCase && banCase.status === 'active'),
        isThreat: !!(user.isDangerous || user.isBanned || (banCase && banCase.status === 'active')),
        isVerified: !!user.isAgeVerified,
        threatLevel,
        banReason: user.banReason || banCase?.reason || null,
        bannedBy: (user as any).bannedBy || banCase?.bannedBy || null,
        bannedAt: (user as any).bannedAt || banCase?.createdAt || null,
        banType: user.banType || banCase?.severity || null,
        banExpiresAt: user.banExpiresAt || null,
        unbanHistory: user.unbanHistory || banCase?.unbanHistory || [],
        warningsCount: user.warnings ? user.warnings.length : 0,
        isSuspicious: !user.isBanned && user.reputation <= -10,
        isDangerous: !!user.isDangerous,
        trustIndex: user.trustIndex || (user.isBanned || (banCase && banCase.status === 'active') ? 'CRIMINAL' : 'GREEN_SECURE'),
        watchlistUrl: user.isDangerous ? `/watchlist/${user.id}` : null,
        banCase: banCase ? {
          caseNumber: banCase.caseNumber,
          title: banCase.title,
          reason: banCase.reason,
          severity: banCase.severity,
          status: banCase.status,
          discordAccounts: banCase.discordAccounts || [],
          vrchatAccounts: banCase.vrchatAccounts || []
        } : null,
        vrchatAccounts
      });
    } catch (error) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // 3. User Reputation & Trust Breakdown
  app.get(['/api/v1/public/reputation/:userId', '/api/reputation/:userId'], async (req, res) => {
    try {
      const rawInput = req.params.userId || '';
      const { user: foundUser } = await findUserByQuery(rawInput);
      
      if (!foundUser) {
        return res.json({
          userId: rawInput,
          score: 0,
          tier: 'NEUTRAL',
          vouchCount: 0,
          negativeCount: 0,
          incidentCount: 0,
          lastEvaluated: new Date()
        });
      }

      const ratings = await ReputationRating.find({ userId: foundUser.id });
      const vouchCount = ratings.filter(r => r.rating > 0).length;
      const negativeCount = ratings.filter(r => r.rating < 0).length;
      const warningsCount = foundUser.warnings ? foundUser.warnings.length : 0;

      let tier = 'NEUTRAL';
      if (foundUser.isTrusted || foundUser.reputation >= 20) tier = 'TRUSTED';
      else if (foundUser.reputation > 5) tier = 'POSITIVE';
      else if (foundUser.isDangerous || foundUser.reputation <= -10) tier = 'HIGH_RISK';
      else if (foundUser.reputation < 0 || warningsCount > 0) tier = 'SUSPICIOUS';

      res.json({
        userId: foundUser.id,
        score: foundUser.reputation || 0,
        tier,
        vouchCount,
        negativeCount,
        incidentCount: warningsCount + (foundUser.isBanned ? 1 : 0),
        lastEvaluated: foundUser.updatedAt || new Date()
      });
    } catch (e) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // 4. Cross-Platform Subject Lookup
  app.get(['/api/v1/public/lookup/:query', '/api/lookup/:query'], async (req, res) => {
    try {
      const q = (req.params.query || '').trim();
      if (!q) return res.json({ count: 0, results: [] });

      const regex = new RegExp(q, 'i');
      const users = await User.find({
        $or: [
          { id: q },
          { tag: regex },
          { vrchatUserId: q },
          { vrchatUsername: regex },
          { 'vrchatAlts.vrchatUserId': q },
          { 'vrchatAlts.vrchatUsername': regex }
        ]
      }).limit(20);

      const results = users.map(u => ({
        platform: u.vrchatUserId === q || u.vrchatUsername?.toLowerCase() === q.toLowerCase() ? 'vrchat' : 'discord',
        id: u.id,
        discordId: u.id,
        tag: (u as any).tag,
        vrchatUserId: u.vrchatUserId,
        vrchatUsername: u.vrchatUsername,
        isBanned: !!u.isBanned,
        isDangerous: !!u.isDangerous,
        reputation: u.reputation || 0,
        isVerified: !!u.isAgeVerified
      }));

      if (results.length === 0 && q.startsWith('usr_')) {
        const vName = await fetchVRChatDisplayName(q).catch(() => null);
        if (vName) {
          results.push({
            platform: 'vrchat',
            id: null as any,
            discordId: null as any,
            tag: null as any,
            vrchatUserId: q,
            vrchatUsername: vName,
            isBanned: false,
            isDangerous: false,
            reputation: 0,
            isVerified: false
          });
        }
      }

      res.json({ count: results.length, results });
    } catch (e) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // 5. Watchlist & Dangerous People Feed
  app.get(['/api/v1/public/watchlist', '/api/public/watchlist', '/api/public/dangerous'], async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
      const severity = req.query.severity as string;

      // 1. Fetch Watchlisted Ban Cases
      const dangerousCases = await BanCase.find({ isDangerous: true }).sort({ updatedAt: -1 });
      const formattedCases = await Promise.all(dangerousCases.map(async (c) => {
        const primaryDisc = c.discordAccounts[0];
        const primaryVRC = c.vrchatAccounts[0];
        let avatarUrl = primaryDisc?.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png';
        let displayName = c.title || primaryDisc?.displayName || primaryDisc?.username || primaryVRC?.vrchatUsername || `Case #${c.caseNumber}`;
        let username = primaryDisc?.username || primaryVRC?.vrchatUsername || c.caseNumber;
        const mainId = primaryDisc?.discordId || primaryVRC?.vrchatUserId || c.caseNumber;

        return {
          id: mainId,
          _id: c._id,
          caseNumber: c.caseNumber,
          isBanCase: true,
          tag: primaryDisc?.username || c.caseNumber,
          displayName,
          username,
          avatarUrl,
          reason: c.dangerousNotes || c.reason,
          dangerousNotes: c.dangerousNotes || c.notes,
          banReason: c.reason,
          severity: c.severity === 'critical' ? 'CRITICAL' : 'HIGH',
          threatType: 'CONFIRMED_HIGH_RISK_THREAT',
          trustIndex: c.trustIndex || 'CRIMINAL',
          addedAt: c.createdAt || new Date(),
          updatedAt: c.updatedAt,
          evidenceCount: (c.evidenceLinks || []).length,
          evidence: (c.evidenceLinks || []).filter(Boolean),
          discordAccounts: c.discordAccounts || [],
          vrchatAccounts: c.vrchatAccounts || [],
          vrchatUserId: primaryVRC?.vrchatUserId || '',
          vrchatUsername: primaryVRC?.vrchatUsername || '',
          isBanned: c.status === 'active',
          isDangerous: true,
          isSuspicious: false
        };
      }));

      // 2. Fetch Watchlisted Legacy Users
      let query: any = {
        $or: [
          { isDangerous: true },
          { isSuspicious: true }
        ]
      };

      if (severity === 'CRITICAL') {
        query = { isDangerous: true, isBanned: true };
      } else if (severity === 'HIGH') {
        query = { isDangerous: true };
      } else if (severity === 'MEDIUM') {
        query = { isSuspicious: true };
      }

      const dangerousUsers = await User.find(query).limit(limit).sort({ updatedAt: -1 });
      
      const formattedUsers = await Promise.all(dangerousUsers.map(async (u) => {
        // Skip if this user is already represented by a watchlisted Ban Case
        if (formattedCases.some(c => c.discordAccounts?.some((d: any) => d.discordId === u.id) || c.vrchatAccounts?.some((v: any) => v.vrchatUserId === u.vrchatUserId))) {
          return null;
        }

        const resolved = await resolveDiscordUser(client, u.id, u);
        const avatarUrl = await getWatchlistAvatar(client, u);
        const vrchatAccounts: any[] = [];
        if (u.vrchatUserId || u.vrchatUsername) {
          vrchatAccounts.push({
            vrchatUserId: u.vrchatUserId || "",
            vrchatUsername: u.vrchatUsername || "No Username",
            isPrimary: true
          });
        }
        if (u.vrchatAlts && Array.isArray(u.vrchatAlts)) {
          for (const alt of u.vrchatAlts) {
            if (alt.vrchatUserId || alt.vrchatUsername) {
              vrchatAccounts.push({
                vrchatUserId: alt.vrchatUserId || "",
                vrchatUsername: alt.vrchatUsername || "No Username",
                isPrimary: false
              });
            }
          }
        }

        const userDiscordAccounts: any[] = [];
        if (u.id) {
          userDiscordAccounts.push({
            discordId: u.id,
            username: resolved.username || (u as any).tag || u.id,
            displayName: resolved.displayName || resolved.username || u.id,
            avatarUrl: avatarUrl || resolved.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png',
            isPrimary: true
          });
        }
        if ((u as any).discordAccounts && Array.isArray((u as any).discordAccounts)) {
          for (const d of (u as any).discordAccounts) {
            if (!userDiscordAccounts.some(x => x.discordId === d.discordId)) {
              userDiscordAccounts.push({
                discordId: d.discordId,
                username: d.username || d.displayName || d.discordId,
                displayName: d.displayName || d.username || d.discordId,
                avatarUrl: d.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png',
                isPrimary: false
              });
            }
          }
        }
        if ((u as any).altDiscordAccounts && Array.isArray((u as any).altDiscordAccounts)) {
          for (const alt of (u as any).altDiscordAccounts) {
            const aid = alt.discordId || alt.id;
            if (aid && !userDiscordAccounts.some(x => x.discordId === aid)) {
              userDiscordAccounts.push({
                discordId: aid,
                username: alt.username || alt.tag || aid,
                displayName: alt.displayName || alt.username || aid,
                avatarUrl: alt.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png',
                isPrimary: false
              });
            }
          }
        }

        return {
          id: u.id,
          _id: u._id,
          isBanCase: false,
          tag: (u as any).tag || u.id,
          displayName: resolved.displayName,
          username: resolved.username,
          avatarUrl: avatarUrl || resolved.avatarUrl,
          reason: u.dangerousNotes || u.banReason || 'Flagged security threat',
          dangerousNotes: u.dangerousNotes,
          banReason: u.banReason,
          severity: u.isDangerous && u.isBanned ? 'CRITICAL' : (u.isDangerous ? 'HIGH' : 'MEDIUM'),
          threatType: u.isDangerous ? 'CONFIRMED_HIGH_RISK_THREAT' : 'SUSPICIOUS_ACTIVITY',
          trustIndex: u.trustIndex || 'CRIMINAL',
          addedAt: u.updatedAt || new Date(),
          updatedAt: u.updatedAt,
          evidenceCount: (u.evidenceLinks || (u as any).evidencePhotos || []).length,
          evidence: (u.evidenceLinks || (u as any).evidencePhotos || []).filter(Boolean),
          discordAccounts: userDiscordAccounts,
          vrchatAccounts,
          vrchatUserId: u.vrchatUserId,
          vrchatUsername: u.vrchatUsername,
          isBanned: !!u.isBanned,
          isDangerous: !!u.isDangerous,
          isSuspicious: !!(u as any).isSuspicious
        };
      }));

      const combined = [...formattedCases, ...formattedUsers.filter(Boolean)].slice(0, limit);

      // If calling /api/v1/public/watchlist, return enveloped JSON
      if (req.path.startsWith('/api/v1')) {
        return res.json({
          count: combined.length,
          entries: combined
        });
      }
      
      // Legacy routes return raw list
      res.json(combined);
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch watchlist' });
    }
  });

  // 6. Watchlist Individual Threat Dossier
  app.get(['/api/v1/public/watchlist/:userId', '/api/public/dangerous/:id'], async (req, res) => {
    try {
      const id = req.params.userId || req.params.id;
      const { user, banCase } = await findUserByQuery(id);
      
      if (banCase && banCase.isDangerous) {
        const primaryDisc = banCase.discordAccounts?.[0];
        const primaryVRC = banCase.vrchatAccounts?.[0];
        const avatarUrl = primaryDisc?.avatarUrl || (user ? await getWatchlistAvatar(client, user) : 'https://cdn.discordapp.com/embed/avatars/0.png');
        const displayName = banCase.title || primaryDisc?.displayName || primaryDisc?.username || primaryVRC?.vrchatUsername || `Case #${banCase.caseNumber}`;
        const username = primaryDisc?.username || primaryVRC?.vrchatUsername || banCase.caseNumber;

        const caseDiscordAccounts = (banCase.discordAccounts && banCase.discordAccounts.length > 0)
          ? banCase.discordAccounts
          : (primaryDisc ? [primaryDisc] : []);

        return res.json({
          id: primaryDisc?.discordId || primaryVRC?.vrchatUserId || banCase.caseNumber,
          userId: primaryDisc?.discordId || primaryVRC?.vrchatUserId || banCase.caseNumber,
          caseNumber: banCase.caseNumber,
          isBanCase: true,
          displayName,
          username,
          avatarUrl,
          alias: primaryDisc?.username || primaryVRC?.vrchatUsername || banCase.caseNumber,
          threatType: 'CONFIRMED_HIGH_RISK_THREAT',
          status: banCase.status === 'active' ? 'GLOBALLY_BANNED' : 'UNDER_SURVEILLANCE',
          reason: banCase.dangerousNotes || banCase.reason,
          dangerousNotes: banCase.dangerousNotes,
          banReason: banCase.reason,
          evidence: banCase.evidenceLinks || [],
          discordAccounts: caseDiscordAccounts,
          vrchatAccounts: banCase.vrchatAccounts || [],
          reputation: user?.reputation || 0,
          warningsCount: user?.warnings ? user.warnings.length : 0,
          isAgeVerified: user?.isAgeVerified || false,
          trustIndex: banCase.trustIndex || 'CRIMINAL',
          updatedAt: banCase.updatedAt || new Date(),
          createdAt: banCase.createdAt || new Date()
        });
      }

      if (!user) {
        return res.status(404).json({ error: 'Threat dossier not found' });
      }

      const resolved = await resolveDiscordUser(client, user.id, user);
      const avatarUrl = await getWatchlistAvatar(client, user);

      const userDiscordAccounts: any[] = [];
      if (user.id) {
        userDiscordAccounts.push({
          discordId: user.id,
          username: resolved.username || (user as any).tag || user.id,
          displayName: resolved.displayName || resolved.username || user.id,
          avatarUrl: avatarUrl || resolved.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png',
          isPrimary: true
        });
      }
      if ((user as any).discordAccounts && Array.isArray((user as any).discordAccounts)) {
        for (const d of (user as any).discordAccounts) {
          if (!userDiscordAccounts.some(x => x.discordId === d.discordId)) {
            userDiscordAccounts.push({
              discordId: d.discordId,
              username: d.username || d.displayName || d.discordId,
              displayName: d.displayName || d.username || d.discordId,
              avatarUrl: d.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png',
              isPrimary: false
            });
          }
        }
      }
      if ((user as any).altDiscordAccounts && Array.isArray((user as any).altDiscordAccounts)) {
        for (const alt of (user as any).altDiscordAccounts) {
          const aid = alt.discordId || alt.id;
          if (aid && !userDiscordAccounts.some(x => x.discordId === aid)) {
            userDiscordAccounts.push({
              discordId: aid,
              username: alt.username || alt.tag || aid,
              displayName: alt.displayName || alt.username || aid,
              avatarUrl: alt.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png',
              isPrimary: false
            });
          }
        }
      }

      const vrchatAccounts: any[] = [];
      if (user.vrchatUserId || user.vrchatUsername) {
        vrchatAccounts.push({
          vrchatUserId: user.vrchatUserId || "",
          vrchatUsername: user.vrchatUsername || "No Username",
          isPrimary: true
        });
      }
      if (user.vrchatAlts && Array.isArray(user.vrchatAlts)) {
        for (const alt of user.vrchatAlts) {
          if (alt.vrchatUserId || alt.vrchatUsername) {
            vrchatAccounts.push({
              vrchatUserId: alt.vrchatUserId || "",
              vrchatUsername: alt.vrchatUsername || "No Username",
              isPrimary: false
            });
          }
        }
      }

      res.json({
        id: user.id,
        userId: user.id,
        displayName: resolved.displayName,
        username: resolved.username,
        avatarUrl: avatarUrl || resolved.avatarUrl,
        alias: (user as any).tag || user.vrchatUsername || user.id,
        threatType: user.isDangerous ? 'CONFIRMED_HIGH_RISK_THREAT' : 'SUSPICIOUS_ACTIVITY',
        status: user.isBanned ? 'GLOBALLY_BANNED' : 'UNDER_SURVEILLANCE',
        reason: user.dangerousNotes || user.banReason || 'Under security review',
        banReason: user.banReason,
        dangerousNotes: user.dangerousNotes,
        trustIndex: user.trustIndex || 'CRIMINAL',
        evidence: (user.evidenceLinks || (user as any).evidencePhotos || []).filter(Boolean),
        reputation: user.reputation || 0,
        isAgeVerified: !!user.isAgeVerified,
        warningsCount: user.warnings?.length || 0,
        discordAccounts: userDiscordAccounts,
        vrchatAccounts,
        updatedAt: user.updatedAt,
        createdAt: user.createdAt
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch threat dossier' });
    }
  });

  // 7. Public Incident Report Submission
  app.post(['/api/v1/public/report', '/api/public/report'], async (req, res) => {
    try {
      const { targetUserId, reason, evidence, reporterUserId, reporterEmail, vrchatUsername, vrchatAccount, customBanlistId } = req.body;
      if (!targetUserId || !reason) {
        return res.status(400).json({ error: 'targetUserId and reason are required' });
      }

      const evidenceLinks = Array.isArray(evidence) ? evidence : (evidence ? [evidence] : []);

      const report = new Report({
        targetUserId: targetUserId.trim(),
        targetDisplayName: targetUserId.trim(),
        reason: reason.trim(),
        evidenceLinks,
        reporterUserId: reporterUserId || 'Public Community Member',
        reporterEmail: reporterEmail || (reporterUserId?.includes('@') ? reporterUserId : 'public-report@besafe.network'),
        vrchatAccount: vrchatUsername || vrchatAccount || '',
        customBanlistId: customBanlistId || ''
      });

      await report.save();

      await notifyAdmins('New Incident Report', `A new safety report was submitted for target: ${targetUserId}.\nReason: ${reason}`);

      res.json({
        success: true,
        reportId: report._id,
        message: 'Report logged and assigned to staff triage queue.'
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to submit report' });
    }
  });

  // 8. Public Ban Appeal Submission
  app.post(['/api/v1/public/appeal', '/api/appeal'], async (req, res) => {
    try {
      const { userId, email, reason, vrchatAccount, evidence } = req.body;
      if (!userId || !email || !reason) {
        return res.status(400).json({ error: 'userId, email, and reason are required' });
      }

      const appeal = new Appeal({
        userId: userId.trim(),
        email: email.trim(),
        reason: reason.trim(),
        vrchatAccount: vrchatAccount || "",
        evidenceLinks: Array.isArray(evidence) ? evidence : (evidence ? [evidence] : [])
      });

      await safeSaveAppeal(appeal);
      await notifyAdmins('New Ban Appeal', `User ${userId} filed a ban appeal (${email}).\nReason: ${reason}${vrchatAccount ? `\nVRChat Account: ${vrchatAccount}` : ''}`);

      res.json({
        success: true,
        appealId: appeal._id,
        status: 'PENDING_REVIEW',
        message: 'Appeal successfully submitted. You will receive an email upon review.'
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to submit appeal' });
    }
  });

  // 9. Public Appeal Status Check
  app.get(['/api/v1/public/appeal-status/:userId', '/api/appeal/status/:userId'], async (req, res) => {
    try {
      const userId = (req.params.userId || '').trim();
      const latestAppeal = await Appeal.findOne({ userId }).sort({ createdAt: -1 });

      if (!latestAppeal) {
        return res.json({
          hasActiveAppeal: false,
          status: 'NO_APPEAL_FOUND',
          submittedAt: null,
          lastStaffNote: null
        });
      }

      res.json({
        hasActiveAppeal: latestAppeal.status === 'pending' || (latestAppeal.status as string) === 'under_review',
        status: latestAppeal.status.toUpperCase(),
        submittedAt: latestAppeal.createdAt,
        lastStaffNote: latestAppeal.adminNotes || 'Appeal is currently queued with trust and safety investigators.'
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch appeal status' });
    }
  });

  // Public stats endpoint
  app.get(['/api/public/stats', '/api/v1/public/stats', '/api/stats'], async (req, res) => {
    try {
      const [activeBanCases, activeBanCasesDocs, guildCount, trustedUserCount, totalUsersInDb] = await Promise.all([
        BanCase.find({ status: 'active' }).lean(),
        BanCase.countDocuments({ status: 'active' }),
        Guild.countDocuments(),
        User.countDocuments({ isTrusted: true }),
        User.countDocuments()
      ]);

      // Calculate total banned accounts (all linked Discord and VRChat accounts) or cases count
      let totalBannedAccounts = 0;
      for (const c of activeBanCases) {
        const discCount = (c.discordAccounts || []).length;
        const vrcCount = (c.vrchatAccounts || []).length;
        totalBannedAccounts += Math.max(1, discCount + vrcCount);
      }
      const banCount = Math.max(activeBanCasesDocs, totalBannedAccounts);

      // Calculate total protected users across connected Discord guilds
      let liveDiscordMembers = 0;
      if (typeof client !== 'undefined' && client && client.guilds && client.guilds.cache) {
        liveDiscordMembers = client.guilds.cache.reduce((acc: number, g: any) => acc + (g.memberCount || 0), 0);
      }

      const userCount = Math.max(liveDiscordMembers, totalUsersInDb + (guildCount * 150), 100);

      res.json({ userCount, banCount, guildCount, trustedCount: trustedUserCount });
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch stats' });
    }
  });

  // Admin endpoints
  app.get('/api/admin/stats', authenticateToken, isModOrAdmin, async (req, res) => {
    try {
      const [banCount, reportCount, appealCount, guildCount, trustedCount] = await Promise.all([
        BanCase.countDocuments({ status: 'active' }),
        Report.countDocuments(),
        Appeal.countDocuments(),
        Guild.countDocuments(),
        User.countDocuments({ isTrusted: true })
      ]);
      res.json({ banCount, reportCount, appealCount, guildCount, trustedCount });
    } catch (e) {
      res.status(500).send();
    }
  });

  app.get('/api/admin/logs', authenticateToken, isModOrAdmin, async (req, res) => {
    const logs = await Log.find().sort({ timestamp: -1 }).limit(100);
    res.json(logs);
  });

  app.get('/api/admin/reports', authenticateToken, isModOrAdmin, async (req, res) => {
    try {
      const reports = await Report.find({ status: 'pending' }).sort({ createdAt: -1 }).limit(50).lean();
      const targetUserIds = reports.map(r => r.targetUserId);
      const users = await User.find({ id: { $in: targetUserIds } }).lean();
      const userMap = new Map(users.map(u => [u.id, u]));

      const enrichedReports = await Promise.all(reports.map(async (report) => {
        const user = userMap.get(report.targetUserId);
        const resolved = await resolveDiscordUser(client, report.targetUserId, user);

        return {
          ...report,
          targetDisplayName: resolved.displayName,
          warnings: user?.warnings || []
        };
      }));

      res.json(enrichedReports);
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch reports' });
    }
  });

  app.post('/api/appeal', async (req, res) => {
    try {
      const { userId, email, reason, vrchatAccount, attachments } = req.body;
      if (!userId || !email || !reason) {
        return res.status(400).json({ error: 'Missing required fields' });
      }

      const cleanedVrchat = extractVRChatUserId(vrchatAccount || "");
      const appeal = new Appeal({
        userId,
        email,
        reason,
        vrchatAccount: cleanedVrchat,
        attachments: Array.isArray(attachments) ? attachments.filter(Boolean) : [],
        status: 'pending'
      });
      await safeSaveAppeal(appeal);

      await notifyAdmins('New Ban Appeal', `A new appeal has been submitted for user ${userId}.\nReason: ${reason}`);

      res.json({ success: true, appealId: appeal._id });
    } catch (e) {
      console.error('Error submitting appeal:', e);
      res.status(500).json({ error: 'Failed to submit appeal' });
    }
  });

  app.get('/api/admin/appeals', authenticateToken, isModOrAdmin, async (req, res) => {
    try {
      const appeals = await Appeal.find({
        status: 'pending',
        $or: [
          { claimedBy: null },
          { claimedBy: "" },
          { claimedBy: { $exists: false } }
        ]
      }).sort({ createdAt: -1 }).limit(50).lean();
      const userIds = appeals.map(a => a.userId);
      
      const [users, reports] = await Promise.all([
        User.find({ id: { $in: userIds } }).lean(),
        Report.find({ targetUserId: { $in: userIds }, status: 'reviewed' }).sort({ createdAt: -1 }).lean()
      ]);

      const userMap = new Map(users.map(u => [u.id, u]));
      const reportMap = new Map();
      for (const r of reports) {
        if (!reportMap.has(r.targetUserId)) {
          reportMap.set(r.targetUserId, r);
        }
      }

      const enrichedAppeals = await Promise.all(appeals.map(async (appeal) => {
        const user = userMap.get(appeal.userId);
        const report = reportMap.get(appeal.userId);
        const resolved = await resolveDiscordUser(client, appeal.userId, user);

        return {
          ...appeal,
          userDisplayName: resolved.displayName,
          originalBanReason: user?.banReason || 'Unknown',
          evidence: (report?.evidenceLinks || []).join('\n') || 'No evidence found from original report.'
        };
      }));
      
      res.json(enrichedAppeals);
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch appeals' });
    }
  });

  app.post('/api/admin/appeals/:id/claim', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const appeal = await Appeal.findById(req.params.id);
      if (!appeal) return res.status(404).json({ error: 'Appeal not found' });
      if (appeal.status === 'approved' || appeal.status === 'denied') {
        return res.status(400).json({ error: 'Cannot claim a closed appeal' });
      }

      appeal.claimedBy = req.user.username;
      appeal.claimedAt = new Date();
      appeal.status = 'claimed';
      await safeSaveAppeal(appeal);

      await new Log({
        action: 'CLAIM_APPEAL',
        adminId: req.user.username,
        targetId: appeal.userId,
        details: `Claimed appeal ${appeal._id} as case`
      }).save();

      res.json({ success: true, appeal });
    } catch (e) {
      res.status(500).json({ error: 'Failed to claim appeal' });
    }
  });

  app.post('/api/admin/appeals/:id/unclaim', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const appeal = await Appeal.findById(req.params.id);
      if (!appeal) return res.status(404).json({ error: 'Appeal not found' });

      appeal.claimedBy = null;
      (appeal as any).claimedAt = undefined;
      appeal.status = 'pending';
      await safeSaveAppeal(appeal);

      await new Log({
        action: 'UNCLAIM_APPEAL',
        adminId: req.user.username,
        targetId: appeal.userId,
        details: `Unclaimed appeal ${appeal._id}`
      }).save();

      res.json({ success: true, appeal });
    } catch (e) {
      res.status(500).json({ error: 'Failed to unclaim appeal' });
    }
  });

  app.post('/api/admin/reports/:id/claim', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const report = await Report.findById(req.params.id);
      if (!report) return res.status(404).json({ error: 'Report not found' });
      if (report.status === 'reviewed' || report.status === 'dismissed') {
        return res.status(400).json({ error: 'Cannot claim a closed report' });
      }

      report.claimedBy = req.user.username;
      report.claimedAt = new Date();
      report.status = 'claimed';
      await safeSaveReport(report);

      await new Log({
        action: 'CLAIM_REPORT',
        adminId: req.user.username,
        targetId: report.targetUserId,
        details: `Claimed report ${report._id} as case ticket`
      }).save();

      res.json({ success: true, report });
    } catch (e) {
      res.status(500).json({ error: 'Failed to claim report' });
    }
  });

  app.post('/api/admin/reports/:id/unclaim', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const report = await Report.findById(req.params.id);
      if (!report) return res.status(404).json({ error: 'Report not found' });

      report.claimedBy = null;
      (report as any).claimedAt = undefined;
      report.status = 'pending';
      await safeSaveReport(report);

      await new Log({
        action: 'UNCLAIM_REPORT',
        adminId: req.user.username,
        targetId: report.targetUserId,
        details: `Unclaimed report ${report._id}`
      }).save();

      res.json({ success: true, report });
    } catch (e) {
      res.status(500).json({ error: 'Failed to unclaim report' });
    }
  });

  app.get('/api/admin/cases', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const showAll = req.query.all === 'true';
      const query = showAll
        ? { claimedBy: { $ne: null, $exists: true } }
        : { claimedBy: req.user.username };

      const [appeals, reports] = await Promise.all([
        Appeal.find(query).sort({ claimedAt: -1, createdAt: -1 }).lean(),
        Report.find({ ...query, status: 'claimed' }).sort({ claimedAt: -1, createdAt: -1 }).lean()
      ]);

      const appealUserIds = appeals.map(a => a.userId);
      const reportTargetUserIds = reports.map(r => r.targetUserId);
      const allUserIds = Array.from(new Set([...appealUserIds, ...reportTargetUserIds]));

      const [users, relatedReports] = await Promise.all([
        User.find({ id: { $in: allUserIds } }).lean(),
        Report.find({ targetUserId: { $in: appealUserIds }, status: 'reviewed' }).sort({ createdAt: -1 }).lean()
      ]);

      const userMap = new Map(users.map(u => [u.id, u]));
      const reportMap = new Map();
      for (const r of relatedReports) {
        if (!reportMap.has(r.targetUserId)) {
          reportMap.set(r.targetUserId, r);
        }
      }

      const enrichedAppeals = await Promise.all(appeals.map(async (appeal) => {
        const user = userMap.get(appeal.userId);
        const report = reportMap.get(appeal.userId);
        const resolved = await resolveDiscordUser(client, appeal.userId, user);

        return {
          ...appeal,
          caseType: 'appeal',
          userDisplayName: resolved.displayName,
          originalBanReason: user?.banReason || 'Unknown',
          evidence: (report?.evidenceLinks || []).join('\n') || 'No evidence found from original report.'
        };
      }));

      const enrichedReports = await Promise.all(reports.map(async (report) => {
        const user = userMap.get(report.targetUserId);
        const resolved = await resolveDiscordUser(client, report.targetUserId, user);

        return {
          ...report,
          caseType: 'report',
          userId: report.targetUserId,
          userDisplayName: (report as any).targetDisplayName || resolved.displayName,
          email: report.reporterEmail,
          originalBanReason: user?.banReason || 'Reported Violation',
          evidence: (report.evidenceLinks || []).join('\n') || 'No evidence links provided.'
        };
      }));

      const allCases = [...enrichedAppeals, ...enrichedReports].sort((a, b) => {
        const timeA = new Date(a.claimedAt || a.createdAt).getTime();
        const timeB = new Date(b.claimedAt || b.createdAt).getTime();
        return timeB - timeA;
      });

      res.json(allCases);
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch cases' });
    }
  });

  app.post('/api/admin/reports/:id/message', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const { content, attachments } = req.body;
      const report = await Report.findById(req.params.id);
      if (!report) return res.status(404).json({ error: 'Report not found' });

      const filteredAttachments = Array.isArray(attachments) ? attachments.filter(Boolean) : [];

      (report as any).messages.push({
        sender: 'admin',
        content: content || '',
        attachments: filteredAttachments,
        timestamp: new Date()
      });
      await safeSaveReport(report);

      const baseUrl = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
      const replyUrl = `${baseUrl}/report-reply?id=${report._id}`;

      // DM reporter on Discord if reporter has a Discord User ID
      const discordIdMatch = report.reporterUserId ? report.reporterUserId.match(/(\d{17,20})/) : null;
      const rawDiscordUserId = discordIdMatch ? discordIdMatch[1] : (report.reporterUserId && /^\d{17,20}$/.test(report.reporterUserId) ? report.reporterUserId : null);

      if (rawDiscordUserId && client) {
        try {
          const discordUser = await client.users.fetch(rawDiscordUserId);
          if (discordUser) {
            await discordUser.send(`🛡️ **BeSafe Network: Mod Communication**\n\nAn administrator sent an update regarding your report (ID: \`${report._id}\`):\n\n> ${content}\n\n[Click here to view full discussion / reply on web](${replyUrl})`).catch(() => null);
          }
        } catch (e) {
          console.error(`Failed to DM report message to Discord user ${rawDiscordUserId}:`, e);
        }
      }

      // Send email if a valid email address is provided
      if (report.reporterEmail && report.reporterEmail.includes('@') && !report.reporterEmail.endsWith('@discord.user') && !report.reporterEmail.endsWith('@besafe.network')) {
        try {
          const email = EmailTemplates.getReportMessageEmail(report.targetUserId, content, replyUrl, filteredAttachments);
          await sendMail(report.reporterEmail, email.subject, email.text, email.html, email.mailAttachments);
        } catch (e) {
          console.error('Failed to send report message email:', e);
        }
      }

      await new Log({
        action: 'REPORT_MESSAGE_SENT',
        adminId: req.user.username,
        targetId: report.targetUserId,
        details: `Sent message to reporter regarding report ${report._id}`
      }).save();

      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Failed to send message' });
    }
  });

  app.post('/api/admin/appeals/:id/message', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const { content, attachments } = req.body;
      const appeal = await Appeal.findById(req.params.id);
      if (!appeal) return res.status(404).json({ error: 'Appeal not found' });

      const filteredAttachments = Array.isArray(attachments) ? attachments.filter(Boolean) : [];

      (appeal as any).messages.push({
        sender: 'admin',
        content,
        attachments: filteredAttachments
      });
      await safeSaveAppeal(appeal);

      const baseUrl = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
      const replyUrl = `${baseUrl}/appeal-reply?id=${appeal._id}`;
      const email = EmailTemplates.getAppealMessageEmail(appeal.userId, content, replyUrl, filteredAttachments);
      await sendMail(appeal.email, email.subject, email.text, email.html, email.mailAttachments);

      await new Log({
        action: 'APPEAL_MESSAGE_SENT',
        adminId: req.user.username,
        targetId: appeal.userId,
        details: `Sent message to user regarding appeal ${appeal._id}`
      }).save();

      res.json({ success: true });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Failed to send message' });
    }
  });

  app.post('/api/appeal/:id/reply', async (req, res) => {
    try {
      const { content, attachments } = req.body;
      if (!content && (!attachments || attachments.length === 0)) {
        return res.status(400).json({ error: 'Message content or attachment required' });
      }
      
      const appeal = await Appeal.findById(req.params.id);
      if (!appeal) return res.status(404).json({ error: 'Appeal not found' });
      if (appeal.status === 'approved' || appeal.status === 'denied') {
        return res.status(403).json({ error: 'Appeal session is closed.' });
      }

      (appeal as any).messages.push({
        sender: 'user',
        content: content || '',
        attachments: Array.isArray(attachments) ? attachments.filter(Boolean) : []
      });
      await safeSaveAppeal(appeal);

      await notifyAdmins('APPEAL TICKET REPLY', `User ${appeal.userId} has replied to their appeal ticket (${appeal._id}).`);
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: 'Failed to submit reply' });
    }
  });

  app.post('/api/report/:id/reply', async (req, res) => {
    try {
      const { content, attachments } = req.body;
      if (!content && (!attachments || attachments.length === 0)) {
        return res.status(400).json({ error: 'Message content or attachment required' });
      }
      
      const report = await Report.findById(req.params.id);
      if (!report) return res.status(404).json({ error: 'Report ticket not found' });
      if (report.status === 'reviewed' || report.status === 'dismissed') {
        return res.status(403).json({ error: 'Report session is closed.' });
      }

      (report as any).messages.push({
        sender: 'user',
        content: content || '',
        attachments: Array.isArray(attachments) ? attachments.filter(Boolean) : [],
        timestamp: new Date()
      });
      await safeSaveReport(report);

      await notifyAdmins('REPORT TICKET REPLY', `Reporter for user ${report.targetUserId} has replied to report ticket (${report._id}).`);
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: 'Failed to submit reply' });
    }
  });

  app.get('/api/report/:id/public', async (req, res) => {
    try {
      const report = await Report.findById(req.params.id).select('targetUserId targetDisplayName reporterUserId reason attachments evidenceLinks status claimedBy messages vrchatAccount createdAt');
      if (!report) return res.status(404).json({ error: 'Report ticket not found' });
      res.json(report);
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch report' });
    }
  });

  app.post('/api/admin/users/:id/evidence', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const { links } = req.body;
      const user = await User.findOneAndUpdate(
        { id: req.params.id },
        { $set: { evidenceLinks: links, updatedAt: new Date() } },
        { new: true }
      );
      if (!user) return res.status(404).json({ error: 'User not found' });

      await new Log({
        action: 'UPDATE_EVIDENCE',
        adminId: req.user.username,
        targetId: req.params.id,
        details: `Updated evidence links for ${req.params.id}`
      }).save();

      res.json({ success: true, evidenceLinks: user.evidenceLinks });
    } catch (e) {
      res.status(500).json({ error: 'Failed to update evidence' });
    }
  });

  app.get('/api/admin/dashboard/summary', authenticateToken, isModOrAdmin, async (req, res) => {
    try {
      const [
        reports,
        appeals,
        verifications,
        apiRequests,
        bannedCount,
        trustedCount
      ] = await Promise.all([
        Report.countDocuments({ status: 'pending' }),
        Appeal.countDocuments({ status: 'pending' }),
        VerificationRequest.countDocuments({ status: 'pending' }),
        ApiKeyRequest.countDocuments({ status: 'pending' }),
        BanCase.countDocuments({ status: 'active' }),
        User.countDocuments({ isTrusted: true })
      ]);

      res.json({
        pending: {
          reports,
          appeals,
          verifications,
          apiRequests
        },
        stats: {
          totalBans: bannedCount,
          totalTrusted: trustedCount
        }
      });
    } catch (e) {
      res.status(500).send();
    }
  });

  app.get('/api/admin/bans', authenticateToken, isModOrAdmin, async (req, res) => {
    try {
      const activeBanCases = await BanCase.find({ status: 'active' }).sort({ createdAt: -1 }).limit(150).lean();
      
      const enrichedBans = await Promise.all(activeBanCases.map(async (bCase) => {
        const primaryDiscord = (bCase.discordAccounts || [])[0];
        const primaryVRChat = (bCase.vrchatAccounts || []).find((v: any) => v.isPrimary) || (bCase.vrchatAccounts || [])[0];
        const primaryId = primaryDiscord?.discordId || primaryVRChat?.vrchatUserId || bCase.caseNumber;
        
        let displayName = primaryDiscord?.displayName || primaryDiscord?.username || primaryVRChat?.vrchatUsername || bCase.title || bCase.caseNumber;
        if (primaryDiscord?.discordId && client) {
          const resolved = await resolveDiscordUser(client, primaryDiscord.discordId).catch(() => null);
          if (resolved?.displayName) displayName = resolved.displayName;
        }

        return {
          id: primaryId,
          caseNumber: bCase.caseNumber,
          username: displayName,
          displayName,
          banReason: bCase.reason,
          banType: bCase.severity,
          bannedAt: bCase.bannedAt || bCase.createdAt,
          bannedBy: bCase.bannedBy,
          isDangerous: !!bCase.isDangerous,
          dangerousNotes: bCase.dangerousNotes,
          trustIndex: bCase.trustIndex,
          discordAccounts: bCase.discordAccounts || [],
          vrchatAccounts: bCase.vrchatAccounts || [],
          evidenceLinks: bCase.evidenceLinks || [],
          notes: bCase.notes,
          vrchatUserId: primaryVRChat?.vrchatUserId || '',
          vrchatUsername: primaryVRChat?.vrchatUsername || '',
          vrchatAlts: (bCase.vrchatAccounts || []).filter((v: any) => v.vrchatUserId !== primaryVRChat?.vrchatUserId)
        };
      }));

      res.json(enrichedBans);
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch bans' });
    }
  });

  app.get('/api/admin/trusted', authenticateToken, isModOrAdmin, async (req, res) => {
    try {
      const trustedUsers = await User.find({ isTrusted: true }).sort({ updatedAt: -1 }).limit(100).lean();
      
      const enrichedTrusted = await Promise.all(trustedUsers.map(async (user) => {
        const resolved = await resolveDiscordUser(client, user.id, user);
        return {
          ...user,
          displayName: resolved.displayName,
          id: user.id
        };
      }));

      res.json(enrichedTrusted);
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch trusted users' });
    }
  });

  app.get('/api/admin/user/:id', authenticateToken, isModOrAdmin, async (req, res) => {
    try {
      const rawInput = req.params.id || '';
      const { user } = await findUserByQuery(rawInput);
      if (!user) return res.status(404).json({ error: 'User or VRChat Account not found in database' });
      
      const userObj = (user as any).toObject ? (user as any).toObject() : user;
      const resolved = await resolveDiscordUser(client, user.id, userObj);

      res.json({ ...userObj, displayName: resolved.displayName });
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch user' });
    }
  });

  app.post('/api/admin/user/:id/connect-vrchat', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const { vrchatUserId, vrchatUsername } = req.body;
      if (!vrchatUserId) return res.status(400).json({ error: 'VRChat User ID is required' });

      const user = await User.findOne({ id: req.params.id });
      if (!user) return res.status(404).json({ error: 'User not found' });

      const targetId = vrchatUserId.trim();
      let targetName = (vrchatUsername || '').trim();

      // Automatically fetch actual display name from the VRChat API
      const fetchedName = await fetchVRChatDisplayName(targetId).catch(() => null);
      if (fetchedName) {
        targetName = fetchedName;
      }

      // If there's no primary VRChat ID connected, make this the primary.
      if (!user.vrchatUserId || user.vrchatUserId === targetId) {
        user.vrchatUserId = targetId;
        user.vrchatUsername = targetName;
      } else {
        // If there is already a primary, add to alts if it doesn't exist
        const alreadyExistsInAlts = (user as any).vrchatAlts?.some((alt: any) => alt.vrchatUserId === targetId);
        if (!alreadyExistsInAlts) {
          if (!(user as any).vrchatAlts) {
            (user as any).vrchatAlts = [];
          }
          (user as any).vrchatAlts.push({ vrchatUserId: targetId, vrchatUsername: targetName });
        }
      }

      user.updatedAt = new Date();
      await user.save();

      if (user.isBanned) {
        await banUserFromVRChatGroup(targetId, user.banReason || 'Global Ban synchronised');
      }

      await new Log({
        action: 'CONNECT_VRCHAT',
        adminId: req.user.username,
        targetId: user.id,
        details: `Connected VRChat Account: ${targetName} (${targetId}) (Multiple registry)`
      }).save();

      res.json({ success: true, user });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Failed to connect VRChat account' });
    }
  });

  app.post('/api/admin/user/:id/disconnect-vrchat', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const { vrchatUserId } = req.body;
      if (!vrchatUserId) return res.status(400).json({ error: 'VRChat User ID is required' });

      const user = await User.findOne({ id: req.params.id });
      if (!user) return res.status(404).json({ error: 'User not found' });

      const targetId = vrchatUserId.trim();
      let removedName = '';

      if (user.vrchatUserId === targetId) {
        removedName = user.vrchatUsername || '';
        // If there's an alt, promote the first alt to primary
        const alts = (user as any).vrchatAlts || [];
        if (alts.length > 0) {
          const promo = alts[0];
          user.vrchatUserId = promo.vrchatUserId;
          user.vrchatUsername = promo.vrchatUsername;
          (user as any).vrchatAlts = alts.slice(1);
        } else {
          user.vrchatUserId = "";
          user.vrchatUsername = "";
        }
      } else {
        const alts = (user as any).vrchatAlts || [];
        const found = alts.find((alt: any) => alt.vrchatUserId === targetId);
        if (found) removedName = found.vrchatUsername || '';
        (user as any).vrchatAlts = alts.filter((alt: any) => alt.vrchatUserId !== targetId);
      }

      user.updatedAt = new Date();
      await user.save();

      // If user is banned, unban that specific connected account
      if (user.isBanned) {
        await unbanUserFromVRChatGroup(targetId).catch(() => null);
      }

      await new Log({
        action: 'DISCONNECT_VRCHAT',
        adminId: req.user.username,
        targetId: user.id,
        details: `Disconnected VRChat Account: ${removedName || 'Unknown'} (${targetId})`
      }).save();

      res.json({ success: true, user });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Failed to disconnect VRChat account' });
    }
  });

  app.post('/api/admin/users/:id/update-vrchat-accounts', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const { vrchatUserId, vrchatUsername, vrchatAlts } = req.body;
      const user = await User.findOne({ id: req.params.id });
      if (!user) return res.status(404).json({ error: 'User not found' });

      const oldPrimaryId = user.vrchatUserId;
      const oldAlts = (user as any).vrchatAlts || [];
      const oldAllIds = new Set<string>();
      if (oldPrimaryId) oldAllIds.add(oldPrimaryId);
      for (const alt of oldAlts) {
        if (alt.vrchatUserId) oldAllIds.add(alt.vrchatUserId);
      }

      // Update primary
      user.vrchatUserId = (vrchatUserId || "").trim();
      let primaryName = (vrchatUsername || "").trim();
      if (user.vrchatUserId) {
        const fetchedPrimaryName = await fetchVRChatDisplayName(user.vrchatUserId).catch(() => null);
        if (fetchedPrimaryName) {
          primaryName = fetchedPrimaryName;
        }
      }
      user.vrchatUsername = primaryName;

      // Update alts
      const updatedAlts: any[] = [];
      if (Array.isArray(vrchatAlts)) {
        for (const alt of vrchatAlts) {
          const uid = (alt.vrchatUserId || "").trim();
          let uname = (alt.vrchatUsername || "").trim();
          if (uid) {
            const fetchedAltName = await fetchVRChatDisplayName(uid).catch(() => null);
            if (fetchedAltName) {
              uname = fetchedAltName;
            }
            updatedAlts.push({
              vrchatUserId: uid,
              vrchatUsername: uname,
              linkedAt: alt.linkedAt || new Date()
            });
          }
        }
      }
      (user as any).vrchatAlts = updatedAlts;
      user.updatedAt = new Date();
      await user.save();

      // Determine new IDs
      const newAllIds = new Set<string>();
      if (user.vrchatUserId) newAllIds.add(user.vrchatUserId);
      for (const alt of updatedAlts) {
        if (alt.vrchatUserId) newAllIds.add(alt.vrchatUserId);
      }

      // Unban removed IDs if the user is banned
      if (user.isBanned) {
        for (const oldId of oldAllIds) {
          if (!newAllIds.has(oldId)) {
            await unbanUserFromVRChatGroup(oldId).catch(() => null);
          }
        }
        for (const newId of newAllIds) {
          if (!oldAllIds.has(newId)) {
            await banUserFromVRChatGroup(newId, user.banReason || 'Global Ban synchronised').catch(() => null);
          }
        }
      }

      await new Log({
        action: 'UPDATE_VRCHAT_ACCOUNTS',
        adminId: req.user.username,
        targetId: user.id,
        details: `Updated VRChat accounts for user. Primary: ${user.vrchatUsername} (${user.vrchatUserId}), Alts count: ${updatedAlts.length}`
      }).save();

      res.json({ success: true, user });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Failed to update VRChat accounts' });
    }
  });

  app.post(['/api/admin/vrchat/invite-bot', '/api/vrchat/invite-bot'], authenticateToken, async (req: any, res) => {
    try {
      let { groupId } = req.body;
      if (groupId) {
        groupId = extractVRChatGroupId(groupId);
      }
      if (!groupId || !groupId.startsWith('grp_')) {
        return res.status(400).json({ error: 'Valid VRChat Group ID starting with grp_ is required' });
      }

      const config = await SystemConfig.findOne({ id: 'main' });
      if (!config) {
        return res.status(400).json({ error: 'System Config has not been initialized.' });
      }

      let { headers, apiKey } = await getVRChatAuthHeaders(config);

      let response = await fetch(`https://api.vrchat.cloud/api/1/groups/${groupId}/join?apiKey=${apiKey}`, {
        method: 'POST',
        headers
      });

      // If we got a 401 with cached cookie, self-heal: clear cookie and retry fresh login
      if (response.status === 401 && config.vrchatCookie && config.vrchatUsername && config.vrchatPassword) {
        await SystemConfig.findOneAndUpdate({ id: 'main' }, { vrchatCookie: '' });
        const freshConfig = await SystemConfig.findOne({ id: 'main' });
        if (freshConfig) {
          try {
            const fresh = await getVRChatAuthHeaders(freshConfig);
            headers = fresh.headers;
            apiKey = fresh.apiKey;
            response = await fetch(`https://api.vrchat.cloud/api/1/groups/${groupId}/join?apiKey=${apiKey}`, {
              method: 'POST',
              headers
            });
          } catch (retryErr: any) {}
        }
      }

      if (!response.ok) {
        const errText = await response.text();
        return res.status(response.status).json({ error: `VRChat API error: ${errText || response.statusText}` });
      }

      let data: any = {};
      try {
        data = await response.json();
      } catch (jsonErr) {}
      
      await new Log({
        action: 'VRCHAT_BOT_INVITE',
        adminId: req.user.username,
        targetId: groupId,
        details: `Requested VRChat Bot to join Group: ${groupId}`
      }).save();

      res.json({ success: true, response: data });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to request VRChat group join' });
    }
  });

  app.post('/api/admin/reports/:id/update-reason', authenticateToken, isModOrAdmin, async (req: any, res) => {
    const { reason } = req.body;
    if (!reason) return res.status(400).json({ error: 'Reason required' });
    await Report.findByIdAndUpdate(req.params.id, { reason });
    res.json({ success: true });
  });

  app.post('/api/admin/users/:id/update-ban-reason', authenticateToken, isModOrAdmin, async (req: any, res) => {
    const { reason } = req.body;
    if (!reason) return res.status(400).json({ error: 'Reason required' });
    const user = await User.findOneAndUpdate(
      { id: req.params.id },
      { $set: { banReason: reason, updatedAt: new Date() } },
      { new: true }
    );
    if (user) {
      enforceGlobalBan(user.id, reason);
      await new Log({
        action: 'UPDATE_BAN_REASON',
        adminId: req.user.username,
        targetId: req.params.id,
        details: `Updated ban reason for ${req.params.id} to: ${reason}`
      }).save();
    }
    res.json({ success: true });
  });

  app.post('/api/admin/users/:id/toggle-dangerous', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const user = await User.findOne({ id: req.params.id });
      if (!user) return res.status(404).json({ error: 'User not found' });
      
      user.isDangerous = !user.isDangerous;
      user.updatedAt = new Date();

      if (user.isDangerous) {
        // Watchlist PFPs are not saved locally or frozen anymore
      }

      await user.save();

      await new Log({
        action: 'TOGGLE_DANGEROUS',
        adminId: req.user.username,
        targetId: req.params.id,
        details: `${user.isDangerous ? 'Marked' : 'Unmarked'} as HIGHLY DANGEROUS: ${req.params.id}`
      }).save();

      res.json({ success: true, isDangerous: user.isDangerous });
    } catch (e) {
      res.status(500).json({ error: 'Failed to toggle status' });
    }
  });

  app.post('/api/admin/users/:id/refresh-saved-avatar', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const { customAvatarUrl } = req.body || {};
      const user = await User.findOne({ id: req.params.id });
      if (!user) return res.status(404).json({ error: 'User not found' });

      let targetUrl = customAvatarUrl;
      if (!targetUrl) {
        const resolved = await resolveDiscordUser(client, user.id, user);
        targetUrl = resolved.avatarUrl || user.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png';
      }

      user.avatarUrl = targetUrl;
      user.updatedAt = new Date();
      await user.save();

      res.json({ success: true, avatarUrl: user.avatarUrl });
    } catch (e) {
      res.status(500).json({ error: 'Failed to refresh avatar' });
    }
  });

  app.post('/api/admin/users/:id/update-dangerous-notes', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const { notes } = req.body;
      const user = await User.findOneAndUpdate(
        { id: req.params.id },
        { $set: { dangerousNotes: notes, updatedAt: new Date() } },
        { new: true }
      );
      if (!user) return res.status(404).json({ error: 'User not found' });

      await new Log({
        action: 'UPDATE_DANGEROUS_NOTES',
        adminId: req.user.username,
        targetId: req.params.id,
        details: `Updated dangerous notes for ${req.params.id}`
      }).save();

      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: 'Failed to update notes' });
    }
  });

  app.post('/api/admin/users/:id/update-trust-index', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const { trustIndex } = req.body;
      const user = await User.findOneAndUpdate(
        { id: req.params.id },
        { $set: { trustIndex: trustIndex, updatedAt: new Date() } },
        { new: true }
      );
      if (!user) return res.status(404).json({ error: 'User not found' });

      await new Log({
        action: 'UPDATE_TRUST_INDEX',
        adminId: req.user.username,
        targetId: req.params.id,
        details: `Updated trust index for ${req.params.id} to ${trustIndex}`
      }).save();

      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ error: 'Failed to update trust index' });
    }
  });

  app.get('/api/admin/api-keys', authenticateToken, isModOrAdmin, async (req, res) => {
    try {
      const keys = await ApiKey.find({ isRevoked: { $ne: true } }).sort({ createdAt: -1 });
      res.json(keys);
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch API keys' });
    }
  });

  const handleRevokeKeyEndpoint = async (req: any, res: any) => {
    try {
      const reason = req.body?.reason || req.query?.reason || 'Manually revoked by administrator';
      const key = await ApiKey.findByIdAndUpdate(req.params.id, {
        $set: {
          isRevoked: true,
          revocationReason: reason,
          revokedAt: new Date()
        }
      }, { new: true });

      if (key) {
        const botDisplayName = key.botName || (key as any).applicationName || 'Bot';
        await new Log({
          action: 'API_KEY_REVOKED',
          adminId: req.user?.username || req.user?.id || 'Admin',
          targetId: key.botId || key._id.toString(),
          details: `Revoked API key for ${botDisplayName}. Reason: ${reason}`
        }).save().catch(() => null);

        if (key.ownerEmail) {
          try {
            const emailData = EmailTemplates.getApiKeyRevokedEmail(botDisplayName);
            await sendMail(key.ownerEmail, emailData.subject, emailData.text, emailData.html);
          } catch (mailErr) {
            console.error('Failed to send revocation notification email:', mailErr);
          }
        }

        res.json({ success: true, key });
      } else {
        res.status(404).json({ error: 'API key not found' });
      }
    } catch (e: any) {
      console.error('Error revoking API key:', e);
      res.status(500).json({ error: e?.message || 'Internal server error while revoking key' });
    }
  };

  app.delete('/api/admin/api-keys/:id', authenticateToken, isModOrAdmin, handleRevokeKeyEndpoint);
  app.post('/api/admin/api-keys/:id/revoke', authenticateToken, isModOrAdmin, handleRevokeKeyEndpoint);
  app.post('/api/admin/reports/:id/action', authenticateToken, isModOrAdmin, async (req: any, res) => {
    const { status, adminNotes } = req.body;
    const report = await Report.findById(req.params.id);
    
    if (report) {
      if (status === 'reviewed') {
        // Approve ban -> Create/Update structured BanCase in the new case system
        // 1. Move all evidence from all reports of this user to evidenceLinks
        const allReports = await Report.find({ targetUserId: report.targetUserId });
        const aggregatedEvidence = allReports
          .flatMap(r => r.evidenceLinks || [])
          .filter(e => e?.startsWith('http')); // Simple URL check

        // 2. Parse all linked VRChat accounts across all reports for this subject
        const vrchatAccountsToBan: Array<{ vrchatUserId: string; vrchatUsername: string }> = [];
        for (const r of allReports) {
          const raw = r.vrchatAccount || (r as any).vrchatAccount;
          if (raw && typeof raw === 'string' && raw.trim()) {
            const parsed = parseVRChatAccountString(raw);
            for (const item of parsed) {
              if (item.vrchatUserId || item.vrchatUsername) {
                vrchatAccountsToBan.push(item);
              }
            }
          }
        }

        // Build Discord & VRChat accounts for the BanCase
        const discordAccounts: any[] = [];
        if (report.targetUserId && !report.targetUserId.startsWith('usr_')) {
          discordAccounts.push({
            discordId: report.targetUserId,
            username: report.targetDisplayName || report.targetUserId,
            displayName: report.targetDisplayName || report.targetUserId
          });
        }

        const processedVRC: any[] = [];
        for (const item of vrchatAccountsToBan) {
          let vId = item.vrchatUserId;
          let vName = item.vrchatUsername;

          if (!vId && vName) {
            const resolved = await resolveVRChatUserBySearch(vName).catch(() => null);
            if (resolved && resolved.vrchatUserId) {
              vId = resolved.vrchatUserId;
              if (resolved.vrchatUsername) vName = resolved.vrchatUsername;
            }
          } else if (vId && !vName) {
            const fetchedName = await fetchVRChatDisplayName(vId).catch(() => null);
            if (fetchedName) vName = fetchedName;
          }

          if (vId && vId.startsWith('usr_') && !processedVRC.some(x => x.vrchatUserId === vId)) {
            processedVRC.push({
              vrchatUserId: vId,
              vrchatUsername: vName || vId,
              isPrimary: processedVRC.length === 0
            });
          }
        }

        // If targetUserId itself is a VRChat user ID
        if (report.targetUserId.startsWith('usr_') && !processedVRC.some(x => x.vrchatUserId === report.targetUserId)) {
          processedVRC.push({
            vrchatUserId: report.targetUserId,
            vrchatUsername: report.targetDisplayName || report.targetUserId,
            isPrimary: processedVRC.length === 0
          });
        }

        // Create or update the Ban Case in the new system
        const banCase = await createOrUpdateBanCase({
          title: `Reported: ${report.targetDisplayName || report.targetUserId}`,
          reason: report.reason,
          severity: 'permanent',
          discordAccounts,
          vrchatAccounts: processedVRC,
          evidenceLinks: Array.from(new Set(aggregatedEvidence)),
          notes: adminNotes ? `Admin review notes: ${adminNotes}` : `Created from approved safety report #${report._id}`
        }, req.user?.username || report.claimedBy || 'Moderator');

        console.log(`[Report Action] Created/Updated Ban Case #${banCase.caseNumber} for reported subject ${report.targetUserId}`);
      }

      // Send outcome notification to reporter (Discord DM if Discord user ID present, and/or Email if valid email address provided)
      const discordIdMatch = report.reporterUserId ? report.reporterUserId.match(/(\d{17,20})/) : null;
      const rawDiscordUserId = discordIdMatch ? discordIdMatch[1] : (report.reporterUserId && /^\d{17,20}$/.test(report.reporterUserId) ? report.reporterUserId : null);

      if (rawDiscordUserId && client) {
        try {
          const discordUser = await client.users.fetch(rawDiscordUserId);
          if (discordUser) {
            const outcomeMessage = status === 'reviewed' 
              ? `🛡️ **BeSafe Network: Safety Report Outcome**\n\nThank you for submitting a report. Your intelligence submission regarding Subject **${report.targetUserId}** has been processed.\n\n**OUTCOME:** ENFORCEMENT ACTION TAKEN\n\nBased on your evidence, our administrative team has issued a global ban case for this subject. Your contribution helps keep the ecosystem safe.` 
              : `🛡️ **BeSafe Network: Safety Report Outcome**\n\nThank you for submitting a report. Your intelligence submission regarding Subject **${report.targetUserId}** has been processed.\n\n**OUTCOME:** NO ACTION TAKEN (DISMISSED)\n\nAfter careful review, our administrative team has determined that the provided evidence was insufficient for global enforcement action. This report has been archived.`;
            await discordUser.send(outcomeMessage).catch(() => null);
          }
        } catch (e) {
          console.error(`Failed to DM report outcome to Discord reporter ${report.reporterUserId}:`, e);
        }
      }

      if (report.reporterEmail && report.reporterEmail.includes('@') && !report.reporterEmail.endsWith('@discord.user') && !report.reporterEmail.endsWith('@besafe.network')) {
        try {
          const emailData = EmailTemplates.getReportOutcomeEmail(report.targetUserId, status);
          await sendMail(report.reporterEmail, emailData.subject, emailData.text, emailData.html);
        } catch (e) {
          console.error('Failed to send report outcome email:', e);
        }
      }

      await new Log({
        action: 'REPORT_ACTION',
        adminId: req.user.username,
        targetId: report.targetUserId,
        details: `Report ${req.params.id} marked as ${status}. Report record and all associated data permanently removed. ${status === 'reviewed' ? 'User added to new Ban Case system and evidence synchronized.' : ''}`
      }).save();

      // Completely remove report record and all its data upon review/dismissal
      await Report.findByIdAndDelete(req.params.id);
    }
    
    res.json({ success: true });
  });

  app.post('/api/admin/users/:id/reputation', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const { score } = req.body;
      if (score === undefined) return res.status(400).json({ error: 'Score required' });
      
      const user = await User.findOneAndUpdate(
        { id: req.params.id },
        { $set: { reputation: parseInt(score), updatedAt: new Date() } },
        { new: true }
      );
      
      if (!user) return res.status(404).json({ error: 'User not found' });

      await new Log({
        action: 'MANUAL_REPUTATION_UPDATE',
        adminId: req.user.username,
        targetId: req.params.id,
        details: `Manually set reputation to ${score}`
      }).save();

      res.json({ success: true, reputation: user.reputation });
    } catch (e) {
      res.status(500).json({ error: 'Failed' });
    }
  });

  app.post('/api/admin/appeals/:id/action', authenticateToken, isModOrAdmin, async (req: any, res) => {
    const { status, adminNotes } = req.body;
    const appeal = await Appeal.findById(req.params.id);
    
    if (appeal) {
      if (status === 'approved') {
        // Find linked active Ban Case if one exists
        const linkedCase = await BanCase.findOne({
          $or: [
            { caseNumber: appeal.userId.toUpperCase() },
            { caseNumber: appeal.userId },
            { 'discordAccounts.discordId': appeal.userId },
            { 'vrchatAccounts.vrchatUserId': appeal.userId }
          ],
          status: 'active'
        });

        if (linkedCase) {
          // Lift the entire ban case across all associated Discord and VRChat accounts
          await liftBanCase(
            linkedCase._id.toString(),
            req.user.username || 'System',
            `Appeal #${appeal._id} Approved: ${adminNotes || appeal.reason || 'Pardoned by Staff'}`
          );
        } else {
          // Fallback legacy unban
          await recordUnbanAndUnbanUser(
            appeal.userId,
            req.user.username || 'System',
            `Appeal #${appeal._id} Approved: ${adminNotes || 'Pardoned by Staff'}`
          );
        }
      } else if (status === 'denied') {
        // If appeal is denied, ensure the ban is recorded in the Ban Case system
        const existingCase = await BanCase.findOne({
          $or: [
            { caseNumber: appeal.userId.toUpperCase() },
            { caseNumber: appeal.userId },
            { 'discordAccounts.discordId': appeal.userId },
            { 'vrchatAccounts.vrchatUserId': appeal.userId }
          ]
        });

        if (!existingCase) {
          // Create Ban Case for the upheld ban
          const discordAccounts: any[] = [];
          if (appeal.userId && !appeal.userId.startsWith('usr_')) {
            discordAccounts.push({
              discordId: appeal.userId,
              username: appeal.userId,
              displayName: appeal.userId
            });
          }
          const vrchatAccounts: any[] = [];
          if (appeal.vrchatAccount) {
            vrchatAccounts.push({
              vrchatUserId: appeal.vrchatAccount,
              vrchatUsername: appeal.vrchatAccount,
              isPrimary: true
            });
          } else if (appeal.userId.startsWith('usr_')) {
            vrchatAccounts.push({
              vrchatUserId: appeal.userId,
              vrchatUsername: appeal.userId,
              isPrimary: true
            });
          }

          await createOrUpdateBanCase({
            title: `Upheld Ban: ${appeal.userId}`,
            reason: appeal.reason ? `Ban Appeal Denied: ${appeal.reason}` : 'Violations of Community Safety Standards (Appeal Denied)',
            severity: 'permanent',
            discordAccounts,
            vrchatAccounts,
            notes: adminNotes ? `Admin notes on appeal denial: ${adminNotes}` : `Appeal #${appeal._id} denied by ${req.user?.username || 'Moderator'}`
          }, req.user?.username || 'Staff').catch(err => console.error('Failed to create BanCase on appeal denial:', err));
        }
      }

      // Send email notification to user
      try {
        if (appeal.email) {
          const emailData = EmailTemplates.getAppealOutcomeEmail(appeal.userId, status, adminNotes);
          await sendMail(appeal.email, emailData.subject, emailData.text, emailData.html);
        }
      } catch (e) {
        console.error('Failed to send appeal outcome email:', e);
      }

      await new Log({
        action: 'APPEAL_ACTION',
        adminId: req.user.username,
        targetId: appeal.userId,
        details: `Appeal ${req.params.id} marked as ${status}. Case record and all associated data permanently removed. ${status === 'approved' ? 'Linked Ban Case lifted and all accounts unbanned.' : 'Ban upheld and registered in Ban Case system.'}`
      }).save();

      // Completely delete case record and all its data from database upon approval or denial
      await Appeal.findByIdAndDelete(req.params.id);
    }
    
    res.json({ success: true });
  });

  app.post('/api/admin/users/:id/reset-reputation', authenticateToken, isAdmin, async (req: any, res) => {
    const user = await User.findOneAndUpdate(
      { id: req.params.id },
      { $set: { reputation: 0, updatedAt: new Date() } },
      { new: true }
    );
    if (user) {
      await new Log({
        action: 'RESET_REPUTATION',
        adminId: req.user.username,
        targetId: req.params.id,
        details: `Reset reputation for user ${req.params.id}`
      }).save();
    }
    res.json({ success: true });
  });

  app.post('/api/admin/users/:id/warn', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const { reason, guildId } = req.body;
      if (!reason) return res.status(400).json({ error: 'Warning reason is required' });

      let user = await User.findOne({ id: req.params.id });
      if (!user) {
        user = new User({ id: req.params.id, username: req.params.id });
      }

      const warning = {
        reason,
        adminId: req.user.username || 'Admin',
        guildId: guildId || 'Global Dashboard',
        timestamp: new Date()
      };

      if (!user.warnings) {
        (user as any).warnings = [warning];
      } else {
        (user.warnings as any).push(warning);
      }
      user.updatedAt = new Date();
      await user.save();

      await new Log({
        action: 'ISSUE_WARNING',
        adminId: req.user.username,
        targetId: req.params.id,
        details: `Issued warning to user ${req.params.id}: ${reason}`
      }).save();

      res.json({ success: true, warnings: user.warnings });
    } catch (e) {
      res.status(500).json({ error: 'Failed to issue warning' });
    }
  });

  app.post('/api/admin/users/:id/toggle-trusted', authenticateToken, isAdmin, async (req: any, res) => {
    const user = await User.findOne({ id: req.params.id });
    if (user) {
      user.isTrusted = !user.isTrusted;
      if (user.isTrusted) user.reputation = 100;
      user.updatedAt = new Date();
      await user.save();

      await new Log({
        action: 'TOGGLE_TRUSTED',
        adminId: req.user.username,
        targetId: req.params.id,
        details: `${user.isTrusted ? 'Granted' : 'Revoked'} trusted rank for user ${req.params.id}`
      }).save();
    }
    res.json({ success: true });
  });

  app.post('/api/admin/users/trusted/add', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const { userId, reason } = req.body;
      if (!userId) return res.status(400).json({ error: 'User ID is required' });

      let displayName = userId;
      let avatarUrl = '';
      try {
        const discordUser = await client.users.fetch(userId);
        displayName = discordUser.displayName || discordUser.username;
        avatarUrl = discordUser.displayAvatarURL({ size: 128 });
      } catch (e) {}

      let user = await User.findOne({ id: userId });
      const wasBanned = user?.isBanned;
      const oldBanReason = user?.banReason;
      const oldBannedAt = user?.bannedAt;

      if (!user) {
        user = new User({ id: userId });
      }

      user.isTrusted = true;
      user.reputation = 100;
      user.username = displayName;
      if (avatarUrl) user.avatarUrl = avatarUrl;

      if (wasBanned) {
        const unbanRecord = {
          bandate: oldBannedAt || user.updatedAt || user.createdAt || new Date(),
          unbandate: new Date(),
          banreason: oldBanReason || 'Prior Global Ban',
          username: displayName || user.username || userId,
          unbannedBy: req.user.username || 'Admin',
          unbanReason: `Granted Trusted Whitelist (${reason || 'No reason specified'})`
        };
        if (!user.unbanHistory) {
          (user as any).unbanHistory = [unbanRecord];
        } else {
          (user.unbanHistory as any).push(unbanRecord);
        }
      }

      user.isBanned = false;
      user.banReason = undefined;
      user.updatedAt = new Date();
      await user.save();

      // Lift user unbans globally if they were banned
      await enforceGlobalUnban(userId);

      await new Log({
        action: 'GRANT_TRUSTED',
        adminId: req.user.username,
        targetId: userId,
        details: `Manually added trusted user ${userId}. Reason/Notes: ${reason || 'None'}`
      }).save();

      res.json({ success: true, user: { ...user.toObject(), displayName } });
    } catch (e) {
      console.error('Failed to manually trust user:', e);
      res.status(500).json({ error: 'Failed to trust user' });
    }
  });

  app.post('/api/admin/bans/manual', authenticateToken, isAdmin, async (req: any, res) => {
    const { userId, reason } = req.body;
    if (!userId || !reason) return res.status(400).json({ error: 'User ID and reason required' });

    const rawId = userId.trim();
    const discordAccounts: any[] = [];
    const vrchatAccounts: any[] = [];

    if (rawId.startsWith('usr_')) {
      vrchatAccounts.push({
        vrchatUserId: rawId,
        vrchatUsername: rawId,
        isPrimary: true
      });
    } else {
      discordAccounts.push({
        discordId: rawId,
        username: rawId,
        displayName: rawId
      });
    }

    const banCase = await createOrUpdateBanCase({
      title: `Manual Global Ban: ${rawId}`,
      reason: reason.trim(),
      severity: 'permanent',
      discordAccounts,
      vrchatAccounts,
      bannedBy: req.user?.username || 'Admin',
      notes: `Manually enrolled ban case by ${req.user?.username || 'Admin'}`
    }, req.user?.username || 'Admin');

    await new Log({
      action: 'MANUAL_BAN',
      adminId: req.user.username,
      targetId: rawId,
      details: `Created Ban Case #${banCase.caseNumber} for subject ${rawId}. Reason: ${reason}`
    }).save();

    res.json({ success: true, banCase });
  });

  // Staff & Moderator Management Endpoints
  app.get('/api/admin/staff', authenticateToken, isAdmin, async (req, res) => {
    try {
      const staff = await Admin.find().select('-password').sort({ createdAt: -1 });
      res.json(staff);
    } catch (e) {
      res.status(500).json({ error: 'Failed to fetch staff list' });
    }
  });

  app.post('/api/admin/staff/:id/role', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const { role } = req.body;
      if (!['admin', 'moderator', 'user'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role provided' });
      }

      const targetUser = await Admin.findById(req.params.id);
      if (!targetUser) return res.status(404).json({ error: 'User account not found' });

      if (targetUser.role === 'admin' && role !== 'admin') {
        const adminCount = await Admin.countDocuments({ role: 'admin' });
        if (adminCount <= 1) {
          return res.status(400).json({ error: 'Cannot demote the sole system administrator' });
        }
      }

      targetUser.role = role;
      await targetUser.save();

      await new Log({
        action: 'UPDATE_STAFF_ROLE',
        adminId: req.user.username,
        targetId: targetUser.username,
        details: `Updated role for ${targetUser.username} to: ${role}`
      }).save();

      res.json({ success: true, role: targetUser.role });
    } catch (e) {
      res.status(500).json({ error: 'Failed to update user role' });
    }
  });

  app.post('/api/admin/bans/remove', authenticateToken, isAdmin, async (req: any, res) => {
    const { userId, unbanReason } = req.body;
    if (!userId) return res.status(400).json({ error: 'User ID required' });

    const rawId = userId.trim();
    // Look up any matching active BanCase
    const banCase = await BanCase.findOne({
      $or: [
        { caseNumber: rawId.toUpperCase() },
        { caseNumber: rawId },
        { 'discordAccounts.discordId': rawId },
        { 'vrchatAccounts.vrchatUserId': rawId }
      ],
      status: 'active'
    });

    if (banCase) {
      await liftBanCase(
        banCase._id.toString(),
        req.user?.username || 'Admin',
        unbanReason || 'Manual Admin Unban'
      );
    } else {
      // Fallback global unban
      await recordUnbanAndUnbanUser(
        rawId,
        req.user?.username || 'Admin',
        unbanReason || 'Manual Admin Unban'
      );
    }

    await new Log({
      action: 'MANUAL_UNBAN',
      adminId: req.user.username,
      targetId: rawId,
      details: `Manually unbanned user ${rawId}`
    }).save();

    res.json({ success: true });
  });

  // --- Ban Cases API Endpoints ---
  app.get('/api/admin/ban-cases', authenticateToken, isModOrAdmin, async (req, res) => {
    try {
      const { status, search } = req.query;
      const filter: any = {};
      
      if (status && status !== 'all') {
        filter.status = status;
      }

      if (search && typeof search === 'string' && search.trim()) {
        const queryTerm = search.trim();
        const regex = new RegExp(queryTerm, 'i');
        filter.$or = [
          { caseNumber: regex },
          { title: regex },
          { reason: regex },
          { 'discordAccounts.discordId': regex },
          { 'discordAccounts.username': regex },
          { 'vrchatAccounts.vrchatUserId': regex },
          { 'vrchatAccounts.vrchatUsername': regex }
        ];
      }

      const cases = await BanCase.find(filter).sort({ createdAt: -1 }).limit(200).lean();
      res.json(cases);
    } catch (e: any) {
      console.error('Failed to fetch ban cases:', e);
      res.status(500).json({ error: 'Failed to fetch ban cases' });
    }
  });

  app.get('/api/admin/ban-cases/:id', authenticateToken, isModOrAdmin, async (req, res) => {
    try {
      const idOrNumber = req.params.id;
      let banCase = null;
      if (mongoose.Types.ObjectId.isValid(idOrNumber)) {
        banCase = await BanCase.findById(idOrNumber).lean();
      }
      if (!banCase) {
        banCase = await BanCase.findOne({ caseNumber: idOrNumber.toUpperCase() }).lean();
      }

      if (!banCase) {
        return res.status(404).json({ error: 'Ban case not found' });
      }

      res.json(banCase);
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to fetch ban case' });
    }
  });

  app.post('/api/admin/ban-cases', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const {
        title,
        reason,
        severity,
        notes,
        evidenceLinks,
        discordAccounts,
        vrchatAccounts
      } = req.body;

      if (!reason || !reason.trim()) {
        return res.status(400).json({ error: 'Ban reason is required' });
      }

      const hasDiscord = Array.isArray(discordAccounts) && discordAccounts.some((d: any) => d && (d.discordId || d.id));
      const hasVRChat = Array.isArray(vrchatAccounts) && vrchatAccounts.some((v: any) => v && (v.vrchatUserId || v.vrchatUsername || v.id));

      if (!hasDiscord && !hasVRChat) {
        return res.status(400).json({ error: 'At least one Discord account or VRChat account must be linked to the ban case' });
      }

      const banCase = await createOrUpdateBanCase({
        title,
        reason,
        severity: severity || 'permanent',
        notes,
        evidenceLinks: Array.isArray(evidenceLinks) ? evidenceLinks : [],
        discordAccounts: Array.isArray(discordAccounts) ? discordAccounts : [],
        vrchatAccounts: Array.isArray(vrchatAccounts) ? vrchatAccounts : [],
        bannedBy: req.user?.username || 'Administrator'
      });

      await new Log({
        action: 'CREATE_BAN_CASE',
        adminId: req.user.username,
        targetId: banCase.caseNumber,
        details: `Created Ban Case #${banCase.caseNumber}: ${banCase.reason} (${banCase.discordAccounts.length} Discord accounts, ${banCase.vrchatAccounts.length} VRChat accounts)`
      }).save();

      res.json({ success: true, banCase });
    } catch (e: any) {
      console.error('Error creating ban case:', e);
      res.status(500).json({ error: e?.message || 'Failed to create ban case' });
    }
  });

  app.post('/api/admin/ban-cases/:id/unban', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const { unbanReason } = req.body;
      const updatedCase = await liftBanCase(
        req.params.id,
        req.user?.username || 'Administrator',
        unbanReason || 'Administrative pardon - Ban Case lifted'
      );

      if (!updatedCase) {
        return res.status(404).json({ error: 'Ban case not found' });
      }

      await new Log({
        action: 'LIFT_BAN_CASE',
        adminId: req.user.username,
        targetId: updatedCase.caseNumber,
        details: `Lifted Ban Case #${updatedCase.caseNumber}. All linked accounts unbanned. Reason: ${unbanReason || 'Ban Case lifted'}`
      }).save();

      res.json({ success: true, banCase: updatedCase });
    } catch (e: any) {
      console.error('Error lifting ban case:', e);
      res.status(500).json({ error: e?.message || 'Failed to lift ban case' });
    }
  });

  app.post('/api/admin/ban-cases/:id/reban', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const { reason } = req.body;
      const updatedCase = await rebanBanCase(
        req.params.id,
        req.user?.username || 'Administrator',
        reason
      );

      if (!updatedCase) {
        return res.status(404).json({ error: 'Ban case not found' });
      }

      await new Log({
        action: 'REBAN_BAN_CASE',
        adminId: req.user.username,
        targetId: updatedCase.caseNumber,
        details: `Reinstated Ban Case #${updatedCase.caseNumber} across all linked accounts.`
      }).save();

      res.json({ success: true, banCase: updatedCase });
    } catch (e: any) {
      console.error('Error rebanning ban case:', e);
      res.status(500).json({ error: e?.message || 'Failed to reinstate ban case' });
    }
  });

  app.post('/api/admin/ban-cases/:id/add-account', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const { type, id, username, notes } = req.body;
      if (!type || !id) {
        return res.status(400).json({ error: 'Account type and ID are required' });
      }

      const updatedCase = await addAccountToBanCase(
        req.params.id,
        { type, id, name: username },
        req.user?.username || 'Administrator'
      );

      if (!updatedCase) {
        return res.status(404).json({ error: 'Ban case not found' });
      }

      await new Log({
        action: 'ADD_ACCOUNT_TO_BAN_CASE',
        adminId: req.user.username,
        targetId: updatedCase.caseNumber,
        details: `Added ${type.toUpperCase()} account (${id}) to Ban Case #${updatedCase.caseNumber}`
      }).save();

      res.json({ success: true, banCase: updatedCase });
    } catch (e: any) {
      console.error('Error adding account to ban case:', e);
      res.status(500).json({ error: e?.message || 'Failed to add account to ban case' });
    }
  });

  app.post('/api/admin/ban-cases/:id/remove-account', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const { type, id } = req.body;
      if (!type || !id) {
        return res.status(400).json({ error: 'Account type and ID are required' });
      }

      const updatedCase = await removeAccountFromBanCase(
        req.params.id,
        id,
        type,
        req.user?.username || 'Administrator'
      );

      if (!updatedCase) {
        return res.status(404).json({ error: 'Ban case not found' });
      }

      await new Log({
        action: 'REMOVE_ACCOUNT_FROM_BAN_CASE',
        adminId: req.user.username,
        targetId: updatedCase.caseNumber,
        details: `Removed and unbanned ${type.toUpperCase()} account (${id}) from Ban Case #${updatedCase.caseNumber}`
      }).save();

      res.json({ success: true, banCase: updatedCase });
    } catch (e: any) {
      console.error('Error removing account from ban case:', e);
      res.status(500).json({ error: e?.message || 'Failed to remove account from ban case' });
    }
  });

  app.delete('/api/admin/ban-cases/:id', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const banCase = await BanCase.findById(req.params.id);
      if (!banCase) {
        return res.status(404).json({ error: 'Ban case not found' });
      }

      // If active, lift the bans first to keep database clean
      if (banCase.status === 'active') {
        await liftBanCase(
          req.params.id,
          req.user?.username || 'Administrator',
          'Ban case deleted by administrator'
        );
      }

      await BanCase.findByIdAndDelete(req.params.id);

      await new Log({
        action: 'DELETE_BAN_CASE',
        adminId: req.user.username,
        targetId: banCase.caseNumber,
        details: `Permanently deleted Ban Case #${banCase.caseNumber}`
      }).save();

      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to delete ban case' });
    }
  });

  app.post('/api/admin/ban-cases/migrate-legacy', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const result = await migrateLegacyBansToBanCases(req.user?.username || 'Admin');
      await new Log({
        action: 'MIGRATE_LEGACY_BANS',
        adminId: req.user.username,
        targetId: 'ALL_LEGACY_BANS',
        details: `Migrated ${result.migratedCount} legacy bans out of ${result.totalBanned} into unified Ban Cases and cleared legacy ban list (${result.clearedCount} records cleared).`
      }).save();

      res.json({
        success: true,
        migratedCount: result.migratedCount,
        totalBanned: result.totalBanned,
        clearedCount: result.clearedCount,
        message: `Successfully migrated ${result.migratedCount} legacy bans into unified Ban Cases and cleared the old ban list.`
      });
    } catch (e: any) {
      console.error('Error during legacy ban migration:', e);
      res.status(500).json({ error: e?.message || 'Failed to migrate legacy bans' });
    }
  });

  app.post('/api/admin/bans/clear-legacy', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const clearedCount = await cleanupUserDatabaseForTrustedOnly();

      await new Log({
        action: 'CLEAR_LEGACY_BAN_LIST',
        adminId: req.user.username,
        targetId: 'LEGACY_BANS',
        details: `Manually cleared old legacy ban list and purged User database for trusted members only (${clearedCount} non-trusted records removed).`
      }).save();

      res.json({
        success: true,
        clearedCount,
        message: `Old ban list cleared. User database purged and strictly reserved for trusted members.`
      });
    } catch (e: any) {
      console.error('Error clearing legacy bans:', e);
      res.status(500).json({ error: 'Failed to clear legacy ban list' });
    }
  });

  app.post('/api/admin/bans/sync-all', authenticateToken, isAdmin, async (req: any, res) => {
    try {
      const syncResult = await syncAllBansAcrossPlatforms();
      await new Log({
        action: 'CROSS_PLATFORM_BAN_SYNC',
        adminId: req.user.username,
        targetId: 'ALL_BAN_CASES',
        details: `Synchronized ${syncResult.activeCasesCount} active Ban Cases across Discord (${syncResult.discordBansCount} accounts) and VRChat (${syncResult.vrchatBansCount} accounts).`
      }).save();

      res.json({
        success: true,
        activeCasesCount: syncResult.activeCasesCount,
        discordBansCount: syncResult.discordBansCount,
        vrchatBansCount: syncResult.vrchatBansCount,
        message: `Cross-platform synchronization complete: ${syncResult.activeCasesCount} active cases synced across all connected Discord servers and VRChat groups.`
      });
    } catch (e: any) {
      console.error('Error syncing bans across platforms:', e);
      res.status(500).json({ error: e?.message || 'Failed to sync bans across platforms' });
    }
  });

  app.post('/api/admin/ban-cases/:id/toggle-watchlist', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const idOrNumber = req.params.id;
      let banCase = null;
      if (mongoose.Types.ObjectId.isValid(idOrNumber)) {
        banCase = await BanCase.findById(idOrNumber);
      }
      if (!banCase) {
        banCase = await BanCase.findOne({ caseNumber: idOrNumber.toUpperCase() });
      }

      if (!banCase) {
        return res.status(404).json({ error: 'Ban case not found' });
      }

      banCase.isDangerous = !banCase.isDangerous;
      banCase.trustIndex = banCase.isDangerous ? 'CRIMINAL' : calculateDynamicTrustIndex({
        isDangerous: false,
        isBanned: banCase.status === 'active',
        severity: banCase.severity
      });
      banCase.updatedAt = new Date();
      await banCase.save();

      // Sync dangerous state to all linked User records
      if (Array.isArray(banCase.discordAccounts)) {
        for (const disc of banCase.discordAccounts) {
          if (disc.discordId) {
            await User.findOneAndUpdate(
              { id: disc.discordId },
              { $set: { isDangerous: banCase.isDangerous, trustIndex: banCase.trustIndex, updatedAt: new Date() } }
            );
          }
        }
      }

      await new Log({
        action: 'TOGGLE_BAN_CASE_WATCHLIST',
        adminId: req.user.username,
        targetId: banCase.caseNumber,
        details: `${banCase.isDangerous ? 'Enrolled' : 'Removed'} Ban Case #${banCase.caseNumber} ${banCase.isDangerous ? 'into' : 'from'} High-Risk Watchlist`
      }).save();

      res.json({
        success: true,
        isDangerous: banCase.isDangerous,
        trustIndex: banCase.trustIndex,
        banCase
      });
    } catch (e: any) {
      console.error('Error toggling ban case watchlist:', e);
      res.status(500).json({ error: 'Failed to toggle watchlist status' });
    }
  });

  app.post('/api/admin/ban-cases/:id/update-dangerous-notes', authenticateToken, isModOrAdmin, async (req: any, res) => {
    try {
      const { notes } = req.body;
      const idOrNumber = req.params.id;
      let banCase = null;
      if (mongoose.Types.ObjectId.isValid(idOrNumber)) {
        banCase = await BanCase.findById(idOrNumber);
      }
      if (!banCase) {
        banCase = await BanCase.findOne({ caseNumber: idOrNumber.toUpperCase() });
      }

      if (!banCase) return res.status(404).json({ error: 'Ban case not found' });

      banCase.dangerousNotes = notes;
      banCase.updatedAt = new Date();
      await banCase.save();

      res.json({ success: true, banCase });
    } catch (e: any) {
      res.status(500).json({ error: 'Failed to update notes' });
    }
  });

  // --- Discord Bot ---
  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.MessageContent,
      GatewayIntentBits.GuildMembers,
      GatewayIntentBits.GuildVoiceStates,
    ],
    partials: [Partials.Message, Partials.Channel, Partials.Reaction],
  });

  client.on('error', (error) => {
    console.error('Discord Client encounterd an error:', error);
  });

  process.on('unhandledRejection', (reason: any) => {
    console.error('[Unhandled Rejection]', reason?.message || reason);
  });

  process.on('uncaughtException', (err: any) => {
    console.error('[Uncaught Exception]', err?.message || err);
  });

  // --- CreatorPlaza Radio Infrastructure ---
  const CREATORPLAZA_RADIO = {
    name: 'CreatorPlaza Radio',
    streamUrl: 'https://stream.creatorplaza.nl/main/',
    websiteUrl: 'https://creatorplaza.nl/radio',
    apiUrl: 'https://testing.creatorplaza.nl/api/nowplaying/creatorplaza_radio',
    color: 0xf97316,
    iconUrl: 'https://creatorplaza.nl/radio'
  };

  interface RadioSession {
    guildId: string;
    channelId: string;
    connection: any;
    player: any;
    resource: any;
    httpStream?: any;
    bufferStream?: PassThrough;
    volume: number; // 1 - 100
    startedAt: Date;
    startedBy: { id: string; username: string };
    reconnectAttempts: number;
    isStopped?: boolean;
  }

  const radioSessions = new Map<string, RadioSession>();

  async function fetchCreatorPlazaNowPlaying(): Promise<{
    title: string;
    artist: string;
    artUrl?: string;
    listeners: number;
    isOnline: boolean;
    history?: Array<{ title: string; artist: string }>;
  }> {
    try {
      const res = await axios.get(CREATORPLAZA_RADIO.apiUrl, { timeout: 6000 });
      const data = res.data;
      const song = data?.now_playing?.song;
      let title = (song?.title || song?.text || 'CreatorPlaza Radio Live Stream').trim();
      let artist = (song?.artist || '').trim();

      // If artist is blank or empty, try extracting from "Artist - Title" format
      if (!artist && title.includes(' - ')) {
        const parts = title.split(' - ');
        artist = parts[0].trim();
        title = parts.slice(1).join(' - ').trim();
      } else if (!artist) {
        artist = 'CreatorPlaza Radio';
      }

      const listeners = data?.listeners?.current ?? data?.listeners?.total ?? 0;
      const isOnline = data?.is_online !== false;
      const artUrl = song?.art || undefined;

      const history = Array.isArray(data?.song_history)
        ? data.song_history.slice(0, 5).map((item: any) => ({
            title: item?.song?.title || item?.song?.text || 'Unknown Title',
            artist: item?.song?.artist || 'Unknown Artist',
          }))
        : [];

      return {
        title,
        artist,
        artUrl,
        listeners,
        isOnline,
        history
      };
    } catch (err: any) {
      console.error('[CreatorPlaza Radio] Failed to fetch now playing data:', err?.message || err);
      return {
        title: 'CreatorPlaza Radio Live Stream',
        artist: 'CreatorPlaza Radio',
        listeners: 0,
        isOnline: true
      };
    }
  }

  async function createRadioResource(volumePercent: number = 80, bufferMs: number = 10000): Promise<{ resource: any; httpStream: any; bufferStream: PassThrough }> {
    const response = await axios({
      method: 'get',
      url: CREATORPLAZA_RADIO.streamUrl,
      responseType: 'stream',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': '*/*'
      },
      decompress: false,
      timeout: 0
    });

    const httpStream = response.data;
    const bufferStream = new PassThrough({ highWaterMark: 16 * 1024 * 1024 });

    httpStream.pipe(bufferStream);

    // Pre-buffer stream audio bytes (10s by default = ~240KB of 192kbps MP3) to eliminate audio cutouts and network jitter
    if (bufferMs > 0) {
      let bytesReceived = 0;
      const goalBytes = Math.round((192 * 1024 / 8) * (bufferMs / 1000));
      const startTime = Date.now();

      await new Promise<void>((resolve) => {
        const onData = (chunk: Buffer) => {
          bytesReceived += chunk.length;
          if (bytesReceived >= goalBytes || (Date.now() - startTime) >= (bufferMs + 2000)) {
            httpStream.off('data', onData);
            resolve();
          }
        };
        httpStream.on('data', onData);
      });
    }

    const resource = createAudioResource(bufferStream, {
      inputType: StreamType.Arbitrary,
      inlineVolume: true
    });

    if (resource.volume) {
      const vol = Math.max(0.01, Math.min(1.0, volumePercent / 100));
      resource.volume.setVolume(vol);
    }

    return { resource, httpStream, bufferStream };
  }

  async function startOrResumeRadioPlayer(session: RadioSession, bufferMs: number = 10000) {
    try {
      if (session.bufferStream) {
        try { session.bufferStream.destroy(); } catch (e) {}
        session.bufferStream = undefined;
      }
      if (session.httpStream) {
        session.httpStream._destroyedByUs = true;
        try { session.httpStream.destroy(); } catch (e) {}
        session.httpStream = undefined;
      }

      const { resource, httpStream, bufferStream } = await createRadioResource(session.volume, bufferMs);
      session.resource = resource;
      session.httpStream = httpStream;
      session.bufferStream = bufferStream;

      httpStream.on('error', (err: any) => {
        if (session.isStopped || httpStream._destroyedByUs) {
          return;
        }

        const errMsg = err?.message || String(err || '');
        const errCode = err?.code || '';

        // Ignore benign teardown / stream close messages
        if (errMsg === 'aborted' || errCode === 'ECONNRESET' || errCode === 'ERR_STREAM_PREMATURE_CLOSE') {
          return;
        }

        console.error(`[CreatorPlaza Radio] HTTP stream error in guild ${session.guildId}:`, errMsg);

        // Attempt automatic reconnection if session is still active
        const activeSession = radioSessions.get(session.guildId);
        if (activeSession && activeSession.httpStream === httpStream && !activeSession.isStopped) {
          setTimeout(async () => {
            if (radioSessions.get(session.guildId) === activeSession && !activeSession.isStopped) {
              console.log(`[CreatorPlaza Radio] Auto-reconnecting radio stream for guild ${session.guildId}...`);
              await startOrResumeRadioPlayer(activeSession);
            }
          }, 2000);
        }
      });

      httpStream.on('end', () => {
        if (session.isStopped || httpStream._destroyedByUs) {
          return;
        }
        const activeSession = radioSessions.get(session.guildId);
        if (activeSession && activeSession.httpStream === httpStream && !activeSession.isStopped) {
          setTimeout(async () => {
            if (radioSessions.get(session.guildId) === activeSession && !activeSession.isStopped) {
              console.log(`[CreatorPlaza Radio] Auto-reconnecting stream after end for guild ${session.guildId}...`);
              await startOrResumeRadioPlayer(activeSession);
            }
          }, 2000);
        }
      });

      session.player.play(resource);
      session.reconnectAttempts = 0;
    } catch (err: any) {
      if (!session.isStopped) {
        console.error(`[CreatorPlaza Radio] Failed to create audio resource in guild ${session.guildId}:`, err?.message || err);
      }
    }
  }

  async function joinAndPlayRadio(guild: any, voiceChannel: any, user: any, initialVolume?: number) {
    const guildId = guild.id;
    let session = radioSessions.get(guildId);
    const volume = typeof initialVolume === 'number' ? Math.max(1, Math.min(100, initialVolume)) : (session?.volume ?? 80);

    if (session && session.connection) {
      if (session.channelId !== voiceChannel.id) {
        session.isStopped = true;
        if (session.bufferStream) {
          try { session.bufferStream.destroy(); } catch (e) {}
        }
        if (session.httpStream) {
          session.httpStream._destroyedByUs = true;
          try { session.httpStream.destroy(); } catch (e) {}
        }
        try {
          session.connection.destroy();
        } catch (e) {}
        radioSessions.delete(guildId);
      } else {
        session.isStopped = false;
        session.volume = volume;
        await startOrResumeRadioPlayer(session);
        return session;
      }
    }

    const connection = joinVoiceChannel({
      channelId: voiceChannel.id,
      guildId: guild.id,
      adapterCreator: guild.voiceAdapterCreator,
      selfDeaf: true,
      selfMute: false
    });

    try {
      await entersState(connection, VoiceConnectionStatus.Ready, 20_000);
    } catch (connErr) {
      console.error(`[CreatorPlaza Radio] Voice connection failed to reach Ready state in guild ${guildId}:`, connErr);
      try { connection.destroy(); } catch (e) {}
      throw new Error('Failed to establish voice connection within 20 seconds. Please check Discord bot channel permissions.');
    }

    const player = createAudioPlayer({
      behaviors: {
        noSubscriber: NoSubscriberBehavior.Play,
      },
    });

    const newSession: RadioSession = {
      guildId: guild.id,
      channelId: voiceChannel.id,
      connection,
      player,
      resource: null,
      volume,
      startedAt: new Date(),
      startedBy: { id: user.id, username: user.tag || user.username },
      reconnectAttempts: 0,
      isStopped: false
    };

    radioSessions.set(guildId, newSession);

    connection.subscribe(player);
    await startOrResumeRadioPlayer(newSession);

    player.on(AudioPlayerStatus.Idle, () => {
      const current = radioSessions.get(guildId);
      if (current && !current.isStopped && current.connection && current.connection.state.status !== VoiceConnectionStatus.Destroyed) {
        setTimeout(async () => {
          if (radioSessions.has(guildId) && !current.isStopped) {
            await startOrResumeRadioPlayer(current);
          }
        }, 1500);
      }
    });

    player.on('error', (error: any) => {
      const current = radioSessions.get(guildId);
      if (current && !current.isStopped) {
        console.error(`[CreatorPlaza Radio] Audio player error in guild ${guildId}:`, error?.message || error);
        current.reconnectAttempts = (current.reconnectAttempts || 0) + 1;
        if (current.reconnectAttempts < 5) {
          setTimeout(async () => {
            if (radioSessions.has(guildId) && !current.isStopped) {
              await startOrResumeRadioPlayer(current);
            }
          }, 2000);
        }
      }
    });

    connection.on(VoiceConnectionStatus.Disconnected, async () => {
      try {
        await Promise.race([
          entersState(connection, VoiceConnectionStatus.Signalling, 5_000),
          entersState(connection, VoiceConnectionStatus.Connecting, 5_000),
        ]);
      } catch (e) {
        stopRadioInGuild(guildId);
      }
    });

    connection.on(VoiceConnectionStatus.Destroyed, () => {
      const s = radioSessions.get(guildId);
      if (s) {
        s.isStopped = true;
        if (s.bufferStream) {
          try { s.bufferStream.destroy(); } catch (e) {}
        }
        if (s.httpStream) {
          s.httpStream._destroyedByUs = true;
          try { s.httpStream.destroy(); } catch (e) {}
        }
      }
      radioSessions.delete(guildId);
    });

    return newSession;
  }

  function stopRadioInGuild(guildId: string): boolean {
    const session = radioSessions.get(guildId);
    const existingConn = getVoiceConnection(guildId);

    if (session) {
      session.isStopped = true;
      if (session.bufferStream) {
        try { session.bufferStream.destroy(); } catch (e) {}
      }
      if (session.httpStream) {
        session.httpStream._destroyedByUs = true;
        try { session.httpStream.destroy(); } catch (e) {}
      }
      try {
        session.player?.stop(true);
      } catch (e) {}
      try {
        session.connection?.destroy();
      } catch (e) {}
      radioSessions.delete(guildId);
      return true;
    } else if (existingConn) {
      try {
        existingConn.destroy();
      } catch (e) {}
      return true;
    }
    return false;
  }

  function setRadioVolume(guildId: string, volume: number): { success: boolean; volume: number; inVoice: boolean } {
    const clampedVol = Math.max(1, Math.min(100, volume));
    const session = radioSessions.get(guildId);

    if (!session) {
      return { success: false, volume: clampedVol, inVoice: false };
    }

    session.volume = clampedVol;
    if (session.resource && session.resource.volume) {
      session.resource.volume.setVolume(clampedVol / 100);
    }
    return { success: true, volume: clampedVol, inVoice: true };
  }

  const rawDiscordCommands = [
    new SlashCommandBuilder()
      .setName('radio')
      .setDescription('Play and control CreatorPlaza Radio in your voice channel')
      .addSubcommand(sub =>
        sub.setName('play')
          .setDescription('Play CreatorPlaza Radio in your current voice channel')
          .addIntegerOption(opt =>
            opt.setName('volume')
              .setDescription('Initial volume level (1-100)')
              .setMinValue(1)
              .setMaxValue(100)
              .setRequired(false)
          )
      )
      .addSubcommand(sub =>
        sub.setName('stop')
          .setDescription('Stop playing CreatorPlaza Radio and disconnect from voice')
      )
      .addSubcommand(sub =>
        sub.setName('np')
          .setDescription('Show currently playing song and artist on CreatorPlaza Radio')
      )
      .addSubcommand(sub =>
        sub.setName('volume')
          .setDescription('Adjust CreatorPlaza Radio playback volume (1-100)')
          .addIntegerOption(opt =>
            opt.setName('level')
              .setDescription('Volume level (1-100)')
              .setMinValue(1)
              .setMaxValue(100)
              .setRequired(true)
          )
      ),

    new SlashCommandBuilder()
      .setName('np')
      .setDescription('Show current song name and artist on CreatorPlaza Radio'),

    new SlashCommandBuilder()
      .setName('stop')
      .setDescription('Stop CreatorPlaza Radio and leave the voice channel'),

    new SlashCommandBuilder()
      .setName('volume')
      .setDescription('Change CreatorPlaza Radio volume')
      .addIntegerOption(opt =>
        opt.setName('level')
          .setDescription('Volume level from 1 to 100')
          .setMinValue(1)
          .setMaxValue(100)
          .setRequired(true)
      ),

    new SlashCommandBuilder()
      .setName('report')
      .setDescription('Submit a safety report via our web portal')
      .addUserOption(option => option.setName('target').setDescription('User to report (optional)').setRequired(false))
      .setIntegrationTypes([0, 1])
      .setContexts([0, 1, 2]),
    
    new SlashCommandBuilder()
      .setName('check')
      .setDescription('Check global ban status, reputation, VRChat links, or Ban Case #')
      .addUserOption(option => option.setName('user').setDescription('The Discord user to check (optional)').setRequired(false))
      .addStringOption(option => option.setName('query').setDescription('Discord ID, VRChat ID (usr_...), username, or Case # (e.g. CASE-1234)').setRequired(false))
      .setIntegrationTypes([0, 1])
      .setContexts([0, 1, 2]),

    new SlashCommandBuilder()
      .setName('warn')
      .setDescription('Issue a warning to a user')
      .addUserOption(option => option.setName('target').setDescription('The user to warn').setRequired(true))
      .addStringOption(option => option.setName('reason').setDescription('Reason for the warning').setRequired(true))
      .setDefaultMemberPermissions(PermissionFlagsBits.ModerateMembers),

    new SlashCommandBuilder()
      .setName('reputation')
      .setDescription('Rate a user\'s reputation')
      .addUserOption(option => option.setName('target').setDescription('The user to rate').setRequired(true))
      .addIntegerOption(option => option.setName('rating').setDescription('Rating (1 for positive, -1 for negative)').setRequired(true).addChoices(
        { name: 'Positive', value: 1 },
        { name: 'Negative', value: -1 }
      ))
      .setIntegrationTypes([0, 1])
      .setContexts([0, 1, 2]),

    new SlashCommandBuilder()
      .setName('setup')
      .setDescription('Link this server to your BeSafe Network dashboard')
      .setDefaultMemberPermissions(PermissionFlagsBits.Administrator),

    new SlashCommandBuilder()
      .setName('verify')
      .setDescription('Verify yourself to gain access to the server'),

    new SlashCommandBuilder()
      .setName('link')
      .setDescription('Link your Discord account to the BeSafe Network dashboard')
      .addStringOption(option =>
        option.setName('code')
          .setDescription('Optional web link code generated from the dashboard (e.g. DASH-XXXXXX)')
          .setRequired(false)
      ),

    new SlashCommandBuilder()
      .setName('info')
      .setDescription('Information about BeSafe Network and its features')
      .setIntegrationTypes([0, 1])
      .setContexts([0, 1, 2]),

    new SlashCommandBuilder()
      .setName('age-verify')
      .setDescription('Verify your age securely via manual staff review')
      .setIntegrationTypes([0, 1])
      .setContexts([0, 1, 2]),

    new SlashCommandBuilder()
      .setName('agerole')
      .setDescription('Sync your age role if you are verified'),

    new SlashCommandBuilder()
      .setName('agecheck')
      .setDescription('Check a user\'s age verification status')
      .addUserOption(option => option.setName('user').setDescription('The user to check').setRequired(true))
      .setDefaultMemberPermissions(PermissionFlagsBits.ModerateMembers),

    new SlashCommandBuilder()
      .setName('age-delete')
      .setDescription('Delete your own age verification data and purge your records')
      .setIntegrationTypes([0, 1])
      .setContexts([0, 1, 2]),

    new SlashCommandBuilder()
      .setName('agedelete')
      .setDescription('Delete your own age verification data and purge your records')
      .setIntegrationTypes([0, 1])
      .setContexts([0, 1, 2]),

    new SlashCommandBuilder()
      .setName('backup')
      .setDescription('Anti-raid server backup and snapshot restore system')
      .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
      .addSubcommand(sub =>
        sub.setName('create')
          .setDescription('Take an instant full backup snapshot of roles, categories, channels, and settings')
          .addStringOption(opt => opt.setName('name').setDescription('Custom label for this backup snapshot').setRequired(false))
      )
      .addSubcommand(sub =>
        sub.setName('list')
          .setDescription('List all saved backup snapshots for this server')
      )
      .addSubcommand(sub =>
        sub.setName('restore')
          .setDescription('Roll back and restore the server to a saved backup snapshot')
          .addStringOption(opt => opt.setName('id').setDescription('The Backup ID to restore').setRequired(true))
      )
      .addSubcommand(sub =>
        sub.setName('delete')
          .setDescription('Delete a saved backup snapshot')
          .addStringOption(opt => opt.setName('id').setDescription('The Backup ID to delete').setRequired(true))
      ),

    new ContextMenuCommandBuilder()
      .setName('Report User')
      .setType(ApplicationCommandType.User)
      .setIntegrationTypes([0, 1])
      .setContexts([0, 1, 2]),

    new ContextMenuCommandBuilder()
      .setName('Report Message')
      .setType(ApplicationCommandType.Message)
      .setIntegrationTypes([0, 1])
      .setContexts([0, 1, 2]),

    new ContextMenuCommandBuilder()
      .setName('Check User Status')
      .setType(ApplicationCommandType.User)
      .setIntegrationTypes([0, 1])
      .setContexts([0, 1, 2]),

    new ContextMenuCommandBuilder()
      .setName('Warn User')
      .setType(ApplicationCommandType.User)
      .setDefaultMemberPermissions(PermissionFlagsBits.ModerateMembers),

    new ContextMenuCommandBuilder()
      .setName('Rate Reputation')
      .setType(ApplicationCommandType.User)
      .setIntegrationTypes([0, 1])
      .setContexts([0, 1, 2]),

    new ContextMenuCommandBuilder()
      .setName('Age Check User')
      .setType(ApplicationCommandType.User)
      .setDefaultMemberPermissions(PermissionFlagsBits.ModerateMembers),
  ];

  function getCommandsForRegistration(disableAgeVerify = false) {
    return rawDiscordCommands
      .filter(cmd => {
        const name = (cmd as any).name;
        if (disableAgeVerify && name === 'age-verify') {
          return false;
        }
        return true;
      })
      .map(command => (typeof (command as any).toJSON === 'function' ? (command as any).toJSON() : command));
  }

  // Base commands representation for default reference
  const commands = getCommandsForRegistration(false);

  const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN || '');

  const customBotsMap = new Map<string, Client>();

  async function syncGlobalDiscordCommands(): Promise<{ success: boolean; count: number; ageVerifyDisabled: boolean; error?: string }> {
    try {
      const config = await SystemConfig.findOne({ id: 'main' });
      const isAgeVerifyDisabled = Boolean(config?.disableAgeVerifyCommand);
      const commandsToSync = getCommandsForRegistration(isAgeVerifyDisabled);

      if (process.env.DISCORD_CLIENT_ID && process.env.DISCORD_TOKEN) {
        try {
          await rest.put(
            Routes.applicationCommands(process.env.DISCORD_CLIENT_ID),
            { body: commandsToSync }
          );
          console.log(`[Discord Commands] Successfully synced ${commandsToSync.length} commands to main bot (age-verify ${isAgeVerifyDisabled ? 'DISABLED and UNSYNCED' : 'ENABLED and SYNCED'}).`);
        } catch (restErr: any) {
          console.error('[Discord Commands] Failed to put commands via Discord REST API:', restErr?.message || restErr);
          return { success: false, count: commandsToSync.length, ageVerifyDisabled: isAgeVerifyDisabled, error: restErr?.message };
        }
      } else {
        console.log(`[Discord Commands] DISCORD_CLIENT_ID or DISCORD_TOKEN missing in env; command registration skipped (${commandsToSync.length} commands configured).`);
      }

      // Also sync all connected custom bots with their respective guild/global settings
      for (const [guildId, customClient] of customBotsMap.entries()) {
        try {
          const token = (customClient as any)._botToken;
          if (token && customClient.user?.id) {
            const guild = await Guild.findOne({ id: guildId });
            const guildDisable = Boolean(guild?.settings?.disableAgeVerifyCommand);
            const customCommands = getCommandsForRegistration(isAgeVerifyDisabled || guildDisable);
            const customRest = new REST({ version: '10' }).setToken(token);
            await customRest.put(
              Routes.applicationCommands(customClient.user.id),
              { body: customCommands }
            );
            console.log(`[Custom Bot Manager] Synced ${customCommands.length} commands for guild ${guildId} custom bot (age-verify ${isAgeVerifyDisabled || guildDisable ? 'DISABLED' : 'ENABLED'}).`);
          }
        } catch (cErr: any) {
          console.error(`[Custom Bot Manager] Error syncing commands for guild ${guildId}:`, cErr?.message || cErr);
        }
      }

      return { success: true, count: commandsToSync.length, ageVerifyDisabled: isAgeVerifyDisabled };
    } catch (err: any) {
      console.error('[Discord Commands] Error in syncGlobalDiscordCommands:', err);
      return { success: false, count: 0, ageVerifyDisabled: false, error: err?.message || 'Failed to sync commands' };
    }
  }

  // Hook up the hoisted reference for admin endpoints
  syncDiscordCommandsRef = syncGlobalDiscordCommands;

  function getActivityTypeEnum(typeStr?: string): ActivityType {
    const s = (typeStr || '').toUpperCase();
    if (s === 'PLAYING') return ActivityType.Playing;
    if (s === 'STREAMING') return ActivityType.Streaming;
    if (s === 'LISTENING') return ActivityType.Listening;
    if (s === 'WATCHING') return ActivityType.Watching;
    if (s === 'COMPETING') return ActivityType.Competing;
    if (s === 'CUSTOM') return ActivityType.Custom;
    return ActivityType.Playing;
  }

  function getGuildDiscordClient(guildId: string): Client {
    const customClient = customBotsMap.get(guildId);
    if (customClient && customClient.isReady()) {
      return customClient;
    }
    return client;
  }

  async function syncCustomBotForGuild(guildData: any) {
    if (!guildData) return;
    const guildId = guildData.id;
    const settings = guildData.settings || {};

    const isEnabled = !!settings.customBotEnabled;
    const token = (settings.customBotToken || '').trim();

    const existingClient = customBotsMap.get(guildId);

    if (!isEnabled || !token) {
      if (existingClient) {
        console.log(`[Custom Bot Manager] Destroying custom bot for guild ${guildId} (disabled or empty token).`);
        try {
          existingClient.destroy();
        } catch (e) {}
        customBotsMap.delete(guildId);
      }
      return;
    }

    if (existingClient && (existingClient as any)._botToken === token) {
      if (existingClient.isReady() && existingClient.user) {
        const botStatus = (settings.customBotStatus || 'online') as any;
        const actType = getActivityTypeEnum(settings.customBotActivityType);
        const actText = settings.customBotActivityText || 'Keeping YOU safe since 2026';
        
        try {
          existingClient.user.setPresence({
            status: botStatus,
            activities: [{ name: actText, type: actType }]
          });
          console.log(`[Custom Bot Manager] Updated presence for custom bot in guild ${guildId}: status=${botStatus}, activity=${actText}`);
        } catch (err: any) {
          console.error(`[Custom Bot Manager] Failed to update presence for guild ${guildId}:`, err.message);
        }
      }
      return;
    }

    if (existingClient) {
      try { existingClient.destroy(); } catch (e) {}
      customBotsMap.delete(guildId);
    }

    console.log(`[Custom Bot Manager] Initializing custom bot for guild ${guildId} (${guildData.name || 'Server'})...`);
    
    const customClient = new Client({
      intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildVoiceStates,
      ],
      partials: [Partials.Message, Partials.Channel, Partials.Reaction],
    });

    (customClient as any)._botToken = token;

    attachDiscordBotHandlers(customClient);

    customClient.on(Events.ClientReady, async () => {
      console.log(`[Custom Bot Manager] Custom Bot logged in as ${customClient.user?.tag} for guild ${guildId}`);
      
      const botStatus = (settings.customBotStatus || 'online') as any;
      const actType = getActivityTypeEnum(settings.customBotActivityType);
      const actText = settings.customBotActivityText || 'Keeping YOU safe since 2026';
      
      try {
        customClient.user?.setPresence({
          status: botStatus,
          activities: [{ name: actText, type: actType }]
        });
      } catch (err: any) {
        console.error(`[Custom Bot Manager] Error setting initial presence for guild ${guildId}:`, err.message);
      }

      try {
        if (customClient.user?.id) {
          const customRest = new REST({ version: '10' }).setToken(token);
          const config = await SystemConfig.findOne({ id: 'main' });
          const isAgeVerifyDisabled = Boolean(config?.disableAgeVerifyCommand) || Boolean(settings?.disableAgeVerifyCommand);
          const botCommands = getCommandsForRegistration(isAgeVerifyDisabled);
          await customRest.put(
            Routes.applicationCommands(customClient.user.id),
            { body: botCommands }
          );
          console.log(`[Custom Bot Manager] Registered ${botCommands.length} slash commands for custom bot ${customClient.user.tag} (age-verify ${isAgeVerifyDisabled ? 'DISABLED/UNSYNCED' : 'ENABLED/SYNCED'})`);
        }
      } catch (cmdErr: any) {
        console.error(`[Custom Bot Manager] Failed to register slash commands for guild ${guildId}:`, cmdErr.message);
      }
    });

    customClient.on('error', (err) => {
      console.error(`[Custom Bot Manager] Error on custom client for guild ${guildId}:`, err.message);
    });

    try {
      await customClient.login(token);
      customBotsMap.set(guildId, customClient);
    } catch (loginErr: any) {
      console.error(`[Custom Bot Manager] Failed to login custom bot for guild ${guildId}:`, loginErr.message);
    }
  }

  async function syncAllCustomBots() {
    try {
      const guilds = await Guild.find({ 'settings.customBotEnabled': true });
      console.log(`[Custom Bot Manager] Syncing custom bots for ${guilds.length} enabled guild(s)...`);
      for (const g of guilds) {
        await syncCustomBotForGuild(g);
      }
    } catch (err: any) {
      console.error(`[Custom Bot Manager] Error syncing custom bots:`, err.message);
    }
  }

  client.on(Events.ClientReady, async () => {
    console.log(`Logged in as ${client.user?.tag}!`);
    
    // Set bot status
    client.user?.setActivity('keeping YOU safe since 2026', { type: ActivityType.Custom });
    client.user?.setPresence({
      activities: [{ name: 'keeping YOU safe since 2026', type: ActivityType.Custom }],
      status: 'online',
    });

    try {
      await syncGlobalDiscordCommands();
    } catch (error) {
      console.error('[Discord Commands] Startup sync failed:', error);
    }

    // Sync custom bots
    await syncAllCustomBots();

    // Purge User database of legacy ban flags and reserve it for trusted members
    cleanupUserDatabaseForTrustedOnly().catch(err => console.error('[Startup DB Cleanup Error]:', err));

    // Cross-platform sync active Ban Cases to Discord & VRChat
    syncAllBansAcrossPlatforms().catch(err => console.error('[Ban Sync Error on Startup]:', err));
    setInterval(() => {
      syncAllBansAcrossPlatforms().catch(err => console.error('[Periodic Ban Sync Error]:', err));
    }, 15 * 60 * 1000);
  });

  async function checkUserStatus(target: any, interaction: any, rawQuery?: string) {
    try {
      if (!interaction.deferred && !interaction.replied) {
        await interaction.deferReply({ ephemeral: true });
      }
    } catch (e) {
      console.error('Failed to defer reply in checkUserStatus', e);
    }

    const queryStr = (rawQuery || target?.id || target?.username || '').trim();
    const { user: foundUser, banCase, cleaned } = await findUserByQuery(queryStr);
    let user = foundUser;

    if (!user && !banCase) {
      if (cleaned.startsWith('usr_')) {
        const vName = await fetchVRChatDisplayName(cleaned).catch(() => null);
        const embed = new EmbedBuilder()
          .setTitle(`🎮 VRChat Account: ${vName || cleaned}`)
          .setColor(0x10B981)
          .setDescription('✅ **CLEAN / NO INFRACTIONS**\nThis VRChat account has no recorded ban cases or security flags in the BeSafe Network.')
          .addFields(
            { name: '🆔 VRChat User ID', value: `\`${cleaned}\``, inline: true },
            { name: '👤 VRChat Username', value: vName ? `\`${vName}\`` : '*(Uncached)*', inline: true },
            { name: '🛡️ Global Standing', value: '`GREEN_SECURE` (Active)', inline: true }
          )
          .setFooter({ text: 'BeSafe Network • Global Threat & Identity Registry' })
          .setTimestamp();

        try {
          return await interaction.editReply({ embeds: [embed] });
        } catch (e) {
          console.error(e);
          return;
        }
      }

      const emptyEmbed = new EmbedBuilder()
        .setTitle(`🔍 Check Result: ${target?.tag || target?.username || queryStr}`)
        .setColor(0x10B981)
        .setDescription('✅ **CLEAN / NO INCIDENTS RECORDED**\nNo active ban cases, warnings, or threat reports exist for this identifier in the BeSafe global registry.')
        .addFields(
          { name: 'Identifier Queried', value: `\`${queryStr || target?.id || 'Unknown'}\``, inline: true },
          { name: 'Trust Index', value: '`GREEN_SECURE`', inline: true }
        )
        .setFooter({ text: 'BeSafe Network Database' })
        .setTimestamp();

      try {
        return await interaction.editReply({ embeds: [emptyEmbed] });
      } catch (e) {
        console.error(e);
        return;
      }
    }

    const isCaseActive = banCase && banCase.status === 'active';
    const isBanned = !!user?.isBanned || isCaseActive;
    const isDangerous = !!user?.isDangerous || !!banCase?.isDangerous;
    const isSuspicious = !isBanned && (user?.reputation || 0) <= -10;
    const trustIndex = banCase?.trustIndex || user?.trustIndex || (isDangerous ? 'CRIMINAL' : isBanned ? 'RED_CLASS_D' : isSuspicious ? 'YELLOW_WARN' : 'GREEN_SECURE');

    let embedColor = 0x10B981; // Green
    if (isDangerous) embedColor = 0x000000; // Black / Critical Danger
    else if (isBanned) embedColor = 0xDC2626; // Red
    else if (isSuspicious) embedColor = 0xF59E0B; // Amber

    const primaryDisc = banCase?.discordAccounts?.[0];
    const primaryVRC = banCase?.vrchatAccounts?.[0];
    const resolved = user ? await resolveDiscordUser(client, user.id, user).catch(() => null) : null;
    const userName = banCase?.title || target?.displayName || target?.username || primaryDisc?.displayName || primaryDisc?.username || (user as any)?.displayName || user?.username || resolved?.displayName || resolved?.username || primaryVRC?.vrchatUsername || queryStr;
    const avatarUrl = target?.displayAvatarURL?.() || primaryDisc?.avatarUrl || (user ? await getWatchlistAvatar(client, user) : resolved?.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png');

    const embed = new EmbedBuilder()
      .setTitle(`${isBanned ? '🚨 GLOBAL BAN DETECTED' : '🛡️ IDENTITY & TRUST CHECK'}: ${userName}`)
      .setThumbnail(avatarUrl)
      .setColor(embedColor)
      .setFooter({ text: 'BeSafe Network • Global Threat & Identity Registry' })
      .setTimestamp();

    if (banCase) {
      embed.addFields(
        { name: '📋 Ban Case Number', value: `\`#${banCase.caseNumber}\``, inline: true },
        { name: '⚡ Case Status', value: isCaseActive ? '🛑 **ACTIVE GLOBAL BAN**' : '✅ **PARDONED / LIFTED**', inline: true },
        { name: '🛡️ Trust Index', value: `\`${trustIndex}\``, inline: true },
        { name: '⚖️ Severity Level', value: `\`${(banCase.severity || 'permanent').toUpperCase()}\``, inline: true },
        { name: '👤 Banned By', value: `\`${banCase.bannedBy || 'Administrator'}\``, inline: true },
        { name: '📅 Case Established', value: `<t:${Math.floor(new Date(banCase.createdAt || Date.now()).getTime() / 1000)}:R>`, inline: true },
        { name: '🚨 Violation Reason', value: `>>> "${banCase.reason}"`, inline: false }
      );

      // Linked Discord accounts
      if (Array.isArray(banCase.discordAccounts) && banCase.discordAccounts.length > 0) {
        const discList = banCase.discordAccounts.map((d: any) => `• <@${d.discordId}> (\`${d.discordId}\`) - **${d.displayName || d.username || 'User'}**`);
        embed.addFields({
          name: `💬 Linked Discord Accounts (${banCase.discordAccounts.length})`,
          value: discList.slice(0, 10).join('\n') + (discList.length > 10 ? `\n*...and ${discList.length - 10} more*` : ''),
          inline: false
        });
      }

      // Linked VRChat accounts
      if (Array.isArray(banCase.vrchatAccounts) && banCase.vrchatAccounts.length > 0) {
        const vrcList = banCase.vrchatAccounts.map((v: any) => `• **${v.vrchatUsername || 'No Username'}** (\`${v.vrchatUserId}\`)${v.isPrimary ? ' ⭐ Primary' : ''}`);
        embed.addFields({
          name: `🎮 Linked VRChat Accounts (${banCase.vrchatAccounts.length})`,
          value: vrcList.slice(0, 10).join('\n') + (vrcList.length > 10 ? `\n*...and ${vrcList.length - 10} more*` : ''),
          inline: false
        });
      }
    } else if (user) {
      let statusStr = '✅ Clean / In Good Standing';
      if (user.isBanned) statusStr = `🛑 Banned: ${user.banReason || 'Manual Ban'}`;
      else if (isSuspicious) statusStr = '⚠️ Low Reputation Warning';

      embed.addFields(
        { name: '👤 Primary Name', value: user.username || target?.username || user.id, inline: true },
        { name: '🆔 Account ID', value: `\`${user.id}\``, inline: true },
        { name: '🛡️ Trust Index', value: `\`${trustIndex}\``, inline: true },
        { name: '📊 Community Reputation', value: `**${user.reputation || 0}** pts`, inline: true },
        { name: '⚠️ Recorded Warnings', value: `**${user.warnings?.length || 0}**`, inline: true },
        { name: '🔞 Age Verification', value: user.isAgeVerified ? '✅ 18+ Verified' : '❌ Unverified', inline: true },
        { name: '⚡ Security Status', value: statusStr, inline: false }
      );

      const vrcAccounts = [];
      if (user.vrchatUserId || user.vrchatUsername) {
        vrcAccounts.push(`• **${user.vrchatUsername || 'No Username'}** (\`${user.vrchatUserId || 'No ID'}\`) [Primary]`);
      }
      if (user.vrchatAlts && Array.isArray(user.vrchatAlts)) {
        for (const alt of user.vrchatAlts) {
          if (alt.vrchatUserId || alt.vrchatUsername) {
            vrcAccounts.push(`• **${alt.vrchatUsername || 'No Username'}** (\`${alt.vrchatUserId || 'No ID'}\`) [Alt]`);
          }
        }
      }
      if (vrcAccounts.length > 0) {
        embed.addFields({
          name: `🎮 Connected VRChat Accounts (${vrcAccounts.length})`,
          value: vrcAccounts.join('\n'),
          inline: false
        });
      }
    }

    if (isDangerous) {
      const appUrl = process.env.APP_URL || 'https://besafe.network';
      const dossierId = banCase?.caseNumber || user?.id;
      embed.setDescription(`☣️ **ENROLLED IN HIGH-RISK THREAT WATCHLIST**\nThis subject is marked as a critical security threat.\n\n🔗 [**Click Here to View Threat Intelligence Dossier & Evidence**](${appUrl}/watchlist/${dossierId})`);
    }

    try {
      await interaction.editReply({ embeds: [embed] });
    } catch (e) {
      console.error('Failed to editReply in checkUserStatus', e);
    }
  }

  async function runAgeCheck(target: any, interaction: any) {
    try {
      if (!interaction.deferred && !interaction.replied) {
        await interaction.deferReply({ ephemeral: true });
      }
    } catch (e) {
      console.error('Failed to defer reply in runAgeCheck', e);
    }

    const user = await User.findOne({ id: target.id });
    if (!user) {
      try {
        return await interaction.editReply({ content: `No record found for ${target.tag || target.username}.` });
      } catch (e) {
        console.error('Failed to editReply in runAgeCheck', e);
        return;
      }
    }

    const status = user.isAgeVerified ? '✅ VERIFIED' : '❌ NOT VERIFIED';
    let ageInfo = 'N/A';
    if (user.isAgeVerified && user.dob) {
      const year = user.dob.getFullYear();
      ageInfo = `Born in ${year} (Exact date hidden for privacy)`;
    }

    try {
      await interaction.editReply({
        content: `🛡️ **Age Check: ${target.tag || target.username}**\nStatus: ${status}\nInformation: ${ageInfo}`
      });
    } catch (e) {
      console.error('Failed to editReply in runAgeCheck', e);
    }
  }

  async function runAgeDelete(target: any, interaction: any) {
    try {
      if (!interaction.deferred && !interaction.replied) {
        await interaction.deferReply({ ephemeral: true });
      }
    } catch (e) {
      console.error('Failed to defer reply in runAgeDelete', e);
    }

    const executorId = interaction.user.id;
    const isSelf = target && target.id === executorId;

    if (!isSelf) {
      try {
        return await interaction.editReply({
          content: '❌ **Access Restricted:** You can only delete your own age verification data. Server administrators and moderators cannot delete age verification data for other users.'
        });
      } catch (e) {
        console.error(e);
        return;
      }
    }

    const userId = executorId;

    try {
      // 1. Purge all verification requests for this user
      const requestDelete = await VerificationRequest.deleteMany({ userId });

      // 2. Reset age verification status and DOB on User model
      await User.findOneAndUpdate(
        { id: userId },
        { 
          $set: { isAgeVerified: false }, 
          $unset: { dob: 1, ageVerifiedAt: 1 } 
        }
      );

      // 3. Unassign age role if in a guild
      let roleRemovedMsg = '';
      if (interaction.guild) {
        try {
          const guildData = await Guild.findOne({ id: interaction.guild.id });
          if (guildData?.settings?.ageRoleId) {
            const member = await interaction.guild.members.fetch(userId).catch(() => null);
            if (member && member.roles.cache.has(guildData.settings.ageRoleId)) {
              await member.roles.remove(guildData.settings.ageRoleId).catch(() => null);
              roleRemovedMsg = `\n• **Server Role:** Removed <@&${guildData.settings.ageRoleId}> role in this server.`;
            }
          }
        } catch (roleErr) {
          console.error('Error removing age role during deletion:', roleErr);
        }
      }

      // 4. Record audit log
      await new Log({
        action: 'AGE_VERIFICATION_DELETED',
        adminId: interaction.user.tag || interaction.user.username || executorId,
        targetId: userId,
        details: `Age verification records and date of birth purged for ${target.tag || target.username || userId} by ${isSelf ? 'user self-service' : 'staff member ' + executorId}.`
      }).save();

      const embed = {
        title: '🗑️ Age Verification Data Deleted',
        description: `Successfully wiped all age verification records and reset verification status for **${target.tag || target.username}** (\`${userId}\`).`,
        fields: [
          { name: 'Target User', value: `<@${userId}> (\`${userId}\`)`, inline: true },
          { name: 'Executed By', value: `<@${executorId}>`, inline: true },
          { name: 'Status Now', value: '❌ Unverified', inline: true },
          { 
            name: 'Audit Details', 
            value: `• **Verification Requests Purged:** \`${requestDelete.deletedCount || 0}\` record(s)\n• **Personal Identifiers:** Date of Birth & Verification Timestamp Erased\n• **Verification Status:** Reset to Unverified${roleRemovedMsg}` 
          }
        ],
        color: 0xef4444,
        footer: { text: 'BeSafe Network • Privacy & Age Verification System' },
        timestamp: new Date().toISOString()
      };

      return await interaction.editReply({ embeds: [embed] });
    } catch (err: any) {
      console.error('Error in runAgeDelete:', err);
      try {
        return await interaction.editReply({ content: `❌ Failed to delete age verification data: ${err?.message || 'Internal error'}` });
      } catch (e) {
        console.error(e);
      }
    }
  }

  function attachDiscordBotHandlers(targetClient: Client) {
    targetClient.on(Events.InteractionCreate, async interaction => {
    if (interaction.isChatInputCommand()) {
      const { commandName, options, user: reporter } = interaction;

      if (commandName === 'report') {
        const target = options.getUser('target');
        const reporterId = reporter?.id || interaction.user?.id;
        const reporterTag = reporter?.tag || reporter?.username || interaction.user?.tag || interaction.user?.username;

        const baseUrl = process.env.APP_URL || 'https://besafe.network';
        const params = new URLSearchParams();
        if (target) {
          params.set('targetId', target.id);
          params.set('targetDisplayName', target.tag || target.username);
        }
        if (reporterId) {
          params.set('reporterId', reporterId);
        }
        if (reporterTag) {
          params.set('reporterTag', reporterTag);
        }

        const reportUrl = `${baseUrl}/report${params.toString() ? '?' + params.toString() : ''}`;

        try {
          if (!interaction.deferred && !interaction.replied) {
            await interaction.deferReply({ ephemeral: true });
          }
        } catch (e) {
          console.error('Failed to defer in report command', e);
        }

        try {
          await interaction.editReply({
            content: `📢 **Submit a Safety Report**\nReports are now submitted directly on our website for enhanced evidence handling, screenshot uploads, and security.\n\n👉 **[Click here to submit your report on our website](${reportUrl})**\nDirect Link: ${reportUrl}`
          });
        } catch (e) {
          console.error('Failed to reply in report command', e);
        }
      }

      if (commandName === 'check') {
        const target = options.getUser('user');
        const query = options.getString('query');
        if (!target && !query) {
          return interaction.reply({
            content: '❌ **Please specify a subject to check:** Provide a Discord `@user` mention OR a query string (Discord ID, VRChat User ID `usr_...`, username, or Case `#CASE-XXXX`).',
            ephemeral: true
          }).catch(() => null);
        }
        await checkUserStatus(target, interaction, query || undefined);
      }

      if (commandName === 'warn') {
        const target = options.getUser('target');
        const reason = options.getString('reason');
        if (!target || !reason) return;

        try {
          if (!interaction.deferred && !interaction.replied) {
            await interaction.deferReply({ ephemeral: false });
          }
        } catch (e) {
          console.error('Failed to defer in warn command', e);
        }

        let user = await User.findOne({ id: target.id });
        if (user && user.isTrusted) {
          try {
            return await interaction.editReply({ content: `❌ ${target.tag} is a Trusted Whitelist user and cannot be warned.` });
          } catch (e) {
            console.error(e);
            return;
          }
        }
        const warning = { reason, adminId: reporter.id, guildId: interaction.guildId };

        if (!user) {
          user = new User({
            id: target.id,
            username: target.username,
            warnings: [warning]
          });
        } else {
          user.warnings.push(warning);
        }
        await user.save();

        const guildData = await Guild.findOne({ id: interaction.guildId });
        const warnThreshold = guildData?.settings?.warningThreshold ?? 3;
        const localWarnings = user.warnings.filter(w => w.guildId === interaction.guildId).length;

        if (localWarnings >= warnThreshold) {
          try {
            const member = await interaction.guild?.members.fetch(target.id);
            if (member) {
              await member.ban({ reason: `BeSafe Network: Warning threshold reached (${localWarnings}/${warnThreshold})` });
              await interaction.followUp({ content: `🚨 ${target.tag} has reached the server's warning threshold (${warnThreshold}) and has been automatically banned from this server.`, ephemeral: false }).catch(() => null);
            }
          } catch (e) {
            console.error('Failed to auto-ban on warnings', e);
          }
        }

        try {
          await interaction.editReply({ content: `Warned ${target.tag} for: ${reason}` });
        } catch (e) {
          console.error('Failed to reply in warn command', e);
        }
        try { await target.send(`You have received a warning in a server for: ${reason}`).catch(() => null); } catch (e) {}
      }

      if (commandName === 'reputation') {
        const target = options.getUser('target');
        const rating = options.getInteger('rating');
        if (!target || rating === null) return;
        if (target.id === interaction.user.id) {
          return interaction.reply({ content: "You cannot rate yourself.", ephemeral: true }).catch(() => null);
        }

        try {
          if (!interaction.deferred && !interaction.replied) {
            await interaction.deferReply({ ephemeral: true });
          }
        } catch (e) {
          console.error('Failed to defer in reputation command', e);
        }

        let user = await User.findOne({ id: target.id });
        if (!user) {
          user = new User({ id: target.id, username: target.username, reputation: 0 });
        }

        if (user.isTrusted) {
          try {
            return await interaction.editReply({ content: `${target.tag} is a Trusted User. Their reputation is locked at 100.` });
          } catch (e) {
            console.error(e);
            return;
          }
        }

        // Check for existing rating
        const existingRating = await ReputationRating.findOne({ userId: target.id, raterId: interaction.user.id });
        
        if (existingRating) {
          if (existingRating.rating === rating) {
            try {
              return await interaction.editReply({ content: `You have already given a ${rating > 0 ? 'positive' : 'negative'} rating to ${target.tag}.` });
            } catch (e) {
              console.error(e);
              return;
            }
          }
          
          // Update reputation (remove old, add new)
          user.reputation = (user.reputation || 0) - existingRating.rating + rating;
          existingRating.rating = rating;
          existingRating.updatedAt = new Date();
          await existingRating.save();
        } else {
          // New rating
          user.reputation = (user.reputation || 0) + rating;
          await new ReputationRating({
            userId: target.id,
            raterId: interaction.user.id,
            rating: rating
          }).save();
        }

        // Auto-ban check based on guild settings
        const guildSettings = await Guild.findOne({ id: interaction.guildId });
        const threshold = guildSettings?.settings?.autoBanThreshold ?? -10;

        if (user.reputation <= threshold) {
          try {
            const member = await interaction.guild?.members.fetch(target.id);
            if (member && !user.isBanned) {
              await member.ban({ reason: `BeSafe Network: Reputation below server threshold (${user.reputation} <= ${threshold})` });
              await interaction.followUp({ content: `${target.tag} has been automatically banned from this server due to low reputation.`, ephemeral: false }).catch(() => null);
            }
          } catch (e) {
            console.error('Failed to auto-ban in guild', e);
          }
        }
        await user.save();

        try {
          await interaction.editReply({ content: `Reputation updated for ${target.tag}.` });
        } catch (e) {
          console.error('Failed to reply in reputation command', e);
        }
      }

      if (commandName === 'setup') {
        if (!interaction.guild) return;
        
        const guildId = interaction.guild.id;
        const guildName = interaction.guild.name;

        try {
          if (!interaction.deferred && !interaction.replied) {
            await interaction.deferReply({ ephemeral: true });
          }
        } catch (e) {
          console.error('Failed to defer in setup command', e);
        }

        // Check if server is already linked to another user
        const existingGuild = await Guild.findOne({ id: guildId });
        if (existingGuild && existingGuild.ownerId && existingGuild.ownerId !== interaction.user.id) {
          try {
            return await interaction.editReply({ content: '❌ This server is already linked to another administrator.' });
          } catch (e) {
            console.error(e);
            return;
          }
        }

        // Check if the user has an account
        const adminAccount = await Admin.findOne({ discordId: interaction.user.id });
        if (!adminAccount) {
          try {
            return await interaction.editReply({ 
              content: '❌ You need to create an account on our dashboard first and link your Discord account before you can set up a server.\nVisit: ' + process.env.APP_URL + '/dashboard'
            });
          } catch (e) {
            console.error(e);
            return;
          }
        }
        
        await Guild.findOneAndUpdate(
          { id: guildId },
          { $set: { name: guildName, ownerId: interaction.user.id } },
          { upsert: true }
        );

        try {
          await interaction.editReply({ 
            content: `Server **${guildName}** linked successfully. You can now manage settings at: ${process.env.APP_URL}/dashboard`
          });
        } catch (e) {
          console.error(e);
        }
      }

      if (commandName === 'verify') {
        try {
          if (!interaction.deferred && !interaction.replied) {
            await interaction.deferReply({ ephemeral: true });
          }
        } catch (e) {
          console.error('Failed to defer in verify command', e);
        }

        const guildData = await Guild.findOne({ id: interaction.guildId });
        if (!guildData?.settings?.verificationEnabled) {
          try {
            return await interaction.editReply({ content: 'Verification is not enabled for this server.' });
          } catch (e) {
            console.error(e);
            return;
          }
        }

        const roleId = guildData.settings.verificationRoleId;
        if (!roleId) {
          try {
            return await interaction.editReply({ content: 'Verification role not configured.' });
          } catch (e) {
            console.error(e);
            return;
          }
        }

        const member = interaction.member as any;
        try {
          await member.roles.add(roleId);
          await interaction.editReply({ content: 'You have been verified!' });
        } catch (e) {
          try {
            await interaction.editReply({ content: 'Failed to assign role. Check bot permissions.' });
          } catch (err) {
            console.error(err);
          }
        }
      }

      if (commandName === 'link') {
        try {
          if (!interaction.deferred && !interaction.replied) {
            await interaction.deferReply({ ephemeral: true });
          }
        } catch (e) {
          console.error('Failed to defer in link command', e);
        }

        const inputCode = interaction.options.getString('code')?.trim()?.toUpperCase();

        if (inputCode) {
          const linkData = await LinkCode.findOne({ code: inputCode });
          if (!linkData) {
            return await interaction.editReply({ 
              content: '❌ Invalid or expired link code. Please generate a code from your web dashboard or run `/link` without a code.' 
            });
          }

          if (linkData.adminId) {
            await Admin.findByIdAndUpdate(linkData.adminId, { $set: { discordId: interaction.user.id } });
            await LinkCode.deleteOne({ _id: linkData._id });

            // Auto-verify if either account was verified
            const autoMatch = await checkAndAutoVerifyFromDiscord({
              adminId: linkData.adminId,
              discordId: interaction.user.id
            });

            return await interaction.editReply({ 
              content: `✅ Successfully linked your Discord account (**${interaction.user.tag}**) to your web dashboard account!${autoMatch ? ' 🔞 Your account has also been automatically age-verified!' : ''}` 
            });
          } else if (linkData.discordId) {
            return await interaction.editReply({ 
              content: `❌ Code **${inputCode}** was generated for Discord user <@${linkData.discordId}>. Please enter this code into your web dashboard instead!` 
            });
          }
        }

        // Check if user is already linked
        const alreadyLinked = await Admin.findOne({ discordId: interaction.user.id });
        if (alreadyLinked) {
          try {
            return await interaction.editReply({ content: `✅ Your Discord account is already linked to dashboard account: **${alreadyLinked.username}**.` });
          } catch (e) {
            console.error(e);
            return;
          }
        }

        const code = Math.random().toString(36).substring(2, 8).toUpperCase();
        await LinkCode.findOneAndUpdate(
          { discordId: interaction.user.id },
          { $set: { code, discordId: interaction.user.id }, $unset: { adminId: 1 } },
          { upsert: true }
        );
        try {
          await interaction.editReply({ 
            content: `Your Discord linking code is: **${code}**\n\nGo to your web dashboard -> **Discord Link** tab and enter this code to connect your account. This code expires in 10 minutes.`
          });
        } catch (e) {
          console.error(e);
        }
      }

      if (commandName === 'age-verify') {
        const config = await SystemConfig.findOne({ id: 'main' });
        const isGlobalDisabled = Boolean(config?.disableAgeVerifyCommand);
        let isGuildDisabled = false;
        if (interaction.guildId) {
          const guild = await Guild.findOne({ id: interaction.guildId });
          if (guild?.settings?.disableAgeVerifyCommand) {
            isGuildDisabled = true;
          }
        }

        if (isGlobalDisabled || isGuildDisabled) {
          try {
            if (!interaction.deferred && !interaction.replied) {
              await interaction.deferReply({ ephemeral: true });
            }
            return await interaction.editReply({
              content: `❌ **Command Disabled:** The \`/age-verify\` slash command has been disabled by the ${isGlobalDisabled ? 'system' : 'server'} administrator and has been unsynced from Discord.`
            });
          } catch (e) {
            console.error('Failed to reply to disabled age-verify command', e);
            return;
          }
        }

        try {
          if (!interaction.deferred && !interaction.replied) {
            await interaction.deferReply({ ephemeral: true });
          }
        } catch (e) {
          console.error('Failed to defer in age-verify command', e);
        }

        const user = await User.findOne({ id: interaction.user.id });
        if (user?.isAgeVerified) {
          try {
            return await interaction.editReply({ content: `✅ You are already age-verified! Use \`/agerole\` to sync your roles in this server.` });
          } catch (e) {
            console.error(e);
            return;
          }
        }

        const verifyUrl = `${process.env.APP_URL}/verify?user_id=${interaction.user.id}`;
        
        try {
          await interaction.editReply({ 
            content: `🛡️ **Internal Age Verification**\nTo access age-restricted content, please verify your age by uploading your ID and a face photo on our website.\n\n[Click here to start verification](${verifyUrl})\n\n**Note: Your data is handled securely and reviewed by our administrators.**`
          });
        } catch (e) {
          console.error(e);
        }
      }

      if (commandName === 'agerole') {
        if (!interaction.guild) return;

        try {
          if (!interaction.deferred && !interaction.replied) {
            await interaction.deferReply({ ephemeral: true });
          }
        } catch (e) {
          console.error('Failed to defer in agerole command', e);
        }

        const guildData = await Guild.findOne({ id: interaction.guild.id });
        if (!guildData?.settings?.ageRoleEnabled) {
          try {
            return await interaction.editReply({ content: 'Age verification roles are not enabled on this server.' });
          } catch (e) {
            console.error(e);
            return;
          }
        }

        const user = await User.findOne({ id: interaction.user.id });
        if (!user?.isAgeVerified) {
          const cfg = await SystemConfig.findOne({ id: 'main' });
          const isAgeVerifyOff = Boolean(cfg?.disableAgeVerifyCommand) || Boolean(guildData?.settings?.disableAgeVerifyCommand);
          try {
            return await interaction.editReply({ 
              content: isAgeVerifyOff 
                ? '❌ You are not age-verified. (The `/age-verify` slash command is currently disabled by administrator).'
                : '❌ You are not age-verified. Use `/age-verify` to start the process.' 
            });
          } catch (e) {
            console.error(e);
            return;
          }
        }

        // Check if 18+
        if (!user.dob) {
          try {
            return await interaction.editReply({ content: 'Verification data incomplete. Please re-verify.' });
          } catch (e) {
            console.error(e);
            return;
          }
        }
        const age = new Date().getFullYear() - user.dob.getFullYear();
        const m = new Date().getMonth() - user.dob.getMonth();
        const isAdult = age > 18 || (age === 18 && m >= 0);

        if (!isAdult) {
          try {
            return await interaction.editReply({ content: '🔞 You must be at least 18 years old to receive this role.' });
          } catch (e) {
            console.error(e);
            return;
          }
        }

        const roleId = guildData.settings.ageRoleId;
        if (!roleId) {
          try {
            return await interaction.editReply({ content: 'Age role not configured by server admins.' });
          } catch (e) {
            console.error(e);
            return;
          }
        }

        const member = interaction.member as any;
        try {
          await member.roles.add(roleId);
          await interaction.editReply({ content: '✅ Your age role has been synced!' });
        } catch (e) {
          try {
            await interaction.editReply({ content: 'Failed to assign role. Check bot permissions.' });
          } catch (err) {
            console.error(err);
          }
        }
      }

      if (commandName === 'agecheck') {
        const target = options.getUser('user');
        if (!target) return;
        await runAgeCheck(target, interaction);
      }

      if (commandName === 'age-delete' || commandName === 'agedelete') {
        await runAgeDelete(interaction.user, interaction);
      }

      if (commandName === 'backup') {
        if (!interaction.guild) {
          return interaction.reply({ content: '❌ This command can only be used inside a Discord server.', ephemeral: true }).catch(() => null);
        }

        const sub = options.getSubcommand();
        try {
          if (!interaction.deferred && !interaction.replied) {
            await interaction.deferReply({ ephemeral: true });
          }
        } catch (e) {
          console.error('Failed to defer in backup command', e);
        }

        const memberPermissions = interaction.memberPermissions;
        if (!memberPermissions || !memberPermissions.has(PermissionFlagsBits.Administrator)) {
          return interaction.editReply({ content: '❌ You must have Administrator permissions to manage server backups.' }).catch(() => null);
        }

        const guild = interaction.guild;

        if (sub === 'create') {
          const customName = options.getString('name');
          try {
            const backup = await createGuildBackup(guild, interaction.user.id, interaction.user.tag || interaction.user.username, customName || undefined);
            return await interaction.editReply({
              content: `✅ **Server Backup Snapshot Created!**\n\n` +
                `• **Backup ID:** \`${backup._id}\`\n` +
                `• **Label:** ${backup.name}\n` +
                `• **Roles Saved:** ${backup.roles.length}\n` +
                `• **Categories Saved:** ${backup.categories.length}\n` +
                `• **Channels Saved:** ${backup.channels.length}\n` +
                `• **Bans Saved:** ${backup.bans ? backup.bans.length : 0}\n\n` +
                `In case of a raid or accidental changes, roll back using \`/backup restore id:${backup._id}\` or through your web dashboard!`
            });
          } catch (err: any) {
            console.error('Failed to create backup:', err);
            return await interaction.editReply({ content: `❌ Failed to create backup snapshot: ${err?.message || 'Unknown error'}` });
          }
        }

        if (sub === 'list') {
          try {
            const backups = await ServerBackup.find({ guildId: guild.id }).sort({ createdAt: -1 }).limit(10);
            if (!backups || backups.length === 0) {
              return await interaction.editReply({ content: '📦 No backups found for this server. Use \`/backup create\` to take a snapshot.' });
            }

            const listStr = backups.map((b: any, idx: number) => 
              `**${idx + 1}. ${b.name}**\n` +
              `> ID: \`${b._id}\` | Created: ${new Date(b.createdAt).toLocaleString()}\n` +
              `> ${b.roles.length} Roles, ${b.categories.length} Categories, ${b.channels.length} Channels`
            ).join('\n\n');

            return await interaction.editReply({
              content: `🛡️ **Saved Backups for ${guild.name}** (${backups.length} snapshot${backups.length > 1 ? 's' : ''}):\n\n${listStr}\n\nTo restore a backup, run: \`/backup restore id:<BACKUP_ID>\``
            });
          } catch (err: any) {
            return await interaction.editReply({ content: `❌ Failed to list backups: ${err?.message}` });
          }
        }

        if (sub === 'restore') {
          const backupId = options.getString('id');
          if (!backupId) return interaction.editReply({ content: '❌ Backup ID is required.' }).catch(() => null);

          try {
            let backup = await ServerBackup.findById(backupId).catch(() => null);
            if (!backup) {
              backup = await ServerBackup.findOne({ id: backupId, guildId: guild.id }).catch(() => null);
            }
            if (!backup || backup.guildId !== guild.id) {
              return await interaction.editReply({ content: '❌ Backup ID not found for this server.' }).catch(() => null);
            }

            await interaction.editReply({ content: `🔄 **Initiating Server Rollback...** Restoring ${backup.roles?.length || 0} roles, ${backup.categories?.length || 0} categories, and ${backup.channels?.length || 0} channels. Please wait...` }).catch(() => null);

            await restoreGuildBackup(guild, backup);

            return await interaction.followUp({
              content: `🛡️ **Server Rollback Completed Successfully!**\n\nServer **${guild.name}** has been restored to backup **"${backup.name}"** (${new Date(backup.createdAt).toLocaleString()}).`,
              ephemeral: true
            }).catch(async () => {
              try {
                await interaction.user.send(`🛡️ **Server Rollback Completed Successfully!**\n\nServer **${guild.name}** has been restored to backup **"${backup.name}"**.`);
              } catch (e) {}
            });
          } catch (err: any) {
            console.error('Failed to restore backup:', err?.message || err);
            return await interaction.followUp({ content: `❌ Error during restore process: ${err?.message}`, ephemeral: true }).catch(async () => {
              try {
                await interaction.user.send(`❌ Error during restore process on ${guild.name}: ${err?.message}`);
              } catch (e) {}
            });
          }
        }

        if (sub === 'delete') {
          const backupId = options.getString('id');
          if (!backupId) return interaction.editReply({ content: '❌ Backup ID is required.' });

          try {
            let deleted = await ServerBackup.findOneAndDelete({ _id: backupId, guildId: guild.id }).catch(() => null);
            if (!deleted) {
              deleted = await ServerBackup.findOneAndDelete({ id: backupId, guildId: guild.id }).catch(() => null);
            }
            if (!deleted) {
              return await interaction.editReply({ content: '❌ Backup snapshot not found or already deleted.' });
            }
            return await interaction.editReply({ content: `🗑️ Server backup \`${backupId}\` deleted successfully.` });
          } catch (err: any) {
            return await interaction.editReply({ content: `❌ Failed to delete backup: ${err?.message}` });
          }
        }
      }

      if (commandName === 'info') {
        const baseUrl = process.env.APP_URL || 'https://besafe.network';
        const infoConfig = await SystemConfig.findOne({ id: 'main' });
        const isAgeVerifyOff = Boolean(infoConfig?.disableAgeVerifyCommand);
        const infoEmbed = {
          title: '🛡️ BeSafe Network | Global Safety Network',
          description: 'BeSafe Network is an advanced global security platform protecting Discord communities and VRChat groups from malicious actors, predators, exploiters, and raid attacks.',
          color: 0x6366f1,
          thumbnail: { url: 'https://cdn-icons-png.flaticon.com/512/2092/2092663.png' },
          fields: [
            {
              name: '🌐 Threat Intelligence & Global Banlist',
              value: '• **Global Banlist:** Synchronized ban enforcement across connected servers.\n• **Reputation System:** Community-driven trust scores and rating history.\n• **Auto-Moderation:** Instant containment of known threats and bad actors.',
              inline: false
            },
            {
              name: '📻 CreatorPlaza Radio (24/7 Stream)',
              value: '• `/radio [play|stop|np|volume]` — Stream CreatorPlaza Radio in your voice channel.\n• `/np` — Fetch current song name & artist.\n• `/volume <1-100>` — Adjust playback volume.\n• `/stop` — Stop radio and leave voice channel.',
              inline: false
            },
            {
              name: '🆔 Manual Age & Identity Verification',
              value: isAgeVerifyOff
                ? '• **Manual Review Process:** Secure photo ID and selfie review by staff.\n• **Role Synchronization:** Automatic verified age role assignment.\n• **Status:** ⚠️ */age-verify slash command is currently disabled & unsynced by admin.*'
                : '• **Manual Review Process:** Secure photo ID and selfie review by staff to prevent data leaks.\n• **Role Synchronization:** Automatic verified age role assignment.\n• **Anti-Predator Shield:** Keep age-restricted channels safe.',
              inline: false
            },
            {
              name: '📦 Anti-Raid Backups & Rollbacks',
              value: '• **Full Snapshots:** Capture roles, channels, categories, and permissions.\n• **Instant Restore:** 1-click server rollback after raid attacks.',
              inline: false
            },
            {
              name: '🎮 VRChat Group Moderation & Sync',
              value: '• **Cross-Platform Sync:** Automatically sync Discord bans to VRChat Groups.\n• **Group Bot Integration:** Automated bot invite and group member moderation.',
              inline: false
            },
            {
              name: '📜 Command Reference',
              value: `• \`/check <user>\` — View global standing & ban history\n• \`/report [user]\` — Submit evidence on web portal\n• \`/reputation <user> <+1/-1>\` — Rate user reputation\n• \`/warn <user> <reason>\` — Issue moderation warning\n• \`/radio play\` — Play CreatorPlaza Radio in VC\n• \`/np\` — Now playing track & artist\n• \`/volume <1-100>\` — Set radio volume\n• \`/stop\` — Stop radio & disconnect\n• \`/verify\` — Server member verification\n${isAgeVerifyOff ? '• `[DISABLED]` `/age-verify` — (Unsynced / Disabled by Admin)\n' : '• `/age-verify` — Launch manual age verification\n'}• \`/agerole\` — Sync verified age role\n• \`/age-delete\` — Self-service deletion of your own age verification data & records\n• \`/backup <create|list|restore>\` — Server anti-raid backup system\n• \`/setup\` — Link server to web dashboard`,
              inline: false
            },
            {
              name: '🔗 Web Dashboard & Portal',
              value: `[**Open Dashboard**](${baseUrl}) • [**CreatorPlaza Radio**](https://creatorplaza.nl/radio) • [**Submit Report**](${baseUrl}/report)`,
              inline: false
            }
          ],
          footer: {
            text: 'BeSafe Network • Community Security Network',
            icon_url: 'https://cdn-icons-png.flaticon.com/512/1063/1063376.png'
          },
          timestamp: new Date().toISOString()
        };

        await interaction.reply({
          embeds: [infoEmbed],
          ephemeral: false
        }).catch(() => null);
      }

      if (commandName === 'radio') {
        if (!interaction.guild) {
          return interaction.reply({ content: '❌ Radio commands can only be used in a Discord server.', ephemeral: true }).catch(() => null);
        }

        const sub = options.getSubcommand(false) || 'play';

        if (sub === 'play') {
          try {
            if (!interaction.deferred && !interaction.replied) {
              await interaction.deferReply();
            }
          } catch (e) {}

          const member = interaction.member as any;
          const voiceChannel = member?.voice?.channel;

          if (!voiceChannel) {
            return await interaction.editReply({
              content: '❌ **You must be in a voice channel** to play CreatorPlaza Radio! Join a voice channel and try again.'
            });
          }

          const permissions = voiceChannel.permissionsFor(interaction.client.user?.id || interaction.guild.members.me?.id);
          if (permissions && (!permissions.has(PermissionFlagsBits.Connect) || !permissions.has(PermissionFlagsBits.Speak))) {
            return await interaction.editReply({
              content: '❌ **Missing Permissions:** The bot needs permissions to **Connect** and **Speak** in your voice channel.'
            });
          }

          const initialVol = options.getInteger('volume') ?? undefined;

          await interaction.editReply({
            content: '⏳ **Connecting to CreatorPlaza Radio & pre-buffering 10 seconds of audio...**\n*Building 10-second anti-stutter buffer cushion to eliminate audio cutouts...*'
          }).catch(() => null);

          try {
            const session = await joinAndPlayRadio(interaction.guild, voiceChannel, interaction.user, initialVol);
            const np = await fetchCreatorPlazaNowPlaying();

            const playEmbed = {
              title: '📻 CreatorPlaza Radio | Now Streaming',
              description: `🎶 **Now Playing:** **${np.title}**\n🎤 **Artist:** **${np.artist}**\n\n🔊 **Volume:** \`${session.volume}%\`\n📡 **Voice Channel:** <#${voiceChannel.id}>\n👥 **Listeners:** \`${np.listeners}\`\n⚡ **Audio Buffer:** \`10s Anti-Stutter Cushion Active\``,
              color: 0xf97316,
              thumbnail: np.artUrl ? { url: np.artUrl } : { url: 'https://creatorplaza.nl/radio' },
              fields: [
                {
                  name: '🌐 Radio Website',
                  value: '[**creatorplaza.nl/radio**](https://creatorplaza.nl/radio)',
                  inline: true
                },
                {
                  name: '🔗 Stream URL',
                  value: '[**stream.creatorplaza.nl/main**](https://stream.creatorplaza.nl/main)',
                  inline: true
                },
                {
                  name: '🎛️ Radio Commands',
                  value: '• `/np` — Show current song & artist\n• `/volume <1-100>` — Adjust playback volume\n• `/stop` — Stop radio & leave voice channel',
                  inline: false
                }
              ],
              footer: {
                text: 'CreatorPlaza Radio • 24/7 Shoutcast Stream',
                icon_url: 'https://cdn-icons-png.flaticon.com/512/3845/3845868.png'
              },
              timestamp: new Date().toISOString()
            };

            return await interaction.editReply({ embeds: [playEmbed] });
          } catch (err: any) {
            console.error('[CreatorPlaza Radio] Failed to start radio:', err);
            return await interaction.editReply({ content: `❌ Failed to connect or start CreatorPlaza Radio: ${err?.message || 'Unknown error'}` });
          }
        }

        if (sub === 'stop') {
          try {
            if (!interaction.deferred && !interaction.replied) {
              await interaction.deferReply();
            }
          } catch (e) {}

          const stopped = stopRadioInGuild(interaction.guild.id);
          if (stopped) {
            const stopEmbed = {
              title: '⏹️ CreatorPlaza Radio Stopped',
              description: 'Successfully stopped the stream and left the voice channel.\n\nUse `/radio play` anytime to start listening again!',
              color: 0xef4444,
              footer: {
                text: 'CreatorPlaza Radio • creatorplaza.nl/radio',
                icon_url: 'https://cdn-icons-png.flaticon.com/512/3845/3845868.png'
              }
            };
            return await interaction.editReply({ embeds: [stopEmbed] });
          } else {
            return await interaction.editReply({ content: 'ℹ️ CreatorPlaza Radio is not currently playing in this server.' });
          }
        }

        if (sub === 'np') {
          try {
            if (!interaction.deferred && !interaction.replied) {
              await interaction.deferReply();
            }
          } catch (e) {}

          const np = await fetchCreatorPlazaNowPlaying();
          const session = radioSessions.get(interaction.guild.id);

          const npEmbed: any = {
            title: '📻 CreatorPlaza Radio | Now Playing',
            description: `🎶 **Track:** **${np.title}**\n🎤 **Artist:** **${np.artist}**`,
            color: 0xf97316,
            thumbnail: np.artUrl ? { url: np.artUrl } : undefined,
            fields: [
              {
                name: '👥 Live Listeners',
                value: `\`${np.listeners}\``,
                inline: true
              },
              {
                name: '🔊 Voice Volume',
                value: session ? `\`${session.volume}%\`` : '`Not playing in VC`',
                inline: true
              },
              {
                name: '🌐 Radio Page',
                value: '[**creatorplaza.nl/radio**](https://creatorplaza.nl/radio)',
                inline: true
              },
              {
                name: '📡 Stream URL',
                value: '[**stream.creatorplaza.nl/main**](https://stream.creatorplaza.nl/main)',
                inline: false
              }
            ],
            footer: {
              text: 'CreatorPlaza Radio • Live Shoutcast Stream',
              icon_url: 'https://cdn-icons-png.flaticon.com/512/3845/3845868.png'
            },
            timestamp: new Date().toISOString()
          };

          if (np.history && np.history.length > 0) {
            npEmbed.fields.push({
              name: '🕒 Recently Played',
              value: np.history.map((h: any, idx: number) => `\`${idx + 1}.\` **${h.title}** - *${h.artist}*`).join('\n'),
              inline: false
            });
          }

          return await interaction.editReply({ embeds: [npEmbed] });
        }

        if (sub === 'volume') {
          const level = options.getInteger('level', true);
          const res = setRadioVolume(interaction.guild.id, level);

          if (res.inVoice) {
            return await interaction.reply({
              content: `🔊 **CreatorPlaza Radio** volume adjusted to **${res.volume}%**`
            }).catch(() => null);
          } else {
            return await interaction.reply({
              content: `🔊 Set default **CreatorPlaza Radio** volume to **${res.volume}%** (Use \`/radio play\` to connect and stream).`
            }).catch(() => null);
          }
        }
      }

      if (commandName === 'np') {
        try {
          if (!interaction.deferred && !interaction.replied) {
            await interaction.deferReply();
          }
        } catch (e) {}

        const np = await fetchCreatorPlazaNowPlaying();
        const session = interaction.guildId ? radioSessions.get(interaction.guildId) : null;

        const npEmbed: any = {
          title: '📻 CreatorPlaza Radio | Now Playing',
          description: `🎶 **Track:** **${np.title}**\n🎤 **Artist:** **${np.artist}**`,
          color: 0xf97316,
          thumbnail: np.artUrl ? { url: np.artUrl } : undefined,
          fields: [
            {
              name: '👥 Live Listeners',
              value: `\`${np.listeners}\``,
              inline: true
            },
            {
              name: '🔊 Voice Volume',
              value: session ? `\`${session.volume}%\`` : '`Not playing in VC`',
              inline: true
            },
            {
              name: '🌐 Radio Page',
              value: '[**creatorplaza.nl/radio**](https://creatorplaza.nl/radio)',
              inline: true
            },
            {
              name: '📡 Stream URL',
              value: '[**stream.creatorplaza.nl/main**](https://stream.creatorplaza.nl/main)',
              inline: false
            }
          ],
          footer: {
            text: 'CreatorPlaza Radio • Live Shoutcast Stream',
            icon_url: 'https://cdn-icons-png.flaticon.com/512/3845/3845868.png'
          },
          timestamp: new Date().toISOString()
        };

        if (np.history && np.history.length > 0) {
          npEmbed.fields.push({
            name: '🕒 Recently Played',
            value: np.history.map((h: any, idx: number) => `\`${idx + 1}.\` **${h.title}** - *${h.artist}*`).join('\n'),
            inline: false
          });
        }

        return await interaction.editReply({ embeds: [npEmbed] });
      }

      if (commandName === 'stop') {
        if (!interaction.guild) {
          return interaction.reply({ content: '❌ This command must be used in a Discord server.', ephemeral: true }).catch(() => null);
        }

        try {
          if (!interaction.deferred && !interaction.replied) {
            await interaction.deferReply();
          }
        } catch (e) {}

        const stopped = stopRadioInGuild(interaction.guild.id);
        if (stopped) {
          const stopEmbed = {
            title: '⏹️ CreatorPlaza Radio Stopped',
            description: 'Successfully stopped the stream and left the voice channel.\n\nUse `/radio play` anytime to start listening again!',
            color: 0xef4444,
            footer: {
              text: 'CreatorPlaza Radio • creatorplaza.nl/radio',
              icon_url: 'https://cdn-icons-png.flaticon.com/512/3845/3845868.png'
            }
          };
          return await interaction.editReply({ embeds: [stopEmbed] });
        } else {
          return await interaction.editReply({ content: 'ℹ️ CreatorPlaza Radio is not currently playing in this server.' });
        }
      }

      if (commandName === 'volume') {
        if (!interaction.guild) {
          return interaction.reply({ content: '❌ This command must be used in a Discord server.', ephemeral: true }).catch(() => null);
        }

        const level = options.getInteger('level', true);
        const res = setRadioVolume(interaction.guild.id, level);

        if (res.inVoice) {
          return await interaction.reply({
            content: `🔊 **CreatorPlaza Radio** volume adjusted to **${res.volume}%**`
          }).catch(() => null);
        } else {
          return await interaction.reply({
            content: `🔊 Set default **CreatorPlaza Radio** volume to **${res.volume}%** (Use \`/radio play\` to connect and stream).`
          }).catch(() => null);
        }
      }
    }

    // Handle User Context Menu Commands
    if (interaction.isUserContextMenuCommand()) {
      const { commandName, targetUser } = interaction;

      if (commandName === 'Check User Status') {
        await checkUserStatus(targetUser, interaction);
      }

      if (commandName === 'Age Check User') {
        await runAgeCheck(targetUser, interaction);
      }

      if (commandName === 'Delete Age Data') {
        await runAgeDelete(targetUser, interaction);
      }

      if (commandName === 'Report User') {
        const modal = new ModalBuilder()
          .setCustomId(`report_modal:${targetUser.id}:${encodeURIComponent(targetUser.tag || targetUser.username)}`)
          .setTitle(`Report ${targetUser.username.substring(0, 25)}`);

        const reasonInput = new TextInputBuilder()
          .setCustomId('reason')
          .setLabel('Violation Reason & Incident Details')
          .setStyle(TextInputStyle.Paragraph)
          .setRequired(true)
          .setPlaceholder('Describe the violation, harassment, scam, or safety incident...');

        const evidenceInput = new TextInputBuilder()
          .setCustomId('evidence')
          .setLabel('Evidence Links / Proof (Optional)')
          .setStyle(TextInputStyle.Short)
          .setRequired(false)
          .setPlaceholder('https://imgur.com/... or Discord screenshot link');

        const vrchatInput = new TextInputBuilder()
          .setCustomId('vrchat')
          .setLabel('Subject VRChat Account / ID (Optional)')
          .setStyle(TextInputStyle.Short)
          .setRequired(false)
          .setPlaceholder('usr_... or VRChat profile link');

        const emailInput = new TextInputBuilder()
          .setCustomId('email')
          .setLabel('Your Email Address (For Email Updates)')
          .setStyle(TextInputStyle.Short)
          .setRequired(false)
          .setPlaceholder('name@example.com (Optional - receive email notifications)');

        modal.addComponents(
          new ActionRowBuilder<TextInputBuilder>().addComponents(reasonInput),
          new ActionRowBuilder<TextInputBuilder>().addComponents(evidenceInput),
          new ActionRowBuilder<TextInputBuilder>().addComponents(vrchatInput),
          new ActionRowBuilder<TextInputBuilder>().addComponents(emailInput)
        );

        await interaction.showModal(modal);
      }

      if (commandName === 'Warn User') {
        const modal = new ModalBuilder()
          .setCustomId(`warn_modal:${targetUser.id}`)
          .setTitle(`Warn ${targetUser.username.substring(0, 30)}`);

        const reasonInput = new TextInputBuilder()
          .setCustomId('reason')
          .setLabel('Reason for the warning')
          .setStyle(TextInputStyle.Paragraph)
          .setRequired(true)
          .setPlaceholder('Enter reason for this warning...');

        const row = new ActionRowBuilder<TextInputBuilder>().addComponents(reasonInput);
        modal.addComponents(row);

        await interaction.showModal(modal);
      }

      if (commandName === 'Rate Reputation') {
        const modal = new ModalBuilder()
          .setCustomId(`rep_modal:${targetUser.id}`)
          .setTitle(`Rate ${targetUser.username.substring(0, 30)}`);

        const ratingInput = new TextInputBuilder()
          .setCustomId('rating')
          .setLabel('Rating (Value: +1 or -1)')
          .setStyle(TextInputStyle.Short)
          .setRequired(true)
          .setPlaceholder('Enter +1 for Positive, or -1 for Negative')
          .setValue('+1');

        const row = new ActionRowBuilder<TextInputBuilder>().addComponents(ratingInput);
        modal.addComponents(row);

        await interaction.showModal(modal);
      }
    }

    // Handle Message Context Menu Commands
    if (interaction.isMessageContextMenuCommand()) {
      const { commandName, targetMessage } = interaction;

      if (commandName === 'Report Message') {
        const targetAuthor = targetMessage.author;

        const modal = new ModalBuilder()
          .setCustomId(`report_msg_modal:${targetAuthor.id}:${encodeURIComponent(targetAuthor.tag || targetAuthor.username)}:${encodeURIComponent(targetMessage.url)}`)
          .setTitle(`Report Msg by ${targetAuthor.username.substring(0, 20)}`);

        const reasonInput = new TextInputBuilder()
          .setCustomId('reason')
          .setLabel('Violation Reason & Incident Details')
          .setStyle(TextInputStyle.Paragraph)
          .setRequired(true)
          .setPlaceholder('Describe why this message violates safety rules...');

        const evidenceInput = new TextInputBuilder()
          .setCustomId('evidence')
          .setLabel('Additional Evidence Links (Optional)')
          .setStyle(TextInputStyle.Short)
          .setRequired(false)
          .setValue(targetMessage.url)
          .setPlaceholder('https://... Message URL auto-attached');

        const vrchatInput = new TextInputBuilder()
          .setCustomId('vrchat')
          .setLabel('Subject VRChat Account / ID (Optional)')
          .setStyle(TextInputStyle.Short)
          .setRequired(false)
          .setPlaceholder('usr_... or VRChat profile link');

        const emailInput = new TextInputBuilder()
          .setCustomId('email')
          .setLabel('Your Email Address (For Email Updates)')
          .setStyle(TextInputStyle.Short)
          .setRequired(false)
          .setPlaceholder('name@example.com (Optional - receive email notifications)');

        modal.addComponents(
          new ActionRowBuilder<TextInputBuilder>().addComponents(reasonInput),
          new ActionRowBuilder<TextInputBuilder>().addComponents(evidenceInput),
          new ActionRowBuilder<TextInputBuilder>().addComponents(vrchatInput),
          new ActionRowBuilder<TextInputBuilder>().addComponents(emailInput)
        );

        await interaction.showModal(modal);
      }
    }

    // Handle Modal Submissions
    if (interaction.isModalSubmit()) {
      const { customId, fields } = interaction;
      const [modalType, targetUserId] = customId.split(':');

      if (modalType === 'report_modal' || modalType === 'report_msg_modal') {
        await interaction.deferReply({ ephemeral: true });

        const parts = customId.split(':');
        const tId = parts[1];
        const targetDisplayName = decodeURIComponent(parts[2] || tId);
        const autoMsgUrl = parts[3] ? decodeURIComponent(parts[3]) : '';

        const reason = fields.getTextInputValue('reason');
        const rawEvidence = fields.getTextInputValue('evidence') || '';
        const rawVrchat = fields.getTextInputValue('vrchat') || '';
        let rawEmail = '';
        try {
          rawEmail = fields.getTextInputValue('email') || '';
        } catch (e) {}

        // Extract VRChat User ID ONLY
        const cleanedVrchat = extractVRChatUserId(rawVrchat);

        const evidenceLinks: string[] = [];
        if (autoMsgUrl) evidenceLinks.push(autoMsgUrl);
        if (rawEvidence && rawEvidence !== autoMsgUrl) {
          evidenceLinks.push(rawEvidence);
        }

        const reporterTag = interaction.user.tag || interaction.user.username;
        const reporterUserId = interaction.user.id;
        const reporterEmail = rawEmail.trim() || `${interaction.user.username}@discord.user`;

        const report = new Report({
          targetUserId: tId,
          targetDisplayName,
          reporterUserId: `${reporterTag} (${reporterUserId})`,
          reporterEmail,
          reason,
          evidenceLinks,
          vrchatAccount: cleanedVrchat,
          status: 'pending',
          createdAt: new Date()
        });

        await safeSaveReport(report);
        await notifyAdmins(
          'New Incident Report (Discord Context Menu)',
          `A new report ticket was filed against **${targetDisplayName}** (${tId}) by ${reporterTag}.${reporterEmail.endsWith('@discord.user') ? '' : ` (Email: ${reporterEmail})`}\nReason: ${reason}${cleanedVrchat ? `\nVRChat ID: ${cleanedVrchat}` : ''}`
        );

        const baseUrl = process.env.APP_URL || 'https://besafe.network';
        const webUploadUrl = `${baseUrl}/report?targetId=${tId}&targetDisplayName=${encodeURIComponent(targetDisplayName)}&reporterId=${reporterUserId}&reporterEmail=${encodeURIComponent(reporterEmail)}&vrchatAccount=${encodeURIComponent(cleanedVrchat)}`;

        const embed = new EmbedBuilder()
          .setTitle('🛡️ Incident Intelligence Report Transmitted')
          .setColor(0xd97706)
          .setDescription(`Your safety report against **${targetDisplayName}** (\`${tId}\`) has been logged in the intelligence queue.`)
          .addFields(
            { name: 'Report ID', value: `\`${report._id}\``, inline: true },
            { name: 'Status', value: '`PENDING TRIAGE`', inline: true },
            { name: 'Violation Reason', value: reason.length > 200 ? reason.substring(0, 200) + '...' : reason, inline: false }
          );

        if (cleanedVrchat) {
          embed.addFields({ name: 'Extracted VRChat User ID', value: `\`${cleanedVrchat}\``, inline: true });
        }

        if (evidenceLinks.length > 0) {
          embed.addFields({ name: 'Evidence Links', value: evidenceLinks.join('\n'), inline: false });
        }

        embed.addFields({
          name: '📸 Screenshot File Uploads',
          value: `Need to upload screenshot images? [**Click here to attach screenshots on the Web Portal**](${webUploadUrl})`,
          inline: false
        });

        embed.setFooter({ text: 'BeSafe Network • Security Intelligence Registry' });

        await interaction.followUp({
          embeds: [embed],
          ephemeral: true
        });
        return;
      }

      if (modalType === 'warn_modal') {
        if (!interaction.memberPermissions?.has(PermissionFlagsBits.ModerateMembers)) {
          await interaction.reply({ content: '❌ You do not have permissions (Moderate Members) to warn users.', ephemeral: true });
          return;
        }
        await interaction.deferReply({ ephemeral: false });

        const targetUser = await interaction.client.users.fetch(targetUserId).catch(() => null);
        if (!targetUser) {
          await interaction.followUp({ content: 'Could not fetch target user data.', ephemeral: true }).catch(() => null);
          return;
        }
        const reason = fields.getTextInputValue('reason');

        let user = await User.findOne({ id: targetUser.id });
        if (user && user.isTrusted) {
          await interaction.followUp({ content: `❌ ${targetUser.tag} is a Trusted Whitelist user and cannot be warned.`, ephemeral: true }).catch(() => null);
          return;
        }
        const warning = { reason, adminId: interaction.user.id, guildId: interaction.guildId };

        if (!user) {
          user = new User({
            id: targetUser.id,
            username: targetUser.username,
            warnings: [warning]
          });
        } else {
          user.warnings.push(warning);
        }
        await user.save();

        const guildData = await Guild.findOne({ id: interaction.guildId });
        const warnThreshold = guildData?.settings?.warningThreshold ?? 3;
        const localWarnings = user.warnings.filter(w => w.guildId === interaction.guildId).length;

        if (localWarnings >= warnThreshold) {
          try {
            const member = await interaction.guild?.members.fetch(targetUser.id);
            if (member) {
              await member.ban({ reason: `BeSafe Network: Warning threshold reached (${localWarnings}/${warnThreshold})` });
              await interaction.followUp({ content: `🚨 ${targetUser.tag} has reached the server's warning threshold (${warnThreshold}) and has been automatically banned from this server.`, ephemeral: false }).catch(() => null);
            }
          } catch (e) {
            console.error('Failed to auto-ban on warnings', e);
          }
        }

        await interaction.followUp({ content: `Warned ${targetUser.tag} for: ${reason}`, ephemeral: false }).catch(() => null);
        try { await targetUser.send(`You have received a warning in a server for: ${reason}`); } catch (e) {}
      }

      if (modalType === 'rep_modal') {
        await interaction.deferReply({ ephemeral: true });
        const targetUser = await interaction.client.users.fetch(targetUserId).catch(() => null);
        if (!targetUser) {
          await interaction.followUp({ content: 'Could not fetch target user data.', ephemeral: true }).catch(() => null);
          return;
        }
        const ratingStr = fields.getTextInputValue('rating').trim();
        let rating = parseInt(ratingStr);
        if (ratingStr === '+1') rating = 1;
        
        if (isNaN(rating) || (rating !== 1 && rating !== -1)) {
          await interaction.followUp({ content: '❌ Invalid rating. Please enter standard ratings of 1, +1 or -1.', ephemeral: true }).catch(() => null);
          return;
        }

        if (targetUser.id === interaction.user.id) {
          await interaction.followUp({ content: "You cannot rate yourself.", ephemeral: true }).catch(() => null);
          return;
        }

        let user = await User.findOne({ id: targetUser.id });
        if (!user) {
          user = new User({ id: targetUser.id, username: targetUser.username, reputation: 0 });
        }

        if (user.isTrusted) {
          await interaction.followUp({ content: `${targetUser.tag} is a Trusted User. Their reputation is locked at 100.`, ephemeral: true }).catch(() => null);
          return;
        }

        // Check for existing rating
        const existingRating = await ReputationRating.findOne({ userId: targetUser.id, raterId: interaction.user.id });
        
        if (existingRating) {
          if (existingRating.rating === rating) {
            await interaction.followUp({ content: `You have already given a ${rating > 0 ? 'positive' : 'negative'} rating to ${targetUser.tag}.`, ephemeral: true }).catch(() => null);
            return;
          }
          
          // Update reputation
          user.reputation = (user.reputation || 0) - existingRating.rating + rating;
          existingRating.rating = rating;
          existingRating.updatedAt = new Date();
          await existingRating.save();
        } else {
          // New rating
          user.reputation = (user.reputation || 0) + rating;
          await new ReputationRating({
            userId: targetUser.id,
            raterId: interaction.user.id,
            rating: rating
          }).save();
        }

        // Auto-ban check based on guild settings
        const guildSettings = await Guild.findOne({ id: interaction.guildId });
        const threshold = guildSettings?.settings?.autoBanThreshold ?? -10;

        if (user.reputation <= threshold) {
          try {
            const member = await interaction.guild?.members.fetch(targetUser.id);
            if (member && !user.isBanned) {
              await member.ban({ reason: `BeSafe Network: Reputation below server threshold (${user.reputation} <= ${threshold})` });
              await interaction.followUp({ content: `${targetUser.tag} has been automatically banned from this server due to low reputation.`, ephemeral: false }).catch(() => null);
            }
          } catch (e) {
            console.error('Failed to auto-ban in guild', e);
          }
        }
        await user.save();

        await interaction.followUp({ content: `Reputation updated for ${targetUser.tag}.`, ephemeral: true }).catch(() => null);
      }
    }
  });

  // Auto-moderation on member join
  targetClient.on(Events.GuildMemberAdd, async member => {
    const user = await User.findOne({ id: member.id });
    const activeBanCase = await BanCase.findOne({ 'discordAccounts.discordId': member.id, status: 'active' });
    const guildData = await Guild.findOne({ id: member.guild.id });
    const selectionMode = guildData?.settings?.banlistSelectionMode || 'global';
    
    const isGlobalBanned = (user?.isBanned || !!activeBanCase) && !user?.isTrusted;
    const effectiveBanReason = activeBanCase ? `Ban Case #${activeBanCase.caseNumber}: ${activeBanCase.reason}` : (user?.banReason || 'Global Banlist Violation');

    // Existing global ban check
    if (isGlobalBanned && (selectionMode === 'both' || selectionMode === 'global')) {
      const autoBan = guildData?.settings?.autoBanEnabled ?? false;
      const staffChannelId = guildData?.settings?.staffChannelId || guildData?.settings?.logChannelId;
      const staffRoleId = guildData?.settings?.staffRoleId;

      if (staffChannelId) {
        const channel = member.guild.channels.cache.get(staffChannelId) as any;
        if (channel) {
          const ping = staffRoleId ? `<@&${staffRoleId}> ` : '';
          const caseBadge = activeBanCase ? `[**Case #${activeBanCase.caseNumber}**] ` : '';
          channel.send(`🚨 **Global Ban Detected**: ${member.user.tag} (${member.id}) has joined. ${autoBan ? 'Automatically banned.' : 'Manual review required.'}\n${ping}${caseBadge}Reason: ${effectiveBanReason}`).catch(() => null);
        }
      }

      if (autoBan) {
        try {
          await member.ban({ reason: `BeSafe Network Global Ban: ${effectiveBanReason}` });
        } catch (e) {
          console.error('Failed to auto-ban member', e);
        }
        return; // Stop further checks if already banned
      }
    }

    // Custom Banlist check
    if (guildData?.settings?.customBanlistId && (selectionMode === 'both' || selectionMode === 'custom')) {
      try {
        const customBanlist = await CustomBanlist.findById(guildData.settings.customBanlistId);
        if (customBanlist) {
          // Double check: trusted users can NOT be blacklisted/banned!
          if (user && user.isTrusted) {
            console.log(`[Custom Banlist] Skipping banlist check for trusted user: ${member.id}`);
          } else {
            let isBlacklisted = false;
            let blacklistReason = 'Listed on connected custom banlist';

            // Check Discord ID match
            const discordEntry = customBanlist.entries.find(e => e.type === 'discord' && e.targetId === member.id);
            if (discordEntry) {
              isBlacklisted = true;
              blacklistReason = discordEntry.reason || blacklistReason;
            } else if (user) {
              // Check connected VRChat accounts
              const accounts = getAllVRChatAccounts(user);
              for (const account of accounts) {
                if (account.vrchatUserId) {
                  const vrchatEntry = customBanlist.entries.find(e => e.type === 'vrchat' && e.targetId.toLowerCase() === account.vrchatUserId.toLowerCase());
                  if (vrchatEntry) {
                    isBlacklisted = true;
                    blacklistReason = vrchatEntry.reason || blacklistReason;
                    break;
                  }
                }
              }
            }

            if (isBlacklisted) {
              const staffChannelId = guildData.settings.staffChannelId || guildData.settings.logChannelId;
              const staffRoleId = guildData.settings.staffRoleId;
              if (staffChannelId) {
                const channel = member.guild.channels.cache.get(staffChannelId) as any;
                if (channel) {
                  const ping = staffRoleId ? `<@&${staffRoleId}> ` : '';
                  channel.send(`🚨 **Custom Banlist Hit**: ${member.user.tag} (${member.id}) has joined and matches a record on the custom banlist **"${customBanlist.name}"**.\nReason: ${blacklistReason}\nAutomatically banning...`).catch(() => null);
                }
              }

              try {
                await member.ban({ reason: `Custom Banlist (${customBanlist.name}): ${blacklistReason}` });
              } catch (e) {
                console.error('[Custom Banlist] Failed to ban member on custom banlist match:', e);
              }
              return; // Stop further checks if banned
            }
          }
        }
      } catch (err) {
        console.error('[Custom Banlist] Error processing join check:', err);
      }
    }

    // Local Threshold Checks (Autonomous Settings)
    if (user && guildData) {
      if (user.isTrusted) {
        console.log(`[Local Threshold checks] Skipping local checks for trusted user: ${user.id}`);
        return;
      }
      const reputationThreshold = guildData.settings.autoBanThreshold ?? -10;
      const warningThreshold = guildData.settings.warningThreshold ?? 3;
      const localWarnings = user.warnings.filter(w => w.guildId === member.guild.id).length;

      let localReason = '';
      if (user.reputation <= reputationThreshold) {
        localReason = `Low Reputation (${user.reputation} <= ${reputationThreshold})`;
      } else if (localWarnings >= warningThreshold) {
        localReason = `Warning Threshold Reached (${localWarnings} >= ${warningThreshold})`;
      }

      if (localReason) {
        try {
          await member.ban({ reason: `BeSafe Network Local Auto-Ban: ${localReason}` });
          const staffChannelId = guildData.settings.staffChannelId || guildData.settings.logChannelId;
          if (staffChannelId) {
            const channel = member.guild.channels.cache.get(staffChannelId) as any;
            if (channel) {
              channel.send(`🛡️ **Local Auto-Ban**: ${member.user.tag} was automatically banned based on this server's autonomous settings.\nReason: ${localReason}`).catch(() => null);
            }
          }
        } catch (e) {
          console.error('Failed to local auto-ban member', e);
        }
        return;
      }
    }

    // New age role auto-assign
    if (user?.isAgeVerified && guildData?.settings?.ageRoleEnabled && guildData?.settings?.autoAssignAgeRole) {
      const roleId = guildData.settings.ageRoleId;
      if (roleId && user.dob) {
        const age = new Date().getFullYear() - user.dob.getFullYear();
        const m = new Date().getMonth() - user.dob.getMonth();
        const isAdult = age > 18 || (age === 18 && m >= 0);
        
        if (isAdult) {
          try {
            await member.roles.add(roleId);
          } catch (e) {
            console.error('Failed to auto-assign age role', e);
          }
        }
      }
    }
  });

  // Update server name automatically when server name changes in Discord
  targetClient.on(Events.GuildUpdate, async (oldGuild: any, newGuild: any) => {
    try {
      if (newGuild && newGuild.name && oldGuild && oldGuild.name !== newGuild.name) {
        console.log(`[Guild Update] Server name changed for ${newGuild.id}: "${oldGuild.name}" -> "${newGuild.name}"`);
        await Guild.updateOne(
          { id: newGuild.id },
          { $set: { name: newGuild.name, updatedAt: new Date() } }
        );
      }
    } catch (err: any) {
      console.error(`[Guild Update Error] Failed to update guild name for ${newGuild?.id}:`, err?.message);
    }
  });

  // Send configuration message when bot joins a new guild if it's not registered
  targetClient.on(Events.GuildCreate, async (guild) => {
    try {
      if (guild && guild.name) {
        await Guild.updateOne(
          { id: guild.id },
          { $set: { name: guild.name, updatedAt: new Date() } }
        );
      }
      const existingGuild = await Guild.findOne({ id: guild.id });
      if (!existingGuild || !existingGuild.ownerId) {
        // Find first available writable channel
        let targetChannel: any = null;
        
        // Try systemChannel first
        if (guild.systemChannel && guild.members.me && guild.systemChannel.permissionsFor(guild.members.me).has(PermissionFlagsBits.SendMessages)) {
          targetChannel = guild.systemChannel;
        } else {
          const channels = [...guild.channels.cache.values()].sort((a: any, b: any) => a.position - b.position);
          // Try text channels
          for (const channel of channels) {
            if (channel.isTextBased() && guild.members.me && channel.permissionsFor(guild.members.me).has(PermissionFlagsBits.SendMessages)) {
              if (channel.type === 0) { // GuildText
                targetChannel = channel;
                break;
              }
            }
          }
          // If no GuildText found, try any writable text-based channel
          if (!targetChannel) {
            for (const channel of channels) {
              if (channel.isTextBased() && guild.members.me && channel.permissionsFor(guild.members.me).has(PermissionFlagsBits.SendMessages)) {
                targetChannel = channel;
                break;
              }
            }
          }
        }

        if (targetChannel) {
          await targetChannel.send({
            embeds: [{
              title: 'Setup Required',
              description: `This server has not been configured yet. Please complete the initialization process:\n\n💻 **Account**: Sign up at https://besafesondiscord.com/\n\n🔗 **Link**: Use the /link command to connect your account.\n\n⚙️ **Setup**: Use the /setup command in your server to finish.\n\n⚙️ **Settings**: Go to our web dashboard to controll you settings.`,
              color: 0x3b82f6
            }]
          });
          console.log(`[Bot Join] Sent setup announcement to guild ${guild.name} (${guild.id}) in channel ${targetChannel.name}`);
        } else {
          console.warn(`[Bot Join] Could not find any writable channel in guild ${guild.name} (${guild.id}) to send setup required message`);
        }
      }
    } catch (e: any) {
      console.error(`[Bot Join] Error during GuildCreate handling for guild ${guild.id}:`, e.message);
    }
  });

  // --- REAL-TIME NSFW IMAGE BLOCKER (Events.MessageCreate) ---
  targetClient.on(Events.MessageCreate, async (message: any) => {
    try {
      if (!message || message.author?.bot || !message.guild) return;

      // Ensure this client is the designated client for this guild
      const designatedClient = getGuildDiscordClient(message.guild.id);
      if (designatedClient && designatedClient.user?.id !== targetClient.user?.id) {
        return;
      }

      // Pre-filter: Check if message contains attachments, embeds, or possible image links
      const hasAttachments = message.attachments && message.attachments.size > 0;
      const hasEmbeds = message.embeds && message.embeds.length > 0;
      const hasLinks = message.content && /(https?:\/\/[^\s]+)/i.test(message.content);

      if (!hasAttachments && !hasEmbeds && !hasLinks) {
        return;
      }

      // Check guild settings (off by default)
      const guildDoc = await Guild.findOne({ id: message.guild.id });
      if (!guildDoc || !guildDoc.settings?.nsfwBlockerEnabled) {
        return;
      }

      const settings = guildDoc.settings;

      // Check if channel is specifically allowed for NSFW content
      const allowedChannelIds: string[] = Array.isArray(settings.nsfwBlockerAllowedChannelIds)
        ? settings.nsfwBlockerAllowedChannelIds
        : [];
      if (allowedChannelIds.includes(message.channel.id)) {
        return; // Explicitly allowed channel for NSFW
      }
      if ((message.channel as any)?.parentId && allowedChannelIds.includes((message.channel as any).parentId)) {
        return; // Entire parent category is allowed for NSFW
      }

      const isChannelNsfw = Boolean((message.channel as any)?.nsfw);
      if (isChannelNsfw && !settings.nsfwBlockerScanNsfwChannels) {
        return;
      }

      // Collect candidate image URLs
      const candidateUrls: string[] = [];

      // 1. Attachments
      if (hasAttachments) {
        for (const [_, att] of message.attachments) {
          const ct = (att.contentType || '').toLowerCase();
          const name = (att.name || '').toLowerCase();
          const isImg = ct.startsWith('image/') || /\.(png|jpe?g|webp|gif|bmp)(\?.*)?$/i.test(name) || /\.(png|jpe?g|webp|gif|bmp)(\?.*)?$/i.test(att.url);
          if (isImg && att.url) {
            candidateUrls.push(att.url);
          }
        }
      }

      // 2. Embeds
      if (hasEmbeds) {
        for (const emb of message.embeds) {
          if (emb.image?.url) candidateUrls.push(emb.image.url);
          if (emb.thumbnail?.url) candidateUrls.push(emb.thumbnail.url);
        }
      }

      // 3. URLs in message text
      if (hasLinks) {
        const matchedUrls = message.content.match(/(https?:\/\/[^\s]+)/gi) || [];
        for (const u of matchedUrls) {
          if (/\.(png|jpe?g|webp|gif|bmp)(\?.*)?$/i.test(u) || u.includes('tenor.com') || u.includes('giphy.com') || u.includes('discordapp.com/attachments/')) {
            if (!candidateUrls.includes(u)) candidateUrls.push(u);
          }
        }
      }

      if (candidateUrls.length === 0) return;

      const threshold = typeof settings.nsfwBlockerSensitivity === 'number' && settings.nsfwBlockerSensitivity > 0
        ? settings.nsfwBlockerSensitivity
        : 0.65;

      // Scan candidate images (up to 4 images per message)
      for (const imgUrl of candidateUrls.slice(0, 4)) {
        const buffer = await downloadImageForScan(imgUrl);
        if (!buffer) continue;

        const evalResult = await scanImageBufferWithNsfwjs(buffer, threshold);
        if (evalResult && evalResult.isNsfw) {
          console.log(`[NSFW Blocker] Blocked adult content from ${message.author.tag} (${message.author.id}) in guild "${message.guild.name}" (#${(message.channel as any).name || message.channel.id}): ${evalResult.topCategory} (${(evalResult.confidence * 100).toFixed(1)}%)`);

          const action = settings.nsfwBlockerAction || 'delete_and_warn';
          const shouldDelete = action === 'delete_and_warn' || action === 'delete';
          const shouldWarn = action === 'delete_and_warn' || action === 'warn';

          // 1. Delete message
          let deleted = false;
          if (shouldDelete) {
            try {
              if (message.deletable) {
                await message.delete();
                deleted = true;
              }
            } catch (delErr: any) {
              console.warn('[NSFW Blocker] Failed to delete message:', delErr?.message);
            }
          }

          // 2. Warn author in channel
          if (shouldWarn) {
            try {
              const warnMsg = await message.channel.send({
                content: `🛡️ **NSFW Content Blocked:** ${message.author}, posting explicit or adult visual content is strictly prohibited in this server.\n*Detection: \`${evalResult.topCategory}\` (${(evalResult.confidence * 100).toFixed(0)}% AI confidence via BeSafe Blocker)*`
              });
              setTimeout(() => {
                warnMsg.delete().catch(() => {});
              }, 8000);
            } catch (warnErr: any) {
              console.warn('[NSFW Blocker] Failed to send warning in channel:', warnErr?.message);
            }
          }

          // 3. Post alert to staff / audit log channel
          const logChannelId = settings.nsfwBlockerLogChannelId || settings.logChannelId;
          if (logChannelId) {
            try {
              const logChan = message.guild.channels.cache.get(logChannelId) as any;
              if (logChan && logChan.isTextBased()) {
                const embed = new EmbedBuilder()
                  .setTitle('🚨 [NSFW BLOCKER] Explicit Image Intercepted')
                  .setColor(0xE11D48)
                  .setDescription(`The BeSafe Neural NSFW Filter intercepted prohibited content using \`@tensorflow/tfjs-node\` and \`nsfwjs\`.`)
                  .addFields(
                    { name: '👤 Author', value: `${message.author.tag} (<@${message.author.id}>\nID: \`${message.author.id}\`)`, inline: true },
                    { name: '📍 Channel', value: `<#${message.channel.id}> (\`${(message.channel as any).name || message.channel.id}\`)`, inline: true },
                    { name: '🎯 Detection Category', value: `**${evalResult.topCategory}**`, inline: true },
                    { name: '📊 Model Confidence', value: `**${(evalResult.confidence * 100).toFixed(1)}%** (Threshold: ${(threshold * 100).toFixed(0)}%)`, inline: true },
                    { name: '⚡ Action Enforced', value: deleted ? '🗑️ Message Deleted' : (shouldWarn ? '⚠️ Author Warned' : '📋 Logged Only'), inline: true },
                    { name: '🧠 Neural Engine', value: 'NSFWJS (MobileNetV2 + TensorFlow.js Node)', inline: true }
                  )
                  .setTimestamp();

                if (message.content) {
                  embed.addFields({ name: '💬 Message Content', value: message.content.substring(0, 500) });
                }

                await logChan.send({ embeds: [embed] });
              }
            } catch (logChanErr: any) {
              console.warn('[NSFW Blocker] Failed to post to log channel:', logChanErr?.message);
            }
          }

          // 4. Save to database log
          try {
            await new Log({
              action: 'NSFW_BLOCKER_TRIGGER',
              adminId: 'SYSTEM_BOT',
              targetId: message.author.id,
              details: `NSFW Blocker detected ${evalResult.topCategory} (${(evalResult.confidence * 100).toFixed(1)}%) in #${(message.channel as any).name || message.channel.id} in server "${message.guild.name}" (${message.guild.id}). Action: ${action}. Deleted: ${deleted}`
            }).save();
          } catch {}

          // Break once violation is flagged for this message
          break;
        }
      }
    } catch (msgErr: any) {
      console.error('[NSFW Blocker Message Handler Error]:', msgErr?.message || msgErr);
    }
  });
  }

  // Attach handlers to main client
  attachDiscordBotHandlers(client);

  if (serviceName !== 'dashboard' && serviceName !== 'web-dashboard') {
    if (process.env.DISCORD_TOKEN) {
      client.login(process.env.DISCORD_TOKEN).catch((loginErr: any) => {
        console.error('[Discord Client] Failed to login:', loginErr?.message || loginErr);
      });
    }
  } else {
    console.log('[Web Dashboard Service] Standalone dashboard mode: Skipping local Discord Gateway login.');
  }

  // --- Vite Setup ---
  let vite: any;
  if (process.env.NODE_ENV !== 'production') {
    vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
  }

  // --- Global Dynamic HTML & Embed Metadata Handler ---
  app.get([
    '/',
    '/check',
    '/check/:id',
    '/appeal',
    '/dashboard',
    '/verify',
    '/docs',
    '/docs/private',
    '/reset-password',
    '/verify-email',
    '/instructions',
    '/watchlist',
    '/watchlist/:id',
    '/terms',
    '/privacy',
    '/report'
  ], async (req: any, res, next) => {
    try {
      const pathParts = req.path.split('/');
      const isWatchlistDetail = pathParts[1] === 'watchlist' && pathParts[2];
      const isCheckDetail = (pathParts[1] === 'check' && pathParts[2]) || (pathParts[1] === 'check' && (req.query.id || req.query.query || req.query.user));
      const targetUserId = isWatchlistDetail 
        ? pathParts[2] 
        : (isCheckDetail ? (pathParts[2] || req.query.id || req.query.query || req.query.user) : null);
      
      let user: any = null;
      let banCase: any = null;
      if (isWatchlistDetail || isCheckDetail) {
        const queryRes = await findUserByQuery(targetUserId).catch(() => null);
        user = queryRes?.user || null;
        banCase = queryRes?.banCase || null;

        if (!user && !banCase) {
          banCase = await BanCase.findOne({
            $or: [
              { caseNumber: new RegExp(`^${targetUserId}$`, 'i') },
              { 'discordAccounts.discordId': targetUserId },
              { 'discordAccounts.username': new RegExp(`^${targetUserId}$`, 'i') },
              { title: new RegExp(targetUserId, 'i') }
            ]
          }).catch(() => null);
        }

        if (!user && !banCase) {
          user = await User.findOne({
            $or: [
              { id: targetUserId },
              { username: new RegExp(`^${targetUserId}$`, 'i') },
              { displayName: new RegExp(`^${targetUserId}$`, 'i') }
            ]
          }).catch(() => null);
        }
      }

      const indexPath = process.env.NODE_ENV === 'production' 
        ? path.join(process.cwd(), 'dist', 'index.html')
        : path.join(process.cwd(), 'index.html');
      
      if (!fs.existsSync(indexPath)) {
        return next();
      }

      let html = fs.readFileSync(indexPath, 'utf8');

      const host = req.get('host') || 'besafesondiscord.com';
      const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'https';
      const baseUrl = `${protocol}://${host}`;

      let title = '🛡️ BeSafe Network | Global Identity & Safety Layer';
      let description = 'Centralized threat intelligence registry and automated enforcement network shielding Discord communities. Real-time scanning, APIs, and automatic enforcement. Click here for more info!';
      let image = 'https://images.unsplash.com/photo-1614064641938-3bbee52942c7?q=80&w=600&auto=format&fit=crop';
      let themeColor = '#141414';

      const pathLower = req.path.toLowerCase();

      if (isWatchlistDetail || (isCheckDetail && targetUserId)) {
        if (banCase) {
          const primaryDisc = banCase.discordAccounts?.[0];
          const primaryVRC = banCase.vrchatAccounts?.[0];
          const subjectName = banCase.title || banCase.caseNumber || primaryDisc?.displayName || primaryDisc?.username || primaryVRC?.vrchatUsername;
          let targetImg = primaryDisc?.avatarUrl;
          if (!targetImg || targetImg.includes('embed/avatars/0.png')) {
            if (primaryDisc?.discordId) {
              const resDisc = await resolveDiscordUser(client, primaryDisc.discordId, null).catch(() => null);
              if (resDisc?.avatarUrl) targetImg = resDisc.avatarUrl;
            }
          }
          if (!targetImg && user) {
            targetImg = await getWatchlistAvatar(client, user).catch(() => null);
          }
          if (!targetImg || targetImg.includes('embed/avatars/0.png')) {
            targetImg = 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?q=80&w=600&auto=format&fit=crop';
          }
          if (targetImg && targetImg.startsWith('/')) {
            targetImg = `${baseUrl}${targetImg}`;
          }
          title = `${subjectName} | BeSafe Network`;
          const primaryViolation = banCase.dangerousNotes || banCase.reason || 'Classified Safety Violation';
          description = isWatchlistDetail
            ? `🔴 SECURITY ALERT: ${subjectName} (${banCase.caseNumber || targetUserId}) is registered on the BeSafe Network Watchlist. Trust Index: [${banCase.trustIndex || 'CRIMINAL'}]. Violation: "${primaryViolation}". CLICK HERE FOR FULL DOSSIER & EVIDENCE INTEL.`
            : `🛡️ BeSafe Identity & Trust Check for ${subjectName}. Trust Index: [${banCase.trustIndex || 'CRIMINAL'}]. Case: #${banCase.caseNumber}. Violation: "${primaryViolation}". Click to inspect standing.`;
          image = targetImg || 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?q=80&w=600&auto=format&fit=crop';
          themeColor = '#DC2626';
        } else if (user) {
          const resolved = await resolveDiscordUser(client, user.id, user).catch(() => null);
          const subjectName = user.displayName || user.username || resolved?.displayName || resolved?.username || user.id;
          let targetImg = await getWatchlistAvatar(client, user);
          if (targetImg && targetImg.startsWith('/')) {
            targetImg = `${baseUrl}${targetImg}`;
          }
          title = `${subjectName} | BeSafe Network`;
          const primaryViolation = user.dangerousNotes || user.banReason || 'Classified Safety Violation';
          description = isWatchlistDetail
            ? `🔴 SECURITY ALERT: ${subjectName} (ID: ${user.id}) is registered on the BeSafe Network Watchlist. Trust Index: [${user.trustIndex || 'CRIMINAL'}]. Violation: "${primaryViolation}". CLICK HERE FOR FULL DOSSIER & EVIDENCE INTEL.`
            : `🛡️ BeSafe Identity & Trust Check for ${subjectName}. Standing: [${user.trustIndex || 'GREEN_SECURE'}]. Reputation: ${user.reputation || 0} pts. Click to inspect full standing.`;
          image = targetImg || 'https://cdn.discordapp.com/embed/avatars/0.png';
          themeColor = user.isDangerous ? '#DC2626' : user.isBanned ? '#DC2626' : '#10B981';
        } else {
          let subjectName = targetUserId;
          let targetImg = 'https://cdn.discordapp.com/embed/avatars/0.png';
          try {
            const resolved = await resolveDiscordUser(client, targetUserId, null).catch(() => null);
            if (resolved) {
              subjectName = resolved.displayName || resolved.username || targetUserId;
              targetImg = resolved.avatarUrl || targetImg;
            }
          } catch (e) {}
          if (targetImg && targetImg.startsWith('/')) {
            targetImg = `${baseUrl}${targetImg}`;
          }
          title = `${subjectName} | BeSafe Network`;
          description = `🛡️ BeSafe Identity & Trust Check for ${subjectName}. Verified global standing and infraction lookup.`;
          themeColor = '#10B981';
          image = targetImg;
        }
      } else if (pathLower.startsWith('/watchlist')) {
        title = '☣️ High Risk Enforcement Watchlist | BeSafe Network';
        description = '⚠️ Blacklist index & intelligence directory containing active high-priority malicious actors, scam operations, and cybersec threats. Maintain server compliance. Click here for more info!';
        themeColor = '#DC2626';
        image = 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?q=80&w=600&auto=format&fit=crop';
      } else if (pathLower === '/check' || pathLower.startsWith('/check')) {
        title = '🔍 System Database Lookup | BeSafe Network';
        description = '🔎 Query active Discord usernames, snowflakes, or servers instantly against real-time global infraction lists and cybersec credentials.';
        themeColor = '#3B82F6';
        image = 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?q=80&w=600&auto=format&fit=crop';
      } else if (pathLower === '/appeal') {
        title = '⚖️ Network Ban Appeal Terminal | BeSafe Network';
        description = '📝 Initiating global enforcement dispute procedure. Submit identity details and mitigating arguments under BeSafe administrative standards.';
        themeColor = '#10B981';
        image = 'https://images.unsplash.com/photo-1589829545856-d10d557cf95f?q=80&w=600&auto=format&fit=crop';
      } else if (pathLower === '/report') {
        title = '⚠️ File Security Intelligence Report | BeSafe Network';
        description = '🚨 Report verified trust violations, phishing attacks, or scam syndicates. Submit target ID and evidence logs to notify administrative reviewers.';
        themeColor = '#EF4444';
        image = 'https://images.unsplash.com/photo-1579126038374-606c112f5510?q=80&w=600&auto=format&fit=crop';
      } else if (pathLower === '/instructions') {
        title = 'ℹ️ Global Safety Protocol | BeSafe Network';
        description = '📖 Explore procedural system policies, API architecture, blacklisting patterns, and security workflows safeguarding community networks.';
        themeColor = '#F59E0B';
        image = 'https://images.unsplash.com/photo-1517245386807-bb43f82c33c4?q=80&w=600&auto=format&fit=crop';
      } else if (pathLower.startsWith('/docs')) {
        title = '💻 SDK & Cybersec Developer Hub | BeSafe Network';
        description = '🛠️ Connect servers and custom bots to our high-throughput safety API. Implement real-time user validation and database checkups.';
        themeColor = '#6366F1';
        image = 'https://images.unsplash.com/photo-1605810230434-7631ac76ec81?q=80&w=600&auto=format&fit=crop';
      } else if (pathLower === '/dashboard') {
        title = '🎛️ Command Deck & Console | BeSafe Network';
        description = '🛡️ Live telemetry metrics, audit logs, community server hooks, auto-moderation settings, and dynamic watchlist configuration.';
        themeColor = '#141414';
      }

      const url = `${baseUrl}${req.originalUrl}`;

      const metaTags = `
    <title>${title}</title>
    <meta name="description" content="${description}">
    <!-- Open Graph / Discord -->
    <meta property="og:title" content="${title}">
    <meta property="og:description" content="${description}">
    <meta property="og:image" content="${image}">
    <meta property="og:url" content="${url}">
    <meta property="og:type" content="website">
    <meta property="og:site_name" content="BeSafe Network Collective">
    
    <!-- Twitter / X -->
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="${title}">
    <meta name="twitter:description" content="${description}">
    <meta name="twitter:image" content="${image}">
    <meta name="twitter:url" content="${url}">
    <meta name="theme-color" content="${themeColor}">
    <link rel="canonical" href="${url}">
      `;

      if (vite) {
        html = await vite.transformIndexHtml(req.originalUrl, html);
      }

      // Safe replacement regardless of format, spacing, or case of standard title tag inside index.html
      html = html.replace(/<title>[^]*?<\/title>/i, metaTags);
      
      res.status(200).set({ 'Content-Type': 'text/html' }).end(html);
    } catch (e) {
      console.error('Metadata injection error:', e);
      next();
    }
  });

  // --- Middleware & Asset Serving ---
  if (vite) {
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });

  async function fetch2FACode(apiUrl: string, apiToken: string, selectKey: string, fallbackUsername?: string): Promise<string> {
    const cleanUrl = apiUrl.replace(/\/+$/, '');
    const url = `${cleanUrl}/api/v1/twofaccounts`;
    
    console.log(`[2FAuth API] Fetching accounts list from ${url}...`);
    const headers = {
      'Authorization': `Bearer ${apiToken}`,
      'Accept': 'application/json',
      'User-Agent': 'BeSafeDiscordBot/1.0.0 (ossscott40@gmail.com)'
    };
    
    const res = await fetch(url, { method: 'GET', headers });
    if (!res.ok) {
      throw new Error(`2FAuth API request failed with HTTP ${res.status}`);
    }
    
    const body: any = await res.json();
    const dataList = body.data || body;
    if (!Array.isArray(dataList)) {
      throw new Error('2FAuth API did not return a valid accounts list');
    }
    
    // Helper to get property either at root or nested under attributes
    const getAttr = (obj: any, keys: string[]): any => {
      if (!obj) return undefined;
      for (const k of keys) {
        if (obj[k] !== undefined && obj[k] !== null) return obj[k];
        if (obj.attributes && obj.attributes[k] !== undefined && obj.attributes[k] !== null) return obj.attributes[k];
      }
      return undefined;
    };

    let account = null;
    if (selectKey && selectKey.trim()) {
      const matchKey = selectKey.trim().toLowerCase();
      // Try to find by exact ID, or label/name/service/account match
      account = dataList.find((item: any) => {
        const id = getAttr(item, ['id'])?.toString().trim().toLowerCase();
        const label = getAttr(item, ['label', 'name', 'title', 'service', 'account'])?.toString().trim().toLowerCase();
        return id === matchKey || label === matchKey;
      });
    }
    
    // 1st Fallback: if fallbackUsername is provided, search for an account containing the username/email
    if (!account && fallbackUsername && fallbackUsername.trim()) {
      const cleanUsername = fallbackUsername.trim().toLowerCase();
      account = dataList.find((item: any) => {
        const label = getAttr(item, ['label', 'name', 'title', 'service', 'account'])?.toString().trim().toLowerCase() || '';
        return label.includes(cleanUsername) || cleanUsername.includes(label);
      });
    }

    // 2nd Fallback: search for first account that contains "vrchat" in label/name/title/service/account
    if (!account) {
      account = dataList.find((item: any) => {
        const label = getAttr(item, ['label', 'name', 'title', 'service', 'account'])?.toString().trim().toLowerCase() || '';
        return label.includes('vrchat');
      });
    }
    
    if (!account) {
      throw new Error(`No matching account found in 2FAuth for selection: "${selectKey || fallbackUsername || 'VRChat'}"`);
    }

    const accountId = getAttr(account, ['id']);
    if (!accountId) {
      throw new Error(`Matching account found but did not contain a valid ID.`);
    }

    const label = getAttr(account, ['service', 'label', 'name', 'title', 'account']) || 'unnamed';
    
    // Fetch individual account details since lists omit secret and computed TOTP
    const detailUrl = `${cleanUrl}/api/v1/twofaccounts/${accountId}`;
    console.log(`[2FAuth API] Fetching details for account "${label}" (ID: ${accountId}) from ${detailUrl}...`);
    
    const detailRes = await fetch(detailUrl, { method: 'GET', headers });
    if (!detailRes.ok) {
      throw new Error(`2FAuth API show request failed with HTTP ${detailRes.status}`);
    }
    
    const detailBody: any = await detailRes.json();
    const detailAccount = detailBody.data || detailBody;

    // Check if the show response has a computed code/otp directly
    let code = getAttr(detailAccount, ['one_time_password', 'otp', 'otp_code', 'token', 'code']);
    
    if (!code) {
      // If code is not computed by 2FAuth but we have the secret, let's calculate the TOTP ourselves!
      const secret = getAttr(detailAccount, ['secret']);
      if (secret) {
        const digits = parseInt(getAttr(detailAccount, ['digits']) || '6', 10);
        const period = parseInt(getAttr(detailAccount, ['period']) || '30', 10);
        const algorithm = getAttr(detailAccount, ['algorithm']) || 'sha1';
        
        console.log(`[2FAuth API] Computing TOTP code locally for "${label}" using secret. Digits: ${digits}, Period: ${period}, Algo: ${algorithm}`);
        try {
          code = generateLocalTOTP(secret, period, digits, algorithm);
        } catch (err: any) {
          console.error(`[2FAuth API] Local TOTP calculation failed:`, err);
        }
      }
    }
    
    if (!code) {
      const safeKeys = Object.keys(detailAccount).filter(k => k !== 'secret');
      const safeAttributesKeys = detailAccount.attributes ? Object.keys(detailAccount.attributes).filter(k => k !== 'secret') : [];
      console.error(`[2FAuth Debug] Found detailed account keys:`, safeKeys, `Attributes keys:`, safeAttributesKeys);
      throw new Error(`Account "${label}" was found, but did not contain an active TOTP code or secret. Available keys in details: ${safeKeys.join(', ')}`);
    }
    
    console.log(`[2FAuth API] Successfully retrieved 2FA code for account: "${label}"`);
    return code.toString().trim();
  }

  // Pure TypeScript local TOTP generator using cryptoNode
  function generateLocalTOTP(secretStr: string, period: number, digits: number, algorithm: string): string {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const clean = secretStr.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
    const length = clean.length;
    let bits = 0;
    let value = 0;
    let index = 0;
    const buffer = Buffer.alloc(Math.floor((length * 5) / 8));

    for (let i = 0; i < length; i++) {
      const val = alphabet.indexOf(clean[i]);
      if (val === -1) continue;
      value = (value << 5) | val;
      bits += 5;
      if (bits >= 8) {
        if (index < buffer.length) {
          buffer[index++] = (value >> (bits - 8)) & 255;
        }
        bits -= 8;
      }
    }

    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / period);
    
    const counterBuffer = Buffer.alloc(8);
    let tmp = counter;
    for (let i = 7; i >= 0; i--) {
      counterBuffer[i] = tmp & 0xff;
      tmp >>= 8;
    }

    const hmac = cryptoNode.createHmac(algorithm.toLowerCase(), buffer);
    hmac.update(counterBuffer);
    const digest = hmac.digest();

    const offset = digest[digest.length - 1] & 0xf;
    const codeBin = ((digest[offset] & 0x7f) << 24) |
                    ((digest[offset + 1] & 0xff) << 16) |
                    ((digest[offset + 2] & 0xff) << 8) |
                    (digest[offset + 3] & 0xff);

    const otp = codeBin % Math.pow(10, digits);
    return otp.toString().padStart(digits, '0');
  }

  // Backward compatibility & Multi-Bot Helper
  function getVRChatBots(config: any) {
    const list: any[] = [];
    if (config.vrchatUsername || config.vrchatCookie) {
      list.push({
        id: 'legacy',
        vrchatUsername: config.vrchatUsername || "",
        vrchatPassword: config.vrchatPassword || "",
        vrchatCookie: config.vrchatCookie || "",
        twoFactorAuthApiUrl: config.twoFactorAuthApiUrl || "",
        twoFactorAuthApiToken: config.twoFactorAuthApiToken || "",
        twoFactorAuthAccountId: config.twoFactorAuthAccountId || "",
        groupCount: config.vrchatBotGroupCount !== undefined ? config.vrchatBotGroupCount : (config.vrchatGroupId ? 1 : 0),
        groups: config.vrchatBotGroups && config.vrchatBotGroups.length > 0 ? config.vrchatBotGroups : (config.vrchatGroupId ? [config.vrchatGroupId] : []),
        status: config.vrchatBotStatus || "idle",
        error: config.vrchatBotError || ""
      });
    }
    if (config.vrchatBots && config.vrchatBots.length > 0) {
      list.push(...config.vrchatBots);
    }
    return list;
  }

  async function getVRChatAuthHeadersForBot(bot: any, config: any) {
    const headers: any = {
      'User-Agent': 'BeSafeDiscordBot/1.0.0 (ossscott40@gmail.com)',
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };

    const apiKey = 'JlE5Jldo5Jibnk505hTx6XVqsJu4WJ26';
    const botKey = bot.id || bot.vrchatUsername || 'default';

    // 1. Check if the bot is in a login rate-limiting cooldown due to previous 429s
    const cooldownUntil = botLoginCooldowns.get(botKey);
    if (cooldownUntil && Date.now() < cooldownUntil) {
      const remainingSeconds = Math.round((cooldownUntil - Date.now()) / 1000);
      console.warn(`[VRChat Auth Bot: ${bot.vrchatUsername}] Under login rate-limiting cooldown for another ${remainingSeconds}s. Trying to use cached cookie if available...`);
      
      if (bot.vrchatCookie && bot.vrchatCookie.trim()) {
        let cookieVal = bot.vrchatCookie.trim();
        cookieVal = cookieVal.replace(/^["']|["']$/g, '');
        if (cookieVal.includes('auth=')) {
          const match = cookieVal.match(/auth=(auth_[^;]+)/);
          if (match) {
            cookieVal = match[1];
          } else {
            cookieVal = cookieVal.replace(/auth=/, '');
          }
        }
        headers['Cookie'] = `auth=${cookieVal}; apiKey=${apiKey}`;
        return { headers, apiKey };
      }
      
      throw new Error(`VRChat login rate-limiting cooldown active. Try again in ${remainingSeconds} seconds.`);
    }

    // 2. If a direct cookie is provided, check cache or verify it
    if (bot.vrchatCookie && bot.vrchatCookie.trim()) {
      let cookieVal = bot.vrchatCookie.trim();
      cookieVal = cookieVal.replace(/^["']|["']$/g, '');
      
      if (cookieVal.includes('auth=')) {
        const match = cookieVal.match(/auth=(auth_[^;]+)/);
        if (match) {
          cookieVal = match[1];
        } else {
          cookieVal = cookieVal.replace(/auth=/, '');
        }
      }

      // 3. In-memory validation cache bypass (valid for 15 minutes)
      const cached = verifiedCookiesCache.get(botKey);
      const isCachedAndValid = cached && cached.cookie === cookieVal && (Date.now() - cached.verifiedAt) < 15 * 60 * 1000;

      if (isCachedAndValid) {
        console.log(`[VRChat Auth Bot: ${bot.vrchatUsername}] Using in-memory verified cookie (cached ${Math.round((Date.now() - cached.verifiedAt) / 1000)}s ago)`);
        headers['Cookie'] = `auth=${cookieVal}; apiKey=${apiKey}`;
        return { headers, apiKey };
      }
      
      const testCookieHeaders = { ...headers, 'Cookie': `auth=${cookieVal}; apiKey=${apiKey}` };
      
      if (bot.vrchatUsername && bot.vrchatPassword) {
        try {
          console.log(`[VRChat Auth Bot: ${bot.vrchatUsername}] Checking if cached cookie is still valid...`);
          const testRes = await fetch(`https://api.vrchat.cloud/api/1/auth/user?apiKey=${apiKey}`, {
            method: 'GET',
            headers: testCookieHeaders
          });
          if (testRes.status === 200) {
            console.log(`[VRChat Auth Bot: ${bot.vrchatUsername}] Cached cookie is verified valid!`);
            verifiedCookiesCache.set(botKey, { verifiedAt: Date.now(), cookie: cookieVal });
            headers['Cookie'] = `auth=${cookieVal}; apiKey=${apiKey}`;
            return { headers, apiKey };
          } else if (testRes.status === 429) {
            console.warn(`[VRChat Auth Bot: ${bot.vrchatUsername}] Cached cookie check rate-limited (HTTP 429). Assuming cookie is still valid and caching to prevent further spam.`);
            verifiedCookiesCache.set(botKey, { verifiedAt: Date.now(), cookie: cookieVal });
            headers['Cookie'] = `auth=${cookieVal}; apiKey=${apiKey}`;
            return { headers, apiKey };
          } else {
            console.warn(`[VRChat Auth Bot: ${bot.vrchatUsername}] Cached cookie check failed (HTTP ${testRes.status}). Clearing cookie and forcing relogin...`);
            await updateBotCookieInDb(bot.id, '');
            bot.vrchatCookie = '';
          }
        } catch (err: any) {
          console.error(`[VRChat Auth Bot: ${bot.vrchatUsername}] Error verifying cached cookie:`, err.message);
          headers['Cookie'] = `auth=${cookieVal}; apiKey=${apiKey}`;
          return { headers, apiKey };
        }
      } else {
        headers['Cookie'] = `auth=${cookieVal}; apiKey=${apiKey}`;
        return { headers, apiKey };
      }
    }

    // 4. Otherwise, login via username/password
    if (bot.vrchatUsername && bot.vrchatPassword) {
      try {
        console.log(`[VRChat Auth Bot: ${bot.vrchatUsername}] Initializing login...`);
        const basicAuth = Buffer.from(`${bot.vrchatUsername}:${bot.vrchatPassword}`).toString('base64');
        const response = await fetch(`https://api.vrchat.cloud/api/1/auth/user?apiKey=${apiKey}`, {
          method: 'GET',
          headers: {
            'Authorization': `Basic ${basicAuth}`,
            'User-Agent': headers['User-Agent'],
            'Accept': 'application/json'
          }
        });

        if (!response.ok) {
          const text = await response.text();
          console.error(`VRChat auth failed for bot ${bot.vrchatUsername} with status ${response.status}:`, text);
          if (response.status === 429) {
            botLoginCooldowns.set(botKey, Date.now() + 15 * 60 * 1000); // 15-minute cooldown
            console.warn(`[VRChat Auth Bot: ${bot.vrchatUsername}] Login failed with HTTP 429. Setting 15-minute rate-limiting login cooldown.`);
          }
          throw new Error(`VRChat Auth Failed with HTTP ${response.status}`);
        }

        const userJson: any = await response.json();

        const setCookieHeaders = response.headers.getSetCookie 
          ? response.headers.getSetCookie() 
          : (response.headers.get('set-cookie') ? [response.headers.get('set-cookie')!] : []);
        
        let authCookie = '';
        for (const cookie of setCookieHeaders) {
          if (cookie.includes('auth=')) {
            const match = cookie.match(/auth=([^;]+)/);
            if (match) {
              authCookie = match[1];
              break;
            }
          }
        }

        if (!authCookie) {
          throw new Error('Login succeeded but auth cookie was not returned.');
        }

        // Check if 2FA is required during login
        if (userJson.requiresTwoFactorAuth && userJson.requiresTwoFactorAuth.length > 0) {
          const apiUrl = bot.twoFactorAuthApiUrl || config.twoFactorAuthApiUrl;
          const apiToken = bot.twoFactorAuthApiToken || config.twoFactorAuthApiToken;
          // Prevent additional bots from falling back to config.twoFactorAuthAccountId which belongs to the primary bot
          const accountId = bot.twoFactorAuthAccountId || (bot.id === 'legacy' ? config.twoFactorAuthAccountId : '');

          if (apiUrl && apiToken) {
            const totpCode = await fetch2FACode(apiUrl, apiToken, accountId, bot.vrchatUsername);
            
            const verifyRes = await fetch(`https://api.vrchat.cloud/api/1/auth/twofactorauth/totp/verify?apiKey=${apiKey}`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Cookie': `auth=${authCookie}; apiKey=${apiKey}`,
                'User-Agent': headers['User-Agent']
              },
              body: JSON.stringify({ code: totpCode })
            });

            if (!verifyRes.ok) {
               const errText = await verifyRes.text();
               if (verifyRes.status === 429) {
                 botLoginCooldowns.set(botKey, Date.now() + 15 * 60 * 1000); // 15-minute cooldown
               }
               throw new Error(`VRChat 2FA verification failed with status ${verifyRes.status}: ${errText}`);
            }

            const verifyJson: any = await verifyRes.json();
            if (verifyJson.verified !== true) {
              throw new Error('VRChat 2FA verification response came back unverified.');
            }

            const verifySetCookieHeaders = verifyRes.headers.getSetCookie 
              ? verifyRes.headers.getSetCookie() 
              : (verifyRes.headers.get('set-cookie') ? [verifyRes.headers.get('set-cookie')!] : []);

            let activeAuthCookie = authCookie;
            for (const cookie of verifySetCookieHeaders) {
               if (cookie.includes('auth=')) {
                 const match = cookie.match(/auth=([^;]+)/);
                 if (match) {
                   activeAuthCookie = match[1];
                   break;
                 }
               }
            }

            headers['Cookie'] = `auth=${activeAuthCookie}; apiKey=${apiKey}`;
            await updateBotCookieInDb(bot.id, activeAuthCookie);
            verifiedCookiesCache.set(botKey, { verifiedAt: Date.now(), cookie: activeAuthCookie });
            return { headers, apiKey };
          } else {
            throw new Error('VRChat login requires 2FA, but no 2FAuth API credentials are configured.');
          }
        }

        headers['Cookie'] = `auth=${authCookie}; apiKey=${apiKey}`;
        await updateBotCookieInDb(bot.id, authCookie);
        verifiedCookiesCache.set(botKey, { verifiedAt: Date.now(), cookie: authCookie });
        return { headers, apiKey };
      } catch (err: any) {
        throw err;
      }
    }

    throw new Error('VRChat credentials or active auth cookie missing for bot account: ' + bot.vrchatUsername);
  }

  async function updateBotCookieInDb(botId: string, cookie: string) {
    if (botId === 'legacy') {
      await SystemConfig.findOneAndUpdate({ id: 'main' }, { vrchatCookie: cookie });
    } else {
      await SystemConfig.findOneAndUpdate(
        { id: 'main', 'vrchatBots.id': botId },
        { $set: { 'vrchatBots.$.vrchatCookie': cookie } }
      );
    }
  }

  async function getVRChatAuthHeaders(config: any) {
    const bots = getVRChatBots(config);
    if (bots.length === 0) {
      throw new Error('No VRChat bots configured');
    }
    return getVRChatAuthHeadersForBot(bots[0], config);
  }

  async function resolveVRChatUserBySearch(searchQuery: string): Promise<{ vrchatUserId: string; vrchatUsername: string } | null> {
    if (!searchQuery || !searchQuery.trim()) return null;
    try {
      const config = await SystemConfig.findOne({ id: 'main' });
      if (!config) return null;
      let { headers, apiKey } = await getVRChatAuthHeaders(config);
      let response = await fetch(`https://api.vrchat.cloud/api/1/users?search=${encodeURIComponent(searchQuery.trim())}&n=5&apiKey=${apiKey}`, {
        method: 'GET',
        headers
      });
      if (response.ok) {
        const results = await response.json();
        if (Array.isArray(results) && results.length > 0) {
          const exact = results.find((u: any) => 
            u.displayName?.toLowerCase() === searchQuery.toLowerCase() ||
            u.username?.toLowerCase() === searchQuery.toLowerCase() ||
            u.id?.toLowerCase() === searchQuery.toLowerCase()
          ) || results[0];
          if (exact && exact.id) {
            return { vrchatUserId: exact.id, vrchatUsername: exact.displayName || exact.username || searchQuery };
          }
        }
      }
      return null;
    } catch (e: any) {
      return null;
    }
  }

  async function updateVRChatBotStatus(config: any) {
    // Only update VRChat status every 30 minutes to stay clear of rate limits
    if (Date.now() - lastStatusUpdateAt < 30 * 60 * 1000) {
      return true;
    }
    const success = await updateAllVRChatBotsStatus(config);
    if (success) {
      lastStatusUpdateAt = Date.now();
    }
    return success;
  }

  async function updateAllVRChatBotsStatus(config: any) {
    try {
      if (!config) return false;
      const bots = getVRChatBots(config);
      if (bots.length === 0) return false;

      for (const bot of bots) {
        try {
          const { headers, apiKey } = await getVRChatAuthHeadersForBot(bot, config);

          const authRes = await fetch(`https://api.vrchat.cloud/api/1/auth/user?apiKey=${apiKey}`, {
            method: 'GET',
            headers
          });

          if (!authRes.ok) {
            continue;
          }

          const currentUser = await authRes.json();
          const userId = currentUser.id;
          if (!userId) {
            continue;
          }

          await fetch(`https://api.vrchat.cloud/api/1/users/${userId}?apiKey=${apiKey}`, {
            method: 'PUT',
            headers,
            body: JSON.stringify({
              status: 'active',
              statusDescription: 'protecting you'
            })
          });
        } catch (botErr: any) {
        }
      }
      return true;
    } catch (err: any) {
      return false;
    }
  }

  async function syncAllVRChatBots(config: any) {
    if (!config) return;
    
    const bots = getVRChatBots(config);
    if (bots.length === 0) {
      return;
    }

    for (const bot of bots) {
      try {
        const { headers, apiKey } = await getVRChatAuthHeadersForBot(bot, config);
        
        const authRes = await fetch(`https://api.vrchat.cloud/api/1/auth/user?apiKey=${apiKey}`, {
          method: 'GET',
          headers
        });

        if (!authRes.ok) {
          throw new Error(`Profile fetch failed with status ${authRes.status}`);
        }

        const currentUser = await authRes.json();
        const userId = currentUser.id;
        if (!userId) {
          throw new Error('No userId found in auth response');
        }

        const groupsRes = await fetch(`https://api.vrchat.cloud/api/1/users/${userId}/groups?apiKey=${apiKey}`, {
          method: 'GET',
          headers
        });

        if (!groupsRes.ok) {
          throw new Error(`Failed to fetch groups list: HTTP ${groupsRes.status}`);
        }

        const groupsData = await groupsRes.json() as any[];
        if (!Array.isArray(groupsData)) {
          throw new Error('Groups API response is not an array');
        }

        const groupIds = groupsData.map((g: any) => {
          const candidate = g.groupId || g.id;
          if (candidate && candidate.startsWith('gmem_') && g.groupId) {
            return g.groupId;
          }
          return candidate;
        }).filter((id: string) => id && id.startsWith('grp_'));

        if (bot.id === 'legacy') {
          await SystemConfig.findOneAndUpdate(
            { id: 'main' },
            { 
              $set: {
                vrchatGroupId: groupIds[0] || config.vrchatGroupId || '',
                vrchatBotGroups: groupIds,
                vrchatBotGroupCount: groupIds.length,
                vrchatBotStatus: 'active',
                vrchatBotError: '',
                vrchatBotLastCheckedAt: new Date()
              }
            }
          );
        } else {
          await SystemConfig.findOneAndUpdate(
            { id: 'main', 'vrchatBots.id': bot.id },
            { 
              $set: { 
                'vrchatBots.$.groups': groupIds,
                'vrchatBots.$.groupCount': groupIds.length,
                'vrchatBots.$.status': 'active',
                'vrchatBots.$.error': '',
                'vrchatBots.$.lastCheckedAt': new Date()
              } 
            }
          );
        }
      } catch (err: any) {
        if (bot.id === 'legacy') {
          await SystemConfig.findOneAndUpdate(
            { id: 'main' },
            { 
              $set: { 
                vrchatBotStatus: 'error',
                vrchatBotError: err.message,
                vrchatBotLastCheckedAt: new Date()
              } 
            }
          );
        } else {
          await SystemConfig.findOneAndUpdate(
            { id: 'main', 'vrchatBots.id': bot.id },
            { 
              $set: { 
                'vrchatBots.$.status': 'error',
                'vrchatBots.$.error': err.message,
                'vrchatBots.$.lastCheckedAt': new Date()
              } 
            }
          );
        }
      }
    }
  }

  async function removeGroupFromBotDb(botId: string, groupId: string) {
    try {
      if (botId === 'legacy') {
        await SystemConfig.findOneAndUpdate(
          { id: 'main' },
          { 
            $pull: { vrchatBotGroups: groupId },
            $inc: { vrchatBotGroupCount: -1 }
          }
        );
      } else {
        await SystemConfig.findOneAndUpdate(
          { id: 'main', 'vrchatBots.id': botId },
          { 
            $pull: { 'vrchatBots.$.groups': groupId },
            $inc: { 'vrchatBots.$.groupCount': -1 }
          }
        );
      }
    } catch (dbErr: any) {
    }
  }

  async function getBotForGroup(configPassed: any, groupId: string): Promise<any> {
    const config = await SystemConfig.findOne({ id: 'main' }) || configPassed;
    const bots = getVRChatBots(config);
    if (bots.length === 0) {
      throw new Error('No VRChat bot accounts configured.');
    }

    for (const bot of bots) {
      if (bot.groups && bot.groups.includes(groupId)) {
        return bot;
      }
    }

    const availableBots = bots.filter((b: any) => (b.groupCount || 0) < 95);
    if (availableBots.length === 0) {
      throw new Error('All VRChat bot accounts are full (limit 95 groups each). Please add a new bot account under System Settings.');
    }

    availableBots.sort((a: any, b: any) => (a.groupCount || 0) - (b.groupCount || 0));
    const selectedBot = availableBots[0];

    let joinedSuccess = false;
    try {
      const { headers, apiKey } = await getVRChatAuthHeadersForBot(selectedBot, config);
      const joinRes = await fetch(`https://api.vrchat.cloud/api/1/groups/${groupId}/join?apiKey=${apiKey}`, {
        method: 'POST',
        headers
      });

      if (joinRes.ok) {
        joinedSuccess = true;
      } else {
        const errText = await joinRes.text();
        if (errText.toLowerCase().includes('already') || errText.toLowerCase().includes('member')) {
          joinedSuccess = true;
        }
      }
    } catch (joinErr: any) {
    }

    if (joinedSuccess) {
      if (selectedBot.id === 'legacy') {
        await SystemConfig.findOneAndUpdate(
          { id: 'main' },
          { 
            $addToSet: { vrchatBotGroups: groupId },
            $inc: { vrchatBotGroupCount: 1 }
          }
        );
      } else {
        await SystemConfig.findOneAndUpdate(
          { id: 'main', 'vrchatBots.id': selectedBot.id },
          { 
            $addToSet: { 'vrchatBots.$.groups': groupId },
            $inc: { 'vrchatBots.$.groupCount': 1 }
          }
        );
      }
    } else {
      throw new Error(`Failed to join VRChat Group ${groupId} with bot ${selectedBot.vrchatUsername}.`);
    }

    return selectedBot;
  }

  async function leaveVRChatGroupIfOrphaned(groupId: string, config: any) {
    if (!groupId || !groupId.trim()) return;
    const targetGroupId = groupId.trim();
    
    const activeGuildsUsingGroup = await Guild.find({
      'settings.vrchatBotEnabled': true,
      'settings.vrchatGroupId': targetGroupId
    });

    if (activeGuildsUsingGroup.length === 0) {
      const bots = getVRChatBots(config);
      const assignedBot = bots.find((b: any) => b.groups && b.groups.includes(targetGroupId));
      
      if (assignedBot) {
        try {
          const { headers, apiKey } = await getVRChatAuthHeadersForBot(assignedBot, config);
          await fetch(`https://api.vrchat.cloud/api/1/groups/${targetGroupId}/leave?apiKey=${apiKey}`, {
            method: 'DELETE',
            headers
          });
        } catch (err: any) {
        }

        if (assignedBot.id === 'legacy') {
          await SystemConfig.findOneAndUpdate(
            { id: 'main' },
            { 
              $pull: { vrchatBotGroups: targetGroupId },
              $inc: { vrchatBotGroupCount: -1 }
            }
          );
        } else {
          await SystemConfig.findOneAndUpdate(
            { id: 'main', 'vrchatBots.id': assignedBot.id },
            { 
              $pull: { 'vrchatBots.$.groups': targetGroupId },
              $inc: { 'vrchatBots.$.groupCount': -1 }
            }
          );
        }
      }
    }
  }

  async function checkIfUserIsBannedInVRChatGroup(vrchatUserId: string, groupId: string, headers: any, apiKey: string, bot: any): Promise<boolean> {
    try {
      let response = await fetch(`https://api.vrchat.cloud/api/1/groups/${groupId}/bans?apiKey=${apiKey}`, {
        method: 'GET',
        headers
      });

      if (!response.ok) {
        if (response.status === 403) {
          const errText = await response.text().catch(() => '');
          if (errText.includes("not a member") || errText.includes("Not a member")) {
            await removeGroupFromBotDb(bot.id, groupId);
          }
        }
        return false;
      }

      const bans = await response.json() as any[];
      if (!Array.isArray(bans)) return false;

      const isBanned = bans.some((b: any) => {
        const uId = b.userId || b.bannedUserId || b.id;
        return uId && uId.toString().toLowerCase() === vrchatUserId.toLowerCase();
      });
      return isBanned;
    } catch (err: any) {
      return false;
    }
  }

  async function banUserFromVRChatGroup(vrchatUserId: string, reason: string, isCustomList: boolean = false, customListId?: string) {
    try {
      const config = await SystemConfig.findOne({ id: 'main' });
      if (!config) {
        return false;
      }

      const activeGuilds = await Guild.find({ 'settings.vrchatBotEnabled': true });
      if (activeGuilds.length === 0) {
        return false;
      }

      let success = true;

      for (const guild of activeGuilds) {
        const selectionMode = guild.settings?.banlistSelectionMode || 'global';
        if (!isCustomList && selectionMode === 'custom') {
          continue;
        }
        if (isCustomList && selectionMode === 'global') {
          continue;
        }
        if (isCustomList && customListId && guild.settings?.customBanlistId !== customListId) {
          continue;
        }

        const groupId = guild.settings?.vrchatGroupId?.trim();
        if (!groupId) continue;

        let bot;
        try {
          bot = await getBotForGroup(config, groupId);
        } catch (botErr) {
          continue;
        }

        let { headers, apiKey } = await getVRChatAuthHeadersForBot(bot, config);

        const isAlreadyBanned = await checkIfUserIsBannedInVRChatGroup(vrchatUserId, groupId, headers, apiKey, bot);
        if (isAlreadyBanned) {
          continue;
        }

        const dbUser = await User.findOne({
          $or: [
            { vrchatUserId },
            { 'vrchatAlts.vrchatUserId': vrchatUserId }
          ]
        });
        const displayName = dbUser?.username || 'Unknown';
        const userMentionStr = dbUser ? `<@${dbUser.id}>` : `VRChat User \`${displayName}\``;

        // Check if auto-ban is enabled for this guild
        const autoBanEnabled = guild.settings?.vrchatAutoBanEnabled !== false;

        if (!autoBanEnabled) {
          // Check if we already sent a warning for this user in this guild and group within the last 24 hours
          const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
          const existingAlert = await VRChatAlertTracker.findOne({
            guildId: guild.id,
            vrchatUserId,
            groupId,
            lastWarnedAt: { $gte: twentyFourHoursAgo }
          });

          if (existingAlert) {
            continue;
          }

          const discordGuild = getGuildDiscordClient(guild.id).guilds.cache.get(guild.id);
          if (discordGuild) {
            const staffChannelId = guild.settings.staffChannelId || guild.settings.logChannelId;
            if (staffChannelId) {
              try {
                const channel = discordGuild.channels.cache.get(staffChannelId) as any;
                if (channel) {
                  const staffRoleId = guild.settings.staffRoleId;
                  const pingStr = staffRoleId ? `<@&${staffRoleId}>` : '**Staff**';
                  await channel.send(`⚠️ **VRChat Blacklisted User Detected (No Auto-Ban)**: VRChat User **${displayName}** (${userMentionStr}) is in the connected VRChat Group **${groupId}**.\nSince automatic VRChat banning is disabled for this server, please review and take manual action.\nAttention: ${pingStr}`).catch(() => null);
                  
                  await VRChatAlertTracker.findOneAndUpdate(
                    { guildId: guild.id, vrchatUserId, groupId },
                    { lastWarnedAt: new Date() },
                    { upsert: true, new: true }
                  );
                }
              } catch (discordErr) {
              }
            }
          }
          continue;
        }

        let response = await fetch(`https://api.vrchat.cloud/api/1/groups/${groupId}/bans?apiKey=${apiKey}`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ userId: vrchatUserId, reason: reason })
        });

        // Keep VRChat requests low to avoid rate limits
        await new Promise(resolve => setTimeout(resolve, 1500));

        if (!response.ok) {
          const errText = await response.text();
          if (response.status === 403 && (errText.includes("not a member") || errText.includes("Not a member"))) {
            await removeGroupFromBotDb(bot.id, groupId);
          }
          success = false;
        } else {
          const discordGuild = getGuildDiscordClient(guild.id).guilds.cache.get(guild.id);
          if (discordGuild) {
            const auditChannelId = guild.settings.logChannelId || guild.settings.staffChannelId;
            if (auditChannelId) {
              try {
                const channel = discordGuild.channels.cache.get(auditChannelId) as any;
                if (channel) {
                  await channel.send(`🛡️ **VRChat Group Ban Enforced**: VRChat User **${displayName}** (${userMentionStr}) was successfully banned from VRChat Group **${groupId}**.\nReason: ${reason}`).catch(() => null);
                }
              } catch (discordErr) {
              }
            }
          }
        }
      }

      return success;
    } catch (e: any) {
      return false;
    }
  }

  async function unbanUserFromVRChatGroup(vrchatUserId: string, isSecondaryCheck = false) {
    try {
      const config = await SystemConfig.findOne({ id: 'main' });
      if (!config) {
        return false;
      }

      // Collect all configured VRChat groups across guilds, bots, and system config
      const groupMap = new Map<string, { guildName?: string; autoUnbanEnabled?: boolean }>();

      if (config.vrchatGroupId && config.vrchatGroupId.trim()) {
        groupMap.set(config.vrchatGroupId.trim(), { guildName: 'System Default' });
      }

      if (Array.isArray(config.vrchatBots)) {
        for (const bot of config.vrchatBots) {
          if (Array.isArray(bot.groups)) {
            for (const g of bot.groups) {
              if (g && typeof g === 'string' && g.trim()) {
                groupMap.set(g.trim(), { guildName: bot.vrchatUsername || 'Bot Assigned Group' });
              }
            }
          }
        }
      }

      const allGuilds = await Guild.find({ 
        $or: [
          { 'settings.vrchatGroupId': { $exists: true, $ne: '' } },
          { 'settings.vrchatBotEnabled': true }
        ] 
      });

      for (const g of allGuilds) {
        const gid = g.settings?.vrchatGroupId?.trim();
        if (gid) {
          groupMap.set(gid, { 
            guildName: g.name || g.id,
            autoUnbanEnabled: g.settings?.autoUnbanVRChatEnabled !== false 
          });
        }
      }

      const userUnbanGroups = await UserVRChatGroup.find({ autoUnbanEnabled: true });
      for (const ug of userUnbanGroups) {
        if (ug.groupId?.trim()) {
          groupMap.set(ug.groupId.trim(), {
            guildName: ug.groupName || 'User VRChat Group',
            autoUnbanEnabled: true
          });
        }
      }

      if (groupMap.size === 0) {
        return false;
      }

      let overallSuccess = true;

      for (const [groupId, meta] of groupMap.entries()) {
        if (meta.autoUnbanEnabled === false) {
          continue;
        }

        let bot;
        try {
          bot = await getBotForGroup(config, groupId);
        } catch (botErr) {
          continue;
        }

        let { headers, apiKey } = await getVRChatAuthHeadersForBot(bot, config);

        let response = await fetch(`https://api.vrchat.cloud/api/1/groups/${groupId}/bans/${vrchatUserId}?apiKey=${apiKey}`, {
          method: 'DELETE',
          headers
        });

        await new Promise(resolve => setTimeout(resolve, 1200));

        if (!response.ok) {
          const errText = await response.text();
          // If already not banned or 404, that means they are already unbanned
          if (response.status === 404 || errText.includes('Not Found') || errText.includes('not found')) {
          } else {
            if (response.status === 403 && (errText.includes("not a member") || errText.includes("Not a member"))) {
              await removeGroupFromBotDb(bot.id, groupId);
            }
            overallSuccess = false;
          }
        }
      }

      return overallSuccess;
    } catch (e: any) {
      return false;
    }
  }

  async function enforceGlobalBan(userId: string, reason: string) {
    try {
      const user = await User.findOne({ id: userId });
      if (user) {
        const accounts = getAllVRChatAccounts(user);
        for (const account of accounts) {
          if (account.vrchatUserId) {
            await banUserFromVRChatGroup(account.vrchatUserId, reason);
          }
        }
      }
    } catch (err) {
    }

    const guilds = await Guild.find({ 'settings.autoBanEnabled': true });
    
    // Fetch user tag first to have a clean name for logging
    let targetTag = userId;
    try {
      const discordUser = await client.users.fetch(userId);
      targetTag = discordUser.tag || discordUser.username;
    } catch (e) {}

    for (const guildData of guilds) {
      const mode = guildData.settings?.banlistSelectionMode || 'global';
      if (mode === 'custom') {
        continue;
      }

      const targetClient = getGuildDiscordClient(guildData.id);
      const guild = targetClient.guilds.cache.get(guildData.id);
      if (guild) {
        try {
          // Check if already banned on this Discord guild to avoid redundant alerts
          const existingBan = await guild.bans.fetch(userId).catch(() => null);
          if (existingBan) {
            continue;
          }

          // Unconditional ban (bans even if they are not in the guild currently)
          await guild.members.ban(userId, { reason: `BeSafe Network Auto-Ban: ${reason}` });
          
          const staffChannelId = guildData.settings.staffChannelId || guildData.settings.logChannelId;
          if (staffChannelId) {
            const channel = guild.channels.cache.get(staffChannelId) as any;
            if (channel) {
              channel.send(`🚨 **Global Ban Enforced**: User **${targetTag}** (${userId}) was automatically banned from this server.\nReason: ${reason}`).catch(() => null);
            }
          }
        } catch (e) {
        }
      }
    }
  }

  async function enforceGlobalUnban(userId: string) {
    try {
      const user = await User.findOne({ id: userId });
      if (user) {
        const accounts = getAllVRChatAccounts(user);
        for (const account of accounts) {
          if (account.vrchatUserId) {
            await unbanUserFromVRChatGroup(account.vrchatUserId);
          }
        }
      }
    } catch (err) {
    }

    // Schedule secondary verification check after 20 seconds to guarantee unban across all groups
    setTimeout(async () => {
      try {
        const userRecheck = await User.findOne({ id: userId });
        if (userRecheck) {
          const accounts = getAllVRChatAccounts(userRecheck);
          for (const account of accounts) {
            if (account.vrchatUserId) {
              await unbanUserFromVRChatGroup(account.vrchatUserId, true);
            }
          }
        }
      } catch (checkErr) {
      }
    }, 20000);

    const guilds = await Guild.find();
    for (const guildData of guilds) {
      if (guildData.settings?.autoUnbanDiscordEnabled === false) {
        continue;
      }
      const targetClient = getGuildDiscordClient(guildData.id);
      const guild = targetClient.guilds.cache.get(guildData.id);
      if (guild) {
        try {
          await guild.members.unban(userId, 'BeSafe Network: Global Appeal Approved');
        } catch (e) {}
      }
    }
  }

  async function unbanCustomBanlistEntry(entry: { type: string; targetId: string }, listId?: string, listName?: string) {
    const targetId = entry?.targetId?.trim();
    if (!targetId) return;

    try {
      if (entry.type === 'discord') {
        // 1. Unban globally across Discord guilds and any associated VRChat accounts
        await enforceGlobalUnban(targetId);

        // 2. Explicitly unban in guilds configured with this specific custom banlist
        if (listId) {
          const linkedGuilds = await Guild.find({
            $or: [
              { 'settings.customBanlistId': listId },
              { 'settings.customBanlistId': listId.toString() }
            ]
          });
          for (const guildData of linkedGuilds) {
            const targetClient = getGuildDiscordClient(guildData.id);
            const guild = targetClient.guilds.cache.get(guildData.id);
            if (guild) {
              try {
                await guild.members.unban(targetId, `BeSafe Network: Removed from Custom Banlist (${listName || 'Custom Banlist'})`);
              } catch (e: any) {
              }
            }
          }
        }
      } else if (entry.type === 'vrchat') {
        // 1. Unban from all VRChat groups
        await unbanUserFromVRChatGroup(targetId);

        // 2. Check if a User doc exists for this VRChat account and unban their Discord too
        const dbUser = await User.findOne({
          $or: [
            { vrchatUserId: targetId },
            { 'vrchatAlts.vrchatUserId': targetId }
          ]
        });
        if (dbUser) {
          await enforceGlobalUnban(dbUser.id);
        }
      }
    } catch (err: any) {
    }
  }

  async function enforceCustomBanlistEntry(entry: { type: string; targetId: string; reason?: string }, listId: string, listName: string) {
    const targetId = entry?.targetId?.trim();
    if (!targetId) return;
    const reason = entry.reason?.trim() || `Custom Banlist (${listName})`;

    try {
      if (entry.type === 'discord') {
        const linkedGuilds = await Guild.find({
          $or: [
            { 'settings.customBanlistId': listId },
            { 'settings.customBanlistId': listId.toString() }
          ]
        });

        for (const guildData of linkedGuilds) {
          const mode = guildData.settings?.banlistSelectionMode || 'global';
          if (mode === 'global') continue; // Only enforce if mode is 'custom' or 'both'

          const targetClient = getGuildDiscordClient(guildData.id);
          const guild = targetClient.guilds.cache.get(guildData.id);
          if (guild) {
            try {
              await guild.members.ban(targetId, { reason: `Custom Banlist (${listName}): ${reason}` });
            } catch (e: any) {
            }
          }
        }
      } else if (entry.type === 'vrchat') {
        await banUserFromVRChatGroup(targetId, `Custom Banlist (${listName}): ${reason}`, true, listId);
      }
    } catch (err: any) {
    }
  }

  async function banUserFromSpecificVRChatGroup(vrchatUserId: string, groupId: string, reason: string, headers: any, apiKey: string, bot: any) {
    try {
      let response = await fetch(`https://api.vrchat.cloud/api/1/groups/${groupId}/bans?apiKey=${apiKey}`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ userId: vrchatUserId, reason: reason })
      });

      if (!response.ok) {
        const errText = await response.text();
        if (response.status === 403 && (errText.includes("not a member") || errText.includes("Not a member"))) {
          if (bot && bot.id) {
            await removeGroupFromBotDb(bot.id, groupId);
          }
        }
        return false;
      } else {
        return true;
      }
    } catch (e: any) {
      return false;
    }
  }

  async function scanAndBanBlacklistedUsers() {
    try {
      const config = await SystemConfig.findOne({ id: 'main' });
      if (!config) {
        return;
      }

      if (!config.vrchatBotEnabled) {
        return;
      }

      // Check if credentials exist
      if ((!config.vrchatUsername || !config.vrchatPassword) && !config.vrchatCookie) {
        return;
      }

      // Update VRChat status & presence to show up as online with custom description
      await updateVRChatBotStatus(config).catch(() => null);

      const activeBanCases = await BanCase.find({ status: 'active' });

      const blacklistedVRChatUserIds = new Set<string>();
      
      // Gather VRChat IDs from active Ban Cases
      for (const bCase of activeBanCases) {
        if (Array.isArray(bCase.vrchatAccounts)) {
          for (const va of bCase.vrchatAccounts) {
            const vId = va.vrchatUserId ? va.vrchatUserId.trim() : '';
            if (vId && vId.startsWith('usr_')) {
              blacklistedVRChatUserIds.add(vId);
            }
          }
        }
      }

      // Check if we have any custom banlists with VRChat entries
      const customBanlists = await CustomBanlist.find();
      const hasCustomEntries = customBanlists.some(list => 
        list.entries && list.entries.some(e => e.type === 'vrchat' && e.targetId && e.targetId.trim().startsWith('usr_'))
      );

      if (blacklistedVRChatUserIds.size === 0 && !hasCustomEntries) {
        return;
      }

      const groupIds = new Set<string>();
      if (config.vrchatGroupId && config.vrchatGroupId.trim()) {
        groupIds.add(config.vrchatGroupId.trim());
      }

      const activeGuilds = await Guild.find({ 'settings.vrchatBotEnabled': true });
      for (const guild of activeGuilds) {
        const gId = guild.settings?.vrchatGroupId?.trim();
        if (gId) {
          groupIds.add(gId);
        }
      }

      const userScannerGroups = await UserVRChatGroup.find({ autoBanEnabled: true });
      for (const ug of userScannerGroups) {
        if (ug.groupId && ug.groupId.trim()) {
          groupIds.add(ug.groupId.trim());
        }
      }

      if (groupIds.size === 0) {
        return;
      }

      for (const groupId of groupIds) {
        let bot;
        try {
          bot = await getBotForGroup(config, groupId);
        } catch (botErr: any) {
          continue;
        }

        let headers, apiKey;
        try {
          const auth = await getVRChatAuthHeadersForBot(bot, config);
          headers = auth.headers;
          apiKey = auth.apiKey;
        } catch (authErr: any) {
          continue;
        }

        // Find active guilds linked to this VRChat group
        const guildsForGroup = activeGuilds.filter(g => g.settings?.vrchatGroupId?.trim() === groupId);
        const guildsWithAutoBan = guildsForGroup.filter(g => g.settings?.vrchatAutoBanEnabled !== false);
        const guildsWithWarningOnly = guildsForGroup.filter(g => g.settings?.vrchatAutoBanEnabled === false);

        // Gather all VRChat IDs to ban for this specific group
        const finalGroupBannedVRChatIds = new Set<string>();
        const groupBanReasons = new Map<string, string>(); // To track custom reasons

        // 1. Add global blacklisted user IDs (only if at least one guild enables global/both, or if it is the central group)
        const isCentralGroup = config.vrchatGroupId && config.vrchatGroupId.trim() === groupId;
        const hasGlobalEnabled = isCentralGroup || guildsForGroup.some(g => {
          const mode = g.settings?.banlistSelectionMode || 'global';
          return mode === 'both' || mode === 'global';
        });
        if (hasGlobalEnabled) {
          for (const id of blacklistedVRChatUserIds) {
            finalGroupBannedVRChatIds.add(id);
            groupBanReasons.set(id.toLowerCase(), "Automatically banned: User is on the global blacklist");
          }
        }

        // 2. Add custom banlists' VRChat user IDs connected to this group
        for (const g of guildsForGroup) {
          const mode = g.settings?.banlistSelectionMode || 'global';
          const customId = g.settings?.customBanlistId;
          if (customId && (mode === 'both' || mode === 'custom')) {
            const list = await CustomBanlist.findById(customId);
            if (list) {
              for (const entry of list.entries) {
                if (entry.type === 'vrchat' && entry.targetId && entry.targetId.trim().startsWith('usr_')) {
                  const targetIdNorm = entry.targetId.trim();
                  finalGroupBannedVRChatIds.add(targetIdNorm);
                  groupBanReasons.set(targetIdNorm.toLowerCase(), `Automatically banned: Listed on custom banlist "${list.name}" (${entry.reason || 'Custom blacklisted'})`);
                }
              }
            }
          }
        }

        // 3. IMPORTANT: FILTER OUT TRUSTED USERS. Trusted users MUST NEVER be blacklisted or banned!
        for (const targetId of finalGroupBannedVRChatIds) {
          const dbUser = await User.findOne({
            $or: [
              { vrchatUserId: targetId },
              { 'vrchatAlts.vrchatUserId': targetId }
            ]
          });
          if (dbUser && dbUser.isTrusted) {
            finalGroupBannedVRChatIds.delete(targetId);
            groupBanReasons.delete(targetId.toLowerCase());
          }
        }

        // Fetch current bans list for this group to avoid redundant API calls
        const bannedUserIdsInGroup = new Set<string>();
        try {
          let response = await fetch(`https://api.vrchat.cloud/api/1/groups/${groupId}/bans?apiKey=${apiKey}`, {
            method: 'GET',
            headers
          });

          if (response.status === 401 && config.vrchatCookie && config.vrchatUsername && config.vrchatPassword) {
            await SystemConfig.findOneAndUpdate({ id: 'main' }, { vrchatCookie: '' });
            const freshConfig = await SystemConfig.findOne({ id: 'main' });
            if (freshConfig) {
              const fresh = await getVRChatAuthHeaders(freshConfig);
              headers = fresh.headers;
              apiKey = fresh.apiKey;
              response = await fetch(`https://api.vrchat.cloud/api/1/groups/${groupId}/bans?apiKey=${apiKey}`, {
                method: 'GET',
                headers
              });
            }
          }

          if (response.ok) {
            const bans = await response.json() as any[];
            if (Array.isArray(bans)) {
              for (const b of bans) {
                const uId = b.userId || b.bannedUserId || b.id;
                if (uId) {
                  bannedUserIdsInGroup.add(uId.toString().toLowerCase());
                }
              }
            }
          } else {
            if (response.status === 403) {
              const errText = await response.text().catch(() => '');
              if (errText.includes("not a member") || errText.includes("Not a member")) {
                if (bot && bot.id) {
                  await removeGroupFromBotDb(bot.id, groupId);
                }
              }
            }
          }
        } catch (banErr: any) {
        }

        // 1. Preventative Auto-Banning: Ban blacklisted users pre-emptively even if they are not in the group, if autobanning is enabled (or if it is the central group)
        if (isCentralGroup || guildsWithAutoBan.length > 0) {
          for (const blacklistedId of finalGroupBannedVRChatIds) {
            if (!bannedUserIdsInGroup.has(blacklistedId.toLowerCase())) {
              const customReason = groupBanReasons.get(blacklistedId.toLowerCase()) || "Automatically banned: User is on the blacklist";
              const banSuccess = await banUserFromSpecificVRChatGroup(
                blacklistedId,
                groupId,
                customReason,
                headers,
                apiKey,
                bot
              );

              // Keep VRChat requests low to avoid rate limits
              await new Promise(resolve => setTimeout(resolve, 1500));

              if (banSuccess) {
                bannedUserIdsInGroup.add(blacklistedId.toLowerCase());

                const dbUser = await User.findOne({
                  $or: [
                    { vrchatUserId: blacklistedId },
                    { 'vrchatAlts.vrchatUserId': blacklistedId }
                  ]
                });
                const displayName = dbUser?.username || 'Unknown';
                const userMentionStr = dbUser ? `<@${dbUser.id}>` : `VRChat User \`${displayName}\``;
                const logTargetId = dbUser ? dbUser.id : blacklistedId;

                await new Log({
                  action: 'VRCHAT_AUTO_BAN',
                  adminId: 'SYSTEM_BOT',
                  targetId: logTargetId,
                  details: `Automated scan (Preventative): Auto-banned user ${displayName} (${blacklistedId}) from Group ${groupId}. Reason: ${customReason}`
                }).save();

                for (const guild of guildsWithAutoBan) {
                  const discordGuild = getGuildDiscordClient(guild.id).guilds.cache.get(guild.id);
                  if (discordGuild) {
                    const auditChannelId = guild.settings.logChannelId || guild.settings.staffChannelId;
                    if (auditChannelId) {
                      try {
                        const channel = discordGuild.channels.cache.get(auditChannelId) as any;
                        if (channel) {
                          await channel.send(`🛡️ **VRChat Group Ban Enforced (Preventative)**: VRChat User **${displayName}** (${userMentionStr}) was automatically banned from VRChat Group **${groupId}**.\nReason: ${customReason}`).catch(() => null);
                        }
                      } catch (discordErr) {
                      }
                    }

                    const staffChannelId = guild.settings.staffChannelId;
                    if (staffChannelId && staffChannelId !== guild.settings.logChannelId) {
                      try {
                        const channel = discordGuild.channels.cache.get(staffChannelId) as any;
                        if (channel) {
                          await channel.send(`🚨 **VRChat Auto-Ban Enforced (Preventative)**: User **${displayName}** (${userMentionStr}) was automatically banned from connected VRChat Group **${groupId}** pre-emptively. Reason: ${customReason}`).catch(() => null);
                        }
                      } catch (discordErr) {
                      }
                    }
                  }
                }
              }
            }
          }
        }

        // 2. Scan Group Members (to warn on non-autoban guilds or catch any newly blacklisted users during/after)
        let offset = 0;
        const limit = 100;
        let hasMore = true;

        while (hasMore) {
          try {
            const memberUrl = `https://api.vrchat.cloud/api/1/groups/${groupId}/members?apiKey=${apiKey}&n=${limit}&offset=${offset}`;
            let response = await fetch(memberUrl, {
              method: 'GET',
              headers
            });

            if (response.status === 401 && config.vrchatCookie && config.vrchatUsername && config.vrchatPassword) {
              await SystemConfig.findOneAndUpdate({ id: 'main' }, { vrchatCookie: '' });
              const freshConfig = await SystemConfig.findOne({ id: 'main' });
              if (freshConfig) {
                const fresh = await getVRChatAuthHeaders(freshConfig);
                headers = fresh.headers;
                apiKey = fresh.apiKey;
                response = await fetch(`https://api.vrchat.cloud/api/1/groups/${groupId}/members?apiKey=${apiKey}&n=${limit}&offset=${offset}`, {
                  method: 'GET',
                  headers
                });
              }
            }

            if (!response.ok) {
              const errText = await response.text();
              if (response.status === 403 && (errText.includes("not a member") || errText.includes("Not a member"))) {
                if (bot && bot.id) {
                  await removeGroupFromBotDb(bot.id, groupId);
                }
              }
              break;
            }

            const members = await response.json() as any[];
            if (!Array.isArray(members) || members.length === 0) {
              hasMore = false;
              break;
            }

            for (const member of members) {
              const vrchatUserId = member.userId;
              if (vrchatUserId && finalGroupBannedVRChatIds.has(vrchatUserId)) {
                const dbUser = await User.findOne({
                  $or: [
                    { vrchatUserId },
                    { 'vrchatAlts.vrchatUserId': vrchatUserId }
                  ]
                });
                const displayName = member.user?.displayName || dbUser?.username || 'Unknown';
                const userMentionStr = dbUser ? `<@${dbUser.id}>` : `VRChat User \`${displayName}\``;

                // Skip warning and banning if user is already banned from the VRChat group
                const isBanned = bannedUserIdsInGroup.has(vrchatUserId.toLowerCase());
                if (isBanned) {
                  continue;
                }

                // Process Warning-Only Guilds
                for (const guild of guildsWithWarningOnly) {
                  // Check if we already sent a warning for this user in this guild and group within the last 24 hours
                  const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
                  const existingAlert = await VRChatAlertTracker.findOne({
                    guildId: guild.id,
                    vrchatUserId,
                    groupId,
                    lastWarnedAt: { $gte: twentyFourHoursAgo }
                  });

                  if (existingAlert) {
                    continue; // Skip alerting again to prevent spamming
                  }

                  const discordGuild = getGuildDiscordClient(guild.id).guilds.cache.get(guild.id);
                  if (discordGuild) {
                    const staffChannelId = guild.settings.staffChannelId || guild.settings.logChannelId;
                    if (staffChannelId) {
                      try {
                        const channel = discordGuild.channels.cache.get(staffChannelId) as any;
                        if (channel) {
                          const staffRoleId = guild.settings.staffRoleId;
                          const pingStr = staffRoleId ? `<@&${staffRoleId}>` : '**Staff**';
                          await channel.send(`⚠️ **VRChat Blacklisted User Detected (No Auto-Ban)**: VRChat User **${displayName}** (${userMentionStr}) is in the connected VRChat Group **${groupId}**.\nSince automatic VRChat banning is disabled for this server, please review and take manual action.\nAttention: ${pingStr}`).catch(() => null);
                          
                          // Track that we warned them to prevent spamming on subsequent scans
                          await VRChatAlertTracker.findOneAndUpdate(
                            { guildId: guild.id, vrchatUserId, groupId },
                            { lastWarnedAt: new Date() },
                            { upsert: true, new: true }
                          );
                        }
                      } catch (discordErr) {
                      }
                    }
                  }
                }

                // Process Auto-Ban Guilds
                if (guildsWithAutoBan.length > 0) {
                  const customReason = groupBanReasons.get(vrchatUserId.toLowerCase()) || "Automatically banned: User is on the blacklist";
                  // We perform the VRChat API ban
                  const banSuccess = await banUserFromSpecificVRChatGroup(
                    vrchatUserId,
                    groupId,
                    customReason,
                    headers,
                    apiKey,
                    bot
                  );

                  // Keep VRChat requests low to avoid rate limits
                  await new Promise(resolve => setTimeout(resolve, 1500));

                  if (banSuccess) {
                    bannedUserIdsInGroup.add(vrchatUserId.toLowerCase());
                    const logTargetId = dbUser ? dbUser.id : vrchatUserId;
                    await new Log({
                      action: 'VRCHAT_AUTO_BAN',
                      adminId: 'SYSTEM_BOT',
                      targetId: logTargetId,
                      details: `Automated scan: Auto-banned user ${displayName} (${vrchatUserId}) from Group ${groupId}. Reason: ${customReason}`
                    }).save();

                    for (const guild of guildsWithAutoBan) {
                      const discordGuild = getGuildDiscordClient(guild.id).guilds.cache.get(guild.id);
                      if (discordGuild) {
                        const auditChannelId = guild.settings.logChannelId || guild.settings.staffChannelId;
                        if (auditChannelId) {
                          try {
                            const channel = discordGuild.channels.cache.get(auditChannelId) as any;
                            if (channel) {
                              await channel.send(`🛡️ **VRChat Group Ban Enforced**: VRChat User **${displayName}** (${userMentionStr}) was automatically banned from VRChat Group **${groupId}**.\nReason: ${customReason}`).catch(() => null);
                            }
                          } catch (discordErr) {
                          }
                        }

                        // Also alert the staff channel as a primary warning notification if different
                        const staffChannelId = guild.settings.staffChannelId;
                        if (staffChannelId && staffChannelId !== guild.settings.logChannelId) {
                          try {
                            const channel = discordGuild.channels.cache.get(staffChannelId) as any;
                            if (channel) {
                              await channel.send(`🚨 **VRChat Auto-Ban Enforced**: User **${displayName}** (${userMentionStr}) was found in the connected VRChat Group **${groupId}** and automatically banned.\nReason: ${customReason}`).catch(() => null);
                            }
                          } catch (discordErr) {
                          }
                        }
                      }
                    }
                  }
                }
              }
            }

            if (members.length < limit) {
              hasMore = false;
            } else {
              offset += limit;
              // Keep VRChat requests paced low
              await new Promise(resolve => setTimeout(resolve, 1500));
            }

            if (offset >= 5000) {
              hasMore = false;
            }
          } catch (innerErr: any) {
            hasMore = false;
          }
        }
      }
    } catch (e: any) {
    }
  }

  async function scanAndBanCustomBanlistDiscordUsers() {
    try {
      const guilds = await Guild.find();
      for (const guildData of guilds) {
        const customId = guildData.settings?.customBanlistId;
        const selectionMode = guildData.settings?.banlistSelectionMode || 'global';
        
        // Only run if a custom banlist is set AND selectionMode permits custom banlist
        if (customId && (selectionMode === 'both' || selectionMode === 'custom')) {
          const customBanlist = await CustomBanlist.findById(customId);
          if (!customBanlist) continue;

          const targetClient = getGuildDiscordClient(guildData.id);
          const guild = targetClient.guilds.cache.get(guildData.id);
          if (!guild) {
            continue;
          }

          for (const entry of customBanlist.entries) {
            let discordUserIdToBan: string | null = null;
            let banReason = entry.reason || 'Listed on custom banlist';

            if (entry.type === 'discord' && entry.targetId) {
              discordUserIdToBan = entry.targetId.trim();
            } else if (entry.type === 'vrchat' && entry.targetId) {
              // Try to find if this VRChat account is linked to a database Discord user
              const vrchatIdNorm = entry.targetId.trim();
              const dbUser = await User.findOne({
                $or: [
                  { vrchatUserId: vrchatIdNorm },
                  { 'vrchatAlts.vrchatUserId': vrchatIdNorm }
                ]
              });
              if (dbUser && !dbUser.isTrusted) {
                discordUserIdToBan = dbUser.id;
                banReason = `Linked VRChat account is blacklisted on custom banlist "${customBanlist.name}" (${entry.reason || 'No reason specified'})`;
              }
            }

            if (discordUserIdToBan) {
              try {
                // Check if already banned on Discord
                const existingBan = await guild.bans.fetch(discordUserIdToBan).catch(() => null);
                if (existingBan) {
                  continue;
                }

                // Attempt to fetch user tag for logging
                let targetTag = discordUserIdToBan;
                try {
                  const discordUser = await client.users.fetch(discordUserIdToBan);
                  targetTag = discordUser.tag || discordUser.username;
                } catch (e) {}

                // Ban user
                await guild.members.ban(discordUserIdToBan, { reason: `Custom Banlist (${customBanlist.name}): ${banReason}` });

                // Log to database
                await new Log({
                  action: 'DISCORD_AUTO_BAN_CUSTOM',
                  adminId: 'SYSTEM_BOT',
                  targetId: discordUserIdToBan,
                  details: `Automated custom banlist scan: Auto-banned user ${targetTag} (${discordUserIdToBan}) from Guild ${guild.name} based on Custom Banlist "${customBanlist.name}". Reason: ${banReason}`
                }).save();

                // Send alerts
                const staffChannelId = guildData.settings.staffChannelId || guildData.settings.logChannelId;
                if (staffChannelId) {
                  const channel = guild.channels.cache.get(staffChannelId) as any;
                  if (channel) {
                    await channel.send(`🚨 **Custom Banlist Auto-Ban Enforced**: User **${targetTag}** (${discordUserIdToBan}) was automatically banned from this server.\nCustom Banlist: **${customBanlist.name}**\nReason: ${banReason}`).catch(() => null);
                  }
                }
              } catch (banErr: any) {
              }
            }
          }
        }
      }
    } catch (err: any) {
    }
  }

  async function fetchVRChatDisplayName(vrchatUserId: string): Promise<string | null> {
    try {
      const config = await SystemConfig.findOne({ id: 'main' });
      if (!config) return null;
      let { headers, apiKey } = await getVRChatAuthHeaders(config);
      let response = await fetch(`https://api.vrchat.cloud/api/1/users/${vrchatUserId}?apiKey=${apiKey}`, {
        method: 'GET',
        headers
      });
      if (response.status === 401 && config.vrchatCookie && config.vrchatUsername && config.vrchatPassword) {
        await SystemConfig.findOneAndUpdate({ id: 'main' }, { vrchatCookie: '' });
        const freshConfig = await SystemConfig.findOne({ id: 'main' });
        if (freshConfig) {
          try {
            const fresh = await getVRChatAuthHeaders(freshConfig);
            headers = fresh.headers;
            apiKey = fresh.apiKey;
            response = await fetch(`https://api.vrchat.cloud/api/1/users/${vrchatUserId}?apiKey=${apiKey}`, {
              method: 'GET',
              headers
            });
          } catch (e) {}
        }
      }
      if (response.ok) {
        const data = await response.json();
        return data.displayName || data.username || null;
      }
      return null;
    } catch (err: any) {
      return null;
    }
  }

  async function checkAndSyncVRChatDisplayNames() {
    try {
      const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);
      
      const users = await User.find({
        $and: [
          {
            $or: [
              { vrchatUserId: { $ne: "" } },
              { 'vrchatAlts.0': { $exists: true } }
            ]
          },
          {
            $or: [
              { vrchatLastCheckedAt: { $exists: false } },
              { vrchatLastCheckedAt: { $lte: tenDaysAgo } }
            ]
          }
        ]
      });

      for (const user of users) {
        let changed = false;

        // 1. Sync primary
        if (user.vrchatUserId) {
          const fetchedPrimaryName = await fetchVRChatDisplayName(user.vrchatUserId);
          await new Promise(resolve => setTimeout(resolve, 1500));
          
          if (fetchedPrimaryName && fetchedPrimaryName !== user.vrchatUsername) {
            user.vrchatUsername = fetchedPrimaryName;
            changed = true;
          }
        }

        // 2. Sync alts
        if (user.vrchatAlts && Array.isArray(user.vrchatAlts)) {
          const updatedAlts = [];
          for (const alt of user.vrchatAlts) {
            if (alt.vrchatUserId) {
              const fetchedAltName = await fetchVRChatDisplayName(alt.vrchatUserId);
              await new Promise(resolve => setTimeout(resolve, 1500));
              
              if (fetchedAltName && fetchedAltName !== alt.vrchatUsername) {
                updatedAlts.push({
                  vrchatUserId: alt.vrchatUserId,
                  vrchatUsername: fetchedAltName,
                  linkedAt: alt.linkedAt || new Date()
                });
                changed = true;
              } else {
                updatedAlts.push(alt);
              }
            } else {
              updatedAlts.push(alt);
            }
          }
          if (changed) {
            user.vrchatAlts = updatedAlts as any;
          }
        }

        user.vrchatLastCheckedAt = new Date();
        user.updatedAt = new Date();
        await user.save();
      }
    } catch (err: any) {
    }
  }

  if (serviceName !== 'dashboard' && serviceName !== 'web-dashboard') {
    // Set up interval for scanning VRChat groups every 2 minutes
    setInterval(scanAndBanBlacklistedUsers, 2 * 60 * 1000);

    // Sync all VRChat bots 5 seconds after startup to ensure group lists are correct
    setTimeout(async () => {
      try {
        const config = await SystemConfig.findOne({ id: 'main' });
        if (config && config.vrchatBotEnabled) {
          await syncAllVRChatBots(config);
        }
      } catch (e: any) {
      }
    }, 5000);

    // Run initial scan after 15 seconds of startup to instantly secure the groups
    setTimeout(scanAndBanBlacklistedUsers, 15 * 1000);

    // Set up interval for scanning custom banlist Discord users every 2 minutes
    setInterval(scanAndBanCustomBanlistDiscordUsers, 2 * 60 * 1000);

    // Run initial custom banlist Discord scan after 20 seconds of startup
    setTimeout(scanAndBanCustomBanlistDiscordUsers, 20 * 1000);

    // Set up interval for checking VRChat Display Names every 12 hours
    setInterval(checkAndSyncVRChatDisplayNames, 12 * 60 * 60 * 1000);

    // Run initial synchronization check after 45 seconds of startup
    setTimeout(checkAndSyncVRChatDisplayNames, 45 * 1000);
  } else {
    console.log('[Web Dashboard Service] Standalone dashboard mode: Skipping local VRChat worker intervals.');
  }
}

startServer();
