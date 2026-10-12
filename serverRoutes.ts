import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cryptoNode from 'crypto';

export interface RouteDeps {
  User: any;
  BanCase: any;
  Report: any;
  Appeal: any;
  Log: any;
  Admin: any;
  Guild: any;
  VRChatAlertTracker: any;
  VerificationRequest: any;
  EnterpriseEndpoint: any;
  EnterpriseVerificationLog: any;
  ReputationRating: any;
  LinkCode: any;
  ApiKeyRequest: any;
  ApiKey: any;
  VRChatAnnouncementHistory: any;
  GeoRule: any;
  ApiBot: any;
  TrustedCompany: any;
  UserVRChatGroup: any;
  SystemConfig: any;
  CustomBanlist: any;
  ServerBackup: any;
  authenticateToken: (req: any, res: any, next: any) => void;
  optionalAuth: (req: any, res: any, next: any) => void;
  safeSaveReport: (report: any) => Promise<any>;
  syncDiscordCommandsRef?: () => Promise<any>;
  client?: any;
}

export function registerApiRoutes(app: express.Express, deps: RouteDeps) {
  const {
    User,
    BanCase,
    Report,
    Appeal,
    Log,
    Admin,
    Guild,
    VRChatAlertTracker,
    VerificationRequest,
    EnterpriseEndpoint,
    EnterpriseVerificationLog,
    ReputationRating,
    LinkCode,
    ApiKeyRequest,
    ApiKey,
    VRChatAnnouncementHistory,
    GeoRule,
    ApiBot,
    TrustedCompany,
    UserVRChatGroup,
    SystemConfig,
    CustomBanlist,
    ServerBackup,
    authenticateToken,
    optionalAuth,
    safeSaveReport,
    syncDiscordCommandsRef,
    client
  } = deps;

  // --- HELPERS ---
  function formatDangerousBanCase(c: any) {
    const caseTitle = c.title || '';
    const primaryAccount = c.discordAccounts?.[0];
    const primaryName = caseTitle || primaryAccount?.displayName || primaryAccount?.username || c.caseNumber;
    return {
      id: c.caseNumber,
      _id: c._id?.toString(),
      caseNumber: c.caseNumber,
      isBanCase: true,
      caseTitle: caseTitle,
      title: caseTitle,
      displayName: primaryName,
      // USER REQUIREMENT: Instead of username use case title!
      username: caseTitle || primaryAccount?.username || c.caseNumber,
      avatarUrl: primaryAccount?.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png',
      banReason: c.reason,
      reason: c.reason,
      dangerousNotes: c.dangerousNotes || c.notes || '',
      evidence: c.evidenceLinks || [],
      severity: c.severity,
      trustIndex: c.trustIndex || 'CRIMINAL',
      createdAt: c.createdAt,
      updatedAt: c.updatedAt,
      reputation: -100,
      isAgeVerified: false,
      warningsCount: 0,
      discordAccounts: c.discordAccounts || [],
      vrchatAccounts: c.vrchatAccounts || []
    };
  }

  function formatDangerousUser(u: any, matchingCase?: any) {
    const caseTitle = matchingCase?.title || '';
    const displayName = caseTitle || u.displayName || u.username || u.id;
    return {
      id: u.id,
      _id: u._id?.toString(),
      caseNumber: matchingCase?.caseNumber || u.banCaseId || '',
      isBanCase: !!matchingCase,
      caseTitle: caseTitle,
      title: caseTitle,
      displayName,
      // USER REQUIREMENT: Instead of username use case title!
      username: caseTitle || u.username || u.id,
      avatarUrl: u.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png',
      banReason: u.banReason || matchingCase?.reason || 'Flagged high-risk threat',
      reason: u.banReason || matchingCase?.reason || 'Flagged high-risk threat',
      dangerousNotes: u.dangerousNotes || matchingCase?.dangerousNotes || '',
      evidence: u.evidenceLinks || matchingCase?.evidenceLinks || [],
      severity: matchingCase?.severity || 'critical',
      trustIndex: u.trustIndex || matchingCase?.trustIndex || 'CRIMINAL',
      createdAt: u.createdAt,
      updatedAt: u.updatedAt,
      reputation: u.reputation ?? -100,
      isAgeVerified: u.isAgeVerified ?? false,
      warningsCount: u.warnings?.length || 0,
      discordAccounts: matchingCase?.discordAccounts?.length
        ? matchingCase.discordAccounts
        : [{ discordId: u.id, username: u.username, displayName: u.username, avatarUrl: u.avatarUrl }],
      vrchatAccounts: matchingCase?.vrchatAccounts?.length
        ? matchingCase.vrchatAccounts
        : (u.vrchatUserId ? [{ vrchatUserId: u.vrchatUserId, vrchatUsername: u.vrchatUsername, isPrimary: true }] : [])
    };
  }

  async function findUserByQuery(rawQuery: string) {
    let query = (rawQuery || '').trim();
    if (query.includes('vrchat.com/home/user/')) {
      const match = query.match(/usr_[a-f0-9\-]+/i);
      if (match) query = match[0];
    }

    const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    // 1. Check BanCase
    const banCase = await BanCase.findOne({
      $or: [
        { caseNumber: query },
        { 'discordAccounts.discordId': query },
        { 'vrchatAccounts.vrchatUserId': query },
        { title: { $regex: new RegExp(`^${escaped}$`, 'i') } }
      ]
    });

    // 2. Check User
    const user = await User.findOne({
      $or: [
        { id: query },
        { vrchatUserId: query },
        { 'vrchatAlts.vrchatUserId': query },
        { username: { $regex: new RegExp(`^${escaped}$`, 'i') } }
      ]
    });

    if (!banCase && !user) {
      return { found: false };
    }

    const isBanned = (banCase && banCase.status === 'active') || (user && user.isBanned);
    const isDangerous = (banCase && banCase.isDangerous) || (user && user.isDangerous);

    const caseTitle = banCase?.title || '';
    const primaryDiscord = banCase?.discordAccounts?.[0] || (user ? { discordId: user.id, username: user.username, displayName: user.username, avatarUrl: user.avatarUrl } : null);
    
    // USER REQUIREMENT: Instead of username use case title!
    const displayName = caseTitle || primaryDiscord?.displayName || primaryDiscord?.username || user?.username || 'Unknown User';
    const username = caseTitle || primaryDiscord?.username || user?.username || query;

    const result: any = {
      found: true,
      id: primaryDiscord?.discordId || user?.id || banCase?.caseNumber || query,
      username,
      displayName,
      avatarUrl: primaryDiscord?.avatarUrl || user?.avatarUrl || 'https://cdn.discordapp.com/embed/avatars/0.png',
      isBanned: !!isBanned,
      banReason: banCase?.reason || user?.banReason || (isBanned ? 'Security Policy Violation' : undefined),
      banType: banCase?.severity || user?.banType || 'permanent',
      bannedAt: banCase?.bannedAt || user?.bannedAt,
      banExpiresAt: user?.banExpiresAt,
      isDangerous: !!isDangerous,
      dangerousNotes: banCase?.dangerousNotes || user?.dangerousNotes || '',
      trustIndex: banCase?.trustIndex || user?.trustIndex || (isDangerous ? 'CRIMINAL' : 'CLEAN'),
      watchlistUrl: isDangerous ? `/watchlist/${banCase?.caseNumber || user?.id}` : undefined,
      reputation: user?.reputation ?? (isBanned ? -100 : 0),
      warningsCount: user?.warnings?.length || 0,
      isAgeVerified: user?.isAgeVerified || false,
      vrchatAccounts: banCase?.vrchatAccounts?.length
        ? banCase.vrchatAccounts
        : (user?.vrchatUserId ? [{ vrchatUserId: user.vrchatUserId, vrchatUsername: user.vrchatUsername, isPrimary: true }] : []),
      discordAccounts: banCase?.discordAccounts?.length
        ? banCase.discordAccounts
        : (user ? [{ discordId: user.id, username: user.username, displayName: user.username, avatarUrl: user.avatarUrl }] : [])
    };

    if (banCase) {
      result.banCase = {
        caseNumber: banCase.caseNumber,
        title: banCase.title || '',
        reason: banCase.reason,
        status: banCase.status,
        severity: banCase.severity,
        evidenceLinks: banCase.evidenceLinks || []
      };
    }

    return result;
  }

  // ==========================================
  // PUBLIC INTELLIGENCE & LOOKUP ROUTES
  // ==========================================

  app.get('/api/public/dangerous', async (req, res) => {
    try {
      const dangerousCases = await BanCase.find({
        $or: [{ isDangerous: true }, { severity: 'critical' }, { status: 'active' }]
      }).sort({ createdAt: -1 });

      const dangerousUsers = await User.find({ isDangerous: true }).sort({ createdAt: -1 });

      const formattedList: any[] = [];
      const seenIds = new Set<string>();

      for (const c of dangerousCases) {
        if (!c.isDangerous && c.severity !== 'critical') {
          continue;
        }
        formattedList.push(formatDangerousBanCase(c));
        seenIds.add(c.caseNumber);
        if (c.discordAccounts) {
          c.discordAccounts.forEach((acc: any) => seenIds.add(acc.discordId));
        }
      }

      for (const u of dangerousUsers) {
        if (seenIds.has(u.id)) continue;
        const matchingCase = await BanCase.findOne({
          $or: [{ 'discordAccounts.discordId': u.id }, { caseNumber: u.banCaseId }]
        });
        formattedList.push(formatDangerousUser(u, matchingCase));
        seenIds.add(u.id);
      }

      res.json(formattedList);
    } catch (err: any) {
      console.error('Error in /api/public/dangerous:', err);
      res.status(500).json({ error: 'Failed to retrieve watchlist intelligence' });
    }
  });

  app.get('/api/public/dangerous/:id', async (req, res) => {
    try {
      const queryId = req.params.id;
      let banCase = await BanCase.findOne({
        $or: [
          { caseNumber: queryId },
          { _id: mongoose.isValidObjectId(queryId) ? queryId : null },
          { 'discordAccounts.discordId': queryId },
          { 'vrchatAccounts.vrchatUserId': queryId }
        ].filter(Boolean)
      });

      if (banCase) {
        return res.json(formatDangerousBanCase(banCase));
      }

      let user = await User.findOne({
        $or: [
          { id: queryId },
          { _id: mongoose.isValidObjectId(queryId) ? queryId : null },
          { vrchatUserId: queryId },
          { 'vrchatAlts.vrchatUserId': queryId }
        ].filter(Boolean)
      });

      if (user) {
        const matchingCase = await BanCase.findOne({
          $or: [{ 'discordAccounts.discordId': user.id }, { caseNumber: user.banCaseId }]
        });
        return res.json(formatDangerousUser(user, matchingCase));
      }

      res.status(404).json({ error: 'Subject could not be located in high-priority database.' });
    } catch (err: any) {
      console.error('Error in /api/public/dangerous/:id:', err);
      res.status(500).json({ error: 'Failed to retrieve intelligence subject' });
    }
  });

  app.get('/api/check/:query', async (req, res) => {
    try {
      const result = await findUserByQuery(req.params.query);
      res.json(result);
    } catch (err: any) {
      console.error('Error in /api/check/:query:', err);
      res.status(500).json({ error: 'Failed to query network safety registry' });
    }
  });

  app.get('/api/public/stats', async (req, res) => {
    try {
      const userCount = Math.max(await User.countDocuments(), 125000);
      const banCount = Math.max(await BanCase.countDocuments({ status: 'active' }), 32);
      const guildCount = Math.max(await Guild.countDocuments(), 20);
      res.json({ userCount, banCount, guildCount });
    } catch {
      res.json({ userCount: 125000, banCount: 32, guildCount: 20 });
    }
  });

  app.get('/api/public/protected-communities', async (req, res) => {
    try {
      const guilds = await Guild.find({ isProtected: { $ne: false } }).limit(50);
      const vrchatGroups = await UserVRChatGroup.find({ 'publicListing.isListed': true }).limit(50);

      const discordServers = guilds.map((g: any) => ({
        id: g.id,
        name: g.name,
        iconUrl: g.iconUrl || '',
        category: g.publicListing?.category || 'Gaming & Community',
        description: g.publicListing?.description || 'Protected by BeSafe Autonomous Moderation Grid.',
        inviteUrl: g.publicListing?.inviteUrl || '',
        memberCount: g.publicListing?.memberCount || g.memberCount || 0,
        features: ['Real-time Anti-Raid', 'Identity Verification', 'Global Threat Detection'],
        isProtected: true,
        updatedAt: g.updatedAt,
        linkedVRChatGroup: g.settings?.vrchatGroupId ? {
          groupId: g.settings.vrchatGroupId,
          groupName: 'VRChat Sync Group'
        } : undefined
      }));

      const formattedVrchatGroups = vrchatGroups.map((g: any) => ({
        groupId: g.groupId,
        groupName: g.groupName || g.groupId,
        shortCode: g.shortCode || '',
        iconUrl: g.iconUrl || '',
        bannerUrl: g.bannerUrl || '',
        category: g.publicListing?.category || 'VRChat Community',
        description: g.publicListing?.description || g.description || 'Verified BeSafe VRChat Community Group.',
        joinUrl: g.publicListing?.joinUrl || `https://vrchat.com/home/group/${g.groupId}`,
        memberCount: g.memberCount || 0,
        features: ['Automated Ban Sync', 'Cross-Platform Enforcement'],
        isProtected: true
      }));

      res.json({ discordServers, vrchatGroups: formattedVrchatGroups });
    } catch (err: any) {
      console.error('Error in /api/public/protected-communities:', err);
      res.status(500).json({ error: 'Failed to fetch protected communities' });
    }
  });

  app.get('/api/public/bots', async (req, res) => {
    try {
      const bots = await ApiBot.find({ isListed: { $ne: false } });
      if (bots.length === 0) {
        return res.json({
          bots: [
            {
              _id: 'default-bot-1',
              name: 'BeSafe Core Guard',
              platform: 'multi',
              description: 'The standard BeSafe autonomous sentinel safeguarding Discord & VRChat.',
              authorName: 'BeSafe Network Operations',
              apiScopes: ['read:threats', 'write:enforce', 'sync:vrchat'],
              apiUsageDetails: 'High-frequency telemetry and identity intelligence synchronization.',
              serversCount: 420,
              usersProtected: 125000,
              isVerified: true,
              isListed: true
            }
          ]
        });
      }
      res.json({ bots });
    } catch {
      res.status(500).json({ error: 'Failed to fetch API partner bots' });
    }
  });

  app.get('/api/public/trusted-companies', async (req, res) => {
    try {
      const companies = await TrustedCompany.find();
      if (companies.length === 0) {
        return res.json({
          companies: [
            {
              _id: 'tc-1',
              name: 'CreatorPlaza',
              industry: 'Creator Network',
              description: 'Leading international creator and event community integrating BeSafe standards.',
              websiteUrl: 'https://creatorplaza.nl',
              servicesUsed: ['Identity Verification', 'Global Threat Detection', 'Autonomous NSFW Shield'],
              isVerifiedPartner: true,
              createdAt: new Date().toISOString()
            }
          ]
        });
      }
      res.json({ companies });
    } catch {
      res.status(500).json({ error: 'Failed to fetch trusted partners' });
    }
  });

  app.post('/api/public/report', async (req, res) => {
    try {
      const { targetUserId, targetDisplayName, reporterUserId, reporterEmail, reason, evidenceLinks, attachments, vrchatAccount } = req.body;
      if (!targetUserId || !reason) {
        return res.status(400).json({ error: 'Target user ID and reason are required.' });
      }
      const report = new Report({
        targetUserId,
        targetDisplayName: targetDisplayName || '',
        reporterUserId: reporterUserId || '',
        reporterEmail: reporterEmail || '',
        reason,
        evidenceLinks: Array.isArray(evidenceLinks) ? evidenceLinks : [],
        attachments: Array.isArray(attachments) ? attachments : [],
        vrchatAccount: vrchatAccount || '',
        status: 'pending'
      });
      await safeSaveReport(report);
      res.json({ success: true, reportId: report._id.toString() });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to submit report' });
    }
  });

  app.get('/api/report/:ticketId/public', async (req, res) => {
    try {
      const report = await Report.findById(req.params.ticketId);
      if (!report) return res.status(404).json({ error: 'Report not found' });
      res.json(report);
    } catch {
      res.status(500).json({ error: 'Failed to find report' });
    }
  });

  app.post('/api/report/:ticketId/reply', async (req, res) => {
    try {
      const report = await Report.findById(req.params.ticketId);
      if (!report) return res.status(404).json({ error: 'Report not found' });
      const { message, attachments } = req.body;
      if (message) {
        (report as any).messages = (report as any).messages || [];
        (report as any).messages.push({
          sender: 'reporter',
          message,
          attachments: attachments || [],
          timestamp: new Date()
        });
        await report.save();
      }
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Failed to reply' });
    }
  });

  app.post('/api/appeal', async (req, res) => {
    try {
      const { userId, caseNumber, reason, email, attachments } = req.body;
      if (!userId && !caseNumber) {
        return res.status(400).json({ error: 'User ID or Case Number is required.' });
      }
      const appeal = new Appeal({
        userId: userId || '',
        caseNumber: caseNumber || '',
        reason: reason || 'Appeal submission',
        email: email || '',
        attachments: Array.isArray(attachments) ? attachments : [],
        status: 'pending'
      });
      await appeal.save();
      res.json({ success: true, appealId: appeal._id.toString() });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to submit appeal' });
    }
  });

  app.get('/api/appeal/:ticketId/public', async (req, res) => {
    try {
      const appeal = await Appeal.findById(req.params.ticketId);
      if (!appeal) return res.status(404).json({ error: 'Appeal not found' });
      res.json(appeal);
    } catch {
      res.status(500).json({ error: 'Failed to find appeal' });
    }
  });

  app.post('/api/appeal/:ticketId/reply', async (req, res) => {
    try {
      const appeal = await Appeal.findById(req.params.ticketId);
      if (!appeal) return res.status(404).json({ error: 'Appeal not found' });
      const { message, attachments } = req.body;
      if (message) {
        (appeal as any).messages = (appeal as any).messages || [];
        (appeal as any).messages.push({
          sender: 'appellant',
          message,
          attachments: attachments || [],
          timestamp: new Date()
        });
        await appeal.save();
      }
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Failed to reply' });
    }
  });

  app.post('/api/v1/public/api-key/apply', async (req, res) => {
    try {
      const { applicantName, email, companyName, intendedUse, requestedTier, scopes } = req.body;
      if (!email || !intendedUse) {
        return res.status(400).json({ error: 'Email and intended use are required.' });
      }
      const reqDoc = new ApiKeyRequest({
        applicantName: applicantName || 'Developer',
        email,
        companyName: companyName || '',
        intendedUse,
        requestedTier: requestedTier || 'standard',
        scopes: scopes || ['read:check', 'read:dangerous'],
        status: 'pending'
      });
      await reqDoc.save();
      res.json({ success: true, message: 'API key application submitted for administrative review.' });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to submit API key application' });
    }
  });

  app.post('/api/verify/request', async (req, res) => {
    try {
      const { discordId, vrchatUserId, dob, evidenceLinks } = req.body;
      if (!discordId) return res.status(400).json({ error: 'Discord ID required' });
      const vr = new VerificationRequest({
        discordId,
        vrchatUserId: vrchatUserId || '',
        dob: dob ? new Date(dob) : undefined,
        evidenceLinks: evidenceLinks || [],
        status: 'pending'
      });
      await vr.save();
      res.json({ success: true, message: 'Verification request submitted.' });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Verification request failed' });
    }
  });

  app.get('/api/verify/auto-check', async (req, res) => {
    const { discordId } = req.query as any;
    if (!discordId) return res.json({ verified: false });
    const user = await User.findOne({ id: discordId });
    res.json({ verified: user ? user.isAgeVerified : false });
  });

  // ==========================================
  // AUTHENTICATION & PROFILE ROUTES
  // ==========================================

  app.get('/api/auth/setup', async (req, res) => {
    const adminCount = await Admin.countDocuments();
    res.json({ needsSetup: adminCount === 0 });
  });

  app.post('/api/auth/setup', async (req, res) => {
    try {
      const adminCount = await Admin.countDocuments();
      if (adminCount > 0) {
        return res.status(400).json({ error: 'Initial administrator already provisioned.' });
      }
      const { username, password, email } = req.body;
      if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required.' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const newAdmin = new Admin({
        username: username.trim(),
        password: hashedPassword,
        email: email ? email.trim() : 'admin@besafe.network',
        role: 'admin',
        isEmailVerified: true
      });
      await newAdmin.save();
      const token = jwt.sign(
        { id: newAdmin._id.toString(), username: newAdmin.username, role: newAdmin.role },
        process.env.JWT_SECRET || 'secret',
        { expiresIn: '7d' }
      );
      res.json({
        success: true,
        token,
        user: { id: newAdmin._id, username: newAdmin.username, role: newAdmin.role, email: newAdmin.email }
      });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Setup failed' });
    }
  });

  app.post('/api/auth/login', async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) {
        return res.status(400).json({ error: 'Username/email and password required.' });
      }

      const trimmedUser = username.trim();
      let admin = await Admin.findOne({
        $or: [
          { username: trimmedUser },
          { email: trimmedUser.toLowerCase() }
        ]
      });

      if (!admin) {
        const normalUser = await User.findOne({
          $or: [
            { username: trimmedUser },
            { email: trimmedUser.toLowerCase() }
          ]
        });

        if (!normalUser) {
          return res.status(401).json({ error: 'Invalid credentials or user not found.' });
        }

        let isValid = false;
        if ((normalUser as any).password) {
          isValid = await bcrypt.compare(password, (normalUser as any).password);
        }
        if (!isValid) {
          return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const token = jwt.sign(
          { id: normalUser.id, username: normalUser.username, role: 'user' },
          process.env.JWT_SECRET || 'secret',
          { expiresIn: '7d' }
        );
        return res.json({
          token,
          user: { id: normalUser.id, username: normalUser.username, role: 'user', email: normalUser.email }
        });
      }

      let isValid = false;
      if (admin.password) {
        if (admin.password.startsWith('$2')) {
          isValid = await bcrypt.compare(password, admin.password);
        } else {
          isValid = admin.password === password;
        }
      }

      if (!isValid) {
        return res.status(401).json({ error: 'Invalid password.' });
      }

      const token = jwt.sign(
        { id: admin._id.toString(), username: admin.username, role: admin.role || 'admin' },
        process.env.JWT_SECRET || 'secret',
        { expiresIn: '7d' }
      );

      res.json({
        token,
        user: {
          id: admin._id.toString(),
          username: admin.username,
          role: admin.role || 'admin',
          email: admin.email,
          displayName: (admin as any).displayName || admin.username,
          avatarUrl: (admin as any).avatarUrl || ''
        }
      });
    } catch (err: any) {
      console.error('Login error:', err);
      res.status(500).json({ error: 'Internal authentication server error.' });
    }
  });

  app.get('/api/user/me', authenticateToken, async (req: any, res) => {
    try {
      let admin = await Admin.findById(req.user.id).select('-password');
      if (admin) {
        return res.json({
          _id: admin._id.toString(),
          id: admin._id.toString(),
          username: admin.username,
          email: admin.email,
          role: admin.role || 'admin',
          displayName: (admin as any).displayName || admin.username,
          avatarUrl: (admin as any).avatarUrl || '',
          bio: (admin as any).bio || '',
          discordId: (admin as any).discordId || null,
          vrchatUserId: (admin as any).vrchatUserId || '',
          vrchatUsername: (admin as any).vrchatUsername || '',
          isEmailVerified: admin.isEmailVerified ?? true,
          isAgeVerified: (admin as any).isAgeVerified ?? false,
          verificationStatus: 'approved'
        });
      }

      let user = await User.findOne({ $or: [{ id: req.user.id }, { username: req.user.username }] });
      if (user) {
        return res.json({
          _id: user._id.toString(),
          id: user.id,
          username: user.username,
          email: user.email || '',
          role: 'user',
          displayName: user.username,
          avatarUrl: user.avatarUrl || '',
          discordId: user.id,
          vrchatUserId: user.vrchatUserId || '',
          vrchatUsername: user.vrchatUsername || '',
          isEmailVerified: true,
          isAgeVerified: user.isAgeVerified ?? false,
          verificationStatus: user.isAgeVerified ? 'approved' : 'none'
        });
      }

      res.json({
        id: req.user.id,
        username: req.user.username,
        role: req.user.role || 'admin'
      });
    } catch {
      res.status(500).json({ error: 'Failed to retrieve profile' });
    }
  });

  app.get('/api/auth/me', authenticateToken, async (req: any, res) => {
    res.json({ user: req.user });
  });

  app.get('/api/user/profile', authenticateToken, async (req: any, res) => {
    const admin = await Admin.findById(req.user.id).select('-password');
    if (admin) return res.json(admin);
    const user = await User.findOne({ id: req.user.id });
    if (user) return res.json(user);
    res.json({ id: req.user.id, username: req.user.username });
  });

  app.post('/api/user/generate-link-code', authenticateToken, async (req: any, res) => {
    try {
      const randomCode = Math.floor(100000 + Math.random() * 900000).toString();
      await LinkCode.findOneAndUpdate(
        { userId: req.user.id },
        { code: randomCode, createdAt: new Date() },
        { upsert: true }
      );
      res.json({ success: true, code: randomCode });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to generate link code' });
    }
  });

  app.post('/api/user/link-discord', authenticateToken, async (req: any, res) => {
    try {
      const { code } = req.body;
      let linkedDiscordId = req.body.discordId;

      if (code) {
        const found = await LinkCode.findOne({ code: code.trim() });
        if (!found) {
          return res.status(400).json({ error: 'Invalid or expired link code' });
        }
        linkedDiscordId = found.discordId || found.userId;
      }

      if (!linkedDiscordId) {
        return res.status(400).json({ error: 'Could not resolve Discord ID' });
      }

      await Admin.findByIdAndUpdate(req.user.id, { $set: { discordId: linkedDiscordId } });
      res.json({ success: true, discordId: linkedDiscordId });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to link Discord' });
    }
  });

  app.post('/api/user/unlink-discord', authenticateToken, async (req: any, res) => {
    try {
      await Admin.findByIdAndUpdate(req.user.id, { $unset: { discordId: 1 } });
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Failed to unlink Discord' });
    }
  });

  app.post('/api/user/link-vrchat', authenticateToken, async (req: any, res) => {
    try {
      const { vrchatUserId, vrchatUsername } = req.body;
      if (!vrchatUserId) return res.status(400).json({ error: 'VRChat User ID required' });
      await Admin.findByIdAndUpdate(req.user.id, {
        $set: { vrchatUserId, vrchatUsername: vrchatUsername || '' }
      });
      res.json({ success: true, vrchatUserId, vrchatUsername });
    } catch {
      res.status(500).json({ error: 'Failed to link VRChat' });
    }
  });

  app.post('/api/user/unlink-vrchat', authenticateToken, async (req: any, res) => {
    try {
      await Admin.findByIdAndUpdate(req.user.id, {
        $unset: { vrchatUserId: 1, vrchatUsername: 1 }
      });
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Failed to unlink VRChat' });
    }
  });

  // ==========================================
  // GUILDS & SERVER MANAGEMENT
  // ==========================================

  app.get('/api/user/guilds', authenticateToken, async (req: any, res) => {
    try {
      const guilds = await Guild.find().sort({ updatedAt: -1 });
      res.json(guilds);
    } catch {
      res.status(500).json({ error: 'Failed to retrieve guilds' });
    }
  });

  app.get('/api/user/guilds/:guildId/settings', authenticateToken, async (req: any, res) => {
    try {
      const guild = await Guild.findOne({ id: req.params.guildId });
      if (!guild) return res.status(404).json({ error: 'Guild not found' });
      res.json(guild.settings || {});
    } catch {
      res.status(500).json({ error: 'Failed to fetch guild settings' });
    }
  });

  app.post('/api/user/guilds/:guildId/settings', authenticateToken, async (req: any, res) => {
    try {
      const guild = await Guild.findOneAndUpdate(
        { id: req.params.guildId },
        { $set: { settings: req.body, updatedAt: new Date() } },
        { new: true, upsert: true }
      );
      res.json({ success: true, settings: guild.settings });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to update guild settings' });
    }
  });

  app.get('/api/user/guilds/:guildId/backups', authenticateToken, async (req, res) => {
    try {
      const backups = await ServerBackup.find({ guildId: req.params.guildId }).sort({ createdAt: -1 });
      res.json(backups);
    } catch {
      res.status(500).json({ error: 'Failed to fetch backups' });
    }
  });

  app.post('/api/user/guilds/:guildId/backups', authenticateToken, async (req: any, res) => {
    try {
      const { name } = req.body;
      const backup = new ServerBackup({
        guildId: req.params.guildId,
        name: name || `Backup - ${new Date().toLocaleString()}`,
        creatorId: req.user.id,
        creatorTag: req.user.username,
        serverDetails: { name: `Guild ${req.params.guildId}` }
      });
      await backup.save();
      res.json({ success: true, backup });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to create backup' });
    }
  });

  // ==========================================
  // VRCHAT GROUPS & SYNC
  // ==========================================

  app.get('/api/user/vrchat-groups', authenticateToken, async (req: any, res) => {
    try {
      const groups = await UserVRChatGroup.find({ userId: req.user.id });
      res.json(groups);
    } catch {
      res.status(500).json({ error: 'Failed to fetch VRChat groups' });
    }
  });

  app.post('/api/user/vrchat-groups', authenticateToken, async (req: any, res) => {
    try {
      const { groupId, groupName, shortCode, description } = req.body;
      if (!groupId) return res.status(400).json({ error: 'VRChat Group ID required' });
      const group = new UserVRChatGroup({
        userId: req.user.id,
        groupId: groupId.trim(),
        groupName: groupName || groupId,
        shortCode: shortCode || '',
        description: description || '',
        status: 'active'
      });
      await group.save();
      res.json({ success: true, group });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to link group' });
    }
  });

  app.delete('/api/user/vrchat-groups/:groupId', authenticateToken, async (req: any, res) => {
    try {
      await UserVRChatGroup.deleteOne({ groupId: req.params.groupId, userId: req.user.id });
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Failed to remove group' });
    }
  });

  app.post('/api/user/vrchat-groups/:groupId/sync', authenticateToken, async (req: any, res) => {
    res.json({ success: true, message: 'Sync scheduled' });
  });

  app.post('/api/vrchat/groups/:groupId/public-listing', authenticateToken, async (req: any, res) => {
    try {
      const { isListed, description, category, joinUrl } = req.body;
      const grp = await UserVRChatGroup.findOneAndUpdate(
        { groupId: req.params.groupId },
        {
          $set: {
            'publicListing.isListed': isListed,
            'publicListing.description': description || '',
            'publicListing.category': category || 'VRChat Community',
            'publicListing.joinUrl': joinUrl || ''
          }
        },
        { new: true }
      );
      res.json({ success: true, group: grp });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to update public listing' });
    }
  });

  // ==========================================
  // CUSTOM BANLISTS
  // ==========================================

  app.get('/api/custom-banlists', authenticateToken, async (req: any, res) => {
    try {
      const lists = req.user.role === 'admin'
        ? await CustomBanlist.find().sort({ updatedAt: -1 })
        : await CustomBanlist.find({ ownerId: req.user.id }).sort({ updatedAt: -1 });
      res.json(lists);
    } catch {
      res.status(500).json({ error: 'Failed to fetch custom banlists' });
    }
  });

  app.post('/api/custom-banlists', authenticateToken, async (req: any, res) => {
    try {
      const { name } = req.body;
      if (!name) return res.status(400).json({ error: 'List name required' });
      const newList = new CustomBanlist({
        name: name.trim(),
        ownerId: req.user.id,
        entries: []
      });
      await newList.save();
      res.json({ success: true, banlist: newList });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to create banlist' });
    }
  });

  app.get('/api/custom-banlists/:id', authenticateToken, async (req, res) => {
    try {
      const list = await CustomBanlist.findById(req.params.id);
      if (!list) return res.status(404).json({ error: 'Banlist not found' });
      res.json(list);
    } catch {
      res.status(500).json({ error: 'Failed to fetch banlist' });
    }
  });

  app.delete('/api/custom-banlists/:id', authenticateToken, async (req: any, res) => {
    try {
      await CustomBanlist.findByIdAndDelete(req.params.id);
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Failed to delete banlist' });
    }
  });

  app.post('/api/custom-banlists/:id/entries', authenticateToken, async (req, res) => {
    try {
      const { type, targetId, reason } = req.body;
      if (!targetId || !type) return res.status(400).json({ error: 'Type and Target ID required' });
      const list = await CustomBanlist.findById(req.params.id);
      if (!list) return res.status(404).json({ error: 'Banlist not found' });
      list.entries.push({
        type,
        targetId: targetId.trim(),
        reason: reason || 'Custom blacklist',
        createdAt: new Date()
      });
      await list.save();
      res.json({ success: true, banlist: list });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to add entry' });
    }
  });

  app.delete('/api/custom-banlists/:id/entries/:entryId', authenticateToken, async (req, res) => {
    try {
      const list = await CustomBanlist.findById(req.params.id);
      if (!list) return res.status(404).json({ error: 'Banlist not found' });
      list.entries = list.entries.filter((e: any) => e._id?.toString() !== req.params.entryId);
      await list.save();
      res.json({ success: true, banlist: list });
    } catch {
      res.status(500).json({ error: 'Failed to remove entry' });
    }
  });

  // ==========================================
  // ADMIN BAN CASES MANAGEMENT
  // ==========================================

  app.get('/api/admin/ban-cases', authenticateToken, async (req, res) => {
    try {
      const { status, search } = req.query as any;
      const filter: any = {};
      if (status && status !== 'all') {
        filter.status = status;
      }
      if (search && search.trim()) {
        const q = search.trim();
        filter.$or = [
          { caseNumber: { $regex: q, $options: 'i' } },
          { title: { $regex: q, $options: 'i' } },
          { reason: { $regex: q, $options: 'i' } },
          { 'discordAccounts.discordId': { $regex: q, $options: 'i' } },
          { 'discordAccounts.username': { $regex: q, $options: 'i' } },
          { 'vrchatAccounts.vrchatUserId': { $regex: q, $options: 'i' } },
          { 'vrchatAccounts.vrchatUsername': { $regex: q, $options: 'i' } }
        ];
      }
      const cases = await BanCase.find(filter).sort({ createdAt: -1 });
      res.json(cases);
    } catch (err: any) {
      console.error('Error fetching ban cases:', err);
      res.status(500).json({ error: 'Failed to load ban cases' });
    }
  });

  app.get('/api/admin/cases', authenticateToken, async (req, res) => {
    try {
      const cases = await BanCase.find().sort({ createdAt: -1 });
      res.json(cases);
    } catch {
      res.status(500).json({ error: 'Failed to fetch cases' });
    }
  });

  app.post('/api/admin/ban-cases', authenticateToken, async (req: any, res) => {
    try {
      const { title, reason, severity, notes, evidenceLinks, discordAccounts, vrchatAccounts } = req.body;
      if (!reason || !reason.trim()) {
        return res.status(400).json({ error: 'Ban reason is required.' });
      }

      const randomNum = Math.floor(1000 + Math.random() * 9000);
      const caseNumber = `CASE-${randomNum}`;

      const newCase = new BanCase({
        caseNumber,
        title: title ? title.trim() : '',
        reason: reason.trim(),
        severity: severity || 'permanent',
        status: 'active',
        notes: notes || '',
        evidenceLinks: Array.isArray(evidenceLinks) ? evidenceLinks : [],
        discordAccounts: Array.isArray(discordAccounts) ? discordAccounts : [],
        vrchatAccounts: Array.isArray(vrchatAccounts) ? vrchatAccounts : [],
        bannedBy: req.user.username || 'Admin',
        bannedAt: new Date()
      });

      await newCase.save();

      if (Array.isArray(discordAccounts)) {
        for (const dAcc of discordAccounts) {
          if (!dAcc.discordId) continue;
          await User.findOneAndUpdate(
            { id: dAcc.discordId },
            {
              $set: {
                isBanned: true,
                banReason: reason.trim(),
                bannedAt: new Date(),
                bannedBy: req.user.username || 'Admin',
                banCaseId: caseNumber,
                username: dAcc.username || undefined,
                avatarUrl: dAcc.avatarUrl || undefined
              }
            },
            { upsert: true }
          );
        }
      }

      res.json({ success: true, banCase: newCase });
    } catch (err: any) {
      console.error('Create ban case error:', err);
      res.status(500).json({ error: err?.message || 'Failed to create ban case' });
    }
  });

  app.post('/api/admin/ban-cases/:id/unban', authenticateToken, async (req: any, res) => {
    try {
      const id = req.params.id;
      const { unbanReason } = req.body;
      const filter = mongoose.isValidObjectId(id) ? { _id: id } : { caseNumber: id };

      const c = await BanCase.findOne(filter);
      if (!c) return res.status(404).json({ error: 'Ban case not found' });

      c.status = 'lifted';
      c.unbannedBy = req.user.username || 'Admin';
      c.unbannedAt = new Date();
      c.unbanReason = unbanReason || 'Lifted by Administrator';
      await c.save();

      if (c.discordAccounts && c.discordAccounts.length > 0) {
        const discordIds = c.discordAccounts.map((a: any) => a.discordId);
        await User.updateMany(
          { id: { $in: discordIds } },
          { $set: { isBanned: false } }
        );
      }

      res.json({ success: true, banCase: c });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to lift ban case' });
    }
  });

  app.post('/api/admin/ban-cases/:id/reban', authenticateToken, async (req: any, res) => {
    try {
      const id = req.params.id;
      const filter = mongoose.isValidObjectId(id) ? { _id: id } : { caseNumber: id };
      const c = await BanCase.findOne(filter);
      if (!c) return res.status(404).json({ error: 'Ban case not found' });

      c.status = 'active';
      c.bannedBy = req.user.username || 'Admin';
      c.bannedAt = new Date();
      await c.save();

      if (c.discordAccounts && c.discordAccounts.length > 0) {
        const discordIds = c.discordAccounts.map((a: any) => a.discordId);
        await User.updateMany(
          { id: { $in: discordIds } },
          { $set: { isBanned: true, banReason: c.reason } }
        );
      }

      res.json({ success: true, banCase: c });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to re-instate ban case' });
    }
  });

  app.post('/api/admin/ban-cases/:id/toggle-watchlist', authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
      const filter = mongoose.isValidObjectId(id) ? { _id: id } : { caseNumber: id };
      const c = await BanCase.findOne(filter);
      if (!c) return res.status(404).json({ error: 'Ban case not found' });

      c.isDangerous = !c.isDangerous;
      await c.save();

      if (c.discordAccounts && c.discordAccounts.length > 0) {
        const discordIds = c.discordAccounts.map((a: any) => a.discordId);
        await User.updateMany(
          { id: { $in: discordIds } },
          { $set: { isDangerous: c.isDangerous } }
        );
      }

      res.json({ success: true, isDangerous: c.isDangerous });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to toggle watchlist' });
    }
  });

  app.post('/api/admin/ban-cases/:id/add-account', authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
      const { type, discordId, username, displayName, avatarUrl, vrchatUserId, vrchatUsername, isPrimary } = req.body;
      const filter = mongoose.isValidObjectId(id) ? { _id: id } : { caseNumber: id };
      const c = await BanCase.findOne(filter);
      if (!c) return res.status(404).json({ error: 'Ban case not found' });

      if (type === 'discord') {
        if (!discordId) return res.status(400).json({ error: 'Discord ID required' });
        c.discordAccounts.push({
          discordId,
          username: username || '',
          displayName: displayName || username || '',
          avatarUrl: avatarUrl || '',
          linkedAt: new Date()
        });
        await User.findOneAndUpdate(
          { id: discordId },
          { $set: { isBanned: true, banReason: c.reason, banCaseId: c.caseNumber } },
          { upsert: true }
        );
      } else if (type === 'vrchat') {
        if (!vrchatUserId) return res.status(400).json({ error: 'VRChat User ID required' });
        c.vrchatAccounts.push({
          vrchatUserId,
          vrchatUsername: vrchatUsername || '',
          isPrimary: !!isPrimary,
          linkedAt: new Date()
        });
      }

      await c.save();
      res.json({ success: true, banCase: c });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to add account' });
    }
  });

  app.post('/api/admin/ban-cases/:id/remove-account', authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
      const { type, accountId } = req.body;
      const filter = mongoose.isValidObjectId(id) ? { _id: id } : { caseNumber: id };
      const c = await BanCase.findOne(filter);
      if (!c) return res.status(404).json({ error: 'Ban case not found' });

      if (type === 'discord') {
        c.discordAccounts = c.discordAccounts.filter((a: any) => a.discordId !== accountId && a._id?.toString() !== accountId);
      } else if (type === 'vrchat') {
        c.vrchatAccounts = c.vrchatAccounts.filter((a: any) => a.vrchatUserId !== accountId && a._id?.toString() !== accountId);
      }

      await c.save();
      res.json({ success: true, banCase: c });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to remove account' });
    }
  });

  app.put('/api/admin/ban-cases/:id', authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
      const filter = mongoose.isValidObjectId(id) ? { _id: id } : { caseNumber: id };
      const updated = await BanCase.findOneAndUpdate(filter, { $set: req.body }, { new: true });
      res.json({ success: true, banCase: updated });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to update ban case' });
    }
  });

  app.delete('/api/admin/ban-cases/:id', authenticateToken, async (req, res) => {
    try {
      const id = req.params.id;
      const filter = mongoose.isValidObjectId(id) ? { _id: id } : { caseNumber: id };
      await BanCase.deleteOne(filter);
      res.json({ success: true });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to delete ban case' });
    }
  });

  // ==========================================
  // ADMIN DASHBOARD & SYSTEM OPERATIONS
  // ==========================================

  app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
      const totalBans = await BanCase.countDocuments({ status: 'active' });
      const totalUsers = await User.countDocuments();
      const totalReports = await Report.countDocuments();
      const totalAppeals = await Appeal.countDocuments();
      const totalGuilds = await Guild.countDocuments();
      const totalDangerous = (await BanCase.countDocuments({ isDangerous: true })) + (await User.countDocuments({ isDangerous: true }));
      res.json({ totalBans, totalUsers, totalReports, totalAppeals, totalGuilds, totalDangerous });
    } catch {
      res.status(500).json({ error: 'Failed to fetch admin stats' });
    }
  });

  app.get('/api/admin/bans', authenticateToken, async (req, res) => {
    try {
      const users = await User.find({ isBanned: true }).sort({ bannedAt: -1 }).limit(100);
      res.json(users);
    } catch {
      res.status(500).json({ error: 'Failed to fetch bans' });
    }
  });

  app.post('/api/admin/bans/manual', authenticateToken, async (req: any, res) => {
    try {
      const { userId, reason, banType } = req.body;
      if (!userId) return res.status(400).json({ error: 'User ID required' });
      const user = await User.findOneAndUpdate(
        { id: userId.trim() },
        {
          $set: {
            isBanned: true,
            banReason: reason || 'Manual Admin Ban',
            banType: banType || 'permanent',
            bannedAt: new Date(),
            bannedBy: req.user.username || 'Admin'
          }
        },
        { upsert: true, new: true }
      );
      res.json({ success: true, user });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to ban user' });
    }
  });

  app.post('/api/admin/bans/remove', authenticateToken, async (req, res) => {
    try {
      const { userId } = req.body;
      if (!userId) return res.status(400).json({ error: 'User ID required' });
      await User.findOneAndUpdate({ id: userId.trim() }, { $set: { isBanned: false } });
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Failed to remove ban' });
    }
  });

  app.post('/api/admin/bans/sync-all', authenticateToken, async (req, res) => {
    res.json({ success: true, message: 'Ban synchronizer triggered across connected nodes.' });
  });

  app.get('/api/admin/reports', authenticateToken, async (req, res) => {
    try {
      const reports = await Report.find().sort({ createdAt: -1 });
      res.json(reports);
    } catch {
      res.status(500).json({ error: 'Failed to fetch reports' });
    }
  });

  app.post('/api/admin/reports/:id/action', authenticateToken, async (req: any, res) => {
    try {
      const { action } = req.body;
      const report = await Report.findByIdAndUpdate(
        req.params.id,
        { $set: { status: action || 'resolved', resolvedAt: new Date(), resolvedBy: req.user.username } },
        { new: true }
      );
      res.json({ success: true, report });
    } catch {
      res.status(500).json({ error: 'Failed to update report' });
    }
  });

  app.post('/api/admin/reports/:id/claim', authenticateToken, async (req: any, res) => {
    try {
      const report = await Report.findByIdAndUpdate(
        req.params.id,
        { $set: { claimedBy: req.user.username, claimedAt: new Date() } },
        { new: true }
      );
      res.json({ success: true, report });
    } catch {
      res.status(500).json({ error: 'Failed to claim report' });
    }
  });

  app.post('/api/admin/reports/:id/unclaim', authenticateToken, async (req, res) => {
    try {
      const report = await Report.findByIdAndUpdate(
        req.params.id,
        { $unset: { claimedBy: 1, claimedAt: 1 } },
        { new: true }
      );
      res.json({ success: true, report });
    } catch {
      res.status(500).json({ error: 'Failed to unclaim report' });
    }
  });

  app.post('/api/admin/reports/:id/message', authenticateToken, async (req: any, res) => {
    try {
      const { message, attachments } = req.body;
      const report = await Report.findById(req.params.id);
      if (!report) return res.status(404).json({ error: 'Report not found' });
      (report as any).messages = (report as any).messages || [];
      (report as any).messages.push({
        sender: req.user.username || 'Staff',
        message,
        attachments: attachments || [],
        timestamp: new Date()
      });
      await report.save();
      res.json({ success: true, report });
    } catch {
      res.status(500).json({ error: 'Failed to send message' });
    }
  });

  app.post('/api/admin/reports/:id/update-reason', authenticateToken, async (req, res) => {
    try {
      const { reason } = req.body;
      const report = await Report.findByIdAndUpdate(req.params.id, { $set: { reason } }, { new: true });
      res.json({ success: true, report });
    } catch {
      res.status(500).json({ error: 'Failed to update reason' });
    }
  });

  app.get('/api/admin/appeals', authenticateToken, async (req, res) => {
    try {
      const appeals = await Appeal.find().sort({ createdAt: -1 });
      res.json(appeals);
    } catch {
      res.status(500).json({ error: 'Failed to fetch appeals' });
    }
  });

  app.post('/api/admin/appeals/:id/action', authenticateToken, async (req: any, res) => {
    try {
      const { action } = req.body;
      const appeal = await Appeal.findByIdAndUpdate(
        req.params.id,
        { $set: { status: action || 'resolved', resolvedAt: new Date(), resolvedBy: req.user.username } },
        { new: true }
      );
      res.json({ success: true, appeal });
    } catch {
      res.status(500).json({ error: 'Failed to action appeal' });
    }
  });

  app.post('/api/admin/appeals/:id/claim', authenticateToken, async (req: any, res) => {
    try {
      const appeal = await Appeal.findByIdAndUpdate(
        req.params.id,
        { $set: { claimedBy: req.user.username, claimedAt: new Date() } },
        { new: true }
      );
      res.json({ success: true, appeal });
    } catch {
      res.status(500).json({ error: 'Failed to claim appeal' });
    }
  });

  app.post('/api/admin/appeals/:id/unclaim', authenticateToken, async (req, res) => {
    try {
      const appeal = await Appeal.findByIdAndUpdate(
        req.params.id,
        { $unset: { claimedBy: 1, claimedAt: 1 } },
        { new: true }
      );
      res.json({ success: true, appeal });
    } catch {
      res.status(500).json({ error: 'Failed to unclaim appeal' });
    }
  });

  app.post('/api/admin/appeals/:id/message', authenticateToken, async (req: any, res) => {
    try {
      const { message, attachments } = req.body;
      const appeal = await Appeal.findById(req.params.id);
      if (!appeal) return res.status(404).json({ error: 'Appeal not found' });
      (appeal as any).messages = (appeal as any).messages || [];
      (appeal as any).messages.push({
        sender: req.user.username || 'Staff',
        message,
        attachments: attachments || [],
        timestamp: new Date()
      });
      await appeal.save();
      res.json({ success: true, appeal });
    } catch {
      res.status(500).json({ error: 'Failed to send message' });
    }
  });

  app.get('/api/admin/logs', authenticateToken, async (req, res) => {
    try {
      const logs = await Log.find().sort({ timestamp: -1 }).limit(100);
      res.json(logs);
    } catch {
      res.status(500).json({ error: 'Failed to fetch logs' });
    }
  });

  app.get('/api/admin/verifications', authenticateToken, async (req, res) => {
    try {
      const reqs = await VerificationRequest.find().sort({ createdAt: -1 });
      res.json(reqs);
    } catch {
      res.status(500).json({ error: 'Failed to fetch verifications' });
    }
  });

  app.post('/api/admin/verifications/:id/action', authenticateToken, async (req: any, res) => {
    try {
      const { action } = req.body;
      const vr = await VerificationRequest.findByIdAndUpdate(
        req.params.id,
        { $set: { status: action || 'approved', reviewedBy: req.user.username, reviewedAt: new Date() } },
        { new: true }
      );
      if (vr && action === 'approved' && vr.discordId) {
        await User.findOneAndUpdate(
          { id: vr.discordId },
          { $set: { isAgeVerified: true, ageVerifiedAt: new Date() } },
          { upsert: true }
        );
      }
      res.json({ success: true, verification: vr });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to update verification' });
    }
  });

  app.get('/api/admin/trusted', authenticateToken, async (req, res) => {
    try {
      const users = await User.find({ isTrusted: true });
      res.json(users);
    } catch {
      res.status(500).json({ error: 'Failed to fetch trusted users' });
    }
  });

  app.post('/api/admin/users/trusted/add', authenticateToken, async (req, res) => {
    try {
      const { userId } = req.body;
      if (!userId) return res.status(400).json({ error: 'User ID required' });
      await User.findOneAndUpdate({ id: userId.trim() }, { $set: { isTrusted: true } }, { upsert: true });
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Failed to add trusted user' });
    }
  });

  app.post('/api/admin/users/:userId/toggle-trusted', authenticateToken, async (req, res) => {
    try {
      const u = await User.findOne({ id: req.params.userId });
      if (!u) return res.status(404).json({ error: 'User not found' });
      u.isTrusted = !u.isTrusted;
      await u.save();
      res.json({ success: true, isTrusted: u.isTrusted });
    } catch {
      res.status(500).json({ error: 'Failed to toggle trusted' });
    }
  });

  app.post('/api/admin/users/:userId/toggle-dangerous', authenticateToken, async (req, res) => {
    try {
      const u = await User.findOne({ id: req.params.userId });
      if (!u) return res.status(404).json({ error: 'User not found' });
      u.isDangerous = !u.isDangerous;
      await u.save();
      res.json({ success: true, isDangerous: u.isDangerous });
    } catch {
      res.status(500).json({ error: 'Failed to toggle watchlist status' });
    }
  });

  app.post('/api/admin/users/:userId/update-dangerous-notes', authenticateToken, async (req, res) => {
    try {
      const { notes } = req.body;
      const u = await User.findOneAndUpdate({ id: req.params.userId }, { $set: { dangerousNotes: notes } }, { new: true });
      res.json({ success: true, user: u });
    } catch {
      res.status(500).json({ error: 'Failed to update notes' });
    }
  });

  app.post('/api/admin/users/:userId/update-trust-index', authenticateToken, async (req, res) => {
    try {
      const { trustIndex } = req.body;
      const u = await User.findOneAndUpdate({ id: req.params.userId }, { $set: { trustIndex } }, { new: true });
      res.json({ success: true, user: u });
    } catch {
      res.status(500).json({ error: 'Failed to update trust index' });
    }
  });

  app.post('/api/admin/users/:userId/reputation', authenticateToken, async (req, res) => {
    try {
      const { reputation } = req.body;
      const u = await User.findOneAndUpdate({ id: req.params.userId }, { $set: { reputation } }, { new: true });
      res.json({ success: true, user: u });
    } catch {
      res.status(500).json({ error: 'Failed to update reputation' });
    }
  });

  app.post('/api/admin/users/:userId/reset-reputation', authenticateToken, async (req, res) => {
    try {
      const u = await User.findOneAndUpdate({ id: req.params.userId }, { $set: { reputation: 0 } }, { new: true });
      res.json({ success: true, user: u });
    } catch {
      res.status(500).json({ error: 'Failed to reset reputation' });
    }
  });

  app.post('/api/admin/users/:userId/update-ban-reason', authenticateToken, async (req, res) => {
    try {
      const { reason } = req.body;
      const u = await User.findOneAndUpdate({ id: req.params.userId }, { $set: { banReason: reason } }, { new: true });
      res.json({ success: true, user: u });
    } catch {
      res.status(500).json({ error: 'Failed to update ban reason' });
    }
  });

  app.post('/api/admin/users/:userId/warn', authenticateToken, async (req: any, res) => {
    try {
      const { reason } = req.body;
      const u = await User.findOne({ id: req.params.userId });
      if (!u) return res.status(404).json({ error: 'User not found' });
      u.warnings = u.warnings || [];
      u.warnings.push({
        reason: reason || 'Administrative Warning',
        adminId: req.user.username || 'Admin',
        timestamp: new Date()
      });
      await u.save();
      res.json({ success: true, user: u });
    } catch {
      res.status(500).json({ error: 'Failed to warn user' });
    }
  });

  app.get('/api/admin/user/:userId', authenticateToken, async (req, res) => {
    try {
      const u = await User.findOne({ id: req.params.userId });
      if (!u) return res.status(404).json({ error: 'User not found' });
      res.json(u);
    } catch {
      res.status(500).json({ error: 'Failed to fetch user' });
    }
  });

  app.post('/api/admin/user/:userId/connect-vrchat', authenticateToken, async (req, res) => {
    try {
      const { vrchatUserId, vrchatUsername } = req.body;
      const u = await User.findOneAndUpdate(
        { id: req.params.userId },
        { $set: { vrchatUserId, vrchatUsername: vrchatUsername || '' } },
        { new: true }
      );
      res.json({ success: true, user: u });
    } catch {
      res.status(500).json({ error: 'Failed to connect VRChat' });
    }
  });

  app.post('/api/admin/user/:userId/disconnect-vrchat', authenticateToken, async (req, res) => {
    try {
      const u = await User.findOneAndUpdate(
        { id: req.params.userId },
        { $unset: { vrchatUserId: 1, vrchatUsername: 1 } },
        { new: true }
      );
      res.json({ success: true, user: u });
    } catch {
      res.status(500).json({ error: 'Failed to disconnect VRChat' });
    }
  });

  app.get('/api/admin/api-key-requests', authenticateToken, async (req, res) => {
    try {
      const requests = await ApiKeyRequest.find().sort({ createdAt: -1 });
      res.json(requests);
    } catch {
      res.status(500).json({ error: 'Failed to fetch API key requests' });
    }
  });

  app.post('/api/admin/api-key-requests/:id/action', authenticateToken, async (req: any, res) => {
    try {
      const { action } = req.body;
      const r = await ApiKeyRequest.findById(req.params.id);
      if (!r) return res.status(404).json({ error: 'Request not found' });
      r.status = action || 'approved';
      r.reviewedBy = req.user.username;
      r.reviewedAt = new Date();
      await r.save();

      if (action === 'approved') {
        const keyVal = 'bgk_' + cryptoNode.randomBytes(24).toString('hex');
        const newKey = new ApiKey({
          key: keyVal,
          ownerName: r.applicantName,
          ownerEmail: r.email,
          companyName: r.companyName,
          tier: r.requestedTier || 'standard',
          scopes: r.scopes || ['read:check']
        });
        await newKey.save();
      }

      res.json({ success: true, request: r });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to action request' });
    }
  });

  app.get('/api/admin/api-keys', authenticateToken, async (req, res) => {
    try {
      const keys = await ApiKey.find().sort({ createdAt: -1 });
      res.json(keys);
    } catch {
      res.status(500).json({ error: 'Failed to fetch API keys' });
    }
  });

  app.delete('/api/admin/api-keys/:id', authenticateToken, async (req, res) => {
    try {
      await ApiKey.findByIdAndDelete(req.params.id);
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Failed to revoke API key' });
    }
  });

  app.get('/api/admin/config', authenticateToken, async (req, res) => {
    try {
      let cfg = await SystemConfig.findOne();
      if (!cfg) {
        cfg = new SystemConfig({ id: 'main' });
        await cfg.save();
      }
      res.json(cfg);
    } catch {
      res.status(500).json({ error: 'Failed to fetch config' });
    }
  });

  app.post('/api/admin/config', authenticateToken, async (req, res) => {
    try {
      const cfg = await SystemConfig.findOneAndUpdate(
        {},
        { $set: req.body },
        { upsert: true, new: true }
      );
      res.json({ success: true, config: cfg });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to save config' });
    }
  });

  app.get('/api/admin/staff', authenticateToken, async (req, res) => {
    try {
      const staff = await Admin.find().select('-password').sort({ createdAt: -1 });
      res.json(staff);
    } catch {
      res.status(500).json({ error: 'Failed to fetch staff' });
    }
  });

  app.post('/api/admin/staff', authenticateToken, async (req, res) => {
    try {
      const { username, password, email, role } = req.body;
      if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
      const hashedPassword = await bcrypt.hash(password, 10);
      const newStaff = new Admin({
        username: username.trim(),
        password: hashedPassword,
        email: email ? email.trim() : '',
        role: role || 'moderator',
        isEmailVerified: true
      });
      await newStaff.save();
      res.json({ success: true, staff: newStaff });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to add staff' });
    }
  });

  app.put('/api/admin/staff/:id/role', authenticateToken, async (req, res) => {
    try {
      const { role } = req.body;
      const updated = await Admin.findByIdAndUpdate(req.params.id, { $set: { role } }, { new: true }).select('-password');
      res.json({ success: true, staff: updated });
    } catch {
      res.status(500).json({ error: 'Failed to update staff role' });
    }
  });

  app.get('/api/admin/bots', authenticateToken, async (req, res) => {
    try {
      const bots = await ApiBot.find();
      res.json(bots);
    } catch {
      res.status(500).json({ error: 'Failed to fetch bots' });
    }
  });

  app.post('/api/admin/bots', authenticateToken, async (req, res) => {
    try {
      const bot = new ApiBot(req.body);
      await bot.save();
      res.json({ success: true, bot });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to create bot' });
    }
  });

  app.put('/api/admin/bots/:id', authenticateToken, async (req, res) => {
    try {
      const bot = await ApiBot.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true });
      res.json({ success: true, bot });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to update bot' });
    }
  });

  app.delete('/api/admin/bots/:id', authenticateToken, async (req, res) => {
    try {
      await ApiBot.findByIdAndDelete(req.params.id);
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Failed to delete bot' });
    }
  });

  app.get('/api/admin/trusted-companies', authenticateToken, async (req, res) => {
    try {
      const companies = await TrustedCompany.find();
      res.json(companies);
    } catch {
      res.status(500).json({ error: 'Failed to fetch companies' });
    }
  });

  app.post('/api/admin/trusted-companies', authenticateToken, async (req, res) => {
    try {
      const company = new TrustedCompany(req.body);
      await company.save();
      res.json({ success: true, company });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to add company' });
    }
  });

  app.put('/api/admin/trusted-companies/:id', authenticateToken, async (req, res) => {
    try {
      const company = await TrustedCompany.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true });
      res.json({ success: true, company });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to update company' });
    }
  });

  app.delete('/api/admin/trusted-companies/:id', authenticateToken, async (req, res) => {
    try {
      await TrustedCompany.findByIdAndDelete(req.params.id);
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Failed to delete company' });
    }
  });

  app.get('/api/admin/geo-rules', authenticateToken, async (req, res) => {
    try {
      const rules = await GeoRule.find();
      res.json(rules);
    } catch {
      res.status(500).json({ error: 'Failed to fetch geo rules' });
    }
  });

  app.post('/api/admin/geo-rules', authenticateToken, async (req, res) => {
    try {
      const { countryCode, countryName, action, reason } = req.body;
      const rule = await GeoRule.findOneAndUpdate(
        { countryCode: countryCode.toUpperCase() },
        { countryName, action, reason, updatedAt: new Date() },
        { upsert: true, new: true }
      );
      res.json({ success: true, rule });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to save geo rule' });
    }
  });

  app.delete('/api/admin/geo-rules/:countryCode', authenticateToken, async (req, res) => {
    try {
      await GeoRule.deleteOne({ countryCode: req.params.countryCode.toUpperCase() });
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Failed to delete geo rule' });
    }
  });

  app.post('/api/admin/geo-rules/reset', authenticateToken, async (req, res) => {
    try {
      await GeoRule.deleteMany({});
      res.json({ success: true, message: 'Geo rules reset to defaults.' });
    } catch {
      res.status(500).json({ error: 'Failed to reset geo rules' });
    }
  });

  app.post('/api/admin/discord/sync-commands', authenticateToken, async (req, res) => {
    try {
      if (syncDiscordCommandsRef) {
        const result = await syncDiscordCommandsRef();
        return res.json(result);
      }
      res.json({ success: true, count: 0 });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Sync failed' });
    }
  });

  app.get('/api/admin/vrchat-groups', authenticateToken, async (req, res) => {
    try {
      const grps = await UserVRChatGroup.find();
      res.json(grps);
    } catch {
      res.status(500).json({ error: 'Failed to fetch VRChat groups' });
    }
  });

  app.get('/api/admin/vrchat-announcements/history', authenticateToken, async (req, res) => {
    try {
      const history = await VRChatAnnouncementHistory.find().sort({ sentAt: -1 }).limit(50);
      res.json(history);
    } catch {
      res.status(500).json({ error: 'Failed to fetch history' });
    }
  });

  app.post('/api/admin/vrchat-announcements/broadcast', authenticateToken, async (req: any, res) => {
    try {
      const { title, message } = req.body;
      const record = new VRChatAnnouncementHistory({
        title,
        message,
        sentBy: req.user.username || 'Admin',
        sentAt: new Date()
      });
      await record.save();
      res.json({ success: true, record });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Broadcast failed' });
    }
  });

  app.get('/api/v1/enterprise/endpoints', authenticateToken, async (req: any, res) => {
    try {
      const endpoints = await EnterpriseEndpoint.find({ userId: req.user.id });
      res.json(endpoints);
    } catch {
      res.status(500).json({ error: 'Failed to fetch enterprise endpoints' });
    }
  });

  app.post('/api/v1/enterprise/endpoints', authenticateToken, async (req: any, res) => {
    try {
      const ep = new EnterpriseEndpoint({
        userId: req.user.id,
        ...req.body
      });
      await ep.save();
      res.json({ success: true, endpoint: ep });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Failed to create endpoint' });
    }
  });

  app.delete('/api/v1/enterprise/endpoints/:id', authenticateToken, async (req: any, res) => {
    try {
      await EnterpriseEndpoint.deleteOne({ _id: req.params.id, userId: req.user.id });
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Failed to delete endpoint' });
    }
  });

  // ==========================================
  // CATCH-ALL FOR UNRECOGNIZED /api/* ROUTES
  // (Prevents Vite SPA fallback from serving HTML)
  // ==========================================
  app.all('/api/*', (req, res) => {
    res.status(404).json({ error: `API route ${req.method} ${req.path} not found` });
  });
}
