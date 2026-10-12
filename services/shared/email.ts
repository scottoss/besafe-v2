import nodemailer from 'nodemailer';
import { config } from './config';
import * as EmailTemplates from '../../emailService';
import { SystemConfig } from './models';

export const transporter = nodemailer.createTransport({
  host: config.smtpHost,
  port: config.smtpPort,
  secure: config.smtpPort === 465,
  auth: config.smtpUser ? {
    user: config.smtpUser,
    pass: config.smtpPass,
  } : undefined,
});

export async function sendMail(to: string, subject: string, text: string, html?: string, attachments?: any[]) {
  if (!config.smtpHost) {
    console.warn('[Email] SMTP not configured. Skipping email to:', to);
    return;
  }
  try {
    await transporter.sendMail({
      from: config.smtpFrom,
      to,
      subject,
      text,
      html: html || text,
      attachments
    });
    console.log(`[Email] Sent to ${to}: ${subject}`);
  } catch (err: any) {
    console.error('[Email] Failed to send email:', err?.message || err);
  }
}

export async function notifyAdmins(subject: string, text: string) {
  try {
    const sysConfig = await SystemConfig.findOne({ id: 'main' });
    if (sysConfig?.notificationEmail) {
      const email = EmailTemplates.getGeneralAlertEmail(subject, text, `${config.appUrl}/dashboard`);
      await sendMail(sysConfig.notificationEmail, email.subject, email.text, email.html);
    }
  } catch (err: any) {
    console.error('[Email] Failed to notify admins:', err?.message || err);
  }
}
