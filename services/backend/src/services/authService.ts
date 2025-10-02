import crypto from 'crypto';
import nodemailer from 'nodemailer';
import db from '../db';
import { User, UserRow } from '../types/user';
import jwtUtils from '../utils/jwt';
import ejs from 'ejs';
import bcrypt from 'bcrypt';
import validator from 'validator';

const BCRYPT_COST = parseInt(process.env.BCRYPT_COST || '12', 10);
const PEPPER = process.env.PEPPER || '';
const ALLOW_LEGACY_PW_MIGRATION = (process.env.ALLOW_LEGACY_PW_MIGRATION || 'true').toLowerCase() === 'true';

async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain + PEPPER, BCRYPT_COST);
}

async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plain + PEPPER, hash);
}

const RESET_TTL = 1000 * 60 * 60;         // 1h
const INVITE_TTL = 1000 * 60 * 60 * 24 * 7; // 7d

class AuthService {

  static async createUser(user: User) {
    const existing = await db<UserRow>('users')
      .where({ username: user.username })
      .orWhere({ email: user.email })
      .first();
    if (existing) throw new Error('User already exists with that username or email');
    // create invite token
    const invite_token = crypto.randomBytes(6).toString('hex');
    const invite_token_expires = new Date(Date.now() + INVITE_TTL);
    const passwordHash = await hashPassword(user.password);
    await db<UserRow>('users')
      .insert({
        username: user.username,
        password: passwordHash,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        invite_token,
        invite_token_expires,
        activated: false
      });
    // send invite email using nodemailer and local SMTP server
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT),
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    const nameRegex = /^[A-Za-zÁÉÍÓÚáéíóúÑñ' \-]{1,80}$/;
    if (!nameRegex.test(user.first_name) || !nameRegex.test(user.last_name))
      throw new Error('Invalid name format');
    if (!validator.isEmail(user.email))
      throw new Error('Invalid email');

    const usernameRegex = /^[a-zA-Z0-9_.-]{3,32}$/;
    if (!usernameRegex.test(user.username))
      throw new Error('Invalid username');

    const dangerous = /<%|%>|require\(|child_process|fs\./i;
    if (dangerous.test(user.first_name) || dangerous.test(user.last_name) || dangerous.test(user.username))
      throw new Error('Invalid characters in input');

    const link = `${process.env.FRONTEND_URL || ''}/activate-user?token=${invite_token}&username=${encodeURIComponent(user.username)}`;

    const templateFile = `
  <html>
    <body>
      <h1>Hello <%= user.first_name %> <%= user.last_name %></h1>
      <p>Click <a href="<%= link %>">here</a> to activate your account.</p>
    </body>
  </html>`;

    const htmlBody = ejs.render(templateFile, {
      user: {
        first_name: user.first_name,
        last_name: user.last_name
      },
      link
    });

    // con el siguiente console.log podemos ver el cuerpo del email generado
    console.log('--- HTML BODY START ---');
    console.log(htmlBody);
    console.log('--- HTML BODY END ---');


    await transporter.sendMail({
      from: "info@example.com",
      to: user.email,
      subject: 'Activate your account',
      html: htmlBody
    });
  }

  static async updateUser(user: User) {
    const existing = await db<UserRow>('users')
      .where({ id: user.id })
      .first();
    if (!existing) throw new Error('User not found');

    const updateData: Partial<UserRow> = {
      username: user.username,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name
    };

    if (user.password && user.password.trim() !== '') {
      updateData.password = await hashPassword(user.password);
    }

    await db<UserRow>('users')
      .where({ id: user.id })
      .update(updateData);
    return existing;
  }

  static async authenticate(username: string, password: string) {
    const user = await db<UserRow>('users')
      .where({ username })
      .andWhere('activated', true)
      .first();
    if (!user) throw new Error('Invalid email or not activated');

    let ok = false;
    const looksHashed = typeof user.password === 'string' && /^\$2[aby]\$/.test(user.password);

    if (looksHashed) {
      ok = await verifyPassword(password, user.password);
    } else {
      // legacy plaintext support gated by feature flag
      if (!ALLOW_LEGACY_PW_MIGRATION) {
        // refuse legacy plaintext passwords when migration window is closed
        throw new Error('Invalid password');
      }
      ok = (password === user.password);
      if (ok) {
        const newHash = await hashPassword(password);
        await db('users').where({ id: user.id }).update({ password: newHash });
      }
    }

    if (!ok) throw new Error('Invalid password');
    return user;
  }

  static async sendResetPasswordEmail(email: string) {
    const user = await db<UserRow>('users')
      .where({ email })
      .andWhere('activated', true)
      .first();
    if (!user) throw new Error('No user with that email or not activated');

    const token = crypto.randomBytes(6).toString('hex');
    const expires = new Date(Date.now() + RESET_TTL);

    await db('users')
      .where({ id: user.id })
      .update({
        reset_password_token: token,
        reset_password_expires: expires
      });

    // send email with reset link using nodemailer and local SMTP server
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    const link = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    await transporter.sendMail({
      to: user.email,
      subject: 'Your password reset link',
      html: `Click <a href="${link}">here</a> to reset your password.`
    });
  }

  static async resetPassword(token: string, newPassword: string) {
    const row = await db<UserRow>('users')
      .where('reset_password_token', token)
      .andWhere('reset_password_expires', '>', new Date())
      .first();
    if (!row) throw new Error('Invalid or expired reset token');

    const newHash = await hashPassword(newPassword);
    await db('users')
      .where({ id: row.id })
      .update({
        password: newHash,
        reset_password_token: null,
        reset_password_expires: null
      });
  }

  static async setPassword(token: string, newPassword: string) {
    const row = await db<UserRow>('users')
      .where('invite_token', token)
      .andWhere('invite_token_expires', '>', new Date())
      .first();
    if (!row) throw new Error('Invalid or expired invite token');

    const newHash2 = await hashPassword(newPassword);
    await db('users')
      .update({
        password: newHash2,
        invite_token: null,
        invite_token_expires: null
      })
      .where({ id: row.id });
  }

  static generateJwt(userId: string): string {
    return jwtUtils.generateToken(userId);
  }
}

export default AuthService;
