const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const QRCode = require("qrcode");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const validator = require("validator");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const Joi = require("joi");
const { Resend } = require("resend");
const crypto = require("crypto");
require("dotenv").config();
const { OAuth2Client } = require("google-auth-library");

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const app = express();

// --- Phase 12: Production Hardening (CORS) ---
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173',
  'http://localhost'
];
// Remove wildcard in production for security
const isProd = process.env.NODE_ENV === 'production';
const corsOrigins = isProd ? allowedOrigins.filter(o => o !== '*') : allowedOrigins;

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || corsOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json({ limit: '10kb' })); // Phase 4: Request size limit
app.use(cookieParser());

// --- Phase 4 & 12: Secure Helmet Configuration ---
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"], // Allow QR codes and Google profile pics
    },
  },
  hsts: isProd ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
  xssFilter: true,
  noSniff: true,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  crossOriginEmbedderPolicy: false // Required for some frontend setups
}));

// --- Phase 10: Rate Limiting ---
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { success: false, message: "Too many login attempts. Please try again later." } });
const otpLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 3, message: { success: false, message: "Too many OTP requests. Please wait." } });
const googleAuthLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { success: false, message: "Too many Google auth attempts." } });

app.use(globalLimiter);

const server = http.createServer(app);

// --- Phase 5: Socket.IO Security ---
const io = new Server(server, {
  cors: { origin: corsOrigins, credentials: true, methods: ["GET", "POST"] },
  pingTimeout: 60000,
  pingInterval: 25000,
  maxHttpBufferSize: 1e6,
  transports: ['websocket', 'polling']
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProd ? { rejectUnauthorized: true } : { rejectUnauthorized: false },
  max: 25,
  min: 2,
  idleTimeoutMillis: 20000,
  connectionTimeoutMillis: 10000,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000,
  allowExitOnIdle: true,
});

pool.on('error', (err) => console.error('Database Pool Error:', err.message));

async function safeQuery(text, params = [], retries = 3) {
  for (let i = 0; i <= retries; i++) {
    try {
      return await pool.query(text, params);
    } catch (err) {
      const isNeonIssue = err.code === '57P01' || err.message.includes('terminating') || err.message.includes('terminated');
      if (i < retries && isNeonIssue) {
        await new Promise(r => setTimeout(r, 700 * (i + 1)));
        continue;
      }
      throw err;
    }
  }
}

async function connectWithRetry() {
  try {
    const client = await pool.connect();
    console.log("✅ Connected to PostgreSQL");
    client.release();
    await initTables();
  } catch (err) {
    console.error("DB Connection failed:", err.message);
  }
}
connectWithRetry();

const JWT_SECRET = process.env.JWT_SECRET || "your-super-secret-jwt-key-change-in-prod";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "your-refresh-secret-key-change-in-prod";
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';
const VALID_ROLES = ['admin', 'principal', 'teacher', 'student', 'guard'];

if (isProd && (JWT_SECRET.startsWith('your-') || REFRESH_SECRET.startsWith('your-'))) {
  console.error("FATAL: Default JWT secrets detected in production.");
  process.exit(1);
}

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const RESEND_FROM = process.env.RESEND_FROM || "SmartPass Pro <onboarding@resend.dev>";

async function sendEmail({ to, subject, html }) {
  if (!resend) return false;
  try {
    const { error } = await resend.emails.send({ from: RESEND_FROM, to, subject, html });
    return !error;
  } catch (err) {
    console.error("Email send error:", err);
    return false;
  }
}

const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

function normalizeOtp(rawOtp) {
  if (rawOtp === null || rawOtp === undefined) return null;
  const str = String(rawOtp).trim();
  return /^\d{6}$/.test(str) ? str : null;
}

async function storeOTP(email, otp, purpose) {
  const cleanEmail = String(email).trim().toLowerCase();
  const cleanOtp = normalizeOtp(otp);
  if (!cleanOtp) throw new Error("storeOTP called with a malformed OTP");

  await safeQuery("UPDATE otp_logs SET used = true WHERE email = $1 AND purpose = $2 AND used = false", [cleanEmail, purpose]);

  const hashedOTP = await bcrypt.hash(cleanOtp, 10);
  const expires = new Date(Date.now() + 10 * 60 * 1000);
  await safeQuery("INSERT INTO otp_logs (email, otp, purpose, expires_at) VALUES ($1, $2, $3, $4)", [cleanEmail, hashedOTP, purpose, expires]);
  return expires;
}

async function verifyOTP(email, otp, purpose) {
  const cleanEmail = email ? String(email).trim().toLowerCase() : null;
  const cleanOtp = normalizeOtp(otp);
  if (!cleanEmail || !cleanOtp || !purpose) return false;

  const result = await safeQuery(
    `SELECT id, otp, expires_at, used FROM otp_logs WHERE email = $1 AND purpose = $2 AND expires_at > NOW() AND used = false ORDER BY created_at DESC LIMIT 1`,
    [cleanEmail, purpose]
  );
  if (!result.rows.length) return false;
  const stored = result.rows[0];
  if (typeof stored.otp !== "string" || !stored.otp.startsWith("$2")) return false;

  const isMatch = await bcrypt.compare(cleanOtp, stored.otp);
  if (isMatch) {
    const burn = await safeQuery("UPDATE otp_logs SET used = true WHERE id = $1 AND used = false RETURNING id", [stored.id]);
    return burn.rows.length > 0;
  }
  return false;
}

// --- Phase 8: Database Security & Schema Upgrades ---
async function initTables() {
  try {
    await safeQuery(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS employee_id VARCHAR(30) UNIQUE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(20) DEFAULT 'password';
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT true;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INT DEFAULT 0;

      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        email VARCHAR(150) UNIQUE NOT NULL,
        password TEXT,
        role VARCHAR(20) CHECK (role IN ('admin', 'principal', 'teacher', 'student', 'guard')) NOT NULL,
        full_name VARCHAR(150),
        department VARCHAR(100),
        phone VARCHAR(20),
        institute VARCHAR(200),
        profile_photo TEXT,
        employee_id VARCHAR(30) UNIQUE,
        auth_provider VARCHAR(20) DEFAULT 'password',
        is_active BOOLEAN DEFAULT true,
        token_version INT DEFAULT 0,
        failed_login_attempts INT DEFAULT 0,
        locked_until TIMESTAMP,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS passes (
        id SERIAL PRIMARY KEY,
        student VARCHAR(150) NOT NULL,
        student_email VARCHAR(150),
        parent_email VARCHAR(150) NOT NULL,
        reason TEXT NOT NULL,
        days INT DEFAULT 1,
        hours INT DEFAULT 8,
        status VARCHAR(20) DEFAULT 'Pending' CHECK (status IN ('Pending', 'Approved', 'Rejected', 'Expired', 'Used')),
        qr_code TEXT,
        expires_at TIMESTAMP NOT NULL,
        created_by INT REFERENCES users(id) ON DELETE SET NULL,
        approved_by INT REFERENCES users(id) ON DELETE SET NULL,
        updated_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS otp_logs (
        id SERIAL PRIMARY KEY,
        email VARCHAR(150) NOT NULL,
        otp TEXT NOT NULL,
        purpose VARCHAR(50),
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE SET NULL,
        action VARCHAR(100) NOT NULL,
        details JSONB,
        ip_address VARCHAR(45),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Phase 7: Session Management Table
      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        refresh_token_hash VARCHAR(255) NOT NULL,
        device_info TEXT,
        ip_address VARCHAR(45),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        revoked BOOLEAN DEFAULT false
      );

      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_passes_status ON passes(status);
      CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(refresh_token_hash);
    `);

    console.log("✅ All Tables and Migrations Ready");
    await seedAdminIfNeeded();
  } catch (e) {
    console.error("❌ Table error during init:", e.message);
  }
}

async function seedAdminIfNeeded() {
  try {
    const existing = await safeQuery("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
    if (existing.rows.length) return;
    const email = process.env.ADMIN_SEED_EMAIL;
    const password = process.env.ADMIN_SEED_PASSWORD;
    const username = process.env.ADMIN_SEED_USERNAME || 'admin';
    if (!email || !password) return;

    const hashed = await bcrypt.hash(password, 12);
    const employeeId = await generateUniqueEmployeeId('admin');
    await safeQuery(
      `INSERT INTO users (username, email, password, role, employee_id, is_active, auth_provider) VALUES ($1, $2, $3, 'admin', $4, true, 'password')`,
      [username, email, hashed, employeeId]
    );
    console.log(`Seeded initial admin account: ${email}`);
  } catch (e) {}
}

function generateEmployeeId(role) {
  const prefix = { teacher: 'TCH', student: 'STU', guard: 'GRD', principal: 'PRN', admin: 'ADM' }[role] || 'EMP';
  return `${prefix}-${Math.floor(1000 + Math.random() * 9000)}`;
}

async function generateUniqueEmployeeId(role) {
  for (let i = 0; i < 10; i++) {
    const candidate = generateEmployeeId(role);
    const clash = await safeQuery("SELECT id FROM users WHERE employee_id = $1", [candidate]);
    if (!clash.rows.length) return candidate;
  }
  return `${(role || 'EMP').slice(0, 3).toUpperCase()}-${Date.now().toString().slice(-6)}`;
}

// --- Phase 2 & 7: Secure Token Generation with JTI and Session Storage ---
function generateTokens(user, deviceInfo, ipAddress) {
  const jti = crypto.randomUUID();
  const accessToken = jwt.sign(
    { id: user.id, email: user.email, role: user.role, tv: user.token_version || 0, jti },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_EXPIRY }
  );
  const refreshToken = jwt.sign(
    { id: user.id, jti, tv: user.token_version || 0 },
    REFRESH_SECRET,
    { expiresIn: REFRESH_TOKEN_EXPIRY }
  );

  const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  // Asynchronous session storage (non-blocking)
  safeQuery(
    `INSERT INTO sessions (user_id, refresh_token_hash, device_info, ip_address, expires_at) VALUES ($1, $2, $3, $4, $5)`,
    [user.id, refreshTokenHash, deviceInfo || 'unknown', ipAddress || 'unknown', expiresAt]
  ).catch(err => console.error("Session storage error:", err));

  return { accessToken, refreshToken };
}

function verifyToken(token, secret = JWT_SECRET) {
  try { return jwt.verify(token, secret); } catch (err) { return null; }
}

// --- Phase 1 Fix: Corrected Authentication Middleware ---
const authenticateJWT = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1] || req.cookies.accessToken;
  if (!token) return res.status(401).json({ success: false, message: "Access token required" });

  const decoded = verifyToken(token);
  if (!decoded) return res.status(403).json({ success: false, message: "Invalid or expired session" });

  const userResult = await safeQuery("SELECT id, token_version, is_active FROM users WHERE id = $1", [decoded.id]);
  if (!userResult.rows.length || !userResult.rows[0].is_active) {
    return res.status(401).json({ success: false, message: "Account not found or disabled" });
  }
  if (decoded.tv !== userResult.rows[0].token_version) {
    return res.status(401).json({ success: false, message: "Token revoked or session expired" });
  }

  req.user = decoded;
  next();
};

async function resolveUserFromToken(token) {
  if (!token) return null;
  const localDecoded = verifyToken(token);
  if (localDecoded && localDecoded.id) {
    try {
      const r = await safeQuery("SELECT * FROM users WHERE id = $1 AND is_active = true", [localDecoded.id]);
      if (!r.rows.length) return null;
      const user = r.rows[0];
      if ((localDecoded.tv || 0) !== (user.token_version || 0)) return null;
      return user;
    } catch (e) { return null; }
  }
  return null;
}

// --- Phase 6: Enterprise Audit Logging ---
async function logAudit(userId, action, details, ip) {
  try {
    await safeQuery("INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES ($1, $2, $3, $4)", [userId, action, details, ip]);
  } catch (e) { console.error("Audit log failed:", e.message); }
}

// --- Phase 11: Security Monitoring (In-memory rate tracking for sockets) ---
const socketRateLimit = new Map();
function checkSocketRateLimit(ip, action, max = 5, windowMs = 60000) {
  const now = Date.now();
  const key = `${ip}:${action}`;
  let record = socketRateLimit.get(key) || { count: 0, resetTime: now + windowMs };
  if (now > record.resetTime) {
    record = { count: 1, resetTime: now + windowMs };
  } else {
    record.count += 1;
  }
  socketRateLimit.set(key, record);
  return record.count <= max;
}

async function handleFailedLogin(userId, ip) {
  const result = await safeQuery(
    `UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1 RETURNING failed_login_attempts`,
    [userId]
  );
  if (result.rows[0].failed_login_attempts >= 5) {
    const lockUntil = new Date(Date.now() + 30 * 60 * 1000);
    await safeQuery("UPDATE users SET locked_until = $1 WHERE id = $2", [lockUntil, userId]);
  }
}

const onlineUsers = new Map();

function broadcastOnlineUsers() {
  const users = Array.from(onlineUsers.values());
  io.to('admins').emit('onlineUsers', users);
  io.to('admins').emit('activeUsers', users);
  io.to('role_principal').emit('onlineUsers', users);
  io.to('role_principal').emit('activeUsers', users);
}

function registerOnline(socket, user) {
  socket.user = user;
  socket.isAuthenticated = true;
  socket.join(`user_${user.id}`);
  socket.join(`role_${user.role}`);
  if (user.role === 'admin') socket.join('admins');

  onlineUsers.set(user.id, {
    id: user.id, username: user.username, email: user.email, role: user.role,
    connectedAt: new Date().toISOString(), socketId: socket.id
  });
  broadcastOnlineUsers();
}

function unregisterOnline(socket) {
  if (!socket.user) return;
  const userId = socket.user.id;
  const stillOnline = Array.from(io.sockets.sockets.values()).some(s => s.id !== socket.id && s.user && s.user.id === userId);
  if (!stillOnline) onlineUsers.delete(userId);
  broadcastOnlineUsers();
}

function requireAdmin(socket) {
  return !!(socket.isAuthenticated && socket.user && socket.user.role === 'admin');
}

function requireAdminOrPrincipal(socket) {
  return !!(socket.isAuthenticated && socket.user && ['admin', 'principal'].includes(socket.user.role));
}

async function issueSession(socket, user, portal, userAgent, ip) {
  await safeQuery("UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = $1", [user.id]);

  const tokens = generateTokens(user, userAgent, ip);
  registerOnline(socket, user);

  socket.emit("loginSuccess", {
    user: { id: user.id, username: user.username, email: user.email, role: user.role, employeeId: user.employee_id },
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken
  });

  await loadPassesForUser(socket, user);
  await logAudit(user.id, "LOGIN_SUCCESS", { role: user.role, portal: portal || user.role, device: userAgent }, ip);
}

async function emitAllPasses() {
  try {
    const result = await safeQuery("SELECT * FROM passes ORDER BY created_at DESC");
    io.emit("updatePasses", result.rows);
  } catch (err) {}
}

async function emitAllUsersToAdmins() {
  try {
    // 1. Fetch ONLY active users for the main directory
    const active = await safeQuery(
      `SELECT id, username, email, role, full_name, department, phone, institute, employee_id, auth_provider, is_active, last_login, created_at
       FROM users WHERE is_active = true ORDER BY created_at DESC`
    );

    // 2. Fetch ONLY removed users for the Recycle Bin
    const removed = await safeQuery(
      `SELECT id, username, email, role, full_name, department, phone, institute, employee_id, auth_provider, is_active, last_login, created_at
       FROM users WHERE is_active = false ORDER BY created_at DESC`
    );

    // 3. Broadcast to all connected admins
    io.to('admins').emit('adminUsersList', active.rows);
    io.to('admins').emit('allUsers', active.rows);
    io.to('admins').emit('removedUsers', removed.rows);
  } catch (err) {
    console.error("Error emitting users to admins:", err);
  }
}
async function loadPassesForUser(socket, user) {
  let query = "SELECT * FROM passes ORDER BY created_at DESC";
  let params = [];

  if (user.role === 'student') {
    query = "SELECT * FROM passes WHERE parent_email = $1 ORDER BY created_at DESC";
    params = [user.email];
  } else if (user.role === 'teacher') {
    query = "SELECT * FROM passes WHERE created_by = $1 ORDER BY created_at DESC";
    params = [user.id];
  }

  const result = await safeQuery(query, params);
  socket.emit("myPasses", result.rows);
}

// --- Phase 5: Socket.IO Authentication Middleware ---
io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.headers.authorization?.split(' ')[1];
  if (!token) {
    socket.isAuthenticated = false;
    return next(); // Allow connection but restrict events
  }
  const user = await resolveUserFromToken(token);
  if (!user) {
    socket.isAuthenticated = false;
    socket.authFailed = true;
    return next();
  }
  registerOnline(socket, user);
  next();
});

io.on("connection", (socket) => {
  const ip = socket.handshake.address;
  const userAgent = socket.handshake.headers['user-agent'] || 'unknown';

  if (socket.authFailed) {
    socket.emit("authError", { message: "Your session has expired. Please refresh your token or log in again." });
  }

  socket.on("sendOTP", async ({ email, purpose }) => {
    if (!checkSocketRateLimit(ip, 'sendOTP', 3, 600000)) return socket.emit("otpError", "Rate limit exceeded.");
    try {
      if (!validator.isEmail(email)) return socket.emit("otpError", "Invalid email");
      const otp = generateOTP();
      await storeOTP(email, otp, purpose);
      const sent = await sendEmail({ to: email, subject: `Your OTP for ${purpose}`, html: `<h3>OTP: <strong>${otp}</strong></h3><p>Valid for 10 minutes.</p>` });
      if (!sent) return socket.emit("otpError", "Failed to send OTP.");
      socket.emit("otpSent", { success: true });
    } catch (err) {
      socket.emit("otpError", "Failed to send OTP.");
    }
  });

  socket.on("login", async ({ email, password, selectedPortal }) => {
    if (!checkSocketRateLimit(ip, 'login', 5, 900000)) return socket.emit("loginError", "Too many attempts. Please wait.");
    if (!email || !password) return socket.emit("loginError", "Email and password are required");

    try {
      const userResult = await safeQuery("SELECT * FROM users WHERE email = $1", [email]);
      if (!userResult.rows.length) {
        return socket.emit("loginError", "Invalid email or password");
      }
      const user = userResult.rows[0];

      if (!user.is_active) return socket.emit("loginError", "Account is disabled.");
      if (user.locked_until && new Date(user.locked_until) > new Date()) {
        return socket.emit("loginError", `Account locked until ${new Date(user.locked_until).toLocaleString()}.`);
      }
      if (!user.password) {
        await handleFailedLogin(user.id, ip);
        return socket.emit("loginError", "This account uses Google Sign-In.");
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        await handleFailedLogin(user.id, ip);
        await logAudit(user.id, "LOGIN_FAILURE", { reason: "Invalid password" }, ip);
        return socket.emit("loginError", "Invalid email or password");
      }

      if (selectedPortal && selectedPortal !== user.role && user.role !== 'admin') {
        await logAudit(user.id, "LOGIN_FAILURE", { reason: "Role mismatch" }, ip);
        return socket.emit("loginError", `This account is registered as ${user.role}.`);
      }

      await issueSession(socket, user, selectedPortal || user.role, userAgent, ip);
    } catch (err) {
      console.error("Login error:", err);
      socket.emit("loginError", "Login failed.");
    }
  });

  socket.on("verifyResetOTP", async ({ email, otp }) => {
    if (!checkSocketRateLimit(ip, 'verifyResetOTP', 5, 600000)) return socket.emit("resetOTPError", "Rate limit exceeded.");
    try {
      const isValid = await verifyOTP(email, otp, 'password_reset');
      if (isValid) socket.emit("resetOTPVerified");
      else socket.emit("resetOTPError", "Invalid or expired security code.");
    } catch (err) {
      socket.emit("resetOTPError", "Server error verifying code.");
    }
  });

  // --- Phase 3 & 4: Authorization & Input Validation ---
  socket.on("createPass", async (data) => {
    if (!socket.isAuthenticated || !socket.user) return socket.emit("passError", "Session expired.");

    // Phase 3 Fix: Check role BEFORE database mutation
    if (!['student', 'teacher', 'admin', 'principal'].includes(socket.user.role)) {
      return socket.emit("passError", "Unauthorized role for creating passes.");
    }

    // Phase 4: Joi Validation
    const schema = Joi.object({
      student: Joi.string().min(2).max(150).required(),
      email: Joi.string().email().required(),
      reason: Joi.string().min(5).max(500).required(),
      days: Joi.number().integer().min(1).max(30).default(1),
      hours: Joi.number().integer().min(1).max(24).default(8)
    });
    const { error, value } = schema.validate(data || {});
    if (error) return socket.emit("passError", "Invalid input data.");

    try {
      const { student, email: parentEmail, reason, days, hours } = value;
      const expiresAt = new Date(Date.now() + (days * 24 * 60 * 60 * 1000) + (hours * 60 * 60 * 1000));
      const qrCode = await QRCode.toDataURL(`PASS-${Date.now()}-${student}`);

      await safeQuery(
        `INSERT INTO passes (student, student_email, parent_email, reason, days, hours, expires_at, created_by, qr_code, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'Pending') RETURNING *`,
        [student, parentEmail, parentEmail, reason, days, hours, expiresAt, socket.user.id, qrCode]
      );

      const otp = generateOTP();
      await storeOTP(parentEmail, otp, 'pass_approval');
      await sendEmail({ to: parentEmail, subject: `Gate Pass OTP for ${student}`, html: `<h3>OTP: <strong>${otp}</strong></h3>` });

      await logAudit(socket.user.id, "PASS_CREATED", { student, passReason: reason }, ip);
      await emitAllPasses();
      socket.emit("passCreated", { success: true });
    } catch (err) {
      console.error("Create pass error:", err);
      socket.emit("passError", "Failed to create pass");
    }
  });

  socket.on("register", async (data) => {
    if (!checkSocketRateLimit(ip, 'register', 3, 3600000)) return socket.emit("registerError", "Rate limit exceeded.");
    try {
      const schema = Joi.object({
        username: Joi.string().min(3).max(100).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(8).pattern(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$/).required(), // Phase 2: Password strength
        role: Joi.string().valid(...VALID_ROLES).required(),
        institute: Joi.string().allow(null, '').optional(),
        department: Joi.string().allow(null, '').optional(),
        phone: Joi.string().allow(null, '').optional(),
        mobile: Joi.string().allow(null, '').optional()
      });
      const { error, value } = schema.validate(data || {});
      if (error) return socket.emit("registerError", "Invalid registration data.");

      if (value.role === 'admin') return socket.emit("registerError", "Admin accounts can only be created by existing admins.");

      const existing = await safeQuery("SELECT id FROM users WHERE email = $1", [value.email]);
      if (existing.rows.length) return socket.emit("registerError", "Email already exists.");

      const hashed = await bcrypt.hash(value.password, 12);
      const employeeId = await generateUniqueEmployeeId(value.role);
      const phoneNumber = (value.phone || value.mobile || "").toString().trim();

      const result = await safeQuery(
        `INSERT INTO users (username, email, password, role, institute, department, phone, employee_id, auth_provider, is_active)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'password', true) RETURNING *`,
        [value.username, value.email, hashed, value.role, value.institute || null, value.department || null, phoneNumber || null, employeeId]
      );

      const user = result.rows[0];
      await logAudit(user.id, "USER_CREATED", { role: user.role }, ip);
      await issueSession(socket, user, value.role, userAgent, ip);
    } catch (err) {
      console.error("Register error:", err);
      socket.emit("registerError", "Registration failed.");
    }
  });

  socket.on("verifyOTP", async ({ passId, otp }) => {
    if (!checkSocketRateLimit(ip, 'verifyOTP', 5, 600000)) return socket.emit("otpError", "Rate limit exceeded.");
    if (!socket.isAuthenticated || !socket.user) return socket.emit("otpError", "Session expired.");

    try {
      const passResult = await safeQuery("SELECT parent_email FROM passes WHERE id = $1", [passId]);
      if (!passResult.rows.length) return socket.emit("otpError", "Pass not found.");

      const isValid = await verifyOTP(passResult.rows[0].parent_email, otp, 'pass_approval');
      if (!isValid) return socket.emit("otpError", "Invalid or expired OTP.");

      await safeQuery(`UPDATE passes SET status = 'Approved', approved_by = $1, updated_at = NOW() WHERE id = $2`, [socket.user.id, passId]);
      await logAudit(socket.user.id, "PASS_APPROVED", { passId }, ip);
      socket.emit("otpVerified", { success: true });
      await emitAllPasses();
    } catch (err) {
      socket.emit("otpError", "Internal server error.");
    }
  });

  socket.on("resendOTP", async ({ passId }) => {
    if (!socket.isAuthenticated || !socket.user) return socket.emit("otpError", "Login required.");
    try {
      const passResult = await safeQuery("SELECT parent_email, created_by FROM passes WHERE id = $1", [passId]);
      if (!passResult.rows.length) return socket.emit("otpError", "Pass not found.");
      const pass = passResult.rows[0];

      // Phase 3: Strict Ownership Check
      if (socket.user.role !== 'admin' && socket.user.id !== pass.created_by) {
        await logAudit(socket.user.id, "UNAUTHORIZED_ACCESS", { action: "resendOTP", passId }, ip);
        return socket.emit("otpError", "Not authorized.");
      }

      const newOTP = generateOTP();
      await storeOTP(pass.parent_email, newOTP, 'pass_approval');
      await sendEmail({ to: pass.parent_email, subject: `New Security Code for Gate Pass #${passId}`, html: `<h3>New OTP: <strong>${newOTP}</strong></h3>` });
      socket.emit("otpResent", { success: true });
    } catch (err) {
      socket.emit("otpError", "Failed to resend OTP.");
    }
  });

  socket.on("markAsUsed", async ({ passId }) => {
    if (!socket.isAuthenticated || !socket.user) return socket.emit("error", "Session expired.");
    if (!['guard', 'principal', 'admin'].includes(socket.user.role)) {
      await logAudit(socket.user.id, "UNAUTHORIZED_ACCESS", { action: "markAsUsed", passId }, ip);
      return socket.emit("error", "Only guards, principals, or admins can record entries");
    }
    if (!passId) return socket.emit("error", "Pass ID required");

    try {
      await safeQuery("UPDATE passes SET status = 'Used' WHERE id = $1 AND status = 'Approved'", [passId]);
      await logAudit(socket.user.id, "PASS_USED", { passId }, ip);
      await emitAllPasses();
      socket.emit("passUsed", { success: true });
    } catch (err) {
      socket.emit("error", "Failed to record entry");
    }
  });

  socket.on("getMyPasses", async () => {
    if (!socket.isAuthenticated || !socket.user) return socket.emit("error", "Session expired.");
    try { await loadPassesForUser(socket, socket.user); } catch (err) {}
  });

  socket.on("resetPassword", async ({ email, otp, newPassword }) => {
    if (!checkSocketRateLimit(ip, 'resetPassword', 3, 600000)) return socket.emit("resetError", "Rate limit exceeded.");
    try {
      const cleanEmail = email ? String(email).trim().toLowerCase() : null;
      const cleanOtp = normalizeOtp(otp);
      if (!cleanEmail || !cleanOtp || !newPassword) return socket.emit("resetError", "All fields required.");
      if (newPassword.length < 8) return socket.emit("resetError", "Password must be at least 8 characters.");

      const isValid = await verifyOTP(cleanEmail, cleanOtp, 'password_reset');
      if (!isValid) return socket.emit("resetError", "Invalid or expired security code.");

      const hashedPassword = await bcrypt.hash(newPassword, 12);
      const updateResult = await safeQuery(
        `UPDATE users SET password = $1, token_version = token_version + 1, failed_login_attempts = 0 WHERE email = $2 AND is_active = true`,
        [hashedPassword, cleanEmail]
      );

      if (updateResult.rowCount === 0) return socket.emit("resetError", "Account not found.");

      // Phase 7: Revoke all existing sessions on password reset
      await safeQuery("UPDATE sessions SET revoked = true WHERE user_id = (SELECT id FROM users WHERE email = $1)", [cleanEmail]);

      socket.emit("resetSuccess", { message: "Password updated successfully!" });
    } catch (err) {
      socket.emit("resetError", "Internal server error.");
    }
  });

  socket.on("logout", async () => {
    try {
      if (!socket.user) return socket.emit("loggedOut", { success: true });
      const uid = socket.user.id;

      // Increment token version to invalidate all JWTs for this user
      await safeQuery("UPDATE users SET token_version = COALESCE(token_version,0) + 1 WHERE id = $1", [uid]);
      // Phase 7: Revoke all refresh sessions
      await safeQuery("UPDATE sessions SET revoked = true WHERE user_id = $1", [uid]);

      socket.isAuthenticated = false;
      socket.user = null;
      onlineUsers.delete(uid);
      broadcastOnlineUsers();
      socket.emit("loggedOut", { success: true });
    } catch (err) {}
  });

   socket.on("getAllUsers", async () => {
    if (!requireAdmin(socket)) {
      await logAudit(socket.user?.id || null, "UNAUTHORIZED_ACCESS", { action: "getAllUsers" }, ip);
      return socket.emit("adminError", "Admin access required");
    }
    try {
      const result = await safeQuery(
        `SELECT id, username, email, role, full_name, department, phone, institute, employee_id, auth_provider, is_active, last_login, created_at
         FROM users WHERE is_active = true ORDER BY created_at DESC`
      );
      socket.emit("allUsers", result.rows);
      socket.emit("adminUsersList", result.rows);
    } catch (err) {
      socket.emit("adminError", "Failed to fetch users");
    }
  });

  socket.on("adminCreateUser", async (data) => {
    if (!requireAdmin(socket)) return socket.emit("adminError", "Admin access required");
    try {
      const schema = Joi.object({
        username: Joi.string().min(3).max(100).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(8).required(),
        role: Joi.string().valid(...VALID_ROLES).required(),
        institute: Joi.string().allow(null, '').optional(),
        employeeId: Joi.string().max(30).allow(null, '').optional(),
      });
      const { error, value } = schema.validate(data || {});
      if (error) return socket.emit("adminError", "Please check the new user's details.");

      const existing = await safeQuery("SELECT id FROM users WHERE email = $1", [value.email]);
      if (existing.rows.length) return socket.emit("adminError", "Email already exists.");

      let employeeId = value.employeeId && value.employeeId.trim();
      if (employeeId) {
        const clash = await safeQuery("SELECT id FROM users WHERE employee_id = $1", [employeeId]);
        if (clash.rows.length) return socket.emit("adminError", "Employee ID already in use.");
      } else {
        employeeId = await generateUniqueEmployeeId(value.role);
      }

      const hashed = await bcrypt.hash(value.password, 12);
      const result = await safeQuery(
        `INSERT INTO users (username, email, password, role, institute, employee_id, auth_provider) VALUES ($1,$2,$3,$4,$5,$6,'password') RETURNING id, username, email, role, employee_id`,
        [value.username, value.email, hashed, value.role, value.institute || null, employeeId]
      );

      await logAudit(socket.user.id, "ADMIN_USER_CREATED", { createdUserId: result.rows[0].id, role: value.role }, ip);
      await emitAllUsersToAdmins();
      socket.emit("adminUserCreated", { success: true, employeeId });
    } catch (err) {
      socket.emit("adminError", "Failed to create user");
    }
  });

   socket.on("adminDeleteUser", async ({ id }) => {
    if (!requireAdmin(socket)) return socket.emit("adminError", "Admin access required");
    try {
      if (!id) return socket.emit("adminError", "User ID required");
      if (socket.user.id === id) return socket.emit("adminError", "You cannot remove your own account.");

      // Soft delete: Set is_active to false
      await safeQuery("UPDATE users SET is_active = false WHERE id = $1", [id]);

      // Phase 7: Revoke all active sessions for this user immediately
      await safeQuery("UPDATE sessions SET revoked = true WHERE user_id = $1", [id]);

      // Force disconnect the user if they are currently online
      for (const [, s] of io.sockets.sockets) {
        if (s.user && s.user.id === id) {
          s.emit("forceLogout", { message: "Your account has been removed by an administrator." });
          s.disconnect(true);
        }
      }

      await logAudit(socket.user.id, "ADMIN_USER_SOFT_DELETED", { deletedUserId: id }, ip);

      // Broadcast updated lists to all admins
      await emitAllUsersToAdmins();

      // Emit specific success event for frontend
      socket.emit("adminRemoveUserSuccess", { success: true });
    } catch (err) {
      console.error("Delete user error:", err);
      socket.emit("adminRemoveUserError", "Failed to remove user");
    }
  });
  socket.on("adminGetOnlineUsers", () => {
    if (!requireAdminOrPrincipal(socket)) return socket.emit("adminError", "Admin or Principal access required");
    socket.emit("onlineUsers", Array.from(onlineUsers.values()));
    socket.emit("activeUsers", Array.from(onlineUsers.values()));
  });
  // --- NEW: Fetch Removed Users for Recycle Bin ---
  socket.on("getRemovedUsers", async () => {
    if (!requireAdmin(socket)) return socket.emit("adminError", "Admin access required");
    try {
      const result = await safeQuery(
        `SELECT id, username, email, role, full_name, department, phone, institute, employee_id, auth_provider, is_active, last_login, created_at
         FROM users WHERE is_active = false ORDER BY created_at DESC`
      );
      socket.emit("removedUsers", result.rows);
    } catch (err) {
      socket.emit("adminError", "Failed to fetch removed users");
    }
  });

  // --- NEW: Restore a Soft-Deleted User ---
  socket.on("adminRestoreUser", async ({ id }) => {
    if (!requireAdmin(socket)) return socket.emit("adminError", "Admin access required");
    try {
      if (!id) return socket.emit("adminError", "User ID required");

      await safeQuery("UPDATE users SET is_active = true WHERE id = $1", [id]);
      await logAudit(socket.user.id, "ADMIN_USER_RESTORED", { restoredUserId: id }, ip);

      await emitAllUsersToAdmins();
      socket.emit("adminRestoreUserSuccess", { success: true });
    } catch (err) {
      console.error("Restore user error:", err);
      socket.emit("adminRestoreUserError", "Failed to restore user");
    }
  });

  // --- NEW: Permanently Delete a User (Hard Delete) ---
  socket.on("adminPermanentDeleteUser", async ({ id }) => {
    if (!requireAdmin(socket)) return socket.emit("adminError", "Admin access required");
    try {
      if (!id) return socket.emit("adminError", "User ID required");
      if (socket.user.id === id) return socket.emit("adminError", "You cannot permanently delete your own account.");

      // Revoke sessions just in case
      await safeQuery("UPDATE sessions SET revoked = true WHERE user_id = $1", [id]);

      // Hard delete from database (Passes created by this user will safely become NULL due to ON DELETE SET NULL)
      await safeQuery("DELETE FROM users WHERE id = $1", [id]);

      await logAudit(socket.user.id, "ADMIN_USER_PERMANENTLY_DELETED", { deletedUserId: id }, ip);

      await emitAllUsersToAdmins();
      socket.emit("adminPermanentDeleteSuccess", { success: true });
    } catch (err) {
      console.error("Permanent delete user error:", err);
      socket.emit("adminPermanentDeleteError", "Failed to permanently delete user");
    }
  });
  socket.on("disconnect", () => {
    unregisterOnline(socket);
  });
});

app.get("/", (req, res) => res.send("SmartPass Pro Enterprise Server Running"));

// --- Phase 9: Google OAuth Security ---
app.post("/auth/google", googleAuthLimiter, async (req, res) => {
    try {
        const { credential, selectedPortal } = req.body;
        if (!credential) return res.status(400).json({ success:false, message:"Missing Google credential." });

        const ticket = await googleClient.verifyIdToken({
            idToken: credential,
            audience: process.env.GOOGLE_CLIENT_ID
        });

        // Phase 9 Fix: Extract payload BEFORE checking properties
        const payload = ticket.getPayload();
        if (!payload.email_verified) {
            return res.status(403).json({ success:false, message:"Google email not verified" });
        }

        const email = payload.email;
        const name = payload.name;
        const picture = payload.picture;
        const ip = req.ip;

        let result = await safeQuery("SELECT * FROM users WHERE LOWER(email)=LOWER($1)", [email]);
        let user;

        if (!result.rows.length) {
            const role = selectedPortal || 'student';
            if (role === 'admin') {
                 return res.status(403).json({ success:false, message:"Admin accounts cannot be created via Google Sign-In." });
            }
            const employeeId = await generateUniqueEmployeeId(role);
            const insertRes = await safeQuery(
                `INSERT INTO users (username, email, role, profile_photo, employee_id, auth_provider, is_active)
                 VALUES ($1, $2, $3, $4, $5, 'google', true) RETURNING *`,
                [name, email, role, picture, employeeId]
            );
            user = insertRes.rows[0];
            await logAudit(user.id, "GOOGLE_LOGIN_NEW_USER", { role }, ip);
        } else {
            user = result.rows[0];
            if (!user.is_active) return res.status(403).json({ success:false, message:"Account disabled." });
            if (selectedPortal && user.role !== selectedPortal && user.role !== 'admin') {
                return res.status(403).json({ success:false, message:`Role mismatch: This account belongs to ${user.role}.` });
            }
            await logAudit(user.id, "GOOGLE_LOGIN_SUCCESS", { role: user.role }, ip);
        }

        const tokens = generateTokens(user, req.headers['user-agent'], ip);
        return res.json({
            success:true,
            user: { id: user.id, username: user.username, email: user.email, role: user.role, employeeId: user.employee_id },
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken
        });
    } catch(err){
        console.error("Google Auth Error:", err);
        return res.status(500).json({ success:false, message:"Google authentication failed." });
    }
});

// --- Phase 7: Refresh Token Rotation ---
app.post("/refresh-token", async (req, res) => {
    const { refreshToken, deviceInfo, ipAddress } = req.body;
    if (!refreshToken) return res.status(401).json({ success:false, message:"Refresh token missing" });

    const decoded = verifyToken(refreshToken, REFRESH_SECRET);
    if (!decoded) return res.status(403).json({ success:false, message:"Invalid refresh token" });

    const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

    // Verify session exists, is not revoked, and matches user
    const sessionResult = await safeQuery(
        `SELECT s.id, s.user_id, u.token_version, u.is_active
         FROM sessions s
         JOIN users u ON s.user_id = u.id
         WHERE s.refresh_token_hash = $1 AND s.revoked = false AND s.expires_at > NOW()`,
        [refreshTokenHash]
    );

    if (!sessionResult.rows.length || sessionResult.rows[0].user_id !== decoded.id) {
        return res.status(403).json({ success:false, message:"Session expired or revoked" });
    }

    const session = sessionResult.rows[0];
    if (decoded.tv !== session.token_version || !session.is_active) {
        return res.status(403).json({ success:false, message:"Session invalidated" });
    }

    // Phase 7: Refresh Token Rotation (Revoke old token)
    await safeQuery(`UPDATE sessions SET revoked = true WHERE id = $1`, [session.id]);

    // Issue new tokens
    const userResult = await safeQuery("SELECT * FROM users WHERE id = $1", [session.user_id]);
    const user = userResult.rows[0];
    const tokens = generateTokens(user, deviceInfo, ipAddress);

    return res.json({ success:true, ...tokens });
});

// --- Phase 7: Logout with "Logout All Devices" Support ---
app.post("/logout", authenticateJWT, async (req, res) => {
  try {
    const { refreshToken, logoutAll } = req.body;

    if (logoutAll) {
      // Invalidate ALL tokens and sessions for this user
      await safeQuery("UPDATE users SET token_version = COALESCE(token_version,0) + 1 WHERE id = $1", [req.user.id]);
      await safeQuery("UPDATE sessions SET revoked = true WHERE user_id = $1", [req.user.id]);
      await logAudit(req.user.id, "LOGOUT_ALL_DEVICES", {}, req.ip);
    } else if (refreshToken) {
      // Revoke only the specific refresh token
      const hash = crypto.createHash('sha256').update(refreshToken).digest('hex');
      await safeQuery("UPDATE sessions SET revoked = true WHERE refresh_token_hash = $1 AND user_id = $2", [hash, req.user.id]);
      await logAudit(req.user.id, "LOGOUT_SINGLE_DEVICE", {}, req.ip);
    } else {
      // Fallback: Increment token version (legacy behavior)
      await safeQuery("UPDATE users SET token_version = COALESCE(token_version,0) + 1 WHERE id = $1", [req.user.id]);
    }

    // Force disconnect active sockets
    for (const [, s] of io.sockets.sockets) {
      if (s.user && s.user.id === req.user.id) {
        s.emit("forceLogout", { message: "You have been logged out." });
        s.isAuthenticated = false;
        s.user = null;
        s.disconnect(true);
      }
    }

    onlineUsers.delete(req.user.id);
    broadcastOnlineUsers();
    res.clearCookie("accessToken", { httpOnly: true, secure: isProd, sameSite: 'strict' });
    res.json({ success: true, message: "Logged out" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ success: false, message: "Logout failed" });
  }
});

// --- Phase 4: Global Error Middleware ---
app.use((err, req, res, next) => {
  console.error("Unhandled Error:", err.message);
  res.status(500).json({ success: false, message: "Unable to complete your request." });
});

// Cleanup expired OTPs
setInterval(async () => {
  try { await safeQuery("DELETE FROM otp_logs WHERE expires_at < NOW()"); } catch (e) {}
}, 10 * 60 * 1000);

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`SmartPass Pro Server running on http://localhost:${PORT}`));

process.on('SIGTERM', () => {
  io.close();
  pool.end();
  process.exit(0);
});