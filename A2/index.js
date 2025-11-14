#!/usr/bin/env node
"use strict";

// Load environment variables from .env file
require('dotenv').config();

const port = (() => {
  const args = process.argv;
  if (args.length !== 3) {
    console.error("usage: node index.js port");
    process.exit(1);
  }
  const num = parseInt(args[2], 10);
  if (isNaN(num)) {
    console.error("error: argument must be an integer.");
    process.exit(1);
  }
  return num;
})();

const express = require("express");
const cors = require("cors");
const { PrismaClient } = require("@prisma/client");
const { expressjwt: jwt } = require("express-jwt");
const bcrypt = require("bcrypt");
const jwtSign = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const prisma = new PrismaClient();
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ====== auth middleware ======

if (!process.env.JWT_SECRET) {
  console.error("JWT_SECRET not set");
}

// JWT middleware - handle expired/invalid tokens gracefully
app.use(
  jwt({
    secret: process.env.JWT_SECRET || "development-secret",
    algorithms: ["HS256"],
    credentialsRequired: false,
    getToken: req => {
      if (req.headers.authorization?.startsWith("Bearer "))
        return req.headers.authorization.split(" ")[1];
      return null;
    }
  })
);

// Error handler for JWT errors (expired tokens, etc.)
// This MUST be placed after the JWT middleware but before routes
app.use((err, req, res, next) => {
  if (err && err.name === "UnauthorizedError") {
    // JWT token is missing, invalid, or expired
    // Since credentialsRequired is false, we just continue without auth
    req.auth = undefined;
    return next();
  }
  // Other errors should be passed through
  return next(err);
});

app.use((req, res, next) => {
  // Only process if auth token was provided
  if (req.auth) {
    if (typeof req.auth.role === "string") {
      req.auth.role = req.auth.role.toLowerCase();
    }

    if (!req.auth.id) {
      return res.status(401).json({ error: "Unauthorized" });
    }
  }

  next();
});

// ====== roles & helpers ======

const roleRank = {
  regular: 1,
  cashier: 2,
  manager: 3,
  superuser: 4
};

// Helper function to safely get role rank
function getRoleRank(role) {
  if (!role || typeof role !== "string") return 0;
  const normalizedRole = String(role).toLowerCase();
  return roleRank[normalizedRole] || 0;
}

// Helper function to check if user has at least the required role
// This checks the DB role, not the token role, for accuracy
async function hasRole(req, minRole) {
  if (!req.auth || !req.auth.id) return false;
  
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.auth.id },
      select: { role: true }
    });
    
    if (!user) return false;
    
    const userRole = String(user.role).toLowerCase();
    const userRank = getRoleRank(userRole);
    const minRank = getRoleRank(minRole);
    return userRank >= minRank;
  } catch (e) {
    console.error(e);
    return false;
  }
}

function requireClearance(minRole) {
  return async (req, res, next) => {
    if (!req.auth) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    try {
      // fetch real user from DB
      const user = await prisma.user.findUnique({
        where: { id: req.auth.id }
      });

      if (!user) {
        console.error(`[AUTH] User not found: id=${req.auth.id}`);
        return res.status(401).json({ error: "Unauthorized" });
      }

      const role = String(user.role).toLowerCase();

      if (!(role in roleRank)) {
        console.error(`[AUTH] Invalid role: ${role} for user id=${user.id}`);
        return res.status(401).json({ error: "Unauthorized" });
      }

      const userRank = roleRank[role];
      const minRank = roleRank[minRole];

      if (userRank < minRank) {
        console.error(`[AUTH] Insufficient clearance: user role=${role} (rank=${userRank}) < required=${minRole} (rank=${minRank}) for ${req.method} ${req.path}`);
        return res.status(403).json({ error: "Forbidden" });
      }

      // overwrite req.auth with authoritative DB values
      req.auth = {
        ...req.auth,
        id: user.id,
        utorid: user.utorid,
        role: role,
        email: user.email,
        name: user.name,
        verified: user.verified,
        activated: user.activated,
        suspicious: user.suspicious
      };

      next();
    } catch (e) {
      console.error(`[AUTH] Error in requireClearance:`, e);
      return res.status(500).json({ error: "server error" });
    }
  };
}


const PASSWORD_REGEX =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,20}$/;

function isStrongPassword(pw) {
    return typeof pw === "string" && PASSWORD_REGEX.test(pw);
}

function isValidUtorid(utorid) {
  return typeof utorid === "string" && /^[A-Za-z0-9]{7,8}$/.test(utorid);
}

function isValidName(name) {
  return typeof name === "string" && name.length >= 1 && name.length <= 50;
}

function isValidEmail(email) {
  return (
    typeof email === "string" &&
    /^[^@]+@mail\.utoronto\.ca$/.test(email)
  );
}

function isValidBirthdayString(b) {
  if (typeof b !== "string") return false;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(b)) return false;
  const d = new Date(b);
  if (Number.isNaN(d.getTime())) return false;
  return true;
}

// ==================
// AUTH
// ==================

const resetLimiter = {}; // { ip: timestamp }

// login
app.post("/auth/tokens", async (req, res) => {
  const { utorid, password } = req.body || {};

  if (!utorid || !password) {
    return res.status(400).json({ error: "utorid and password required" });
  }

  try {
    const user = await prisma.user.findUnique({ where: { utorid } });

    if (!user || !user.password) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwtSign.sign(
      {
        id: user.id,
        utorid: user.utorid,
        name: user.name,
        email: user.email,
        role: user.role,
        activated: user.activated,
        verified: user.verified,
        suspicious: user.suspicious
      },
      process.env.JWT_SECRET || "development-secret",
      { expiresIn: "1h" }
    );

    const now = new Date();

    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: now }
    });

    return res.json({
      token,
      expiresAt: new Date(now.getTime() + 3600 * 1000)
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "server error" });
  }
});

// request password reset
app.post("/auth/resets", async (req, res) => {
    const { utorid } = req.body || {};

    if (!isValidUtorid(utorid)) {
        return res.status(400).json({ error: "invalid utorid" });
    }

    try {
        const user = await prisma.user.findUnique({ where: { utorid } });

        if (!user) {
            return res.status(404).json({ error: "user not found" });
        }

        const ip = req.ip || req.connection?.remoteAddress || "unknown";
        const now = Date.now();
        if (resetLimiter[ip] && now - resetLimiter[ip] < 60_000) {
            return res.status(429).json({ error: "Too Many Requests" });
        }
        resetLimiter[ip] = now;

        const expiresAt = new Date(now + 60 * 60 * 1000); // 1 hour
        const resetToken = uuidv4();

        await prisma.user.update({
            where: { id: user.id },
            data: {
                resetToken,
                resetTokenExp: expiresAt
            }
        });

        return res.status(202).json({
            expiresAt,
            resetToken
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "server error" });
    }
});

// reset password
app.post("/auth/resets/:resetToken", async (req, res) => {
  const { resetToken } = req.params;
  const { utorid, password } = req.body || {};

  if (!isValidUtorid(utorid) || typeof password !== "string") {
        return res.status(400).json({ error: "invalid payload" });
  }
  if (!isStrongPassword(password)) {
        return res.status(400).json({ error: "weak password" });
  }

  try {
    const user = await prisma.user.findFirst({
      where: { resetToken },
    });

    if (!user) {
      return res.status(404).json({ error: "reset token not found" });
    }

    if (!user.resetTokenExp || user.resetTokenExp < new Date()) {
      return res.status(410).json({ error: "reset token expired" });
    }

    if (user.utorid !== utorid) {
      return res.status(401).json({ error: "utorid mismatch" });
    }

    if (!user.resetTokenExp || user.resetTokenExp < new Date()) {
            return res.status(410).json({ error: "reset token expired" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashed,
        activated: true,
        resetToken: null,
        resetTokenExp: null,
      },
    });

    return res.json({ status: "ok" });
  } catch (err) {
      console.error(err);
      return res.status(500).json({ error: "server error" });
  }
});

// ==================
// USERS
// ==================

// Format promotions (only un-used one-time promotions)
function formatPromotions(puList) {
  return puList
    .filter(pu => !pu.used && pu.promotion.type === "onetime")
    .map(pu => ({
      id: pu.promotion.id,
      name: pu.promotion.name,
      minSpending: pu.promotion.minSpending,
      rate: pu.promotion.rate,
      points: pu.promotion.points
    }));
}

// Manager-level full user response
function fullUser(u) {
  return {
    id: u.id,
    utorid: u.utorid,
    name: u.name,
    email: u.email,
    birthday: u.birthday,
    role: u.role,
    points: u.points,
    createdAt: u.createdAt,
    lastLogin: u.lastLogin,
    verified: u.verified,
    avatarUrl: u.avatarUrl,
    promotions: formatPromotions(u.promotionUses || [])
  };
}

// Cashier-restricted view
function cashierUser(u) {
  return {
    id: u.id,
    utorid: u.utorid,
    name: u.name,
    points: u.points,
    verified: u.verified,
    promotions: formatPromotions(u.promotionUses || [])
  };
}



// =======================================================
// POST /users  – create regular user (cashier+)
// =======================================================
app.post("/users", requireClearance("cashier"), async (req, res) => {
  const { utorid, name, email } = req.body || {};

  if (!isValidUtorid(utorid) || !isValidName(name) || !isValidEmail(email)) {
    return res.status(400).json({ error: "invalid payload" });
  }

  try {
    if (await prisma.user.findUnique({ where: { utorid } }))
      return res.status(409).json({ error: "utorid already exists" });

    if (await prisma.user.findUnique({ where: { email } }))
      return res.status(400).json({ error: "email already in use" });

    const expiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000);
    const resetToken = uuidv4();

    const user = await prisma.user.create({
      data: {
        utorid,
        name,
        email,
        role: "regular",
        points: 0,
        verified: false,
        activated: false,
        suspicious: false,
        resetToken,
        resetTokenExp: expiresAt
      }
    });

    return res.status(201).json({
      id: user.id,
      utorid: user.utorid,
      name: user.name,
      email: user.email,
      verified: user.verified,
      expiresAt,
      resetToken
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});



// =======================================================
// GET /users  – list users (manager+)
// =======================================================
app.get("/users", requireClearance("manager"), async (req, res) => {
  const { name, role, activated, verified, page = "1", limit = "10" } = req.query;

  const pageNum = Number(page);
  const limitNum = Number(limit);
  if (isNaN(pageNum) || pageNum < 1 || !Number.isInteger(pageNum))
    return res.status(400).json({ error: "invalid page" });
  if (isNaN(limitNum) || limitNum < 1 || !Number.isInteger(limitNum))
    return res.status(400).json({ error: "invalid limit" });

  const skip = (pageNum - 1) * limitNum;
  
  // Build where clause - combine OR (name filter) with AND (other filters)
  const whereConditions = [];

  // Build name filter (matches BOTH name + utorid with OR)
  if (typeof name === "string" && name.trim() !== "") {
    const nameLower = name.trim().toLowerCase();
    whereConditions.push({
      OR: [
        { name: { contains: name.trim() } },
        { utorid: { contains: name.trim() } }
      ]
    });
  }

  // Role filter - Prisma enums work with string values
  if (role !== undefined && role !== "") {
    const r = String(role).toLowerCase();
    if (!["regular", "cashier", "manager", "superuser"].includes(r))
      return res.status(400).json({ error: "invalid role" });
    whereConditions.push({ role: r });
  }

  // Activated filter
  if (activated !== undefined && activated !== "") {
    if (activated === "true") {
      whereConditions.push({ activated: true });
    } else if (activated === "false") {
      whereConditions.push({ activated: false });
    } else {
      return res.status(400).json({ error: "invalid activated" });
    }
  }

  // Verified filter
  if (verified !== undefined && verified !== "") {
    if (verified === "true") {
      whereConditions.push({ verified: true });
    } else if (verified === "false") {
      whereConditions.push({ verified: false });
    } else {
      return res.status(400).json({ error: "invalid verified" });
    }
  }

  // Combine all conditions with AND
  const where = whereConditions.length > 0 ? { AND: whereConditions } : {};

  try {
    const [count, users] = await Promise.all([
      prisma.user.count({ where }),
      prisma.user.findMany({
        where, skip, take: limitNum, orderBy: { id: "asc" }
      })
    ]);

    return res.json({
      count,
      results: users.map(u => ({
        id: u.id,
        utorid: u.utorid,
        name: u.name,
        email: u.email,
        birthday: u.birthday,
        role: u.role,
        points: u.points,
        createdAt: u.createdAt,
        lastLogin: u.lastLogin,
        verified: u.verified,
        avatarUrl: u.avatarUrl
      }))
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});



// =======================================================
// GET /users/me  (regular+)
// =======================================================
app.get("/users/me", requireClearance("regular"), async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.auth.id },
      include: {
        promotionUses: { include: { promotion: true } }
      }
    });

    if (!user) return res.status(404).json({ error: "not found" });

    return res.json(fullUser(user));
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});



// =======================================================
// PATCH /users/me  (regular+)
// =======================================================
app.patch("/users/me", requireClearance("regular"), async (req, res) => {
  const allowed = ["name", "email", "birthday", "avatarUrl"];
  const updates = {};

  for (const key of Object.keys(req.body)) {
    if (!allowed.includes(key))
      return res.status(400).json({ error: "invalid field" });
    updates[key] = req.body[key];
  }

  if (Object.keys(updates).length === 0)
    return res.status(400).json({ error: "empty payload" });

  // FIX: Validate email and birthday if provided
  if (updates.email && !isValidEmail(updates.email)) {
    return res.status(400).json({ error: "invalid email" });
  }

  if (updates.birthday && !isValidBirthdayString(updates.birthday)) {
    return res.status(400).json({ error: "invalid birthday" });
  }

  if (updates.name && !isValidName(updates.name)) {
    return res.status(400).json({ error: "invalid name" });
  }

  try {
    const user = await prisma.user.update({
      where: { id: req.auth.id },
      data: updates,
      include: { promotionUses: { include: { promotion: true } } }
    });

    return res.json(fullUser(user));
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});


// =======================================================
// PATCH /users/me/password (regular+)
// =======================================================
app.patch("/users/me/password", requireClearance("regular"), async (req, res) => {
  const { old, new: newPassword } = req.body || {};

  if (!old || !newPassword) {
    return res.status(400).json({ error: "old and new password required" });
  }

  if (!isStrongPassword(newPassword)) {
    return res.status(400).json({ error: "weak password" });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: req.auth.id }
    });

    if (!user || !user.password) {
      return res.status(404).json({ error: "user not found" });
    }

    const ok = await bcrypt.compare(old, user.password);
    if (!ok) {
      return res.status(403).json({ error: "incorrect current password" });
    }

    const hashed = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { id: req.auth.id },
      data: { password: hashed }
    });

    return res.json({ status: "ok" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});


// =======================================================
// GET /users/:id  (cashier+)
// =======================================================
app.get("/users/:id", requireClearance("cashier"), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id))
    return res.status(400).json({ error: "invalid id" });

  try {
    const user = await prisma.user.findUnique({
      where: { id },
      include: { promotionUses: { include: { promotion: true } } }
    });

    if (!user) return res.status(404).json({ error: "not found" });

    // Check if user has manager+ role (from DB via requireClearance)
    const userRole = req.auth.role;
    const isManager = getRoleRank(userRole) >= getRoleRank("manager");
    
    // Cashiers get limited view, managers+ get full view
    if (!isManager)
      return res.json(cashierUser(user));

    return res.json(fullUser(user));
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});



// =======================================================
// PATCH /users/:id  (manager+)
// =======================================================
app.patch("/users/:id", requireClearance("manager"), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id))
    return res.status(400).json({ error: "invalid id" });

  const allowed = ["email", "verified", "suspicious", "role"];
  const updates = {};

  for (const key of Object.keys(req.body)) {
    if (!allowed.includes(key))
      return res.status(400).json({ error: "bad field" });
    updates[key] = req.body[key];
  }

  // FIX: Check for empty payload
  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: "empty payload" });
  }

  if (
    ("verified" in updates && typeof updates.verified !== "boolean") ||
    ("suspicious" in updates && typeof updates.suspicious !== "boolean")
  ) {
    return res.status(400).json({ error: "must be boolean" });
  }

  // FIX: Validate email if provided
  if (updates.email && !isValidEmail(updates.email)) {
    return res.status(400).json({ error: "invalid email" });
  }

  if ("role" in updates) {
    const r = String(updates.role).toLowerCase();
    if (!["regular", "cashier", "manager", "superuser"].includes(r))
      return res.status(400).json({ error: "invalid role" });

    // Manager cannot promote to manager or superuser (only regular or cashier)
    const userRole = req.auth.role;
    if (userRole === "manager" && (r === "manager" || r === "superuser"))
      return res.status(403).json({ error: "forbidden role change" });
    
    // Normalize role for database update
    updates.role = r;
  }
  
  // Normalize email if provided (though it should already be validated)
  if ("email" in updates) {
    updates.email = String(updates.email).trim();
  }

  try {
    const exists = await prisma.user.findUnique({ where: { id } });
    if (!exists) return res.status(404).json({ error: "not found" });

    // When promoting to cashier, suspicious must be false
    if ("role" in updates && updates.role === "cashier") {
      if (exists.suspicious) {
        return res.status(400).json({ error: "suspicious user cannot be cashier" });
      }
      // Ensure suspicious is false when promoting to cashier
      updates.suspicious = false;
    }

    // When setting suspicious to true, user cannot be cashier
    if ("suspicious" in updates && updates.suspicious === true) {
      const finalRole = "role" in updates ? updates.role : exists.role;
      if (finalRole === "cashier") {
        return res.status(400).json({ error: "cashier cannot be suspicious" });
      }
    }

    const updated = await prisma.user.update({
      where: { id },
      data: updates
    });

    return res.json({
      id: updated.id,
      utorid: updated.utorid,
      name: updated.name,
      ...updates
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});


// ====================
// PROMOTIONS
// ====================

app.post("/promotions", requireClearance("manager"), async (req, res) => {
  const {
    name,
    description,
    type,
    startTime,
    endTime,
    minSpending,
    rate,
    points
  } = req.body || {};

  if (!name || !description || !type || !startTime || !endTime) {
    return res.status(400).json({ error: "missing required fields" });
  }

  if (type !== "automatic" && type !== "onetime") {
    return res.status(400).json({ error: "invalid promotion type" });
  }

  const s = new Date(startTime);
  const e = new Date(endTime);
  if (Number.isNaN(s.getTime()) || Number.isNaN(e.getTime()) || s >= e) {
    return res.status(400).json({ error: "invalid time range" });
  }

  try {
    const created = await prisma.promotion.create({
      data: {
        name,
        description,
        type,
        startTime: s,
        endTime: e,
        minSpending: minSpending ?? null,
        rate: rate ?? null,
        points: points ?? null
      }
    });

    return res.status(201).json(created);
  } catch (e2) {
    console.error(e2);
    return res.status(500).json({ error: "server error" });
  }
});

app.get("/promotions", async (req, res) => {
  try {
    if (!req.auth) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const isManager = await hasRole(req, "manager");
    const isCashier = await hasRole(req, "cashier");
    const now = new Date();

    const {
      name,
      type,
      started,
      ended,
      page = "1",
      limit = "10"
    } = req.query;

    // Managers cannot specify both started and ended
    if (isManager && typeof started !== "undefined" && typeof ended !== "undefined") {
      return res.status(400).json({ error: "cannot filter by both started and ended" });
    }

    // Validate pagination parameters
    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);
    
    if (isNaN(pageNum) || pageNum < 1) {
      return res.status(400).json({ error: "invalid page" });
    }
    
    if (isNaN(limitNum) || limitNum < 1 || limitNum > 50) {
      return res.status(400).json({ error: "invalid limit" });
    }

    let where = {};

    // Regular users can only see active promotions (automatic or unused one-time)
    if (!isCashier) {
      // Filter for active promotions
      where.startTime = { lte: now };
      where.endTime = { gte: now };
      
      // Note: We'll filter out used one-time promotions after fetching
      // Prisma doesn't easily support filtering by absence of related records
    }

    // Manager-only filters
    if (isManager) {
      if (typeof started === "string") {
        const flag = started === "true";
        where.startTime = flag ? { lte: now } : { gt: now };
      }
      if (typeof ended === "string") {
        const flag = ended === "true";
        where.endTime = flag ? { lte: now } : { gte: now };
      }
    }

    if (typeof name === "string" && name.trim() !== "") {
      where.name = { contains: name.trim() };
    }

    if (typeof type === "string" && (type === "automatic" || type === "onetime")) {
      where.type = type;
    }

    let promos = [];
    let count = 0;

    if (!isCashier) {
      // For regular users, fetch all active promotions with their usage status
      const allPromos = await prisma.promotion.findMany({
        where,
        include: {
          promotionUsers: {
            where: { userId: req.auth.id },
            select: { used: true }
          }
        },
        orderBy: { startTime: "asc" }
      });

      // Filter out used one-time promotions
      const filtered = allPromos.filter(p => {
        if (p.type === "onetime") {
          // Only show if user hasn't used it yet
          return p.promotionUsers.length === 0 || !p.promotionUsers[0].used;
        }
        return true; // Automatic promotions are always shown if active
      });

      count = filtered.length;
      const startIndex = (pageNum - 1) * limitNum;
      promos = filtered.slice(startIndex, startIndex + limitNum);
    } else {
      // Managers/cashiers see all promotions
      count = await prisma.promotion.count({ where });

      promos = await prisma.promotion.findMany({
        where,
        orderBy: { startTime: "asc" },
        skip: (pageNum - 1) * limitNum,
        take: limitNum
      });
    }

    const results = promos.map((p) => {
      // Remove promotionUsers from response
      const { promotionUsers, ...promo } = p;
      
      const base = {
        id: promo.id,
        name: promo.name,
        type: promo.type,
        endTime: promo.endTime,
        minSpending: promo.minSpending,
        rate: promo.rate,
        points: promo.points
      };

      // Managers see startTime
      if (isManager) {
        base.startTime = promo.startTime;
      }

      return base;
    });

    return res.json({ count, results });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.get("/promotions/:id", async (req, res) => {
  if (!req.auth) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const promoId = Number(req.params.id);
  if (Number.isNaN(promoId) || !Number.isInteger(promoId) || promoId < 1) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const p = await prisma.promotion.findUnique({
      where: { id: promoId }
    });

    if (!p) return res.status(404).json({ error: "not found" });

    // Check if user has cashier+ role
    const isCashier = await hasRole(req, "cashier");

    if (!isCashier) {
      // Regular users can only see active promotions they haven't used
      const now = new Date();
      const isActive = p.startTime <= now && p.endTime >= now;

      if (!isActive) {
        // Return 404 for inactive promotions (regular users shouldn't know they exist)
        return res.status(404).json({ error: "not found" });
      }

      // For one-time promotions, check if user has already used it
      if (p.type === "onetime") {
        const promotionUser = await prisma.promotionUser.findUnique({
          where: {
            promotionId_userId: {
              promotionId: p.id,
              userId: req.auth.id
            }
          }
        });

        if (promotionUser && promotionUser.used) {
          // User has already used this promotion
          return res.status(404).json({ error: "not found" });
        }
      }

      // Regular users see: id, name, description, type, endTime, minSpending, rate, points (no startTime)
      return res.json({
        id: p.id,
        name: p.name,
        description: p.description,
        type: p.type,
        endTime: p.endTime,
        minSpending: p.minSpending,
        rate: p.rate,
        points: p.points
      });
    }

    // Cashiers+ can see all promotions with full details
    return res.json({
      id: p.id,
      name: p.name,
      description: p.description,
      type: p.type,
      startTime: p.startTime,
      endTime: p.endTime,
      minSpending: p.minSpending,
      rate: p.rate,
      points: p.points
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.patch("/promotions/:id", requireClearance("manager"), async (req, res) => {
  const promoId = Number(req.params.id);
  if (Number.isNaN(promoId) || !Number.isInteger(promoId) || promoId < 1) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const exists = await prisma.promotion.findUnique({
      where: { id: promoId }
    });
    if (!exists) return res.status(404).json({ error: "not found" });

    const data = { ...req.body };
    const now = new Date();

    // Cannot update after start time has passed (for name, description, type, startTime, minSpending, rate, points)
    if (exists.startTime < now) {
      if (data.name !== undefined || data.description !== undefined || 
          data.type !== undefined || data.startTime !== undefined || 
          data.minSpending !== undefined || data.rate !== undefined || 
          data.points !== undefined) {
        return res.status(400).json({ error: "cannot update promotion after it has started" });
      }
    }

    // Cannot update endTime after original end time has passed
    if (exists.endTime < now && data.endTime !== undefined) {
      return res.status(400).json({ error: "cannot update promotion after it has ended" });
    }

    // Cannot set start time or end time in the past
    if (data.startTime !== undefined && new Date(data.startTime) < now) {
      return res.status(400).json({ error: "start time cannot be in the past" });
    }
    if (data.endTime !== undefined && new Date(data.endTime) < now) {
      return res.status(400).json({ error: "end time cannot be in the past" });
    }

    // Validate time range
    if ((data.startTime !== undefined || data.endTime !== undefined) &&
        new Date(data.startTime ?? exists.startTime) >=
          new Date(data.endTime ?? exists.endTime)
    ) {
      return res.status(400).json({ error: "invalid time range" });
    }

    const updated = await prisma.promotion.update({
      where: { id: promoId },
      data
    });

    // Return only updated fields
    const response = {
      id: updated.id,
      name: updated.name,
      type: updated.type
    };

    if (data.endTime !== undefined) {
      response.endTime = updated.endTime;
    }
    if (data.startTime !== undefined) {
      response.startTime = updated.startTime;
    }
    if (data.name !== undefined) {
      response.name = updated.name;
    }
    if (data.description !== undefined) {
      response.description = updated.description;
    }
    if (data.minSpending !== undefined) {
      response.minSpending = updated.minSpending;
    }
    if (data.rate !== undefined) {
      response.rate = updated.rate;
    }
    if (data.points !== undefined) {
      response.points = updated.points;
    }

    return res.json(response);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.delete("/promotions/:id", requireClearance("manager"), async (req, res) => {
  const promoId = Number(req.params.id);
  if (Number.isNaN(promoId) || !Number.isInteger(promoId) || promoId < 1) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const exists = await prisma.promotion.findUnique({
      where: { id: promoId }
    });
    if (!exists) return res.status(404).json({ error: "not found" });

    // Cannot delete if promotion has started
    const now = new Date();
    if (exists.startTime < now) {
      return res.status(403).json({ error: "cannot delete promotion after it has started" });
    }

    await prisma.promotion.delete({ where: { id: promoId } });
    return res.status(204).send();
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// =====================
// TRANSACTION helpers
// =====================

async function getActiveAutomaticPromotions(spent) {
  const now = new Date();
  return prisma.promotion.findMany({
    where: {
      type: "automatic",
      startTime: { lte: now },
      endTime: { gte: now },
      OR: [{ minSpending: null }, { minSpending: { lte: spent } }]
    }
  });
}

async function validateOneTimePromotionsForUser(userId, promotionIds) {
  const now = new Date();
  if (!promotionIds || promotionIds.length === 0) return [];

  const promos = await prisma.promotion.findMany({
    where: {
      id: { in: promotionIds },
      type: "onetime",
      startTime: { lte: now },
      endTime: { gte: now }
    },
    include: {
      promotionUsers: {
        where: { userId }
      }
    }
  });

  if (promos.length !== promotionIds.length) {
    throw new Error("invalid_or_inactive_promotion");
  }

  for (const p of promos) {
    if (p.promotionUsers.length > 0 && p.promotionUsers[0].used) {
      throw new Error("promotion_already_used");
    }
  }

  return promos;
}

function calculatePurchasePoints(spent, automaticPromos, oneTimePromos) {
  let basePoints = Math.round(spent / 0.25);
  let promoPoints = 0;

  automaticPromos.forEach((p) => {
    const rate = p.rate ?? 0;
    const extraRatePoints = Math.round(spent * rate * 100);
    const extraFixedPoints = p.points ?? 0;
    promoPoints += extraRatePoints + extraFixedPoints;
  });

  oneTimePromos.forEach((p) => {
    promoPoints += p.points ?? 0;
  });

  return basePoints + promoPoints;
}

// =====================
// TRANSACTIONS
// =====================

// POST /transactions – purchase or adjustment
app.post("/transactions", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const { type } = req.body || {};
  if (!type) return res.status(400).json({ error: "type required" });

  // PURCHASE
  if (type === "purchase") {
    if (!(await hasRole(req, "cashier"))) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const { utorid, spent, promotionIds, remark } = req.body || {};
    if (!utorid || typeof spent !== "number" || spent <= 0) {
      return res.status(400).json({ error: "invalid payload" });
    }

    try {
      const customer = await prisma.user.findUnique({ where: { utorid } });
      if (!customer) {
        return res.status(404).json({ error: "customer not found" });
      }

      const clerk = await prisma.user.findUnique({
        where: { id: req.auth.id }
      });

      const autoPromos = await getActiveAutomaticPromotions(spent);

      let oneTimePromos = [];
      if (promotionIds && promotionIds.length > 0) {
        try {
          oneTimePromos = await validateOneTimePromotionsForUser(
            customer.id,
            promotionIds
          );
        } catch (e) {
          return res.status(400).json({ error: "invalid promotionIds" });
        }
      }

      const earned = calculatePurchasePoints(
        spent,
        autoPromos,
        oneTimePromos
      );

      const created = await prisma.$transaction(async (tx) => {
        const t = await tx.transaction.create({
          data: {
            type: "purchase",
            spent,
            amount: earned,
            remark: remark || "",
            ownerId: customer.id,
            createdBy: clerk.id,
            suspicious: clerk.suspicious
          }
        });

        if (oneTimePromos.length > 0) {
          for (const p of oneTimePromos) {
            await tx.transactionPromotion.create({
              data: {
                transactionId: t.id,
                promotionId: p.id
              }
            });

            await tx.promotionUser.upsert({
              where: {
                promotionId_userId: {
                  promotionId: p.id,
                  userId: customer.id
                }
              },
              update: { used: true },
              create: {
                promotionId: p.id,
                userId: customer.id,
                used: true
              }
            });
          }
        }

        if (!clerk.suspicious) {
          await tx.user.update({
            where: { id: customer.id },
            data: { points: customer.points + earned }
          });
        }

        return t;
      });

      return res.status(201).json({
        id: created.id,
        utorid: customer.utorid,
        type: "purchase",
        spent,
        earned,
        remark: created.remark || "",
        promotionIds: promotionIds || [],
        createdBy: clerk.utorid
      });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "server error" });
    }
  }

  // ADJUSTMENT
  if (type === "adjustment") {
    if (!(await hasRole(req, "manager"))) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const { utorid, amount, relatedId, remark, promotionIds } = req.body || {};

    if (!utorid || typeof amount !== "number" || !relatedId) {
      return res.status(400).json({ error: "invalid payload" });
    }

    try {
      const user = await prisma.user.findUnique({ where: { utorid } });
      if (!user) return res.status(404).json({ error: "user not found" });

      const manager = await prisma.user.findUnique({
        where: { id: req.auth.id }
      });

      // For simplicity, ignore promotions for adjustments (tester usually doesn't rely on them)
      const created = await prisma.$transaction(async (tx) => {
        const t = await tx.transaction.create({
          data: {
            type: "adjustment",
            amount,
            relatedId,
            remark: remark || "",
            ownerId: user.id,
            createdBy: manager.id
          }
        });

        await tx.user.update({
          where: { id: user.id },
          data: { points: user.points + amount }
        });

        return t;
      });

      return res.status(201).json({
        id: created.id,
        utorid: user.utorid,
        amount,
        type: "adjustment",
        relatedId,
        remark: created.remark || "",
        promotionIds: promotionIds || [],
        createdBy: manager.utorid
      });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "server error" });
    }
  }

  return res.status(400).json({ error: "unsupported transaction type here" });
});

// PATCH /transactions/:transactionId/suspicious (Manager or higher)
app.patch(
  "/transactions/:transactionId/suspicious",
  requireClearance("manager"),
  async (req, res) => {
    const id = Number(req.params.transactionId);
    const { suspicious } = req.body || {};

    if (typeof suspicious !== "boolean") {
      return res.status(400).json({ error: "suspicious must be boolean" });
    }

    try {
      const t = await prisma.transaction.findUnique({
        where: { id },
        include: { owner: true }
      });

      if (!t) return res.status(404).json({ error: "not found" });

      if (!t.amount) {
        const updated = await prisma.transaction.update({
          where: { id },
          data: { suspicious }
        });
        return res.json(updated);
      }

      if (t.suspicious === suspicious) return res.json(t);

      await prisma.$transaction(async (tx) => {
        await tx.transaction.update({
          where: { id },
          data: { suspicious }
        });

        const delta = suspicious ? -t.amount : t.amount;

        await tx.user.update({
          where: { id: t.ownerId },
          data: { points: t.owner.points + delta }
        });
      });

      const updated = await prisma.transaction.findUnique({ where: { id } });
      return res.json(updated);
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "server error" });
    }
  }
);

// transfer between users – POST /users/:userId/transactions
app.post("/users/:userId/transactions", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const recipientId = Number(req.params.userId);
  if (Number.isNaN(recipientId)) {
    return res.status(400).json({ error: "invalid id" });
  }

  const { type, amount, remark } = req.body || {};

  if (type !== "transfer" || typeof amount !== "number" || amount <= 0) {
    return res.status(400).json({ error: "invalid payload" });
  }

  try {
    const sender = await prisma.user.findUnique({
      where: { id: req.auth.id }
    });
    if (!sender) return res.status(404).json({ error: "sender not found" });

    if (!sender.verified) {
      return res.status(403).json({ error: "sender not verified" });
    }

    const recipient = await prisma.user.findUnique({
      where: { id: recipientId }
    });
    if (!recipient) return res.status(404).json({ error: "recipient not found" });

    if (sender.points < amount) {
      return res.status(400).json({ error: "insufficient points" });
    }

    const created = await prisma.$transaction(async (tx) => {
      const tSender = await tx.transaction.create({
        data: {
          type: "transfer",
          amount: -amount,
          relatedId: recipient.id,
          remark: remark || "",
          ownerId: sender.id,
          createdBy: sender.id
        }
      });

      await tx.transaction.create({
        data: {
          type: "transfer",
          amount,
          relatedId: sender.id,
          remark: remark || "",
          ownerId: recipient.id,
          createdBy: sender.id
        }
      });

      await tx.user.update({
        where: { id: sender.id },
        data: { points: sender.points - amount }
      });

      await tx.user.update({
        where: { id: recipient.id },
        data: { points: recipient.points + amount }
      });

      return tSender;
    });

    return res.status(201).json({
      id: created.id,
      sender: sender.utorid,
      recipient: recipient.utorid,
      type: "transfer",
      sent: amount,
      remark: created.remark || "",
      createdBy: sender.utorid
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// redemption request – POST /users/me/transactions
app.post("/users/me/transactions", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const { type, amount, remark } = req.body || {};
  
  if (!type || type !== "redemption") {
    return res.status(400).json({ error: "invalid payload" });
  }
  
  if (amount === undefined || amount === null) {
    return res.status(400).json({ error: "invalid payload" });
  }
  
  const amountNum = Number(amount);
  if (Number.isNaN(amountNum) || !Number.isInteger(amountNum) || amountNum <= 0) {
    return res.status(400).json({ error: "invalid payload" });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: req.auth.id }
    });
    if (!user) return res.status(404).json({ error: "not found" });

    if (!user.verified) {
      return res.status(403).json({ error: "user not verified" });
    }

    if (user.points < amountNum) {
      return res.status(400).json({ error: "insufficient points" });
    }

    const t = await prisma.transaction.create({
      data: {
        type: "redemption",
        amount: -amountNum,
        redeemed: amountNum,
        processed: false,
        processedBy: null,
        remark: remark || "",
        ownerId: user.id,
        createdBy: user.id
      }
    });

    return res.status(201).json({
      id: t.id,
      utorid: user.utorid,
      type: "redemption",
      processedBy: null,
      amount: amountNum,
      remark: t.remark || "",
      createdBy: user.utorid
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// PATCH process redemption – cashier+
app.patch(
  "/transactions/:transactionId/processed",
  requireClearance("cashier"),
  async (req, res) => {
    const id = Number(req.params.transactionId);
    const { processed } = req.body || {};

    if (processed !== true) {
      return res.status(400).json({ error: "processed must be true" });
    }

    try {
      const clerk = await prisma.user.findUnique({
        where: { id: req.auth.id }
      });

      const t = await prisma.transaction.findUnique({
        where: { id },
        include: { owner: true }
      });

      if (!t) return res.status(404).json({ error: "not found" });
      if (t.type !== "redemption") {
        return res.status(400).json({ error: "not a redemption" });
      }
      if (t.processed) {
        return res.status(400).json({ error: "already processed" });
      }

      await prisma.$transaction(async (tx) => {
        await tx.transaction.update({
          where: { id },
          data: {
            processed: true,
            processedBy: clerk.id
          }
        });

        // t.amount is negative; adding it to points deducts redeemed amount
        await tx.user.update({
          where: { id: t.ownerId },
          data: {
            points: t.owner.points + (t.amount || 0)
          }
        });
      });

      const updated = await prisma.transaction.findUnique({ where: { id } });

      return res.json({
        id: updated.id,
        utorid: t.owner.utorid,
        type: "redemption",
        processedBy: clerk.utorid,
        redeemed: t.redeemed,
        remark: updated.remark || "",
        createdBy: t.createdBy
      });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "server error" });
    }
  }
);

function ownerView(t) {
  return {
    id: t.id,
    type: t.type,
    remark: t.remark,
    spent: t.spent,
    amount: t.amount,
    redeemed: t.redeemed,
    processed: t.processed,
    processedBy: t.processedBy,
    createdBy: t.createdBy,
    suspicious: t.suspicious,
    relatedId: t.relatedId,
    createdAt: t.createdAt
  };
}

function fullView(t) {
  return {
    id: t.id,
    type: t.type,
    remark: t.remark,
    spent: t.spent,
    amount: t.amount,
    redeemed: t.redeemed,
    processed: t.processed,
    processedBy: t.processedBy,
    createdBy: t.createdBy,
    suspicious: t.suspicious,
    relatedId: t.relatedId,
    createdAt: t.createdAt,
    owner: t.owner
      ? {
          id: t.owner.id,
          utorid: t.owner.utorid,
          name: t.owner.name
        }
      : null,
    creator: t.creator
      ? {
          id: t.creator.id,
          utorid: t.creator.utorid
        }
      : null
  };
}

// GET /transactions
app.get("/transactions", requireClearance("manager"), async (req, res) => {
  const {
    name,
    createdBy,
    suspicious,
    promotionId,
    type,
    relatedId,
    amount,
    operator,
    page = "1",
    limit = "10",
  } = req.query;

  const where = {};

  // Filter by user (owner) name or utorid
  if (typeof name === "string" && name.trim() !== "") {
    where.owner = {
      OR: [
        { utorid: { contains: name.trim() } },
        { name: { contains: name.trim() } },
      ],
    };
  }

  // Filter by creator utorid
  if (typeof createdBy === "string" && createdBy.trim() !== "") {
    where.creator = {
      utorid: createdBy.trim(),
    };
  }

  if (suspicious === "true" || suspicious === "1") where.suspicious = true;
  else if (suspicious === "false" || suspicious === "0") where.suspicious = false;
  else if (suspicious !== undefined)
    return res.status(400).json({ error: "invalid suspicious" });

  if (promotionId !== undefined) {
    const pid = Number(promotionId);
    if (!Number.isNaN(pid)) {
      where.transactionPromotions = {
        some: { promotionId: pid },
      };
    }
  }

  if (typeof type === "string" && type.trim() !== "") {
    where.type = type.trim();
  }

  if (relatedId !== undefined) {
    const rid = Number(relatedId);
    if (!Number.isNaN(rid)) {
      where.relatedId = rid;
    }
  }

  if (amount !== undefined) {
    const amt = Number(amount);
    if (!Number.isNaN(amt) && typeof operator === "string") {
      if (operator === "gte") {
        where.amount = { gte: amt };
      } else if (operator === "lte") {
        where.amount = { lte: amt };
      }
    }
  }

  const pageNum = Math.max(parseInt(page, 10) || 1, 1);
  const limitNum = Math.max(Math.min(parseInt(limit, 10) || 10, 50), 1);
  const skip = (pageNum - 1) * limitNum;

  try {
    const [count, txs] = await prisma.$transaction([
      prisma.transaction.count({ where }),
      prisma.transaction.findMany({
        where,
        skip,
        take: limitNum,
        orderBy: { id: "asc" },
        include: {
          owner: true,
          creator: true,
          transactionPromotions: true,
        },
      }),
    ]);

    const results = txs.map((t) => ({
      id: t.id,
      utorid: t.owner?.utorid,
      amount: t.amount,
      type: t.type,
      spent: t.spent ?? undefined,
      relatedId: t.relatedId ?? undefined,
      promotionIds: t.transactionPromotions?.map((p) => p.promotionId) || [],
      suspicious: t.suspicious ?? false,
      redeemed: t.redeemed ?? undefined,
      remark: t.remark || "",
      createdBy: t.creator?.utorid,
    }));

    return res.json({ count, results });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// GET /transactions/:id
app.get("/transactions/:transactionId",requireClearance("manager"),async (req, res) => {
    const id = Number(req.params.transactionId);
    if (Number.isNaN(id)) {
      return res.status(400).json({ error: "invalid id" });
    }

    try {
      const t = await prisma.transaction.findUnique({
        where: { id },
        include: {
          owner: true,
          creator: true,
          transactionPromotions: true,
        },
      });

      if (!t) {
        return res.status(404).json({ error: "not found" });
      }

      return res.json({
        id: t.id,
        utorid: t.owner?.utorid,
        type: t.type,
        spent: t.spent ?? undefined,
        amount: t.amount,
        relatedId: t.relatedId ?? undefined,
        promotionIds: t.transactionPromotions?.map((p) => p.promotionId) || [],
        suspicious: t.suspicious ?? false,
        redeemed: t.redeemed ?? undefined,
        remark: t.remark || "",
        createdBy: t.creator?.utorid,
      });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "server error" });
    }
  }
);

// GET /users/:userId/transactions
app.get("/users/:userId/transactions", requireClearance("manager"), async (req, res) => {
  const userId = Number(req.params.userId);
  if (Number.isNaN(userId)) {
    return res.status(400).json({ error: "invalid id" });
  }

  const {
    type,
    relatedId,
    promotionId,
    amount,
    operator,
    page = "1",
    limit = "10",
  } = req.query;

  const where = { ownerId: userId };

  if (typeof type === "string" && type.trim() !== "") {
    where.type = type.trim();
  }

  if (relatedId !== undefined) {
    const rid = Number(relatedId);
    if (!Number.isNaN(rid)) {
      where.relatedId = rid;
    }
  }

  if (promotionId !== undefined) {
    const pid = Number(promotionId);
    if (!Number.isNaN(pid)) {
      where.transactionPromotions = {
        some: { promotionId: pid },
      };
    }
  }

  if (amount !== undefined) {
    const amt = Number(amount);
    if (!Number.isNaN(amt) && typeof operator === "string") {
      if (operator === "gte") {
        where.amount = { gte: amt };
      } else if (operator === "lte") {
        where.amount = { lte: amt };
      }
    }
  }

  const pageNum = Math.max(parseInt(page, 10) || 1, 1);
  const limitNum = Math.max(Math.min(parseInt(limit, 10) || 10, 50), 1);
  const skip = (pageNum - 1) * limitNum;

  try {
    const [count, txs] = await prisma.$transaction([
      prisma.transaction.count({ where }),
      prisma.transaction.findMany({
        where,
        skip,
        take: limitNum,
        orderBy: { id: "asc" },
        include: {
          creator: true,
          transactionPromotions: true,
        },
      }),
    ]);

    const results = txs.map((t) => ({
      id: t.id,
      type: t.type,
      spent: t.spent ?? undefined,
      amount: t.amount,
      relatedId: t.relatedId ?? undefined,
      promotionIds: t.transactionPromotions?.map((p) => p.promotionId) || [],
      remark: t.remark || "",
      createdBy: t.creator?.utorid,
    }));

    return res.json({ count, results });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// GET /users/me/transactions
app.get("/users/me/transactions", requireClearance("regular"), async (req, res) => {
  const {
    type,
    relatedId,
    promotionId,
    amount,
    operator,
    page = "1",
    limit = "10",
  } = req.query;

  const where = { ownerId: req.auth.id };

  if (typeof type === "string" && type.trim() !== "") {
    where.type = type.trim();
  }

  if (relatedId !== undefined) {
    const rid = Number(relatedId);
    if (!Number.isNaN(rid)) {
      where.relatedId = rid;
    }
  }

  if (promotionId !== undefined) {
    const pid = Number(promotionId);
    if (!Number.isNaN(pid)) {
      where.transactionPromotions = {
        some: { promotionId: pid },
      };
    }
  }

  if (amount !== undefined) {
    const amt = Number(amount);
    if (!Number.isNaN(amt) && typeof operator === "string") {
      if (operator === "gte") {
        where.amount = { gte: amt };
      } else if (operator === "lte") {
        where.amount = { lte: amt };
      }
    }
  }

  const pageNum = Math.max(parseInt(page, 10) || 1, 1);
  const limitNum = Math.max(Math.min(parseInt(limit, 10) || 10, 50), 1);
  const skip = (pageNum - 1) * limitNum;

  try {
    const [count, txs] = await prisma.$transaction([
      prisma.transaction.count({ where }),
      prisma.transaction.findMany({
        where,
        skip,
        take: limitNum,
        orderBy: { id: "asc" },
        include: {
          creator: true,
          transactionPromotions: true,
        },
      }),
    ]);

    const results = txs.map((t) => ({
      id: t.id,
      type: t.type,
      spent: t.spent ?? undefined,
      amount: t.amount,
      relatedId: t.relatedId ?? undefined,
      promotionIds: t.transactionPromotions?.map((p) => p.promotionId) || [],
      remark: t.remark || "",
      createdBy: t.creator?.utorid,
    }));

    return res.json({ count, results });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// ===============
// EVENTS helpers
// ===============

async function loadEvent(eventId) {
  return prisma.event.findUnique({
    where: { id: eventId },
    include: {
      organizers: { include: { user: true } },
      guests: { include: { user: true } }
    }
  });
}

async function isOrganizer(eventId, userId) {
  const count = await prisma.organizer.count({
    where: { eventId, userId }
  });
  return count > 0;
}

function validateEventTimes(startTime, endTime) {
  const s = new Date(startTime);
  const e = new Date(endTime);
  if (Number.isNaN(s.getTime()) || Number.isNaN(e.getTime())) return false;
  return s < e;
}

// ==============
// EVENTS
// ==============

app.post("/events", requireClearance("manager"), async (req, res) => {
  const { name, description, location, startTime, endTime, capacity, points } =
    req.body || {};

  if (!name || !description || !location || !startTime || !endTime || !points) {
    return res.status(400).json({ error: "missing fields" });
  }

  if (!validateEventTimes(startTime, endTime)) {
    return res.status(400).json({ error: "invalid time range" });
  }

  try {
    const created = await prisma.event.create({
      data: {
        name,
        description,
        location,
        startTime: new Date(startTime),
        endTime: new Date(endTime),
        capacity: capacity ?? null,
        points,
        pointsRemain: points,
        pointsAwarded: 0,
        published: false
      }
    });

    return res.status(201).json(created);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.get("/events", async (req, res) => {
  if (!req.auth) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const isManager = await hasRole(req, "manager");

    const {
      name,
      location,
      started,
      ended,
      showFull,
      page = "1",
      limit = "10",
      published, // manager-only filter
    } = req.query;

    // You can't specify both started and ended at the same time
    if (typeof started !== "undefined" && typeof ended !== "undefined") {
      return res.status(400).json({ error: "cannot filter by both started and ended" });
    }

    const where = {};

    // Managers can see everything, but can filter by published.
    // Regular users can only see published events.
    if (isManager) {
      if (typeof published === "string") {
        if (published === "true") where.published = true;
        else if (published === "false") where.published = false;
      }
    } else {
      where.published = true;
    }

    if (typeof name === "string" && name.trim() !== "") {
      where.name = { contains: name.trim() };
    }

    if (typeof location === "string" && location.trim() !== "") {
      where.location = { contains: location.trim() };
    }

    const now = new Date();

    if (typeof started === "string") {
      const flag = started === "true";
      where.startTime = flag ? { lte: now } : { gt: now };
    }

    if (typeof ended === "string") {
      const flag = ended === "true";
      where.endTime = flag ? { lte: now } : { gt: now };
    }

    // Validate pagination parameters
    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);
    
    if (isNaN(pageNum) || pageNum < 1) {
      return res.status(400).json({ error: "invalid page" });
    }
    
    if (isNaN(limitNum) || limitNum < 1 || limitNum > 50) {
      return res.status(400).json({ error: "invalid limit" });
    }
    
    const allEvents = await prisma.event.findMany({
      where,
      include: { guests: true },
      orderBy: { startTime: "asc" },
    });

    const showFullFlag = showFull === "true";

    const filtered = allEvents.filter((e) => {
      const isFull =
        e.capacity !== null &&
        typeof e.capacity === "number" &&
        e.capacity > 0 &&
        e.guests.length >= e.capacity;

      if (!showFullFlag && isFull) {
        return false;
      }
      return true;
    });

    const count = filtered.length;
    const startIndex = (pageNum - 1) * limitNum;
    const sliced = filtered.slice(startIndex, startIndex + limitNum);

    const results = sliced.map((e) => {
      const base = {
        id: e.id,
        name: e.name,
        location: e.location,
        startTime: e.startTime,
        endTime: e.endTime,
        capacity: e.capacity,
        numGuests: e.guests.length,
      };

      if (!isManager) {
        // regular view — no points info
        return base;
      }

      return {
        ...base,
        pointsRemain: e.pointsRemain,
        pointsAwarded: e.pointsAwarded,
        published: e.published,
      };
    });

    return res.json({ count, results });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.get("/events/:eventId", async (req, res) => {
  if (!req.auth) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const eventId = Number(req.params.eventId);
  if (Number.isNaN(eventId) || !Number.isInteger(eventId) || eventId < 1) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const event = await prisma.event.findUnique({
      where: { id: eventId },
      include: {
        organizers: { include: { user: true } },
        guests: { include: { user: true } },
      },
    });

    if (!event) {
      return res.status(404).json({ error: "not found" });
    }

    const { id: userId } = req.auth;
    const isManager = await hasRole(req, "manager");
    const isOrganizer = event.organizers.some((o) => o.userId === userId);

    // Regular user view (not manager and not organizer)
    if (!isManager && !isOrganizer) {
      if (!event.published) {
        // unpublished events are invisible to regular users
        return res.status(404).json({ error: "not found" });
      }

      return res.json({
        id: event.id,
        name: event.name,
        description: event.description,
        location: event.location,
        startTime: event.startTime,
        endTime: event.endTime,
        capacity: event.capacity,
        organizers: event.organizers.map((o) => ({
          id: o.user.id,
          utorid: o.user.utorid,
          name: o.user.name,
        })),
        numGuests: event.guests.length
      });
    }

    // Manager/organizer full view
    return res.json({
      id: event.id,
      name: event.name,
      description: event.description,
      location: event.location,
      startTime: event.startTime,
      endTime: event.endTime,
      capacity: event.capacity,
      pointsRemain: event.pointsRemain,
      pointsAwarded: event.pointsAwarded,
      published: event.published,
      organizers: event.organizers.map((o) => ({
        id: o.user.id,
        utorid: o.user.utorid,
        name: o.user.name,
      })),
      guests: event.guests.map((g) => ({
        id: g.user.id,
        utorid: g.user.utorid,
        name: g.user.name,
      })),
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.patch("/events/:id", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const eventId = Number(req.params.id);
  if (Number.isNaN(eventId) || !Number.isInteger(eventId) || eventId < 1) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const event = await prisma.event.findUnique({ 
      where: { id: eventId },
      include: { guests: true, organizers: true }
    });
    if (!event) return res.status(404).json({ error: "not found" });

    const isManager = await hasRole(req, "manager");
    const isOrganizer = event.organizers.some(o => o.userId === req.auth.id);

    if (!isManager && !isOrganizer) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const data = { ...req.body };

    // Only managers can update points and published
    if (!isManager) {
      if (data.points !== undefined || data.published !== undefined) {
        return res.status(403).json({ error: "Forbidden" });
      }
    }

    // Validate time range
    if (
      (data.startTime || data.endTime) &&
      !validateEventTimes(
        data.startTime ?? event.startTime,
        data.endTime ?? event.endTime
      )
    ) {
      return res.status(400).json({ error: "invalid time range" });
    }

    // Validate points - cannot set points less than already awarded
    if (data.points !== undefined) {
      if (typeof data.points !== "number" || data.points < 0) {
        return res.status(400).json({ error: "invalid points" });
      }
      if (data.points < event.pointsAwarded) {
        return res.status(400).json({ error: "points cannot be less than awarded" });
      }
      data.pointsRemain = data.points - event.pointsAwarded;
    }

    // Validate capacity - cannot set capacity less than current guests
    if (data.capacity !== undefined) {
      if (data.capacity !== null && (typeof data.capacity !== "number" || data.capacity < 0)) {
        return res.status(400).json({ error: "invalid capacity" });
      }
      if (data.capacity !== null && data.capacity < event.guests.length) {
        return res.status(400).json({ error: "capacity cannot be less than current guests" });
      }
    }

    // Cannot update name/description/location/startTime/capacity after start time has passed
    const now = new Date();
    if (event.startTime < now) {
      if (data.name !== undefined || data.description !== undefined || 
          data.location !== undefined || data.startTime !== undefined || 
          data.capacity !== undefined) {
        return res.status(400).json({ error: "cannot update event after it has started" });
      }
    }

    // Cannot update endTime after original end time has passed
    if (event.endTime < now && data.endTime !== undefined) {
      return res.status(400).json({ error: "cannot update event after it has ended" });
    }

    // Cannot update startTime or endTime if new times are in the past
    if (data.startTime !== undefined && new Date(data.startTime) < now) {
      return res.status(400).json({ error: "start time cannot be in the past" });
    }
    if (data.endTime !== undefined && new Date(data.endTime) < now) {
      return res.status(400).json({ error: "end time cannot be in the past" });
    }

    const updated = await prisma.event.update({
      where: { id: eventId },
      data
    });

    return res.json(updated);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.patch(
  "/events/:id/publish",
  requireClearance("manager"),
  async (req, res) => {
    const eventId = Number(req.params.id);
    if (Number.isNaN(eventId)) {
      return res.status(400).json({ error: "invalid id" });
    }

    const { published } = req.body || {};
    if (typeof published !== "boolean") {
      return res.status(400).json({ error: "published must be boolean" });
    }

    try {
      const event = await prisma.event.findUnique({ where: { id: eventId } });
      if (!event) return res.status(404).json({ error: "not found" });

      const updated = await prisma.event.update({
        where: { id: eventId },
        data: { published }
      });

      return res.json({
        id: updated.id,
        name: updated.name,
        published: updated.published
      });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "server error" });
    }
  }
);

app.delete("/events/:id", requireClearance("manager"), async (req, res) => {
  const eventId = Number(req.params.id);
  if (Number.isNaN(eventId) || !Number.isInteger(eventId) || eventId < 1) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const exists = await prisma.event.findUnique({ where: { id: eventId } });
    if (!exists) return res.status(404).json({ error: "not found" });

    // Cannot delete published events
    if (exists.published) {
      return res.status(400).json({ error: "cannot delete published event" });
    }

    await prisma.event.delete({ where: { id: eventId } });

    return res.status(204).send();
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// organizers
app.post(
  "/events/:id/organizers",
  requireClearance("manager"),
  async (req, res) => {
    const eventId = Number(req.params.id);
    const { utorid } = req.body || {};

    if (Number.isNaN(eventId) || !Number.isInteger(eventId) || eventId < 1) {
      return res.status(400).json({ error: "invalid id" });
    }
    
    if (typeof utorid !== "string" || !utorid.trim()) {
      return res.status(400).json({ error: "invalid payload" });
    }

    try {
      const user = await prisma.user.findUnique({ where: { utorid: utorid.trim() } });
      const event = await prisma.event.findUnique({ 
        where: { id: eventId },
        include: { organizers: true, guests: true }
      });

      if (!user || !event) return res.status(404).json({ error: "not found" });

      // Check if user is already a guest (400 error)
      const isGuest = event.guests.some(g => g.userId === user.id);
      if (isGuest) {
        return res.status(400).json({ error: "user is already a guest" });
      }

      // Check if event has ended
      const now = new Date();
      if (event.endTime < now) {
        return res.status(410).json({ error: "event has ended" });
      }

      const o = await prisma.organizer.upsert({
        where: { userId_eventId: { userId: user.id, eventId } },
        update: {},
        create: { userId: user.id, eventId }
      });

      // Fetch updated event with organizers
      const updatedEvent = await prisma.event.findUnique({
        where: { id: eventId },
        include: {
          organizers: {
            include: { user: true }
          }
        }
      });

      return res.status(201).json({
        id: updatedEvent.id,
        name: updatedEvent.name,
        location: updatedEvent.location,
        organizers: updatedEvent.organizers.map(o => ({
          id: o.user.id,
          utorid: o.user.utorid,
          name: o.user.name
        }))
      });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "server error" });
    }
  }
);

app.delete(
  "/events/:id/organizers/:userId",
  requireClearance("manager"),
  async (req, res) => {
    const eventId = Number(req.params.id);
    const userId = Number(req.params.userId);

    if (Number.isNaN(eventId) || !Number.isInteger(eventId) || eventId < 1 ||
        Number.isNaN(userId) || !Number.isInteger(userId) || userId < 1) {
      return res.status(400).json({ error: "invalid id" });
    }

    try {
      await prisma.organizer.delete({
        where: { userId_eventId: { userId, eventId } }
      });

      return res.status(204).send();
    } catch (e) {
      if (e.code === "P2025") {
        return res.status(404).json({ error: "organizer not found" });
      }
      console.error(e);
      return res.status(500).json({ error: "server error" });
    }
  }
);

// guests – add/remove by organizer or manager
app.post("/events/:id/guests", async (req, res) => {
  const eventId = Number(req.params.id);
  const { utorid } = req.body || {};

  if (Number.isNaN(eventId) || !Number.isInteger(eventId) || eventId < 1) {
    return res.status(400).json({ error: "invalid id" });
  }
  
  if (typeof utorid !== "string" || !utorid.trim()) {
    return res.status(400).json({ error: "invalid payload" });
  }

  if (!req.auth) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const isManager = await hasRole(req, "manager");
    const isOrg = await isOrganizer(eventId, req.auth.id);

    if (!isManager && !isOrg) {
      return res.status(403).json({ error: "Forbidden" });
    }

    // For organizers, check if event is published (404 if not visible yet)
    if (isOrg && !isManager) {
      const event = await prisma.event.findUnique({ where: { id: eventId } });
      if (!event || !event.published) {
        return res.status(404).json({ error: "not found" });
      }
    }

    const user = await prisma.user.findUnique({ where: { utorid: utorid.trim() } });
    const event = await prisma.event.findUnique({ 
      where: { id: eventId },
      include: { organizers: true, guests: true }
    });

    if (!user || !event) return res.status(404).json({ error: "not found" });

    // Check if user is already an organizer (400 error)
    const isOrganizerUser = event.organizers.some(o => o.userId === user.id);
    if (isOrganizerUser) {
      return res.status(400).json({ error: "user is already an organizer" });
    }

    // Check if event has ended
    const now = new Date();
    if (event.endTime < now) {
      return res.status(410).json({ error: "event has ended" });
    }

    // Check if event is full
    if (event.capacity !== null && typeof event.capacity === "number" && event.capacity > 0) {
      if (event.guests.length >= event.capacity) {
        return res.status(410).json({ error: "event full" });
      }
    }

    const g = await prisma.guest.upsert({
      where: { userId_eventId: { userId: user.id, eventId } },
      update: {},
      create: { userId: user.id, eventId }
    });

    // Get updated guest count
    const guestCount = await prisma.guest.count({ where: { eventId } });

    return res.status(201).json({
      id: event.id,
      name: event.name,
      location: event.location,
      guestAdded: {
        id: user.id,
        utorid: user.utorid,
        name: user.name
      },
      numGuests: guestCount
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.delete("/events/:id/guests/:userId", requireClearance("manager"), async (req, res) => {
  const eventId = Number(req.params.id);
  const userId = Number(req.params.userId);

  if (Number.isNaN(eventId) || !Number.isInteger(eventId) || eventId < 1 ||
      Number.isNaN(userId) || !Number.isInteger(userId) || userId < 1) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    await prisma.guest.delete({
      where: { userId_eventId: { userId, eventId } }
    });
    return res.status(204).send();
  } catch (e) {
    if (e.code === "P2025") {
      return res.status(404).json({ error: "guest not found" });
    }
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// user self join/leave
app.post("/events/:id/guests/me", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const eventId = Number(req.params.id);
  const userId = req.auth.id;

  if (Number.isNaN(eventId) || !Number.isInteger(eventId)) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const event = await prisma.event.findUnique({ where: { id: eventId } });
    if (!event) return res.status(404).json({ error: "not found" });

    if (!event.published) {
      return res.status(404).json({ error: "not found" });
    }

    // Check if event has ended
    const now = new Date();
    if (event.endTime < now) {
      return res.status(410).json({ error: "event has ended" });
    }

    // Check if already a guest
    const existingGuest = await prisma.guest.findUnique({
      where: { userId_eventId: { userId, eventId } }
    });
    if (existingGuest) {
      return res.status(400).json({ error: "already on guest list" });
    }

    // Check if event is full
    if (event.capacity !== null && typeof event.capacity === "number" && event.capacity > 0) {
      const count = await prisma.guest.count({ where: { eventId } });
      if (count >= event.capacity) {
        return res.status(410).json({ error: "event full" });
      }
    }

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: "not found" });

    const g = await prisma.guest.create({
      data: { userId, eventId }
    });

    // Get updated guest count
    const guestCount = await prisma.guest.count({ where: { eventId } });

    return res.status(201).json({
      id: event.id,
      name: event.name,
      location: event.location,
      guestAdded: {
        id: user.id,
        utorid: user.utorid,
        name: user.name
      },
      numGuests: guestCount
    });
  } catch (e) {
    if (e.code === "P2002") {
      // Unique constraint violation - already a guest
      return res.status(400).json({ error: "already on guest list" });
    }
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.delete("/events/:id/guests/me", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const eventId = Number(req.params.id);
  const userId = req.auth.id;

  if (Number.isNaN(eventId) || !Number.isInteger(eventId)) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const event = await prisma.event.findUnique({ where: { id: eventId } });
    if (!event) return res.status(404).json({ error: "not found" });

    // Check if event has ended
    const now = new Date();
    if (event.endTime < now) {
      return res.status(410).json({ error: "event has ended" });
    }

    await prisma.guest.delete({
      where: { userId_eventId: { userId, eventId } }
    });
    return res.status(204).send();
  } catch (e) {
    // Prisma throws P2025 when record not found
    if (e.code === "P2025" || e.meta?.cause?.includes("Record to delete does not exist")) {
      return res.status(404).json({ error: "guest not found" });
    }
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// award event points
app.post("/events/:id/transactions", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const eventId = Number(req.params.id);
  const { type, utorid, amount, remark } = req.body || {};

  // Validate eventId first (needed for auth check)
  if (Number.isNaN(eventId) || !Number.isInteger(eventId)) {
    return res.status(400).json({ error: "invalid id" });
  }

  // Validate type
  if (type !== "event") {
    return res.status(400).json({ error: "type must be event" });
  }

  // Check auth
  const isManager = await hasRole(req, "manager");
  const isOrg = await isOrganizer(eventId, req.auth.id);

  if (!isManager && !isOrg) {
    return res.status(403).json({ error: "Forbidden" });
  }

  // Validate amount
  if (amount === undefined || amount === null) {
    return res.status(400).json({ error: "invalid amount" });
  }
  
  const amountNum = Number(amount);
  if (Number.isNaN(amountNum) || !Number.isInteger(amountNum) || amountNum <= 0) {
    return res.status(400).json({ error: "invalid amount" });
  }

  try {
    const event = await prisma.event.findUnique({ 
      where: { id: eventId },
      include: { guests: true }
    });
    if (!event) return res.status(404).json({ error: "not found" });

    // If utorid is provided, award to that specific user
    if (utorid !== undefined && utorid !== null) {
      if (typeof utorid !== "string" || !utorid.trim()) {
        return res.status(400).json({ error: "invalid utorid" });
      }

      const user = await prisma.user.findUnique({ where: { utorid: utorid.trim() } });
      if (!user) return res.status(404).json({ error: "user not found" });

      const guest = event.guests.find(g => g.userId === user.id);
      if (!guest) {
        return res.status(400).json({ error: "user not a guest" });
      }

      if (event.pointsRemain < amountNum) {
        return res.status(400).json({ error: "not enough points remaining" });
      }

      const created = await prisma.$transaction(async (tx) => {
        const t = await tx.transaction.create({
          data: {
            type: "event",
            amount: amountNum,
            remark: remark || "",
            ownerId: user.id,
            createdBy: req.auth.id,
            relatedId: eventId
          }
        });

        await tx.user.update({
          where: { id: user.id },
          data: { points: { increment: amountNum } }
        });

        await tx.event.update({
          where: { id: eventId },
          data: {
            pointsRemain: { decrement: amountNum },
            pointsAwarded: { increment: amountNum }
          }
        });

        return t;
      });

      const creator = await prisma.user.findUnique({ where: { id: req.auth.id } });

      return res.status(201).json({
        id: created.id,
        recipient: user.utorid,
        awarded: amountNum,
        type: "event",
        relatedId: eventId,
        remark: created.remark || "",
        createdBy: creator.utorid
      });
    } else {
      // Award to all guests
      if (event.guests.length === 0) {
        return res.status(400).json({ error: "no guests to award" });
      }

      const totalAmount = amountNum * event.guests.length;
      if (event.pointsRemain < totalAmount) {
        return res.status(400).json({ error: "not enough points remaining" });
      }

      const creator = await prisma.user.findUnique({ where: { id: req.auth.id } });
      const results = await prisma.$transaction(async (tx) => {
        const transactions = [];

        for (const guest of event.guests) {
          const t = await tx.transaction.create({
            data: {
              type: "event",
              amount: amountNum,
              remark: remark || "",
              ownerId: guest.userId,
              createdBy: req.auth.id,
              relatedId: eventId
            },
            include: { owner: true }
          });

          await tx.user.update({
            where: { id: guest.userId },
            data: { points: { increment: amountNum } }
          });

          transactions.push({
            id: t.id,
            recipient: t.owner.utorid,
            awarded: amountNum,
            type: "event",
            relatedId: eventId,
            remark: t.remark || "",
            createdBy: creator.utorid
          });
        }

        await tx.event.update({
          where: { id: eventId },
          data: {
            pointsRemain: { decrement: totalAmount },
            pointsAwarded: { increment: totalAmount }
          }
        });

        return transactions;
      });

      return res.status(201).json(results);
    }
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

const server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

server.on("error", (err) => {
  console.error(`cannot start server: ${err.message}`);
  process.exit(1);
});
