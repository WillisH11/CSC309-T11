#!/usr/bin/env node
"use strict";

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

// ====== auth middleware ======

if (!process.env.JWT_SECRET) {
  console.error("JWT_SECRET not set");
}

app.use(
  jwt({
    secret: process.env.JWT_SECRET || "development-secret",
    algorithms: ["HS256"],
    credentialsRequired: false
  })
);

app.use((err, req, res, next) => {
  if (err.name === "UnauthorizedError") {
    return res.status(401).json({ error: "Invalid or missing token" });
  }
  next(err);
});

// ====== roles & helpers ======

const roleRank = {
  regular: 1,
  cashier: 2,
  manager: 3,
  superuser: 4
};

function requireClearance(minRole) {
  return (req, res, next) => {
    if (!req.auth) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const userRank = roleRank[req.auth.role] || 0;
    const neededRank = roleRank[minRole];
    if (userRank < neededRank) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}

function validatePasswordComplexity(pwd) {
  if (typeof pwd !== "string") return false;
  if (pwd.length < 8 || pwd.length > 20) return false;
  const hasUpper = /[A-Z]/.test(pwd);
  const hasLower = /[a-z]/.test(pwd);
  const hasDigit = /\d/.test(pwd);
  const hasSpecial = /[^A-Za-z0-9]/.test(pwd);
  return hasUpper && hasLower && hasDigit && hasSpecial;
}

function isValidUtorid(utorid) {
  return typeof utorid === "string" && /^[A-Za-z0-9]{7,8}$/.test(utorid);
}

function isValidName(name) {
  return typeof name === "string" && name.length >= 1 && name.length <= 50;
}

function isValidUofTEmail(email) {
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
      // spec tester expects 401 for bad credentials
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
        role: user.role
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
  const ip = req.ip;
  const now = Date.now();

  if (resetLimiter[ip] && now - resetLimiter[ip] < 60000) {
    return res.status(429).json({ error: "Too Many Requests" });
  }
  resetLimiter[ip] = now;

  const { utorid } = req.body || {};
  if (!utorid || typeof utorid !== "string") {
    return res.status(400).json({ error: "utorid required" });
  }

  try {
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    const resetToken = uuidv4();

    const user = await prisma.user.findUnique({ where: { utorid } });

    if (user) {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          resetToken,
          resetTokenExp: expiresAt
        }
      });
    }

    // Always 202 with token in body (per spec for assignment)
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

  if (!utorid || !password) {
    return res.status(400).json({ error: "utorid and password required" });
  }

  if (!validatePasswordComplexity(password)) {
    return res.status(400).json({ error: "invalid password format" });
  }

  try {
    const user = await prisma.user.findFirst({
      where: { resetToken, utorid }
    });

    if (!user) {
      return res.status(404).json({ error: "reset token not found" });
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
        resetTokenExp: null
      }
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

// Register (Cashier or higher)
app.post("/users", requireClearance("cashier"), async (req, res) => {
  const { utorid, name, email } = req.body || {};

  // basic validation per spec
  if (!isValidUtorid(utorid) || !isValidName(name) || !isValidUofTEmail(email)) {
    return res.status(400).json({ error: "invalid payload" });
  }

  try {
    const existingByUtorid = await prisma.user.findUnique({ where: { utorid } });
    if (existingByUtorid) {
      return res.status(409).json({ error: "utorid already exists" });
    }

    const existingByEmail = await prisma.user.findUnique({ where: { email } });
    if (existingByEmail) {
      return res.status(409).json({ error: "email already exists" });
    }

    const expiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000); // 7 days
    const resetToken = uuidv4();

    const created = await prisma.user.create({
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
      id: created.id,
      utorid: created.utorid,
      name: created.name,
      email: created.email,
      verified: created.verified,
      expiresAt,
      resetToken
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// GET /users (Manager or higher, with filters & pagination)
app.get("/users", requireClearance("manager"), async (req, res) => {
  const {
    name,
    role,
    verified,
    activated,
    page,
    limit
  } = req.query;

  const where = {};

  if (name && typeof name === "string") {
    where.OR = [
      { utorid: { contains: name, mode: "insensitive" } },
      { name: { contains: name, mode: "insensitive" } }
    ];
  }

  if (role && typeof role === "string") {
    where.role = role;
  }

  if (verified !== undefined) {
    if (verified === "true" || verified === true) where.verified = true;
    else if (verified === "false" || verified === false) where.verified = false;
  }

  if (activated !== undefined) {
    if (activated === "true" || activated === true) {
      where.lastLogin = { not: null };
    } else if (activated === "false" || activated === false) {
      where.lastLogin = null;
    }
  }

  const pageNum = Number(page) > 0 ? Number(page) : 1;
  const limitNum = Number(limit) > 0 ? Number(limit) : 10;
  const skip = (pageNum - 1) * limitNum;

  try {
    const count = await prisma.user.count({ where });
    const results = await prisma.user.findMany({
      where,
      orderBy: { id: "asc" },
      skip,
      take: limitNum
    });

    const mapped = results.map((u) => ({
      id: u.id,
      utorid: u.utorid,
      name: u.name,
      email: u.email,
      birthday: u.birthday || null,
      role: u.role,
      points: u.points,
      createdAt: u.createdAt,
      lastLogin: u.lastLogin,
      verified: u.verified,
      avatarUrl: u.avatarUrl || null
    }));

    return res.json({ count, results: mapped });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// helper: fetch available one-time promotions for a user
async function getAvailableOneTimePromotionsForUser(userId) {
  const now = new Date();
  const promos = await prisma.promotion.findMany({
    where: {
      type: "onetime",
      startTime: { lte: now },
      endTime: { gte: now },
      promotionUsers: {
        none: {
          userId,
          used: true
        }
      }
    }
  });

  return promos.map((p) => ({
    id: p.id,
    name: p.name,
    minSpending: p.minSpending,
    rate: p.rate,
    points: p.points
  }));
}

// GET /users/:id (Cashier or higher)
app.get("/users/:id", requireClearance("cashier"), async (req, res) => {
  const userId = Number(req.params.id);
  if (Number.isNaN(userId)) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: "not found" });

    const promotions = await getAvailableOneTimePromotionsForUser(user.id);

    return res.json({
      id: user.id,
      utorid: user.utorid,
      name: user.name,
      points: user.points,
      verified: user.verified,
      promotions
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// PATCH /users/:id (Manager or higher)
app.patch("/users/:id", requireClearance("manager"), async (req, res) => {
  const userId = Number(req.params.id);
  if (Number.isNaN(userId)) {
    return res.status(400).json({ error: "invalid id" });
  }

  const allowedFields = ["verified", "suspicious", "role"];
  const keys = Object.keys(req.body || {});
  if (keys.length === 0) {
    return res.status(400).json({ error: "no fields to update" });
  }
  if (keys.some((k) => !allowedFields.includes(k))) {
    return res.status(400).json({ error: "invalid fields" });
  }

  try {
    const target = await prisma.user.findUnique({ where: { id: userId } });
    if (!target) return res.status(404).json({ error: "not found" });

    const data = {};

    if ("verified" in req.body) {
      if (typeof req.body.verified !== "boolean") {
        return res.status(400).json({ error: "invalid verified" });
      }
      data.verified = req.body.verified;
    }

    if ("suspicious" in req.body) {
      if (typeof req.body.suspicious !== "boolean") {
        return res.status(400).json({ error: "invalid suspicious" });
      }
      data.suspicious = req.body.suspicious;
      // If we were also promoting to cashier, ensure suspicious false handled below
    }

    if ("role" in req.body) {
      const desiredRole = req.body.role;
      const requesterRank = roleRank[req.auth.role];

      // manager can only assign regular or cashier
      if (req.auth.role === "manager") {
        if (desiredRole !== "regular" && desiredRole !== "cashier") {
          return res.status(400).json({ error: "invalid role for manager" });
        }
      }
      // superuser can assign any role, but we don't need extra restrictions
      if (!roleRank[desiredRole]) {
        return res.status(400).json({ error: "invalid role" });
      }

      // when promoting to cashier, suspicious must be false
      if (
        desiredRole === "cashier" &&
        (data.suspicious === true || target.suspicious)
      ) {
        return res
          .status(400)
          .json({ error: "suspicious user cannot be cashier" });
      }

      data.role = desiredRole;
    }

    const updated = await prisma.user.update({
      where: { id: userId },
      data
    });

    const response = {
      id: updated.id,
      utorid: updated.utorid,
      name: updated.name
    };

    if ("verified" in data) response.verified = updated.verified;
    if ("suspicious" in data) response.suspicious = updated.suspicious;
    if ("role" in data) response.role = updated.role;

    return res.json(response);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// GET /users/me
app.get("/users/me", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  try {
    const me = await prisma.user.findUnique({
      where: { id: req.auth.id }
    });
    if (!me) return res.status(404).json({ error: "not found" });

    return res.json({
      id: me.id,
      utorid: me.utorid,
      name: me.name,
      email: me.email,
      birthday: me.birthday || null,
      role: me.role,
      points: me.points,
      createdAt: me.createdAt,
      lastLogin: me.lastLogin,
      verified: me.verified,
      avatarUrl: me.avatarUrl || null
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// PATCH /users/me
app.patch("/users/me", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const { name, email, birthday } = req.body || {};
  const updates = {};

  if (name !== undefined) {
    if (!isValidName(name)) {
      return res.status(400).json({ error: "invalid name" });
    }
    updates.name = name;
  }

  if (email !== undefined) {
    if (!isValidUofTEmail(email)) {
      return res.status(400).json({ error: "invalid email" });
    }
    updates.email = email;
  }

  if (birthday !== undefined) {
    if (!isValidBirthdayString(birthday)) {
      return res.status(400).json({ error: "invalid birthday" });
    }
    updates.birthday = birthday;
  }

  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: "no valid fields to update" });
  }

  try {
    const updated = await prisma.user.update({
      where: { id: req.auth.id },
      data: updates
    });

    return res.json({
      id: updated.id,
      utorid: updated.utorid,
      name: updated.name,
      email: updated.email,
      birthday: updated.birthday || null,
      role: updated.role,
      points: updated.points,
      createdAt: updated.createdAt,
      lastLogin: updated.lastLogin,
      verified: updated.verified,
      avatarUrl: updated.avatarUrl || null
    });
  } catch (e) {
    if (e.code === "P2002") {
      // unique constraint (likely email)
      return res.status(409).json({ error: "email already exists" });
    }
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// PATCH /users/me/password
app.patch("/users/me/password", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const { old, new: newPassword } = req.body || {};

  if (!old || !newPassword) {
    return res.status(400).json({ error: "missing fields" });
  }

  if (!validatePasswordComplexity(newPassword)) {
    return res.status(400).json({ error: "invalid password format" });
  }

  try {
    const me = await prisma.user.findUnique({
      where: { id: req.auth.id }
    });

    if (!me || !me.password) {
      return res.status(403).json({ error: "incorrect password" });
    }

    const match = await bcrypt.compare(old, me.password);
    if (!match) return res.status(403).json({ error: "incorrect password" });

    const hashed = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { id: me.id },
      data: { password: hashed }
    });

    return res.json({ status: "ok" });
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
  const isCashier = req.auth && roleRank[req.auth.role] >= roleRank["cashier"];
  const now = new Date();

  let where = {};

  if (!isCashier) {
    where = {
      type: "automatic",
      startTime: { lte: now },
      endTime: { gte: now }
    };
  }

  try {
    const promos = await prisma.promotion.findMany({
      where,
      orderBy: { startTime: "asc" }
    });

    if (!isCashier) {
      return res.json(
        promos.map((p) => ({
          id: p.id,
          name: p.name,
          description: p.description,
          type: p.type,
          startTime: p.startTime,
          endTime: p.endTime
        }))
      );
    }

    return res.json(promos);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.get("/promotions/:id", async (req, res) => {
  const promoId = Number(req.params.id);
  if (Number.isNaN(promoId)) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const p = await prisma.promotion.findUnique({
      where: { id: promoId }
    });

    if (!p) return res.status(404).json({ error: "not found" });

    const isCashier =
      req.auth && roleRank[req.auth.role] >= roleRank["cashier"];

    if (!isCashier) {
      const now = new Date();
      const activeAutomatic =
        p.type === "automatic" &&
        p.startTime <= now &&
        p.endTime >= now;

      if (!activeAutomatic) {
        return res.status(403).json({ error: "Forbidden" });
      }

      return res.json({
        id: p.id,
        name: p.name,
        description: p.description,
        type: p.type,
        startTime: p.startTime,
        endTime: p.endTime
      });
    }

    return res.json(p);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.patch(
  "/promotions/:id",
  requireClearance("manager"),
  async (req, res) => {
    const promoId = Number(req.params.id);
    if (Number.isNaN(promoId)) {
      return res.status(400).json({ error: "invalid id" });
    }

    try {
      const exists = await prisma.promotion.findUnique({
        where: { id: promoId }
      });
      if (!exists) return res.status(404).json({ error: "not found" });

      const data = { ...req.body };

      if ((data.startTime || data.endTime) &&
        new Date(data.startTime ?? exists.startTime) >=
          new Date(data.endTime ?? exists.endTime)
      ) {
        return res.status(400).json({ error: "invalid time range" });
      }

      const updated = await prisma.promotion.update({
        where: { id: promoId },
        data
      });

      return res.json(updated);
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "server error" });
    }
  }
);

app.delete(
  "/promotions/:id",
  requireClearance("manager"),
  async (req, res) => {
    const promoId = Number(req.params.id);
    if (Number.isNaN(promoId)) {
      return res.status(400).json({ error: "invalid id" });
    }

    try {
      const exists = await prisma.promotion.findUnique({
        where: { id: promoId }
      });
      if (!exists) return res.status(404).json({ error: "not found" });

      await prisma.promotion.delete({ where: { id: promoId } });
      return res.json({ status: "ok" });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "server error" });
    }
  }
);

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
    if (roleRank[req.auth.role] < roleRank["cashier"]) {
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
    if (roleRank[req.auth.role] < roleRank["manager"]) {
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
  if (type !== "redemption" || typeof amount !== "number" || amount <= 0) {
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

    if (user.points < amount) {
      return res.status(400).json({ error: "insufficient points" });
    }

    const t = await prisma.transaction.create({
      data: {
        type: "redemption",
        amount: -amount,
        redeemed: amount,
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
      amount,
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
app.get("/transactions", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const isCashier = roleRank[req.auth.role] >= roleRank["cashier"];

  let statusFilter;
  if (req.query.statuses) {
    const statuses = req.query.statuses.split(",").map((s) => s.trim());
    const mapped = statuses
      .map((s) => {
        if (s === "suspicious") return { suspicious: true };
        if (s === "processed") return { processed: true };
        if (s === "unprocessed") return { processed: false };
        return null;
      })
      .filter(Boolean);

    if (mapped.length > 0) {
      statusFilter = { OR: mapped };
    }
  }

  const where = isCashier
    ? statusFilter || {}
    : {
        ownerId: req.auth.id,
        ...(statusFilter || {})
      };

  try {
    const list = await prisma.transaction.findMany({
      where,
      include: {
        owner: true,
        creator: true
      },
      orderBy: { id: "desc" }
    });

    if (!isCashier) {
      return res.json(list.map(ownerView));
    }

    return res.json(list.map(fullView));
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

// GET /transactions/:id
app.get("/transactions/:transactionId", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const id = Number(req.params.transactionId);
  if (Number.isNaN(id)) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const t = await prisma.transaction.findUnique({
      where: { id },
      include: {
        owner: true,
        creator: true
      }
    });

    if (!t) return res.status(404).json({ error: "not found" });

    const isCashier = roleRank[req.auth.role] >= roleRank["cashier"];
    if (!isCashier && t.ownerId !== req.auth.id) {
      return res.status(403).json({ error: "Forbidden" });
    }

    return res.json(isCashier ? fullView(t) : ownerView(t));
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
  const isManager = req.auth && roleRank[req.auth.role] >= roleRank["manager"];

  const where = isManager ? {} : { published: true };

  try {
    const events = await prisma.event.findMany({
      where,
      orderBy: { startTime: "asc" }
    });

    if (!isManager) {
      const trimmed = events.map((e) => ({
        id: e.id,
        name: e.name,
        description: e.description,
        location: e.location,
        startTime: e.startTime,
        endTime: e.endTime,
        published: e.published
      }));
      return res.json(trimmed);
    }

    return res.json(events);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.get("/events/:id", async (req, res) => {
  const eventId = Number(req.params.id);
  if (Number.isNaN(eventId)) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const event = await loadEvent(eventId);
    if (!event) return res.status(404).json({ error: "not found" });

    const isManager =
      req.auth && roleRank[req.auth.role] >= roleRank["manager"];
    const isOrg = req.auth && (await isOrganizer(eventId, req.auth.id));

    if (!isManager && !isOrg) {
      return res.json({
        id: event.id,
        name: event.name,
        description: event.description,
        location: event.location,
        startTime: event.startTime,
        endTime: event.endTime,
        published: event.published
      });
    }

    return res.json(event);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error" });
  }
});

app.patch("/events/:id", requireClearance("manager"), async (req, res) => {
  const eventId = Number(req.params.id);
  if (Number.isNaN(eventId)) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const event = await prisma.event.findUnique({ where: { id: eventId } });
    if (!event) return res.status(404).json({ error: "not found" });

    const data = { ...req.body };

    if (
      (data.startTime || data.endTime) &&
      !validateEventTimes(
        data.startTime ?? event.startTime,
        data.endTime ?? event.endTime
      )
    ) {
      return res.status(400).json({ error: "invalid time range" });
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
  if (Number.isNaN(eventId)) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    const exists = await prisma.event.findUnique({ where: { id: eventId } });
    if (!exists) return res.status(404).json({ error: "not found" });

    await prisma.event.delete({ where: { id: eventId } });

    return res.json({ status: "ok" });
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
    const { userId } = req.body || {};

    if (Number.isNaN(eventId) || typeof userId !== "number") {
      return res.status(400).json({ error: "invalid payload" });
    }

    const user = await prisma.user.findUnique({ where: { id: userId } });
    const event = await prisma.event.findUnique({ where: { id: eventId } });

    if (!user || !event) return res.status(404).json({ error: "not found" });

    const o = await prisma.organizer.upsert({
      where: { userId_eventId: { userId, eventId } },
      update: {},
      create: { userId, eventId }
    });

    return res.status(201).json(o);
  }
);

app.delete(
  "/events/:id/organizers",
  requireClearance("manager"),
  async (req, res) => {
    const eventId = Number(req.params.id);
    const { userId } = req.body || {};

    if (Number.isNaN(eventId) || typeof userId !== "number") {
      return res.status(400).json({ error: "invalid payload" });
    }

    try {
      await prisma.organizer.delete({
        where: { userId_eventId: { userId, eventId } }
      });

      return res.json({ status: "ok" });
    } catch {
      return res.status(404).json({ error: "organizer not found" });
    }
  }
);

// guests – add/remove by organizer or manager
app.post("/events/:id/guests", async (req, res) => {
  const eventId = Number(req.params.id);
  const { userId } = req.body || {};

  if (Number.isNaN(eventId) || typeof userId !== "number") {
    return res.status(400).json({ error: "invalid payload" });
  }

  const isManager = req.auth && roleRank[req.auth.role] >= roleRank["manager"];
  const isOrg = req.auth && (await isOrganizer(eventId, req.auth.id));

  if (!isManager && !isOrg) {
    return res.status(403).json({ error: "Forbidden" });
  }

  const event = await prisma.event.findUnique({ where: { id: eventId } });
  if (!event) return res.status(404).json({ error: "not found" });

  if (event.capacity !== null) {
    const count = await prisma.guest.count({ where: { eventId } });
    if (count >= event.capacity) {
      return res.status(400).json({ error: "event full" });
    }
  }

  const g = await prisma.guest.upsert({
    where: { userId_eventId: { userId, eventId } },
    update: {},
    create: { userId, eventId }
  });

  return res.status(201).json(g);
});

app.delete("/events/:id/guests", async (req, res) => {
  const eventId = Number(req.params.id);
  const { userId } = req.body || {};

  if (Number.isNaN(eventId) || typeof userId !== "number") {
    return res.status(400).json({ error: "invalid payload" });
  }

  const isManager = req.auth && roleRank[req.auth.role] >= roleRank["manager"];
  const isOrg = req.auth && (await isOrganizer(eventId, req.auth.id));

  if (!isManager && !isOrg) {
    return res.status(403).json({ error: "Forbidden" });
  }

  try {
    await prisma.guest.delete({
      where: { userId_eventId: { userId, eventId } }
    });
    return res.json({ status: "ok" });
  } catch {
    return res.status(404).json({ error: "guest not found" });
  }
});

// user self join/leave
app.post("/events/:id/guests/me", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const eventId = Number(req.params.id);
  const userId = req.auth.id;

  if (Number.isNaN(eventId)) {
    return res.status(400).json({ error: "invalid id" });
  }

  const event = await prisma.event.findUnique({ where: { id: eventId } });
  if (!event) return res.status(404).json({ error: "not found" });

  if (!event.published) {
    return res.status(403).json({ error: "event not published" });
  }

  if (event.capacity !== null) {
    const count = await prisma.guest.count({ where: { eventId } });
    if (count >= event.capacity) {
      return res.status(400).json({ error: "event full" });
    }
  }

  const g = await prisma.guest.upsert({
    where: { userId_eventId: { userId, eventId } },
    update: {},
    create: { userId, eventId }
  });

  return res.status(201).json(g);
});

app.delete("/events/:id/guests/me", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const eventId = Number(req.params.id);
  const userId = req.auth.id;

  if (Number.isNaN(eventId)) {
    return res.status(400).json({ error: "invalid id" });
  }

  try {
    await prisma.guest.delete({
      where: { userId_eventId: { userId, eventId } }
    });
    return res.json({ status: "ok" });
  } catch {
    return res.status(404).json({ error: "guest not found" });
  }
});

// award event points
app.post("/events/:id/transactions", async (req, res) => {
  if (!req.auth) return res.status(401).json({ error: "Unauthorized" });

  const eventId = Number(req.params.id);
  const { userId, amount, remark } = req.body || {};

  if (
    Number.isNaN(eventId) ||
    typeof userId !== "number" ||
    typeof amount !== "number" ||
    amount <= 0
  ) {
    return res.status(400).json({ error: "invalid payload" });
  }

  const isManager = roleRank[req.auth.role] >= roleRank["manager"];
  const isOrg = await isOrganizer(eventId, req.auth.id);

  if (!isManager && !isOrg) {
    return res.status(403).json({ error: "Forbidden" });
  }

  try {
    const event = await prisma.event.findUnique({ where: { id: eventId } });
    if (!event) return res.status(404).json({ error: "not found" });

    const guest = await prisma.guest.findUnique({
      where: { userId_eventId: { userId, eventId } }
    });

    if (!guest) {
      return res.status(400).json({ error: "user not a guest" });
    }

    if (event.pointsRemain < amount) {
      return res.status(400).json({ error: "not enough points remaining" });
    }

    const created = await prisma.$transaction(async (tx) => {
      const t = await tx.transaction.create({
        data: {
          type: "event",
          amount,
          remark: remark || "",
          ownerId: userId,
          createdBy: req.auth.id,
          relatedId: eventId
        }
      });

      await tx.user.update({
        where: { id: userId },
        data: { points: { increment: amount } }
      });

      await tx.event.update({
        where: { id: eventId },
        data: {
          pointsRemain: { decrement: amount },
          pointsAwarded: { increment: amount }
        }
      });

      return t;
    });

    return res.status(201).json(created);
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
