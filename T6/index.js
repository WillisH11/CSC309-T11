#!/usr/bin/env node
'use strict';

const express = require("express");
const { PrismaClient } = require('@prisma/client');
const basicAuth = require('./middleware/basicAuth');

const prisma = new PrismaClient();
const app = express();
app.use(express.json());

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

const jsonErr = (res, status, message) => res.status(status).json({ message });

// ========== simple root ==========
app.get("/", (req, res) => {
    res.send("Hello World!");
});

// ========== USERS ==========
app.post('/users', async (req, res) => {
  const { username, password } = req.body ?? {};

  if (typeof username !== 'string' || username.trim() === '' ||
      typeof password !== 'string' || password.trim() === '') {
    return jsonErr(res, 400, 'Invalid payload');
  }

  try {
    const existing = await prisma.user.findUnique({ where: { username } });
    if (existing) {
      return jsonErr(res, 409, 'A user with that username already exists');
    }

    const user = await prisma.user.create({
      data: { username: username.trim(), password: password.trim() },
    });

    return res.status(201).json(user);
  } catch (err) {
    console.error(err);
    return jsonErr(res, 500, 'Internal server error');
  }
});

// ========== NOTES ==========
app.post('/notes', basicAuth, async (req, res) => {
  if (!req.user) return jsonErr(res, 401, 'Not authenticated');

  const { title, description, completed, public: isPublic } = req.body ?? {};

  if (typeof title !== 'string' || title.trim() === '' ||
      typeof description !== 'string' || description.trim() === '' ||
      typeof completed !== 'boolean' ||
      typeof isPublic !== 'boolean') {
    return jsonErr(res, 400, 'Invalid payload');
  }

  try {
    const note = await prisma.note.create({
      data: {
        title: title.trim(),
        description: description.trim(),
        completed,
        public: isPublic,
        user: { connect: { id: req.user.id } },
      },
    });

    return res.status(201).json(note);
  } catch (err) {
    console.error(err);
    return jsonErr(res, 500, 'Internal server error');
  }
});

app.get('/notes', async (req, res) => {
  const { done } = req.query;

  const where = { public: true };

  if (done !== undefined) {
    if (done === 'true') where.completed = true;
    else if (done === 'false') where.completed = false;
    else return jsonErr(res, 400, 'Invalid payload');
  }

  try {
    const notes = await prisma.note.findMany({ where });
    return res.json(notes);
  } catch (err) {
    console.error(err);
    return jsonErr(res, 500, 'Internal server error');
  }
});


app.get('/notes/:noteId', basicAuth, async (req, res) => {
  if (!req.user) return jsonErr(res, 401, 'Not authenticated');

  const id = Number(req.params.noteId);
  if (!Number.isInteger(id)) {
    return jsonErr(res, 404, 'Not found');
  }

  try {
    const note = await prisma.note.findUnique({ where: { id } });
    if (!note) return jsonErr(res, 404, 'Not found');

    if (note.userId !== req.user.id) return jsonErr(res, 403, 'Not permitted');

    return res.json(note);
  } catch (err) {
    console.error(err);
    return jsonErr(res, 500, 'Internal server error');
  }
});


app.patch('/notes/:noteId', basicAuth, async (req, res) => {
  if (!req.user) return jsonErr(res, 401, 'Not authenticated');

  const id = Number(req.params.noteId);
  if (!Number.isInteger(id)) return jsonErr(res, 404, 'Not found');

  try {
    const existing = await prisma.note.findUnique({ where: { id } });
    if (!existing) return jsonErr(res, 404, 'Not found');

    if (existing.userId !== req.user.id) return jsonErr(res, 403, 'Not permitted');

    const payload = req.body ?? {};
    const updates = {};
    let any = false;

    if (Object.prototype.hasOwnProperty.call(payload, 'title')) {
      any = true;
      if (typeof payload.title !== 'string' || payload.title.trim() === '') {
        return jsonErr(res, 400, 'Invalid payload');
      }
      updates.title = payload.title.trim();
    }

    if (Object.prototype.hasOwnProperty.call(payload, 'description')) {
      any = true;
      if (typeof payload.description !== 'string' || payload.description.trim() === '') {
        return jsonErr(res, 400, 'Invalid payload');
      }
      updates.description = payload.description.trim();
    }

    if (Object.prototype.hasOwnProperty.call(payload, 'completed')) {
      any = true;
      if (typeof payload.completed !== 'boolean') {
        return jsonErr(res, 400, 'Invalid payload');
      }
      updates.completed = payload.completed;
    }

    if (Object.prototype.hasOwnProperty.call(payload, 'public')) {
      any = true;
      if (typeof payload.public !== 'boolean') {
        return jsonErr(res, 400, 'Invalid payload');
      }
      updates.public = payload.public;
    }

    if (!any) return jsonErr(res, 400, 'Invalid payload');

    const updated = await prisma.note.update({
      where: { id },
      data: updates,
    });

    return res.json(updated);
  } catch (err) {
    console.error(err);
    return jsonErr(res, 500, 'Internal server error');
  }
});

app.get('/hello', basicAuth, (req, res) => {
  if (req.user) {
    res.json(req.user);
  } else {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

app.use((req, res) => jsonErr(res, 404, 'Not found'));

const server = app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

server.on('error', (err) => {
    console.error(`cannot start server: ${err.message}`);
    process.exit(1);
});