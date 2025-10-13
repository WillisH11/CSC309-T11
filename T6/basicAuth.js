const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const basicAuth = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    req.user = null;
    return next();
  }

  if (typeof authHeader !== 'string' || !authHeader.startsWith('Basic ')) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const base64 = authHeader.slice(6).trim();
  let decoded;
  try {
    decoded = Buffer.from(base64, 'base64').toString('utf8');
  } catch (err) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const sepIndex = decoded.indexOf(':');
  if (sepIndex === -1) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  const username = decoded.slice(0, sepIndex);
  const password = decoded.slice(sepIndex + 1);

  if (!username || !password) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  try {
    const user = await prisma.user.findUnique({ where: { username } });
    if (!user || user.password !== password) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    req.user = user;
    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
};

module.exports = basicAuth;