const jwt = require('jsonwebtoken');
const { User } = require('../models');

const SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const TOKEN_NAME = 'watchdog_token';

// Optional auth — will not throw if missing
async function attachUser(req, res, next) {
  try {
    const token =
      (req.cookies && req.cookies[TOKEN_NAME]) ||
      (req.headers.authorization && req.headers.authorization.split(' ')[1]);

    if (!token) return next(); // no user logged in — continue normally

    const payload = jwt.verify(token, SECRET);

    const user = await User.findOne({ where: { username: payload.sub } });

    if (!user) return next();

    req.user = {
      id: user.id,
      username: user.username,
      role: user.role,
    };

    next();
  } catch (err) {
    next(); // still allow request
  }
}

async function requireAuth(req, res, next) {
  if (req.user) return next();
  if (req.session && req.session.user) {
    req.user = req.session.user;
    return next();
  }
  return res.status(401).json({ error: "not authenticated" });
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "not authenticated" });
    if (req.user.role !== role) return res.status(403).json({ error: "forbidden" });
    next();
  };
}

module.exports = { attachUser, requireAuth, requireRole };
