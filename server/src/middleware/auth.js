const jwt = require('jsonwebtoken');
const { query } = require('../db');

const SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const TOKEN_NAME = 'watchdog_token';

async function attachUser(req, res, next) {
  try {
    const token =
      (req.cookies && req.cookies[TOKEN_NAME]) ||
      (req.headers.authorization && req.headers.authorization.split(' ')[1]);

    if (!token) {
      return next();
    }

    const payload = jwt.verify(token, SECRET);

    const userResult = await query(
      `
        SELECT id, username, role
        FROM users
        WHERE username = $1
        LIMIT 1
      `,
      [payload.sub],
    );

    const user = userResult.rows[0];

    if (!user) {
      return next();
    }

    req.user = {
      id: user.id,
      username: user.username,
      role: user.role,
    };

    return next();
  } catch (err) {
    return next();
  }
}

function requireAuth(req, res, next) {
  if (req.user) {
    return next();
  }

  if (req.session && req.session.user) {
    req.user = req.session.user;
    return next();
  }

  return res.status(401).json({ error: 'not authenticated' });
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'not authenticated' });
    }

    if (req.user.role !== role) {
      return res.status(403).json({ error: 'forbidden' });
    }

    return next();
  };
}

module.exports = { attachUser, requireAuth, requireRole };