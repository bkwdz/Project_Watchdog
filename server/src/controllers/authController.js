const bcrypt = require("bcrypt");
const { query } = require("../db");

module.exports = {
  register: async (req, res) => {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.status(400).json({ error: "Missing fields" });
      }

      const countResult = await query("SELECT COUNT(*)::int AS count FROM users");
      const userCount = countResult.rows[0].count;

      const role = userCount === 0 ? "admin" : "user";

      if (userCount > 0) {
        if (!req.session.user || req.session.user.role !== "admin") {
          return res.status(403).json({ error: "Admin required" });
        }
      }

      const passwordHash = await bcrypt.hash(password, 10);

      const insertResult = await query(
        `
          INSERT INTO users (username, password_hash, role)
          VALUES ($1, $2, $3)
          RETURNING id, role
        `,
        [username, passwordHash, role],
      );

      const newUser = insertResult.rows[0];
      return res.json({ success: true, id: newUser.id, role: newUser.role });
    } catch (err) {
      if (err.code === "23505") {
        return res.status(409).json({ error: "Username already exists" });
      }

      console.error("Register error:", err);
      return res.status(500).json({ error: "Server error" });
    }
  },

  login: async (req, res) => {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.status(400).json({ error: "Missing fields" });
      }

      const userResult = await query(
        `
          SELECT id, username, password_hash, role
          FROM users
          WHERE username = $1
          LIMIT 1
        `,
        [username],
      );

      const user = userResult.rows[0];

      if (!user) {
        return res.status(400).json({ error: "Invalid login" });
      }

      const match = await bcrypt.compare(password, user.password_hash);

      if (!match) {
        return res.status(400).json({ error: "Invalid login" });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role,
      };

      return res.json({ success: true, user: req.session.user });
    } catch (err) {
      console.error("Login error:", err);
      return res.status(500).json({ error: "Server error" });
    }
  },

  logout: (req, res) => {
    req.session.destroy(() => {
      res.json({ success: true });
    });
  },

  me: (req, res) => {
    if (!req.session.user) {
      return res.status(401).json({ error: "Not logged in" });
    }

    return res.json(req.session.user);
  },
};