const { User } = require("../models");
const bcrypt = require("bcrypt");

module.exports = {

  // ---------------------------------------------------------
  // REGISTER
  // ---------------------------------------------------------
  register: async (req, res) => {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.status(400).json({ error: "Missing fields" });
      }

      // Count existing users
      const userCount = await User.count();

      // First user becomes admin automatically
      const role = userCount === 0 ? "admin" : "user";

      // Non-admin users cannot create additional accounts
      if (userCount > 0) {
        if (!req.session.user || req.session.user.role !== "admin") {
          return res.status(403).json({ error: "Admin required" });
        }
      }

      const hash = await bcrypt.hash(password, 10);

      const newUser = await User.create({
        username,
        passwordHash: hash,
        role
      });

      return res.json({ success: true, id: newUser.id, role });

    } catch (err) {
      console.error("Register error:", err);
      return res.status(500).json({ error: "Server error" });
    }
  },

  // ---------------------------------------------------------
  // LOGIN
  // ---------------------------------------------------------
  login: async (req, res) => {
    try {
      // 🔥 Log login request body
      console.log("LOGIN BODY:", req.body);

      const { username, password } = req.body;

      const user = await User.findOne({ where: { username } });

      // 🔥 Log whether user exists
      console.log("FOUND USER:", user);

      if (!user) {
        return res.status(400).json({ error: "Invalid login" });
      }

      const match = await bcrypt.compare(password, user.passwordHash);

      // password log
      console.log("PASSWORD MATCH:", match);

      if (!match) {
        return res.status(400).json({ error: "Invalid login" });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
      };

      return res.json({ success: true, user: req.session.user });

    } catch (err) {
      console.error("Login error:", err);
      return res.status(500).json({ error: "Server error" });
    }
  },

  
  // LOGOUT
  
  logout: (req, res) => {
    req.session.destroy(() => {
      res.json({ success: true });
    });
  },

  
  // /auth/me
 
  me: (req, res) => {
    if (!req.session.user) {
      return res.status(401).json({ error: "Not logged in" });
    }
    res.json(req.session.user);
  }
};
