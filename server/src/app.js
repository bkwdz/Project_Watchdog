const express = require("express");
const session = require("express-session");
const cors = require("cors");
const authRoutes = require("./routes/auth");

const app = express();

const deviceRoutes = require("./routes/devices");
const scanRoutes = require("./routes/scans");

app.use("/api/devices", deviceRoutes);
app.use("/api/scans", scanRoutes);

app.use(cors({
  origin: "http://localhost:5173",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));


app.use(express.json());


app.use(session({
  secret: "dev_secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false // important for localhost
  }
}));


app.use("/auth", authRoutes);

module.exports = app;
