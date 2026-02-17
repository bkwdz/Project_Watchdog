const express = require("express");
const session = require("express-session");
const cors = require("cors");
const authRoutes = require("./routes/auth");

const app = express();

const deviceRoutes = require("./routes/devices");
const scanRoutes = require("./routes/scans");

const corsOrigin = process.env.CORS_ORIGIN;
const parsedCorsOrigins = corsOrigin
  ? corsOrigin
      .split(",")
      .map((origin) => origin.trim())
      .filter(Boolean)
  : true;

app.use(
  cors({
    origin: parsedCorsOrigins,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || "dev_secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false // important for localhost
  }
}));


app.use("/api/auth", authRoutes);
app.use("/api/devices", deviceRoutes);
app.use("/api/scans", scanRoutes);

module.exports = app;
