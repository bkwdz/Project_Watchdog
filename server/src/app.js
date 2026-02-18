const express = require("express");
const session = require("express-session");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const authRoutes = require("./routes/auth");
const { attachUser } = require("./middleware/auth");

const app = express();

const deviceRoutes = require("./routes/devices");
const scanRoutes = require("./routes/scans");
const scannerRoutes = require("./routes/scanner");

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
app.use(cookieParser());

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

app.use(attachUser);

app.use("/api/auth", authRoutes);
app.use("/api/devices", deviceRoutes);
app.use("/api/scans", scanRoutes);
app.use("/api/scanner", scannerRoutes);

module.exports = app;
