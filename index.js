require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const admin = require("firebase-admin");

const app = express();
app.use(cors());
app.use(express.json());

/* ================= FIREBASE ADMIN ================= */
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
  });
}

/* ================= HEALTH CHECK ================= */
app.get("/healthz", (req, res) => {
  res.status(200).send("OK");
});

/* ================= ROOT ================= */
app.get("/", (req, res) => {
  res.send("Gloves backend is running 🚀");
});

/* ================= DISCORD LOGIN ================= */
app.get("/auth/discord", (req, res) => {
  const redirectUri = encodeURIComponent(process.env.DISCORD_REDIRECT_URI);

  const url =
    "https://discord.com/oauth2/authorize" +
    `?client_id=${process.env.DISCORD_CLIENT_ID}` +
    `&redirect_uri=${redirectUri}` +
    "&response_type=code" +
    "&scope=identify email";

  res.redirect(url);
});

/* ================= DISCORD CALLBACK ================= */
app.get("/auth/discord/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("No code");

  try {
    // exchange code -> token
    const tokenRes = await axios.post(
      "https://discord.com/api/oauth2/token",
      new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: process.env.DISCORD_REDIRECT_URI,
      }),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }
    );

    const accessToken = tokenRes.data.access_token;

    // get user info
    const userRes = await axios.get("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    const discordUser = userRes.data;

    // create firebase custom token
    const uid = `discord:${discordUser.id}`;
    const firebaseToken = await admin.auth().createCustomToken(uid, {
      provider: "discord",
      email: discordUser.email,
      username: discordUser.username,
    });

    res.json({
      firebaseToken,
      discordUser,
    });
  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: "Discord auth failed" });
  }
});

/* ================= START SERVER ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
