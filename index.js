require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const admin = require("firebase-admin");
const crypto = require("crypto");

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

/* ================= CONSTANTS ================= */
function base64URLEncode(str) {
  return str
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest();
}

const PORT = process.env.PORT || 3000;

const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI =
  "https://gloves-backend.onrender.com/auth/discord/callback";

/* ================= ROUTES ================= */

// health check
app.get("/", (req, res) => {
  res.send("Gloves backend is running 🚀");
});
app.get("/auth/x", (req, res) => {
  const codeVerifier = base64URLEncode(crypto.randomBytes(32));
  const codeChallenge = base64URLEncode(sha256(codeVerifier));

  // ⚠️ В реальном проекте храни в Redis / DB
  global.codeVerifier = codeVerifier;

  const authUrl =
    "https://twitter.com/i/oauth2/authorize" +
    `?response_type=code` +
    `&client_id=${process.env.X_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(process.env.X_REDIRECT_URI)}` +
    `&scope=users.read tweet.read` +
    `&state=state` +
    `&code_challenge=${codeChallenge}` +
    `&code_challenge_method=S256`;

  res.redirect(authUrl);
});
app.get("/auth/x/callback", async (req, res) => {
  const code = req.query.code;

  if (!code) {
    return res.status(400).send("No code");
  }

  try {
    /* 1️⃣ TOKEN */
    const tokenRes = await axios.post(
      "https://api.twitter.com/2/oauth2/token",
      new URLSearchParams({
        code,
        grant_type: "authorization_code",
        client_id: process.env.X_CLIENT_ID,
        redirect_uri: process.env.X_REDIRECT_URI,
        code_verifier: global.codeVerifier,
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const accessToken = tokenRes.data.access_token;

    /* 2️⃣ USER */
    const userRes = await axios.get(
      "https://api.twitter.com/2/users/me",
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );

    const twitterUser = userRes.data.data;
    const uid = `twitter:${twitterUser.id}`;

    /* 3️⃣ FIREBASE USER */
    let userRecord;
    try {
      userRecord = await admin.auth().getUser(uid);
    } catch {
      userRecord = await admin.auth().createUser({
        uid,
        displayName: twitterUser.username,
      });
    }

    /* 4️⃣ FIREBASE TOKEN */
    const customToken = await admin.auth().createCustomToken(uid);

    res.json({
      provider: "twitter",
      uid,
      username: twitterUser.username,
      token: customToken,
    });
  } catch (err) {
    console.error("X auth error:", err.response?.data || err.message);
    res.status(500).send("X auth failed");
  }
});

/* ---------- DISCORD LOGIN ---------- */
app.get("/auth/discord", (req, res) => {
  const discordAuthUrl =
    `https://discord.com/api/oauth2/authorize` +
    `?client_id=${DISCORD_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}` +
    `&response_type=code` +
    `&scope=identify email`;

  res.redirect(discordAuthUrl);
});

/* ---------- DISCORD CALLBACK ---------- */
app.get("/auth/discord/callback", async (req, res) => {
  const code = req.query.code;

  if (!code) {
    return res.status(400).send("No code");
  }

  try {
    /* 1️⃣ TOKEN */
    const tokenResponse = await axios.post(
      "https://discord.com/api/oauth2/token",
      new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: DISCORD_REDIRECT_URI,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const accessToken = tokenResponse.data.access_token;

    /* 2️⃣ USER INFO */
    const userResponse = await axios.get(
      "https://discord.com/api/users/@me",
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const discordUser = userResponse.data;

    const uid = `discord:${discordUser.id}`;

    /* 3️⃣ FIREBASE USER */
    let userRecord;
    try {
      userRecord = await admin.auth().getUser(uid);
    } catch {
      userRecord = await admin.auth().createUser({
        uid,
        displayName: discordUser.username,
        photoURL: discordUser.avatar
          ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`
          : undefined,
      });
    }

    /* 4️⃣ CUSTOM TOKEN */
    const customToken = await admin.auth().createCustomToken(uid);

    /* 5️⃣ RESULT */
    res.json({
      provider: "discord",
      uid: userRecord.uid,
      username: discordUser.username,
      email: discordUser.email,
      token: customToken,
    });
  } catch (err) {
    console.error("Discord auth error:", err.response?.data || err.message);
    res.status(500).json({ error: "Discord auth failed" });
  }
});

/* ================= START ================= */

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
