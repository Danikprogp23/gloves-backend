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

/* ================= UTILS ================= */

function base64URLEncode(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest();
}

/* ================= CONSTANTS ================= */

const PORT = process.env.PORT || 3000;

// Discord
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;

// X (Twitter)
const X_CLIENT_ID = process.env.X_CLIENT_ID;
const X_REDIRECT_URI = process.env.X_REDIRECT_URI;

// Android deep link
const ANDROID_REDIRECT = "kz.gloves.glovesapp://oauth";

// временно (для PKCE)
let X_CODE_VERIFIER = null;

/* ================= ROUTES ================= */

// Health
app.get("/", (_, res) => {
  res.send("Gloves backend is running 🚀");
});

/* ======================================================
   ===================== X (TWITTER) ====================
   ====================================================== */

app.get("/auth/x", (req, res) => {
  const codeVerifier = base64URLEncode(crypto.randomBytes(32));
  const codeChallenge = base64URLEncode(sha256(codeVerifier));

  X_CODE_VERIFIER = codeVerifier;

  const authUrl =
    "https://twitter.com/i/oauth2/authorize" +
    `?response_type=code` +
    `&client_id=${X_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(X_REDIRECT_URI)}` +
    `&scope=users.read tweet.read` +
    `&state=state` +
    `&code_challenge=${codeChallenge}` +
    `&code_challenge_method=S256`;

  res.redirect(authUrl);
});

app.get("/auth/x/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("No code");

  try {
    // 1. TOKEN
    const tokenRes = await axios.post(
      "https://api.twitter.com/2/oauth2/token",
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: X_CLIENT_ID,
        redirect_uri: X_REDIRECT_URI,
        code_verifier: X_CODE_VERIFIER,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const accessToken = tokenRes.data.access_token;

    // 2. USER
    const userRes = await axios.get(
      "https://api.twitter.com/2/users/me",
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const user = userRes.data.data;
    const uid = `twitter:${user.id}`;

    // 3. FIREBASE USER
    try {
      await admin.auth().getUser(uid);
    } catch {
      await admin.auth().createUser({
        uid,
        displayName: user.username,
      });
    }

    // 4. CUSTOM TOKEN
    const firebaseToken = await admin.auth().createCustomToken(uid);

    // 5. REDIRECT TO ANDROID
    res.redirect(
      `${ANDROID_REDIRECT}?firebaseToken=${firebaseToken}&provider=x`
    );
  } catch (err) {
    console.error("X auth error:", err.response?.data || err.message);
    res.status(500).send("X auth failed");
  }
});

/* ======================================================
   ===================== DISCORD ========================
   ====================================================== */

app.get("/auth/discord", (_, res) => {
  const url =
    "https://discord.com/api/oauth2/authorize" +
    `?client_id=${DISCORD_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}` +
    `&response_type=code` +
    `&scope=identify email`;

  res.redirect(url);
});

app.get("/auth/discord/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("No code");

  try {
    // 1. TOKEN
    const tokenRes = await axios.post(
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

    const accessToken = tokenRes.data.access_token;

    // 2. USER
    const userRes = await axios.get(
      "https://discord.com/api/users/@me",
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    const user = userRes.data;
    const uid = `discord:${user.id}`;

    // 3. FIREBASE USER
    try {
      await admin.auth().getUser(uid);
    } catch {
      await admin.auth().createUser({
        uid,
        displayName: user.username,
        photoURL: user.avatar
          ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
          : undefined,
      });
    }

    // 4. CUSTOM TOKEN
    const firebaseToken = await admin.auth().createCustomToken(uid);

    // 5. REDIRECT TO ANDROID
    res.redirect(
      `${ANDROID_REDIRECT}?firebaseToken=${firebaseToken}&provider=discord`
    );
  } catch (err) {
    console.error("Discord auth error:", err.response?.data || err.message);
    res.status(500).send("Discord auth failed");
  }
});

/* ================= START ================= */

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
