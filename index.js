require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const admin = require("firebase-admin");
const crypto = require("crypto");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());
const cloudinary = require("cloudinary").v2;
/* ================= FIREBASE ADMIN ================= */

if (!admin.apps.length) {
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
  }),
  databaseURL: process.env.FIREBASE_DATABASE_URL,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET
});
}
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});
/* ================= UTILS ================= */
function retrainModel() {
  return new Promise((resolve, reject) => {
    const process = spawn("python", ["train.py"]);

    process.stdout.on("data", (data) => {
      console.log(data.toString());
    });

    process.stderr.on("data", (data) => {
      console.error(data.toString());
    });

    process.on("close", (code) => {

  console.log(
    "TRAIN EXIT CODE:",
    code
  );

  if (code === 0) {

    resolve();

  } else {

    reject(
      new Error(
        `Training failed: ${code}`
      )
    );
  }
});
  });
}
function generateVoice(
  text,
  voice,
  output
) {

  return new Promise((resolve, reject) => {

    const process = spawn(
      "python",
      [
        "generate_voice.py",
        text,
        voice,
        output
      ]
    );

    process.on("close", code => {

      if (code === 0) {
        resolve();
      } else {
        reject(
          new Error("Voice generation failed")
        );
      }

    });

  });

}
async function uploadVoice(
  fileName
) {

  const bucket =
    admin.storage().bucket();

  await bucket.upload(
    fileName,
    {
      destination:
        `voices/${fileName}`
    }
  );

  const file =
    bucket.file(
      `voices/${fileName}`
    );

  const [url] =
    await file.getSignedUrl({
      action: "read",
      expires: "01-01-2100"
    });

  return url;
}
async function createGestureVoices(
  gesture,
  kk,
  ru,
  en
) {

  const kkFile =
    `${gesture}_kk.mp3`;

  const ruFile =
    `${gesture}_ru.mp3`;

  const enFile =
    `${gesture}_en.mp3`;

  await generateVoice(
    kk,
    "kk-KZ-AigulNeural",
    kkFile
  );

  await generateVoice(
    ru,
    "ru-RU-SvetlanaNeural",
    ruFile
  );

  await generateVoice(
    en,
    "en-US-JennyNeural",
    enFile
  );

  const kkUrl =
    await uploadVoice(
      kkFile
    );

  const ruUrl =
    await uploadVoice(
      ruFile
    );

  const enUrl =
    await uploadVoice(
      enFile
    );

  await admin.database()
    .ref(`voices/${gesture}`)
    .set({
      kk: kkUrl,
      ru: ruUrl,
      en: enUrl
    });

}

app.get("/test-python", (req, res) => {

  const process = spawn("python", ["train.py"]);

  let output = "";

  process.stdout.on("data", data => {
    output += data.toString();
  });

  process.stderr.on("data", data => {
    output += data.toString();
  });

  process.on("close", code => {
    res.send(`CODE=${code}\n\n${output}`);
  });

});
function base64URLEncode(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}
async function deleteGestureVoices(
  gesture
) {

  const bucket =
    admin.storage().bucket();

  const files = [
    `${gesture}_kk.mp3`,
    `${gesture}_ru.mp3`,
    `${gesture}_en.mp3`
  ];

  for (const file of files) {

    try {

      await bucket.file(
        `voices/${file}`
      ).delete();

    } catch (e) {

      console.log(
        "Voice not found:",
        file
      );

    }

  }

  await admin.database()
    .ref(`voices/${gesture}`)
    .remove();
}
app.post(
  "/createGesture",
  async (req, res) => {

    try {

      const {
        gesture,
        kk,
        ru,
        en,
        features
      } = req.body;

      await admin.database()
        .ref(`gestures/${gesture}`)
        .set({
          kk,
          ru,
          en
        });

      await admin.database()
        .ref("samples")
        .push()
        .set({
          gesture,
          features
        });

      await createGestureVoices(
        gesture,
        kk,
        ru,
        en
      );

      await buildDataset();

      await retrainModel();

      await uploadModel();

      await increaseVersion();

      res.json({
        success: true
      });

    } catch (e) {

      console.error(e);

      res.status(500).json({
        success: false,
        error: e.message
      });

    }

  }
);
app.post(
  "/deleteGesture",
  async (req, res) => {

    try {

      const {
        gesture
      } = req.body;

      await admin.database()
        .ref(`gestures/${gesture}`)
        .remove();

      const snapshot =
        await admin.database()
          .ref("samples")
          .once("value");

      snapshot.forEach(child => {

        const data =
          child.val();

        if (
          data.gesture === gesture
        ) {
          child.ref.remove();
        }

      });

      await deleteGestureVoices(
        gesture
      );

      await buildDataset();

      await retrainModel();

      await uploadModel();

      await increaseVersion();

      res.json({
        success: true
      });

    } catch (e) {

      console.error(e);

      res.status(500).json({
        success: false,
        error: e.message
      });

    }

  }
);
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
const ANDROID_REDIRECT = "glovesapp://auth";

// временно (для PKCE)
let X_CODE_VERIFIER = null;

/* ================= ROUTES ================= */
async function buildDataset() {

  const snapshot =
    await admin.database()
      .ref("samples")
      .once("value");

  const samples = snapshot.val();

  if (!samples) {
    throw new Error("No samples found");
  }

  const csvRows = [];

  const header = [];

  for (let i = 0; i < 40; i++) {
    header.push(`f${i}`);
  }

  header.push("gesture");

  csvRows.push(header.join(","));

  Object.values(samples).forEach(sample => {

    const row = [
      ...sample.features,
      sample.gesture
    ];

    csvRows.push(row.join(","));

  });

  fs.writeFileSync(
    "dataset.csv",
    csvRows.join("\n")
  );
}
async function uploadModel() {

  const bucket = admin.storage().bucket();

  await bucket.upload(
    "smartglove.tflite",
    {
      destination:
        "models/smartglove.tflite"
    }
  );

  await bucket.upload(
    "labels.txt",
    {
      destination:
        "models/labels.txt"
    }
  );
}
async function increaseVersion() {

  const ref =
    admin.database()
      .ref("modelVersion");

  const snap =
    await ref.once("value");

  const version =
    snap.val() || 1;

  await ref.set(
    version + 1
  );
}
// Health
app.get("/", (_, res) => {
  res.send("Gloves backend is running 🚀");
});
app.get("/cloudinary/sign", (req, res) => {
  const timestamp = Math.round(Date.now() / 1000);

  const signature = cloudinary.utils.api_sign_request(
  { timestamp },
  process.env.CLOUDINARY_API_SECRET
);

res.json({
  cloudName: process.env.CLOUDINARY_CLOUD_NAME,
  apiKey: process.env.CLOUDINARY_API_KEY,
  timestamp,
  signature
});
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
app.post("/retrain", async (req, res) => {

  try {

    console.log(
      "Building dataset..."
    );

    await buildDataset();

    console.log(
      "Training model..."
    );

    await retrainModel();

    console.log(
      "Uploading model..."
    );

    await uploadModel();

    console.log(
      "Updating version..."
    );

    await increaseVersion();

    res.json({
      success: true
    });

  } catch (e) {

    console.error(e);

    res.status(500).json({
      success: false,
      error: e.message
    });

  }

});
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
