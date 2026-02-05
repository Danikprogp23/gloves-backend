const functions = require('firebase-functions')
const express = require('express')
const axios = require('axios')
const cors = require('cors')
const crypto = require('crypto')
const admin = require('firebase-admin')

admin.initializeApp()

const app = express()
app.use(cors())

// ===== CONFIG =====
const config = functions.config()

const DISCORD_CLIENT_ID = config.discord.client_id
const DISCORD_CLIENT_SECRET = config.discord.client_secret
const DISCORD_REDIRECT_URI = config.discord.redirect_uri

const X_CLIENT_ID = config.x.client_id
const X_CLIENT_SECRET = config.x.client_secret
const X_REDIRECT_URI = config.x.redirect_uri

// ===== PKCE =====
const pkceStore = new Map()

function base64URLEncode(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest()
}

/* ===================== DISCORD ===================== */

app.get('/auth/discord', (req, res) => {
  const url =
    'https://discord.com/oauth2/authorize?' +
    new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      response_type: 'code',
      scope: 'identify email',
      redirect_uri: DISCORD_REDIRECT_URI
    })

  res.redirect(url)
})

app.get('/auth/discord/callback', async (req, res) => {
  const { code } = req.query
  if (!code) return res.status(400).send('No code')

  try {
    const tokenRes = await axios.post(
      'https://discord.com/api/oauth2/token',
      new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: DISCORD_REDIRECT_URI
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    )

    const accessToken = tokenRes.data.access_token

    const userRes = await axios.get(
      'https://discord.com/api/users/@me',
      { headers: { Authorization: `Bearer ${accessToken}` } }
    )

    const uid = `discord_${userRes.data.id}`

    const firebaseToken = await admin.auth().createCustomToken(uid, {
      provider: 'discord',
      username: userRes.data.username
    })

    res.redirect(
      `glovesapp://auth?firebaseToken=${firebaseToken}&provider=discord`
    )
  } catch (e) {
    console.error(e)
    res.status(500).send('Discord OAuth error')
  }
})

/* ===================== X (Twitter) ===================== */

app.get('/auth/x', (req, res) => {
  const codeVerifier = base64URLEncode(crypto.randomBytes(32))
  const codeChallenge = base64URLEncode(sha256(codeVerifier))
  const state = crypto.randomUUID()

  pkceStore.set(state, codeVerifier)

  const url =
    'https://twitter.com/i/oauth2/authorize?' +
    new URLSearchParams({
      response_type: 'code',
      client_id: X_CLIENT_ID,
      redirect_uri: X_REDIRECT_URI,
      scope: 'tweet.read users.read',
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256'
    })

  res.redirect(url)
})

app.get('/auth/x/callback', async (req, res) => {
  const { code, state } = req.query
  const codeVerifier = pkceStore.get(state)
  pkceStore.delete(state)

  if (!codeVerifier) return res.status(400).send('Invalid PKCE')

  try {
    const tokenRes = await axios.post(
      'https://api.twitter.com/2/oauth2/token',
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: X_REDIRECT_URI,
        client_id: X_CLIENT_ID,
        code_verifier: codeVerifier
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        auth: {
          username: X_CLIENT_ID,
          password: X_CLIENT_SECRET
        }
      }
    )

    const accessToken = tokenRes.data.access_token

    const userRes = await axios.get(
      'https://api.twitter.com/2/users/me',
      { headers: { Authorization: `Bearer ${accessToken}` } }
    )

    const uid = `x_${userRes.data.data.id}`

    const firebaseToken = await admin.auth().createCustomToken(uid, {
      provider: 'x',
      username: userRes.data.data.username
    })

    res.redirect(
      `glovesapp://auth?firebaseToken=${firebaseToken}&provider=x`
    )
  } catch (e) {
    console.error(e)
    res.status(500).send('X OAuth error')
  }
})

// ===== EXPORT =====
exports.oauth = functions.https.onRequest(app)
