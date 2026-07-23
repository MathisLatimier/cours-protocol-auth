const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const path = require('path')
const QRCode = require('qrcode')
const { authenticator } = require('@otplib/preset-v11')
const db = require('../config/db')
const isAuthenticated = require('../middlewares/isAuthenticated')

const router = express.Router()

// ANSSI : ≥12 caractères, 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial
const ANSSI_PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$/

function issueAuthCookies(res, user) {
  const accessToken = jwt.sign(
    { id: user.id, username: user.username },
    process.env.SESSION_SECRET,
    { expiresIn: '15m' }
  )

  const refreshToken = crypto.randomBytes(64).toString('hex')
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000

  db.prepare(
    'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)'
  ).run(user.id, refreshToken, expiresAt)

  res.cookie('access_token', accessToken, {
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000,
  })

  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  })
}

router.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'views', 'login.html'))
})


router.post('/login', async (req, res) => {
  const { username, password } = req.body

  if (!username || !password) {
    return res.status(400).send('Veuillez remplir tous les champs.')
  }

  const user = db
    .prepare("SELECT * FROM users WHERE username = ? AND provider = 'local'")
    .get(username)

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).send('Identifiants invalides.')
  }

  // Zéro-confiance : aucun jeton tant que la 2FA n'est pas validée
  if (!user.two_factor_enabled) {
    return res.status(403).json({
      error: 'L\'activation de la 2FA est obligatoire avant toute connexion.',
    })
  }

  return res.json({
    requires2FA: true,
    message: 'Étape 1 validée. Veuillez fournir votre code TOTP.',
    username: user.username,
  })
})

// Second facteur : validation TOTP puis distribution des jetons
router.post('/verify-2fa', (req, res) => {
  const { username } = req.body
  const code = req.body.code ?? req.body.codeTOTP ?? req.body.totp

  if (!username || !code) {
    return res.status(400).json({ error: 'Nom d\'utilisateur et code TOTP requis.' })
  }

  const user = db
    .prepare("SELECT * FROM users WHERE username = ? AND provider = 'local'")
    .get(username)

  if (!user || !user.two_factor_enabled || !user.two_factor_secret) {
    return res.status(401).json({ error: 'Authentification 2FA impossible.' })
  }

  const isValid = authenticator.check(String(code), user.two_factor_secret)

  if (!isValid) {
    return res.status(401).json({ error: 'Code TOTP invalide ou expiré.' })
  }

  issueAuthCookies(res, user)

  res.json({ message: 'Authentification réussie.' })
})


router.post('/refresh', (req, res) => {
  const refreshToken = req.cookies.refresh_token

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token manquant.' })
  }

  const stored = db.prepare(`
    SELECT rt.*, u.username
    FROM refresh_tokens rt
    JOIN users u ON u.id = rt.user_id
    WHERE rt.token = ?
  `).get(refreshToken)

  if (!stored || stored.expires_at < Date.now()) {
    res.clearCookie('access_token')
    res.clearCookie('refresh_token')
    return res.status(401).json({ error: 'Refresh token invalide ou expiré.' })
  }

  const accessToken = jwt.sign(
    { id: stored.user_id, username: stored.username },
    process.env.SESSION_SECRET,
    { expiresIn: '15m' }
  )

  res.cookie('access_token', accessToken, {
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000 // 15 minutes
  })

  res.json({ message: 'Access token rafraîchi.' })
})

router.get('/logout', (req, res) => {
  const refreshToken = req.cookies.refresh_token
  if (refreshToken) {
    db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(refreshToken)
  }
  res.clearCookie('access_token')
  res.clearCookie('refresh_token')
  res.redirect('/auth/login')
})

router.post('/change-password', isAuthenticated, async (req, res) => {
  const { oldPassword, newPassword } = req.body

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Veuillez remplir tous les champs.' })
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)

  if (!user || !(await bcrypt.compare(oldPassword, user.password_hash))) {
    return res.status(403).json({ error: 'Ancien mot de passe incorrect.' })
  }

  if (!ANSSI_PASSWORD_REGEX.test(newPassword)) {
    return res.status(400).json({
      error: 'Le nouveau mot de passe doit contenir au moins 12 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial.',
    })
  }

  const hash = await bcrypt.hash(newPassword, 10)
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id)

  res.json({ message: 'Mot de passe modifié avec succès.' })
})

// Initialisation 2FA : génère le secret + QR code, sans activer encore (two_factor_enabled = 0)
router.post('/2fa/setup', isAuthenticated, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id)

  if (!user) {
    return res.status(404).json({ error: 'Utilisateur introuvable.' })
  }

  if (user.two_factor_enabled) {
    return res.status(400).json({ error: 'La 2FA est déjà activée sur ce compte.' })
  }

  const secret = authenticator.generateSecret()
  const otpauthUrl = authenticator.keyuri(user.username, 'Batcave', secret)

  db.prepare(`
    UPDATE users
    SET two_factor_secret = ?, two_factor_enabled = 0
    WHERE id = ?
  `).run(secret, user.id)

  const qrCode = await QRCode.toDataURL(otpauthUrl)

  res.json({ qrCode, secret })
})

// Confirmation 2FA : valide le premier code TOTP avant d'activer définitivement
router.post('/2fa/confirm', isAuthenticated, (req, res) => {
  const { username, code } = req.body

  if (!username || !code) {
    return res.status(400).json({ error: 'Nom d\'utilisateur et code à 6 chiffres requis.' })
  }

  const user = db
    .prepare("SELECT * FROM users WHERE username = ? AND provider = 'local'")
    .get(username)

  if (!user || !user.two_factor_secret) {
    return res.status(400).json({ error: 'Aucune initialisation 2FA en attente pour cet utilisateur.' })
  }

  if (user.id !== req.user.id) {
    return res.status(403).json({ error: 'Vous ne pouvez confirmer que votre propre 2FA.' })
  }

  if (user.two_factor_enabled) {
    return res.status(400).json({ error: 'La 2FA est déjà activée sur ce compte.' })
  }

  const isValid = authenticator.check(String(code), user.two_factor_secret)

  if (!isValid) {
    return res.status(401).json({ error: 'Code 2FA invalide ou expiré.' })
  }

  db.prepare('UPDATE users SET two_factor_enabled = 1 WHERE id = ?').run(user.id)

  res.json({ message: '2FA activée avec succès.' })
})

router.post('/register', async (req, res) => {
  let { username, password } = req.body

  username = username.trim()

  const user_already_exists = db
    .prepare("SELECT * FROM users WHERE username = ? AND provider = 'local'")
    .get(username)
  if (user_already_exists) {
    return res.status(409).send("Erreur : l'utilisateur existe déjà.")
  }
  
  if (!username || !password) {
    return res.status(400).send("Veuillez remplir tous les champs.")
  }

  if (password.length < 8) {
    return res.status(400).send("Le mot de passe doit contenir au moins 8 caractères.")
  }

  

  const hash = await bcrypt.hash(password, 10)

  try {
    const insert = db.prepare(
      "INSERT INTO users (username, password_hash, provider, provider_id) VALUES (?, ?, 'local', ?)"
    )
    const result = insert.run(username, hash, username)
    const user = { id: Number(result.lastInsertRowid), username }

    // Session temporaire post-inscription pour permettre l'enrôlement 2FA
    issueAuthCookies(res, user)

    res.status(201).json({
      message: 'Utilisateur créé avec succès ! Activez la 2FA depuis le Bat-Computer.',
      redirect: '/bat-computer',
    })
  } catch (err) {
    res.status(400).send("Erreur : l'utilisateur n'a pas pu être créé.")
  }
})

module.exports = router
