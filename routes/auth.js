const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const path = require('path')
const db = require('../config/db')

const router = express.Router()

router.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'views', 'login.html'))
})


router.post('/login', async (req, res) => {
  const { username, password } = req.body

  if (!username || !password) {
    return res.status(400).send('Veuillez remplir tous les champs.')
  }

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username)

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).send('Identifiants invalides.')
  }

  // Génération de l'accessToken JWT (15 secondes pour les tests)
  const accessToken = jwt.sign(
    { id: user.id, username: user.username },
    process.env.SESSION_SECRET,
    { expiresIn: '15s' }
  )

  // Génération du refreshToken opaque
  const refreshToken = crypto.randomBytes(64).toString('hex')
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 jours

  // Stockage du refreshToken en BDD
  db.prepare('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)').run(user.id, refreshToken, expiresAt)

  // Envoi des deux tokens via cookies sécurisés
  res.cookie('access_token', accessToken, {
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 15 * 1000 // 15 secondes
  })

  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 jours
  })

  res.redirect('/bat-computer')
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

router.post('/register', async (req, res) => {
  let { username, password } = req.body

  username = username.trim()

  const user_already_exists = db.prepare('SELECT * FROM users WHERE username = ?').get(username)
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
      'INSERT INTO users (username, password_hash) VALUES (?, ?)'
    )
    insert.run(username, hash)
    res.status(201).send('Utilisateur créé avec succès !')
  } catch (err) {
    res.status(400).send("Erreur : l'utilisateur n'a pas pu être créé.")
  }
})

module.exports = router
