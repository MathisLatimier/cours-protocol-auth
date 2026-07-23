const express = require('express')
const path = require('path')
const db = require('../config/db')
const isAuthenticated = require('../middlewares/isAuthenticated')

const router = express.Router()

router.get('/bat-computer', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'views', 'bat-computer.html'))
})

router.get('/bat-computer/user', isAuthenticated, (req, res) => {
  const user = db
    .prepare('SELECT username, provider, two_factor_enabled FROM users WHERE id = ?')
    .get(req.user.id)

  if (!user) {
    return res.status(404).json({ error: 'Utilisateur introuvable.' })
  }

  res.json({
    username: user.username,
    provider: user.provider,
    two_factor_enabled: Boolean(user.two_factor_enabled),
  })
})

module.exports = router
