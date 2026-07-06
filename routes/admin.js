const express = require('express')
const path = require('path')
const isAuthenticated = require('../middlewares/isAuthenticated')

const router = express.Router()

// Route protégée par session
router.get('/bat-computer', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'views', 'bat-computer.html'))
})

// API pour récupérer le username en session (utilisé par le front)
router.get('/bat-computer/user', isAuthenticated, (req, res) => {
  res.json({ username: req.session.user.username })
})

module.exports = router
