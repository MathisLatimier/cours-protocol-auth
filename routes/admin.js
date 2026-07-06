const express = require('express')
const path = require('path')
const isAuthenticated = require('../middlewares/isAuthenticated')

const router = express.Router()

router.get('/bat-computer', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'views', 'bat-computer.html'))
})

router.get('/bat-computer/user', isAuthenticated, (req, res) => {
  res.json({ username: req.user.username })
})

module.exports = router
