const express = require('express')
const path = require('path')
const checkAuth = require('../middlewares/checkAuth')

const router = express.Router()

// ...
router.get('/admin-page', checkAuth, (req, res) => {
  // La route sert uniquement le fichier HTML
  res.sendFile(path.join(__dirname, '..', 'views', 'admin-page.html'))
})

module.exports = router
