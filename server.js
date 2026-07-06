require('dotenv').config()
const express = require('express')
const session = require('express-session')
const authRoutes = require('./routes/auth')
const adminRoutes = require('./routes/admin')

const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))

app.use(session({
  name: 'bat_identity',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: true,
    maxAge: 1800000
  }
}))

// Routes
app.use('/auth', authRoutes)
app.use('/', adminRoutes)

// Lance le serveur en local
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
})