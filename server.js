require('dotenv').config()
const express = require('express')
const helmet = require('helmet')
const cookieParser = require('cookie-parser')
const authRoutes = require('./routes/auth')
const adminRoutes = require('./routes/admin')

const app = express()

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'https://cdn.jsdelivr.net'],
        styleSrc: ["'self'", 'https://cdn.jsdelivr.net', "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'", 'https://cdn.jsdelivr.net'],
      },
    },
  })
)
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(express.static('public'))

// Routes
app.use('/auth', authRoutes)
app.use('/api', authRoutes)
app.use('/', adminRoutes)

// Lance le serveur en local
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
})
