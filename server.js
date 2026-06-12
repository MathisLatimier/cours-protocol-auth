const express = require('express')
const authRoutes = require('./routes/auth')
const adminRoutes = require('./routes/admin')

const app = express()

app.use(express.json())
app.use(express.static('public'))

// Routes
app.use('/auth', authRoutes)
app.use(adminRoutes)

// Lance le serveur en local, sur le port 3000
const PORT = 3000
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
})