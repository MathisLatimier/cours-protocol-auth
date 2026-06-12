// Import des librairies et de la BDD
const express = require('express')
const bcrypt = require('bcrypt')
const db = require('./db')

// Créé du serveur Express
const app = express()
// Rend possible la lecture et l'écriture du JSON
app.use(express.json())
// Ouvre les fichiers frontend non protégés
app.use(express.static('public'))

// Lance le serveur en local, sur le port 3000
const PORT = 3000
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`)
})

// ...
app.post('/register', async (req, res) => {
  // Récupère les identifiants saisis par l'utilisateur
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

  

  // Hachage du mot de passe avant stockage !
  const hash = await bcrypt.hash(password, 10)

  try {
    // Requête SQL pour insérer le nouvel utilisateur en base
    const insert = db.prepare(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)'
    )
    insert.run(username, hash)
    res.status(201).send('Utilisateur créé avec succès !')
  } catch (err) {
    res.status(400).send("Erreur : l'utilisateur n'a pas pu être créé.")
  }
})

const checkAuth = async (req, res, next) => {
  // Récupère l'en-tête pour la vérifier avant d'atteindre les routes protégées
  const authHeader = req.headers.authorization

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    // Ajoute l'en-tête pour demander au navigateur d'ouvrir la fenêtre de connexion
    res.setHeader('WWW-Authenticate', 'Basic realm="Administration"')
    return res.status(401).send('Authentification requise')
  }

  // Décodage du Base64
  const base64 = authHeader.split(' ')[1]
  const [username, password] = Buffer.from(base64, 'base64')
    .toString()
    .split(':')

  // Vérification en BDD
  const user = db
    .prepare('SELECT * FROM users WHERE username = ?')
    .get(username)

  // Comparaison des mots de passe avec bcrypt
  if (user && (await bcrypt.compare(password, user.password_hash))) {
    req.user = user // On conserve l'utilisateur dans la requête, si besoin
    next()
  } else {
    return res.status(401).send('Identifiants invalides')
  }
}

// ...
app.get('/admin-page', checkAuth, (req, res) => {
  // La route sert uniquement le fichier HTML
  res.sendFile(__dirname + '/views/admin-page.html')
})