const express = require('express')
const bcrypt = require('bcrypt')
const path = require('path')
const db = require('../config/db')

const router = express.Router()

// Formulaire de connexion
router.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'views', 'login.html'))
})

// Traitement de la connexion
router.post('/login', async (req, res) => {
  const { username, password } = req.body

  if (!username || !password) {
    return res.status(400).send('Veuillez remplir tous les champs.')
  }

  // Vérification en BDD
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username)

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).send('Identifiants invalides.')
  }

  // Régénération de session pour éviter la fixation de session
  req.session.regenerate((err) => {
    if (err) return res.status(500).send('Erreur serveur.')
    // 1. Stocker le username dans la nouvelle session
    req.session.user = { id: user.id, username: user.username }
    // 2. Sauvegarder explicitement
    req.session.save((err) => {
      if (err) return res.status(500).send('Erreur serveur.')
      // 3. Rediriger vers le tableau de bord
      res.redirect('/bat-computer')
    })
  })
})

// Déconnexion propre
router.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).send('Erreur serveur.')
    // Effacer le cookie du navigateur
    res.clearCookie('bat_identity')
    res.redirect('/auth/login')
  })
})

// ...
router.post('/register', async (req, res) => {
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

module.exports = router
