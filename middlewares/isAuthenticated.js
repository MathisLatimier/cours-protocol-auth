const jwt = require('jsonwebtoken')

const isAuthenticated = (req, res, next) => {
  const token = req.cookies.access_token

  if (!token) {
    return res.status(401).json({ error: 'Non authentifié.' })
  }

  try {
    const decoded = jwt.verify(token, process.env.SESSION_SECRET)
    req.user = decoded
    next()
  } catch (err) {
    return res.status(401).json({ error: 'Access token invalide ou expiré.' })
  }
}

module.exports = isAuthenticated
