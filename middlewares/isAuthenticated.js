const jwt = require('jsonwebtoken')

const sendUnauthorized = (req, res) => {
  // Les appels API (fetch) doivent recevoir un 401 JSON pour le Retry Pattern
  const wantsHtml = req.headers.accept?.includes('text/html')
  if (wantsHtml) {
    return res.status(401).redirect('/auth/login')
  }
  return res.status(401).json({ error: 'Non authentifié.' })
}

const isAuthenticated = (req, res, next) => {
  const token = req.cookies.access_token

  if (!token) {
    return sendUnauthorized(req, res)
  }

  try {
    const decoded = jwt.verify(token, process.env.SESSION_SECRET)
    req.user = decoded
    next()
  } catch (err) {
    return sendUnauthorized(req, res)
  }
}

module.exports = isAuthenticated
