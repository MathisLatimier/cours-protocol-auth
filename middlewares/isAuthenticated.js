const jwt = require('jsonwebtoken')

const isAuthenticated = (req, res, next) => {
  const token = req.cookies.access_token

  if (!token) {
    return res.status(401).redirect('/auth/login')
  }

  try {
    const decoded = jwt.verify(token, process.env.SESSION_SECRET)
    req.user = decoded
    next()
  } catch (err) {
    return res.status(401).redirect('/auth/login')
  }
}

module.exports = isAuthenticated
