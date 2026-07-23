const crypto = require('crypto')

/**
 * Configuration des trois fournisseurs OAuth 2.0 (Authorization Code + PKCE).
 * Aucune librairie Passport : fetch + crypto uniquement.
 */
const providers = {
  google: {
    name: 'Google',
    authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenEndpoint: 'https://oauth2.googleapis.com/token',
    userInfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
    scopes: ['openid', 'email', 'profile'],
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    redirectUri: process.env.GOOGLE_REDIRECT_URI,
  },
  github: {
    name: 'GitHub',
    authorizationEndpoint: 'https://github.com/login/oauth/authorize',
    tokenEndpoint: 'https://github.com/login/oauth/access_token',
    userInfoEndpoint: 'https://api.github.com/user',
    emailsEndpoint: 'https://api.github.com/user/emails',
    scopes: ['read:user', 'user:email'],
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    redirectUri: process.env.GITHUB_REDIRECT_URI,
  },
  discord: {
    name: 'Discord',
    authorizationEndpoint: 'https://discord.com/api/oauth2/authorize',
    tokenEndpoint: 'https://discord.com/api/oauth2/token',
    userInfoEndpoint: 'https://discord.com/api/users/@me',
    scopes: ['identify', 'email'],
    clientId: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    redirectUri: process.env.DISCORD_REDIRECT_URI,
  },
}

function base64UrlEncode(buffer) {
  return Buffer.from(buffer)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

/** PKCE : code_verifier aléatoire (43–128 caractères) */
function generateCodeVerifier() {
  return base64UrlEncode(crypto.randomBytes(32))
}

/** PKCE : code_challenge = BASE64URL(SHA256(code_verifier)) */
function generateCodeChallenge(codeVerifier) {
  const hash = crypto.createHash('sha256').update(codeVerifier).digest()
  return base64UrlEncode(hash)
}

/** State anti-CSRF */
function generateState() {
  return base64UrlEncode(crypto.randomBytes(24))
}

function getProvider(name) {
  const provider = providers[name]
  if (!provider) return null
  if (!provider.clientId || !provider.clientSecret || !provider.redirectUri) {
    return null
  }
  return provider
}

/**
 * Normalise le profil IdP → { providerId, username, email }
 */
async function fetchUserProfile(providerKey, accessToken) {
  const provider = providers[providerKey]

  if (providerKey === 'google') {
    const res = await fetch(provider.userInfoEndpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    if (!res.ok) throw new Error(`Google userinfo: ${res.status}`)
    const data = await res.json()
    return {
      providerId: String(data.sub),
      username: data.name || data.email || data.sub,
      email: data.email || null,
    }
  }

  if (providerKey === 'github') {
    const res = await fetch(provider.userInfoEndpoint, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Bat-Computer-OAuth',
      },
    })
    if (!res.ok) throw new Error(`GitHub userinfo: ${res.status}`)
    const data = await res.json()

    let email = data.email
    if (!email) {
      const emailsRes = await fetch(provider.emailsEndpoint, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'Bat-Computer-OAuth',
        },
      })
      if (emailsRes.ok) {
        const emails = await emailsRes.json()
        const primary = emails.find((e) => e.primary && e.verified) || emails[0]
        email = primary?.email || null
      }
    }

    return {
      providerId: String(data.id),
      username: data.login || email || String(data.id),
      email,
    }
  }

  if (providerKey === 'discord') {
    const res = await fetch(provider.userInfoEndpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    if (!res.ok) throw new Error(`Discord userinfo: ${res.status}`)
    const data = await res.json()
    return {
      providerId: String(data.id),
      username: data.global_name || data.username || data.email || data.id,
      email: data.email || null,
    }
  }

  throw new Error(`Provider inconnu: ${providerKey}`)
}

/**
 * Échange authorization code → access_token (avec code_verifier PKCE)
 */
async function exchangeCodeForToken(providerKey, code, codeVerifier) {
  const provider = providers[providerKey]

  const body = new URLSearchParams({
    client_id: provider.clientId,
    client_secret: provider.clientSecret,
    code,
    redirect_uri: provider.redirectUri,
    grant_type: 'authorization_code',
    code_verifier: codeVerifier,
  })

  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: 'application/json',
  }

  const res = await fetch(provider.tokenEndpoint, {
    method: 'POST',
    headers,
    body,
  })

  const data = await res.json().catch(() => ({}))

  if (!res.ok || data.error || !data.access_token) {
    const msg = data.error_description || data.error || `HTTP ${res.status}`
    throw new Error(`Échange de jeton ${providerKey} échoué: ${msg}`)
  }

  return data
}

function buildAuthorizationUrl(providerKey, { state, codeChallenge }) {
  const provider = providers[providerKey]
  const params = new URLSearchParams({
    client_id: provider.clientId,
    redirect_uri: provider.redirectUri,
    response_type: 'code',
    scope: provider.scopes.join(' '),
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })

  // Google : forcer le compte + consentement frais utile en TP
  if (providerKey === 'google') {
    params.set('access_type', 'online')
    params.set('prompt', 'select_account')
  }

  return `${provider.authorizationEndpoint}?${params.toString()}`
}

module.exports = {
  providers,
  getProvider,
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
  buildAuthorizationUrl,
  exchangeCodeForToken,
  fetchUserProfile,
}
