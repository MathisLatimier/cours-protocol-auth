async function fetchWithRetry(url, options = {}) {
  const requestOptions = {
    ...options,
    redirect: 'manual',
    headers: {
      Accept: 'application/json',
      ...(options.headers || {}),
    },
  }

  const response = await fetch(url, requestOptions)

  const needsRefresh =
    response.status === 401 ||
    response.status === 302 ||
    response.type === 'opaqueredirect'

  if (!needsRefresh) {
    return response
  }

  console.log('[auth] Access token expiré → rafraîchissement transparent…')

  const refreshResponse = await fetch('/auth/refresh', {
    method: 'POST',
    headers: { Accept: 'application/json' },
  })

  if (!refreshResponse.ok) {
    console.log('[auth] Refresh échoué → redirection login')
    window.location.href = '/auth/login'
    return
  }

  console.log('[auth] Access token rafraîchi, rejeu de la requête')

  return fetch(url, {
    ...options,
    headers: {
      Accept: 'application/json',
      ...(options.headers || {}),
    },
  })
}

let currentUsername = null

async function loadUser() {
  const response = await fetchWithRetry('/bat-computer/user')
  if (!response || !response.ok) return

  const data = await response.json()
  currentUsername = data.username
  document.getElementById('username').textContent = data.username
  updateTwoFactorUI(Boolean(data.two_factor_enabled))
}

function updateTwoFactorUI(enabled) {
  const status = document.getElementById('twofa-status')
  const setupBlock = document.getElementById('twofa-setup-block')

  if (enabled) {
    status.className = 'text-success'
    status.textContent = '2FA activée sur ce compte.'
    setupBlock.classList.add('d-none')
    return
  }

  status.className = 'text-warning'
  status.textContent =
    '2FA non activée — obligatoire pour les prochaines connexions. Configurez-la maintenant.'
  setupBlock.classList.remove('d-none')
}

async function setup2FA() {
  const message = document.getElementById('twofa-message')
  message.textContent = ''

  const response = await fetchWithRetry('/auth/2fa/setup', { method: 'POST' })
  if (!response) return

  const data = await response.json()

  if (!response.ok) {
    message.className = 'mt-3 text-danger'
    message.textContent = data.error || 'Impossible d\'initialiser la 2FA.'
    return
  }

  document.getElementById('twofa-qr').src = data.qrCode
  document.getElementById('twofa-secret').textContent = data.secret
  document.getElementById('twofa-qr-block').classList.remove('d-none')
}

async function confirm2FA(event) {
  event.preventDefault()

  const message = document.getElementById('twofa-message')
  const code = document.getElementById('confirm-2fa-code').value.trim()

  const response = await fetchWithRetry('/auth/2fa/confirm', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: currentUsername, code }),
  })

  if (!response) return

  const data = await response.json()

  if (!response.ok) {
    message.className = 'mt-3 text-danger'
    message.textContent = data.error || 'Code invalide.'
    return
  }

  message.className = 'mt-3 text-success'
  message.textContent = data.message
  document.getElementById('twofa-qr-block').classList.add('d-none')
  document.getElementById('confirm-2fa-form').reset()
  updateTwoFactorUI(true)
}

async function changePassword(event) {
  event.preventDefault()

  const oldPassword = document.getElementById('oldPassword').value
  const newPassword = document.getElementById('newPassword').value
  const messageElement = document.getElementById('password-message')

  const response = await fetchWithRetry('/auth/change-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ oldPassword, newPassword }),
  })

  if (!response) return

  const data = await response.json()

  if (response.ok) {
    messageElement.className = 'mt-3 text-success'
    messageElement.textContent = data.message
    document.getElementById('change-password-form').reset()
    return
  }

  messageElement.className = 'mt-3 text-danger'
  messageElement.textContent =
    data.error || 'Erreur lors du changement de mot de passe.'
}

document.getElementById('setup-2fa-btn').addEventListener('click', setup2FA)
document.getElementById('confirm-2fa-form').addEventListener('submit', confirm2FA)
document
  .getElementById('change-password-form')
  .addEventListener('submit', changePassword)

loadUser()
