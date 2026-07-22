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

  // JWT expiré : pause la requête, tente un rafraîchissement
  const refreshResponse = await fetch('/auth/refresh', {
    method: 'POST',
    headers: { Accept: 'application/json' },
  })

  if (!refreshResponse.ok) {
    // Refresh token expiré ou révoqué → retour au login
    window.location.href = '/auth/login'
    return
  }

  // Rafraîchissement OK → rejoue la requête initiale
  return fetch(url, {
    ...options,
    headers: {
      Accept: 'application/json',
      ...(options.headers || {}),
    },
  })
}

async function loadUser() {
  const response = await fetchWithRetry('/bat-computer/user')
  if (!response || !response.ok) return

  const data = await response.json()
  document.getElementById('username').textContent = data.username
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
  messageElement.textContent = data.error || 'Erreur lors du changement de mot de passe.'
}

document
  .getElementById('change-password-form')
  .addEventListener('submit', changePassword)

loadUser()
