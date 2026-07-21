async function fetchWithRetry(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      Accept: 'application/json',
      ...(options.headers || {}),
    },
  })

  if (response.status !== 401) {
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

loadUser()
