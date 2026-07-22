const loginForm = document.getElementById('login-form')
const totpForm = document.getElementById('totp-form')
const loginMessage = document.getElementById('login-message')
const totpMessage = document.getElementById('totp-message')
const totpHint = document.getElementById('totp-hint')

let pendingUsername = null

async function parseBody(response) {
  const contentType = response.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    return response.json()
  }
  return { error: await response.text() }
}

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault()
  loginMessage.textContent = ''
  loginMessage.className = 'mt-3'

  const username = document.getElementById('username').value.trim()
  const password = document.getElementById('password').value

  const response = await fetch('/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ username, password }),
  })

  const data = await parseBody(response)

  if (response.status === 403) {
    loginMessage.className = 'mt-3 text-danger'
    loginMessage.innerHTML =
      (data.error || 'Activation 2FA obligatoire.') +
      ' <a href="/register.html">Créez un compte</a> puis activez la 2FA depuis le Bat-Computer.'
    return
  }

  if (!response.ok) {
    loginMessage.className = 'mt-3 text-danger'
    loginMessage.textContent = data.error || 'Identifiants invalides.'
    return
  }

  if (data.requires2FA) {
    pendingUsername = data.username
    totpHint.textContent = data.message
    loginForm.classList.add('d-none')
    totpForm.classList.remove('d-none')
    document.getElementById('totp-code').focus()
    return
  }

  window.location.href = '/bat-computer'
})

totpForm.addEventListener('submit', async (event) => {
  event.preventDefault()
  totpMessage.textContent = ''
  totpMessage.className = 'mt-3'

  const code = document.getElementById('totp-code').value.trim()

  const response = await fetch('/api/verify-2fa', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ username: pendingUsername, code }),
  })

  const data = await parseBody(response)

  if (!response.ok) {
    totpMessage.className = 'mt-3 text-danger'
    totpMessage.textContent = data.error || 'Code TOTP invalide.'
    return
  }

  window.location.href = '/bat-computer'
})

document.getElementById('totp-back').addEventListener('click', () => {
  pendingUsername = null
  totpForm.classList.add('d-none')
  totpForm.reset()
  totpMessage.textContent = ''
  loginForm.classList.remove('d-none')
})
