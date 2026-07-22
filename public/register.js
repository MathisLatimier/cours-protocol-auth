document.getElementById('register-form').onsubmit = async (e) => {
  e.preventDefault()

  const username = document.getElementById('username').value
  const password = document.getElementById('password').value
  const messageElement = document.getElementById('message')

  const response = await fetch('/auth/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({ username, password }),
  })

  const contentType = response.headers.get('content-type') || ''
  const data = contentType.includes('application/json')
    ? await response.json()
    : { error: await response.text() }

  if (response.ok) {
    messageElement.className = 'mt-3 text-success'
    messageElement.textContent =
      data.message || 'Inscription réussie ! Redirection vers le Bat-Computer…'
    setTimeout(() => {
      window.location.href = data.redirect || '/bat-computer'
    }, 1000)
    return
  }

  messageElement.className = 'mt-3 text-danger'
  messageElement.textContent = data.error || (typeof data === 'string' ? data : 'Erreur')
}
