document.getElementById('register-form').onsubmit = async (e) => {
  e.preventDefault()

  const username = document.getElementById('username').value
  const password = document.getElementById('password').value
  const messageElement = document.getElementById('message')

  const response = await fetch('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })

  if (response.ok) {
    messageElement.className = 'mt-3 text-success'
    messageElement.textContent = 'Inscription réussie ! Redirection…'
    setTimeout(() => {
      window.location.href = '/auth/login'
    }, 1000)
    return
  }

  messageElement.className = 'mt-3 text-danger'
  messageElement.textContent = await response.text()
}
