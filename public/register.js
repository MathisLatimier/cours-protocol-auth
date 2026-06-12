document.getElementById('register-form').onsubmit = async e => {
  e.preventDefault()
  const username = document.getElementById('username').value
  const password = document.getElementById('password').value

  const response = await fetch('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  })

  const messageElement = document.getElementById('message')
  if (response.ok) {
    messageElement.style.color = 'green'
    messageElement.innerText = "Inscription réussie !"
  } else {
    messageElement.style.color = 'red'
    messageElement.innerText = await response.text()
  }
}