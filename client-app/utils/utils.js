function loginSuccessTemplate(expires_in) {
  const ahora = new Date().toLocaleString();
  return `
    <h3>Logged in!</h3>
    <p><strong>Login time:</strong> ${ahora}</p>
    <p>Access token expires in <span id="timer">${expires_in}</span> seconds.</p>
    
    <hr />
    <a href="/profile">Call Protected API</a>
    <br /><br />
    <a href="/refresh">Refresh Access Token</a>

    <script>
      (function() {
        let seconds = ${expires_in};
        const display = document.getElementById('timer');
        const countdown = setInterval(() => {
          seconds--;
          if (seconds >= 0) display.textContent = seconds;
          if (seconds <= 0) {
            clearInterval(countdown);
            display.parentElement.style.color = "red";
            display.parentElement.innerHTML = "<strong>Token expired!</strong>";
          }
        }, 1000);
      })();
    </script>
  `;
}

export { loginSuccessTemplate };
