document.getElementById('loginForm').addEventListener('submit', function(event) {
  event.preventDefault();

  // Get input values
  var username = document.getElementById('username').value;
  var password = document.getElementById('password').value;

  // Check username and password
  if (username === 'catsmoker' && password === 'catsmoker123@') {
    // Redirect to another site
    window.location.href = 'ftp://catsmoker.ddns.net/'; // Replace 'https://example.com' with the URL you want to redirect to
  } else {
    alert('Invalid username or password. Please try again.');
  }
});
