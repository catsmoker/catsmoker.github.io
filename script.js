// script.js

// Function to handle button hover effects
function handleButtonHover(event) {
    const button = event.currentTarget;
    button.style.backgroundColor = event.type === 'mouseenter' ? '#0056b3' : '#007bff';
}

// Function to handle subscription button hover effects
function handleSubscriptionHover(event) {
    const button = event.currentTarget;
    button.style.backgroundColor = event.type === 'mouseenter' ? '#c82333' : '#dc3545';
}

// Function to handle email button click
function handleEmailClick() {
    window.location.href = 'mailto:boulhada08@gmail.com';
}

// Event listeners for button hover effects
document.querySelectorAll('.subscribe-button').forEach(button => {
    button.addEventListener('mouseenter', handleSubscriptionHover);
    button.addEventListener('mouseleave', handleSubscriptionHover);
});

document.querySelectorAll('.email-button').forEach(button => {
    button.addEventListener('click', handleEmailClick);
});

// Event listeners for link hover effects
document.querySelectorAll('.quick-links a, .social-links a').forEach(link => {
    link.addEventListener('mouseenter', handleButtonHover);
    link.addEventListener('mouseleave', handleButtonHover);
});

// Function to handle theme toggle button click
function handleThemeToggle() {
    // Toggle the 'dark-mode' class on the body element (entire page)
    document.body.classList.toggle('dark-mode');

    // Update the button text based on the current mode
    if (document.body.classList.contains('dark-mode')) {
        toggleButton.textContent = 'Light Mode';
    } else {
        toggleButton.textContent = 'Dark Mode';
    }
}

// Get the toggle button and set its initial text based on the current mode
const toggleButton = document.getElementById('theme-toggle');
if (document.body.classList.contains('dark-mode')) {
    toggleButton.textContent = 'Light Mode';
} else {
    toggleButton.textContent = 'Dark Mode';
}

// Add event listener to the toggle button
toggleButton.addEventListener('click', handleThemeToggle);
