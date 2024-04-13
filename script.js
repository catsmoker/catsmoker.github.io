// Function to handle hover effects on buttons and links
function handleHover(event) {
    const element = event.currentTarget;
    const isEntering = event.type === 'mouseenter';
    
    // Determine the element type and set background color accordingly
    if (element.classList.contains('subscribe-button')) {
        element.style.backgroundColor = isEntering ? '#c82333' : '#dc3545';
    } else if (element.classList.contains('email-button')) {
        // Email button hover is handled differently, no background color change
    } else {
        element.style.backgroundColor = isEntering ? '#0056b3' : '#007bff';
    }
}

// Function to handle email button click
function handleEmailClick() {
    window.location.href = 'mailto:boulhada08@gmail.com';
}

// Function to handle theme toggle button click
function handleThemeToggle() {
    // Toggle the 'dark-mode' class on the body element
    document.body.classList.toggle('dark-mode');

    // Update the button text based on the current mode
    const isDarkMode = document.body.classList.contains('dark-mode');
    toggleButton.textContent = isDarkMode ? 'Light Mode' : 'Dark Mode';
}

// Add hover effect event listeners to subscribe and email buttons
document.querySelectorAll('.subscribe-button, .email-button').forEach(button => {
    button.addEventListener('mouseenter', handleHover);
    button.addEventListener('mouseleave', handleHover);
});

// Add event listener to email button click
document.querySelectorAll('.email-button').forEach(button => {
    button.addEventListener('click', handleEmailClick);
});

// Add hover effect event listeners to links
document.querySelectorAll('.quick-links a, .social-links a').forEach(link => {
    link.addEventListener('mouseenter', handleHover);
    link.addEventListener('mouseleave', handleHover);
});

// Initialize the theme toggle button
const toggleButton = document.getElementById('theme-toggle');
toggleButton.textContent = document.body.classList.contains('dark-mode') ? 'Light Mode' : 'Dark Mode';

// Add event listener to the theme toggle button
toggleButton.addEventListener('click', handleThemeToggle);
