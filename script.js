document.getElementById('Downloads').addEventListener('click', function() {
    window.location.href = 'downloads.html'; // Navigate to the Downloads
});

// Function to handle email button click
const handleEmailClick = () => {
    window.location.href = 'mailto:boulhada08@gmail.com';
};

// Function to handle call button click
const handleCallClick = () => {
    window.location.href = 'tel:00212775804065';
};

// Function to handle WhatsApp button click
const handleWhatsAppClick = () => {
    window.open('https://web.whatsapp.com/send/?phone=212775804065&text&type=phone_number&app_absent=0', '_blank');
};

// Function to toggle between dark and light mode
const handleThemeToggle = () => {
    const body = document.body;
    const isDarkMode = body.classList.toggle('dark-mode');
    const themeToggleBtn = document.getElementById('theme-toggle');
    
    // Update the button text based on the current mode
    themeToggleBtn.textContent = isDarkMode ? 'Light Mode' : 'Dark Mode';
};

// Function to initialize the theme toggle button
const initializeThemeToggle = () => {
    const body = document.body;
    const themeToggleBtn = document.getElementById('theme-toggle');
    
    // Update the button text based on the current mode
    themeToggleBtn.textContent = body.classList.contains('dark-mode') ? 'Light Mode' : 'Dark Mode';
};

// Function to handle page views count
const handlePageViewsCount = () => {
    const counter = document.createElement('img');
    counter.src = 'https://profile-counter.glitch.me/catsmoker/count.svg';
    counter.alt = 'Profile views count';
    document.getElementById('viewers').appendChild(counter);
};

// Add event listeners after DOM content has loaded
document.addEventListener('DOMContentLoaded', () => {
    // Add event listener for the theme toggle button
    document.getElementById('theme-toggle').addEventListener('click', handleThemeToggle);
    
    // Add event listener for the email button
    document.getElementById('myBtn').addEventListener('click', handleEmailClick);
    
    // Initialize the theme toggle button state
    initializeThemeToggle();
    
    // Handle the page views count
    handlePageViewsCount();

    // Add event listeners for the additional contact buttons
    document.getElementById('callBtn').addEventListener('click', handleCallClick);
    document.getElementById('whatsappBtn').addEventListener('click', handleWhatsAppClick);
});

// animated text
const spans = document.querySelectorAll('.animated-text span');

let delay = 0;
spans.forEach(span => {
  span.style.animationDelay = `${delay}s`;
  delay += 1; // Adjust delay as needed
});

