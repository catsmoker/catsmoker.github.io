// Function to open the side navigation
function openNav() {
    document.getElementById("mySidenav").style.width = "250px";
}

// Function to close the side navigation
function closeNav() {
    document.getElementById("mySidenav").style.width = "0";
}

// Function to handle email button click
function handleEmailClick() {
    window.location.href = 'mailto:boulhada08@gmail.com';
}

// Function to toggle between dark and light mode
function handleThemeToggle() {
    const body = document.body;
    const isDarkMode = body.classList.toggle('dark-mode');
    const themeToggleBtn = document.getElementById('theme-toggle');

    // Update the button text based on the current mode
    themeToggleBtn.textContent = isDarkMode ? 'Light Mode' : 'Dark Mode';

    // Update the favicon based on the current mode
    const favicon = document.querySelector('link[rel="icon"]');
    favicon.href = isDarkMode ? 'catsmoker/images/favicon-dark.ico' : 'catsmoker/images/favicon.ico';

    // Update the background music based on the current mode
    const audio = document.getElementById('backgroundMusic');
    audio.src = isDarkMode ? 'catsmoker/audio/backgroundmusic-dark.mp3' : 'catsmoker/audio/backgroundmusic.mp3';
}

// Function to initialize the theme toggle button
function initializeThemeToggle() {
    const body = document.body;
    const isDarkMode = body.classList.contains('dark-mode');
    const themeToggleBtn = document.getElementById('theme-toggle');
    
    // Update the button text based on the current mode
    themeToggleBtn.textContent = isDarkMode ? 'Light Mode' : 'Dark Mode';
}

// Function to handle page views count
function handlePageViewsCount() {
    const counter = document.createElement('img');
    counter.src = 'https://profile-counter.glitch.me/catsmoker/count.svg';
    counter.alt = 'Profile views count';
    document.getElementById('viewers').appendChild(counter);
}

// Add event listeners after DOM content has loaded
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('theme-toggle').addEventListener('click', handleThemeToggle);
    document.getElementById('email-button').addEventListener('click', handleEmailClick); // Corrected ID

    // Initialize
    initializeThemeToggle();
    handlePageViewsCount();
});
