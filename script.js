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
    document.getElementById('myBtn').addEventListener('click', handleEmailClick);
    
    initializeThemeToggle(); // Initialize theme toggle
    handlePageViewsCount(); // Handle page views count
});
