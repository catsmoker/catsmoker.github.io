// script.js

// Function to toggle the visibility of a section
function toggleSectionVisibility(sectionId) {
    const section = document.getElementById(sectionId);
    if (section) {
        const isHidden = section.classList.toggle('hidden');
        return !isHidden;
    }
    return false;
}

// Function to handle form submission
function handleFormSubmission(event) {
    event.preventDefault();
    
    // Add your form handling logic here (e.g., sending data to a server)
    // For demonstration, we will just log a message
    console.log("Form submitted!");
    
    // You can display a confirmation message to the user
    alert("Form submitted successfully!");
    
    // Optionally reset the form
    event.target.reset();
}

// Function to add event listeners to form submissions
function setupFormSubmission(formId) {
    const form = document.getElementById(formId);
    if (form) {
        form.addEventListener('submit', handleFormSubmission);
    }
}

// Function to initialize the page interactions
function initializePage() {
    // Add event listener for form submission
    setupFormSubmission('contactForm'); // Assuming the form ID is 'contactForm'
    
    // Add event listeners for any other interactive elements (e.g., buttons)
    // For demonstration, we will add a click listener to toggle a section
    const toggleButton = document.getElementById('toggleSectionButton');
    if (toggleButton) {
        toggleButton.addEventListener('click', () => {
            const sectionVisible = toggleSectionVisibility('toggleSection');
            toggleButton.textContent = sectionVisible ? 'Hide Section' : 'Show Section';
        });
    }
}

// Initialize the page interactions when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', initializePage);
