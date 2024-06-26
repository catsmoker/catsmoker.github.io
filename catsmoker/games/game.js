// Function to start the selected game
function startGame(game) {
    // Define the URL for each game
    const gameUrls = {
        snake: 'snake/snake.html', // URL for Snake game
        comingsoon: 'comingsoon.html' // URL for comingsoon game
        // Add more games here if needed
    };
    
    // Check if the selected game exists in the gameUrls object
    if (gameUrls.hasOwnProperty(game)) {
        // Redirect to the selected game's page
        window.location.href = gameUrls[game];
    } else {
        console.error(`Game "${game}" not found`);
    }
}

// Add event listeners to game buttons
document.addEventListener("DOMContentLoaded", () => {
    // Get all game option buttons
    const gameButtons = document.querySelectorAll(".game-option button");

    // Add a click event listener to each button
    gameButtons.forEach(button => {
        button.addEventListener("click", event => {
            // Get the game type from the button's data attribute
            const gameType = button.dataset.game;
            
            // Start the selected game
            startGame(gameType);
        });
    });
});
