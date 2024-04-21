// Get the canvas and context
const canvas = document.getElementById("gameCanvas");
const ctx = canvas.getContext("2d");

// Game variables
let snake, snakeDirection, foods, gameOver, score;
let snakeSpeedModifier = 0;

// Constants
const cellSize = 20; // Size of each cell (square) on the canvas
const rows = canvas.height / cellSize;
const cols = canvas.width / cellSize;
const initialSpeed = 150; // Initial game speed (milliseconds)

// Main game loop
function gameLoop() {
    if (gameOver) return;

    // Update snake
    updateSnake();

    // Check for collisions
    checkCollision();

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw snake
    drawSnake();

    // Draw foods
    drawFoods();

    // Display score
    ctx.fillStyle = "#333";
    ctx.font = "24px 'Roboto', sans-serif";
    ctx.fillText("Score: " + score, 10, 30);

    // Continue the game loop
    setTimeout(gameLoop, getSpeed());
}

// Start or restart the game
function startGame() {
    // Initialize game variables
    snake = [{ x: 10, y: 10 }];
    snakeDirection = { x: 1, y: 0 };
    foods = [];
    gameOver = false;
    score = 0;
    snakeSpeedModifier = 0; // Reset snakeSpeedModifier

    // Place initial food
    placeFood();

    // Start the game loop
    gameLoop();
}

// Update snake position
function updateSnake() {
    const head = { x: snake[0].x + snakeDirection.x, y: snake[0].y + snakeDirection.y };

    // Check if the snake eats food
    let ateFood = false;
    foods.forEach((food, index) => {
        if (head.x === food.x && head.y === food.y) {
            score += food.score;
            foods.splice(index, 1);
            placeFood();
            adjustSpeed(food.speedModifier);
            ateFood = true;
            return;
        }
    });

    // If the snake didn't eat food, remove the last part of the tail
    if (!ateFood) {
        snake.pop();
    }

    // Add the new head to the snake
    snake.unshift(head);
}

// Draw snake
function drawSnake() {
    ctx.fillStyle = "#2ecc71"; // Green color
    snake.forEach(part => {
        ctx.fillRect(part.x * cellSize, part.y * cellSize, cellSize, cellSize);
    });
}

// Draw foods
function drawFoods() {
    foods.forEach(food => {
        ctx.fillStyle = food.color;
        ctx.fillRect(food.x * cellSize, food.y * cellSize, cellSize, cellSize);
    });
}

// Place food randomly on the canvas
function placeFood() {
    while (foods.length < 3) {
        const food = generateFood();
        foods.push(food);
    }
}

// Adjust game speed
function adjustSpeed(modifier) {
    if (modifier === 0) return;
    snakeSpeedModifier += modifier;
}

// Generate food with random effects
function generateFood() {
    const x = Math.floor(Math.random() * cols);
    const y = Math.floor(Math.random() * rows);
    let score = 1;
    let speedModifier = 0;

    // Randomly select the type of food
    const random = Math.random();
    let color;
    if (random < 0.5) {
        color = "#e74c3c"; // Red: Gives score
    } else if (random < 0.7) {
        color = "#f39c12"; // Orange: Gives score and increases speed
        speedModifier = -10; // Decrease speed by 10%
    } else if (random < 0.9) {
        color = "#3498db"; // Blue: Gives score and decreases speed
        speedModifier = 10; // Increase speed by 10%
    } else {
        color = "#9b59b6"; // Purple: No score, but you lose two score
        score = -2;
    }

    return { x, y, score, speedModifier, color };
}

// Get game speed based on score
function getSpeed() {
    const maxSpeed = 50; // Max game speed (milliseconds)
    const minSpeed = 200; // Min game speed (milliseconds)
    let speed = initialSpeed - score * 5;
    speed += speed * (snakeSpeedModifier / 100); // Adjust speed based on modifier

    return Math.min(Math.max(speed, maxSpeed), minSpeed);
}

// Check for collisions (with walls)
function checkCollision() {
    const head = snake[0];
    // Check for collision with walls
    if (head.x < 0 || head.x >= cols || head.y < 0 || head.y >= rows) {
        gameOver = true;
        alert("Game Over! Your score: " + score);
    }
}

// Handle button click events
document.getElementById("up").addEventListener("click", () => {
    if (snakeDirection.y !== 1) {
        snakeDirection.x = 0;
        snakeDirection.y = -1;
    }
});

document.getElementById("down").addEventListener("click", () => {
    if (snakeDirection.y !== -1) {
        snakeDirection.x = 0;
        snakeDirection.y = 1;
    }
});

document.getElementById("left").addEventListener("click", () => {
    if (snakeDirection.x !== 1) {
        snakeDirection.x = -1;
        snakeDirection.y = 0;
    }
});

document.getElementById("right").addEventListener("click", () => {
    if (snakeDirection.x !== -1) {
        snakeDirection.x = 1;
        snakeDirection.y = 0;
    }
});

document.getElementById("restart").addEventListener("click", () => {
    startGame();
});

// Handle keyboard input
document.addEventListener("keydown", (event) => {
    if (event.key === "w" || event.key === "ArrowUp") {
        if (snakeDirection.y !== 1) {
            snakeDirection.x = 0;
            snakeDirection.y = -1;
        }
    } else if (event.key === "s" || event.key === "ArrowDown") {
        if (snakeDirection.y !== -1) {
            snakeDirection.x = 0;
            snakeDirection.y = 1;
        }
    } else if (event.key === "a" || event.key === "ArrowLeft") {
        if (snakeDirection.x !== 1) {
            snakeDirection.x = -1;
            snakeDirection.y = 0;
        }
    } else if (event.key === "d" || event.key === "ArrowRight") {
        if (snakeDirection.x !== -1) {
            snakeDirection.x = 1;
            snakeDirection.y = 0;
        }
    }
});

// Start the game
startGame();
