// Get the canvas and context
const canvas = document.getElementById("gameCanvas");
const ctx = canvas.getContext("2d");

// Snake game variables
const snake = [{ x: 10, y: 10 }];
let snakeDirection = { x: 1, y: 0 };
let food = { x: 15, y: 15 };
let gameOver = false;
let score = 0;

// Constants
const cellSize = 20; // Size of each cell (square) on the canvas
const rows = canvas.height / cellSize;
const cols = canvas.width / cellSize;

// Main game loop
function gameLoop() {
    if (gameOver) return;
    
    // Update snake
    updateSnake();

    // Check for collision
    checkCollision();

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw snake
    drawSnake();

    // Draw food
    drawFood();

    // Display score
    ctx.fillStyle = "black";
    ctx.fillText("Score: " + score, 10, 10);

    // Continue the game loop
    setTimeout(gameLoop, 200);
}

// Update snake position
function updateSnake() {
    const head = { x: snake[0].x + snakeDirection.x, y: snake[0].y + snakeDirection.y };
    snake.unshift(head);

    // Check if the snake eats food
    if (head.x === food.x && head.y === food.y) {
        score++;
        placeFood();
    } else {
        snake.pop();
    }
}

// Draw snake
function drawSnake() {
    ctx.fillStyle = "red";
    snake.forEach(part => {
        ctx.fillRect(part.x * cellSize, part.y * cellSize, cellSize, cellSize);
    });
}

// Draw food
function drawFood() {
    ctx.fillStyle = "green";
    ctx.fillRect(food.x * cellSize, food.y * cellSize, cellSize, cellSize);
}

// Place food randomly on the canvas
function placeFood() {
    food.x = Math.floor(Math.random() * cols);
    food.y = Math.floor(Math.random() * rows);
}

// Check for collisions (with walls or itself)
function checkCollision() {
    const head = snake[0];
    // Check for collision with walls
    if (head.x < 0 || head.x >= cols || head.y < 0 || head.y >= rows) {
        gameOver = true;
        alert("Game Over! Your score: " + score);
        return;
    }

    // Check for collision with itself
    for (let i = 1; i < snake.length; i++) {
        if (head.x === snake[i].x && head.y === snake[i].y) {
            gameOver = true;
            alert("Game Over! Your score: " + score);
            return;
        }
    }
}

// Handle keyboard input
window.addEventListener("keydown", (event) => {
    if (event.key === "w" && snakeDirection.y !== 1) {
        snakeDirection.x = 0;
        snakeDirection.y = -1;
    } else if (event.key === "s" && snakeDirection.y !== -1) {
        snakeDirection.x = 0;
        snakeDirection.y = 1;
    } else if (event.key === "a" && snakeDirection.x !== 1) {
        snakeDirection.x = -1;
        snakeDirection.y = 0;
    } else if (event.key === "d" && snakeDirection.x !== -1) {
        snakeDirection.x = 1;
        snakeDirection.y = 0;
    }
});


// Start the game loop
gameLoop();
