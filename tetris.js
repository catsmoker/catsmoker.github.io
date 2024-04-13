// Get the canvas and context
const canvas = document.getElementById("tetrisCanvas");
const ctx = canvas.getContext("2d");

// Define the size of each square in the Tetris game
const squareSize = 20;

// Define the canvas rows and columns
const rows = canvas.height / squareSize;
const cols = canvas.width / squareSize;

// Define the shapes of Tetris pieces
const shapes = [
    // I shape
    [[1, 1, 1, 1]],
    // O shape
    [
        [1, 1],
        [1, 1]
    ],
    // T shape
    [
        [1, 1, 1],
        [0, 1, 0]
    ],
    // L shape
    [
        [1, 0, 0],
        [1, 1, 1]
    ],
    // J shape
    [
        [0, 0, 1],
        [1, 1, 1]
    ],
    // S shape
    [
        [0, 1, 1],
        [1, 1, 0]
    ],
    // Z shape
    [
        [1, 1, 0],
        [0, 1, 1]
    ]
];

// Game variables
let grid = createEmptyGrid(rows, cols);
let currentPiece = getRandomPiece();
let piecePosition = { x: 0, y: 0 };
let gameOver = false;

// Function to create an empty grid
function createEmptyGrid(rows, cols) {
    const grid = [];
    for (let row = 0; row < rows; row++) {
        grid[row] = [];
        for (let col = 0; col < cols; col++) {
            grid[row][col] = 0;
        }
    }
    return grid;
}

// Function to get a random Tetris piece
function getRandomPiece() {
    const randomIndex = Math.floor(Math.random() * shapes.length);
    return shapes[randomIndex];
}

// Function to draw the grid
function drawGrid() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (let row = 0; row < rows; row++) {
        for (let col = 0; col < cols; col++) {
            if (grid[row][col] === 1) {
                ctx.fillStyle = "blue";
                ctx.fillRect(col * squareSize, row * squareSize, squareSize, squareSize);
                ctx.strokeRect(col * squareSize, row * squareSize, squareSize, squareSize);
            }
        }
    }
}

// Function to draw the current Tetris piece
function drawPiece(piece, position) {
    ctx.fillStyle = "red";
    piece.forEach((row, rowIndex) => {
        row.forEach((cell, colIndex) => {
            if (cell === 1) {
                ctx.fillRect(
                    (position.x + colIndex) * squareSize,
                    (position.y + rowIndex) * squareSize,
                    squareSize,
                    squareSize
                );
                ctx.strokeRect(
                    (position.x + colIndex) * squareSize,
                    (position.y + rowIndex) * squareSize,
                    squareSize,
                    squareSize
                );
            }
        });
    });
}

// Function to move the piece
function movePiece(dx, dy) {
    piecePosition.x += dx;
    piecePosition.y += dy;

    // Check if the move is valid
    if (!isValidMove()) {
        // Reverse the move if it's invalid
        piecePosition.x -= dx;
        piecePosition.y -= dy;
        return false;
    }

    return true;
}

// Function to rotate the piece
function rotatePiece() {
    // Clone the current piece
    const newPiece = currentPiece.map(row => [...row]);

    // Rotate the piece clockwise
    for (let row = 0; row < newPiece.length; row++) {
        for (let col = 0; col < row; col++) {
            [newPiece[row][col], newPiece[col][row]] = [newPiece[col][row], newPiece[row][col]];
        }
    }
    newPiece.forEach(row => row.reverse());

    // Check if the rotation is valid
    const originalPiece = currentPiece;
    currentPiece = newPiece;
    if (!isValidMove()) {
        currentPiece = originalPiece; // Revert if invalid
    }
}

// Function to check if the move is valid
function isValidMove() {
    for (let row = 0; row < currentPiece.length; row++) {
        for (let col = 0; col < currentPiece[row].length; col++) {
            if (currentPiece[row][col] === 1) {
                const newX = piecePosition.x + col;
                const newY = piecePosition.y + row;

                // Check if the piece is out of bounds
                if (newX < 0 || newX >= cols || newY >= rows) {
                    return false;
                }

                // Check if the piece collides with the grid
                if (newY >= 0 && grid[newY][newX] === 1) {
                    return false;
                }
            }
        }
    }
    return true;
}

// Function to update the game state
function updateGameState() {
    // Move the piece down
    movePiece(0, 1);

    // Check if the piece has landed
    if (!isValidMove()) {
        // Revert the move
        piecePosition.y--;

        // Merge the piece with the grid
        mergePiece();

        // Check for completed lines
        checkForCompleteLines();

        // Get a new piece
        currentPiece = getRandomPiece();
        piecePosition = { x: Math.floor(cols / 2) - 1, y: 0 };

        // Check if the new piece immediately causes a game over
        if (!isValidMove()) {
            gameOver = true;
            alert("Game Over!");
        }
    }
}

// Function to merge the current piece with the grid
function mergePiece() {
    currentPiece.forEach((row, rowIndex) => {
        row.forEach((cell, colIndex) => {
            if (cell === 1) {
                grid[piecePosition.y + rowIndex][piecePosition.x + colIndex] = 1;
            }
        });
    });
}

// Function to check for complete lines and remove them
function checkForCompleteLines() {
    for (let row = rows - 1; row >= 0; row--) {
        const isComplete = grid[row].every(cell => cell === 1);

        if (isComplete) {
            // Remove the complete line
            grid.splice(row, 1);

            // Add a new empty line at the top
            grid.unshift(Array(cols).fill(0));

            // Move the rows down
            row++;
        }
    }
}

// Function to handle keyboard input
window.addEventListener("keydown", (event) => {
    if (event.key === "ArrowLeft") {
        movePiece(-1, 0);
    } else if (event.key === "ArrowRight") {
        movePiece(1, 0);
    } else if (event.key === "ArrowDown") {
        movePiece(0, 1);
    } else if (event.key === "ArrowUp") {
        rotatePiece();
    }
});

// Function to render the game
function render() {
    if (gameOver) return;

    // Update the game state
    updateGameState();

    // Draw the grid
    drawGrid();

    // Draw the current piece
    drawPiece(currentPiece, piecePosition);

    // Request the next animation frame
    requestAnimationFrame(render);
}

// Start the game loop
render();
