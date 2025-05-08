// aiwriter.js - Page specific JS for aiwriter.html

document.addEventListener('DOMContentLoaded', () => {
    // Configuration & State
    const MAX_ARTICLES = 10; // Set max limit
    let currentCategory = '1'; // Default category
    let apiKey = localStorage.getItem('gemini_api_key') || '';
    let isGenerating = false;

    // DOM Elements
    const apiKeyInput = document.getElementById('apiKey');
    const apiSection = document.getElementById('apiSection');
    const mainUI = document.getElementById('mainUI');
    const generateBtn = document.getElementById('generateBtn');
    const changeApiBtn = document.getElementById('changeApiBtn');
    const categoryCards = document.querySelectorAll('.category-card');
    const customTopicSection = document.getElementById('customTopicSection');
    const customTopicInput = document.getElementById('customTopicInput');
    const articleCountInput = document.getElementById('articleCount');
    const progressBar = document.getElementById('progressBar');
    const statusBar = document.getElementById('statusBar');
    const apiKeyStatus = document.getElementById('apiKeyStatus');

    // --- Initialization ---
    function initialize() {
        initCategoryCards();
        if (apiKey) {
            showMainUI();
        } else {
            showApiSection();
        }
        articleCountInput.addEventListener('input', validateArticleCount);
        customTopicInput?.addEventListener('input', validateCustomTopic);
    }

    function initCategoryCards() {
        categoryCards.forEach(card => {
            card.addEventListener('click', handleCategorySelection);
            card.addEventListener('keydown', (e) => {
                 if (e.key === 'Enter' || e.key === ' ') {
                    handleCategorySelection.call(card); // Use call to set 'this' correctly
                 }
            });
        });
        // Activate the default category visually
        const defaultCard = document.querySelector(`.category-card[data-category="${currentCategory}"]`);
        if (defaultCard) defaultCard.classList.add('active');
    }

    function handleCategorySelection() {
         categoryCards.forEach(c => c.classList.remove('active'));
         this.classList.add('active');
         currentCategory = this.dataset.category;
         
         customTopicSection.classList.toggle('hidden', currentCategory !== '4');
         
         if(currentCategory === '4') {
             customTopicInput.focus();
         }
         clearStatus(); // Clear status when changing category
    }

    function showApiSection() {
        apiSection.classList.remove('hidden');
        mainUI.classList.add('hidden');
        apiKeyInput?.focus();
    }
    
    function showMainUI() {
        apiSection.classList.add('hidden');
        mainUI.classList.remove('hidden');
        clearStatus(); // Clear any previous status messages
    }

    // --- API Key Handling ---
    window.saveAPIKey = function() { // Make global for onclick
        apiKey = apiKeyInput.value.trim();
        if (!apiKey) {
            setApiKeyStatus('Please enter a valid API key', 'error');
            apiKeyInput.focus();
            return;
        }
        
        // Basic validation (can be improved)
        if (apiKey.length < 30) { 
             setApiKeyStatus('API key seems too short.', 'error');
             apiKeyInput.focus();
             return;
        }

        localStorage.setItem('gemini_api_key', apiKey);
        setApiKeyStatus('API key saved successfully!', 'success');
        setTimeout(() => { // Show main UI after a short delay
            showMainUI();
             setApiKeyStatus(''); // Clear status after transition
        }, 800);
    }

    window.changeApiKey = function() { // Make global for onclick
        showApiSection();
        setApiKeyStatus('Enter your new API Key.');
    }

    function setApiKeyStatus(message, type = 'info') {
        if (!apiKeyStatus) return;
        apiKeyStatus.textContent = message;
        apiKeyStatus.className = `api-key-status ${type}`; // Add class for styling
    }

    // --- Input Validation ---
    function validateArticleCount() {
        let value = parseInt(articleCountInput.value);
        if (isNaN(value) || value < 1) {
            articleCountInput.value = 1;
        } else if (value > MAX_ARTICLES) {
            articleCountInput.value = MAX_ARTICLES;
            showStatus(`Maximum ${MAX_ARTICLES} articles at a time.`, 'error');
        }
    }

    function validateCustomTopic() {
        if (currentCategory === '4' && customTopicInput.value.trim().length > 150) {
            showStatus('Topic should be less than 150 characters.', 'error');
            return false;
        }
        return true;
    }

    function validateInputs(topic, count) {
        clearStatus(); // Clear previous errors
        if (!apiKey) {
            showStatus('API key is missing. Please save your API key.', 'error');
            showApiSection(); // Show API section if key missing
            return false;
        }
        if (count < 1 || count > MAX_ARTICLES) {
            showStatus(`Please enter a number between 1 and ${MAX_ARTICLES}.`, 'error');
            articleCountInput.focus();
            return false;
        }
        if (currentCategory === '4') {
            if (!topic) {
                showStatus('Please enter a custom article topic/title.', 'error');
                customTopicInput.focus();
                return false;
            }
            if (!validateCustomTopic()) { // Re-validate length
                 customTopicInput.focus();
                 return false;
            }
        }
        return true;
    }

    // --- Article Generation ---
    window.generateArticles = async function() { // Make global for onclick
        if (isGenerating) return;

        const count = parseInt(articleCountInput.value) || 1;
        const topic = currentCategory === '4' 
            ? customTopicInput.value.trim()
            : getDefaultTopic(); // Use function to get default topic

        if (!validateInputs(topic, count)) {
            return;
        }

        isGenerating = true;
        generateBtn.disabled = true;
        generateBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
        showStatus('Initializing generation process...', 'info');
        resetProgress();

        const zip = new JSZip();
        let generatedCount = 0;
        let failedCount = 0;
        const delayBetweenRequests = 1000; // 1 second delay to avoid rate limits

        try {
            for (let i = 0; i < count; i++) {
                updateStatus(`Generating article ${i + 1} of ${count}...`);
                try {
                    const content = await fetchArticleFromGemini(topic);
                    const filename = generateFilename(topic, i + 1);
                    zip.file(filename, content);
                    generatedCount++;
                } catch (error) {
                    console.error(`Failed to generate article ${i + 1}:`, error);
                    failedCount++;
                    // Optionally add a placeholder file for failed articles
                    zip.file(`FAILED_article_${i+1}.txt`, `Article generation failed.\nTopic: ${topic}\nError: ${error.message}`);
                }
                updateProgress(((i + 1) / count) * 100);

                // Add delay if not the last article
                if (i < count - 1) {
                    await new Promise(resolve => setTimeout(resolve, delayBetweenRequests));
                }
            }

            if (generatedCount > 0) {
                showStatus('Compressing articles into a zip file...', 'info');
                const zipContent = await zip.generateAsync({ type: 'blob' });
                downloadZipFile(zipContent, topic);

                let finalMessage = `Successfully generated ${generatedCount} article(s)!`;
                if (failedCount > 0) {
                    finalMessage += ` (${failedCount} failed).`;
                }
                finalMessage += ' Download started.';
                showStatus(finalMessage, 'success');

            } else {
                showStatus(`Failed to generate any articles. ${failedCount > 0 ? 'All attempts failed.' : 'Please check your API key or prompt.'}`, 'error');
            }

        } catch (error) { // Catch errors during the loop or zipping
            console.error('Generation process error:', error);
            showStatus(`An unexpected error occurred: ${error.message}`, 'error');
        } finally {
            isGenerating = false;
            generateBtn.disabled = false;
            generateBtn.innerHTML = '<i class="fas fa-rocket"></i> Generate Articles';
            // Optionally reset progress after a delay if showing success/error message
            setTimeout(resetProgress, 3000);
        }
    }

    async function fetchArticleFromGemini(topic) {
        const prompt = generatePrompt(topic); // Get the tailored prompt
        const requestBody = {
            contents: [{ parts: [{ text: prompt }] }],
             // Optional: Add safety settings and generation config if needed
            // safetySettings: [{ category: "HARM_CATEGORY_...", threshold: "BLOCK_MEDIUM_AND_ABOVE" }],
            // generationConfig: { temperature: 0.7, maxOutputTokens: 2048 } 
        };

        try {
            // Using gemini-1.5-flash as a faster, cheaper alternative suitable for many tasks
            const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody)
            });

            if (!response.ok) {
                let errorData;
                try {
                    errorData = await response.json();
                } catch (e) {
                    // Handle cases where the error response isn't valid JSON
                    throw new Error(`API request failed with status ${response.status} ${response.statusText}`);
                }
                 // Look for detailed error messages
                const message = errorData?.error?.message || `API Error ${response.status}`;
                console.error('Gemini API Error:', errorData);
                throw new Error(message);
            }

            const data = await response.json();

            // Check for content blocks or safety issues
            if (data.promptFeedback && data.promptFeedback.blockReason) {
                 throw new Error(`Content blocked due to: ${data.promptFeedback.blockReason}. Try rephrasing your topic.`);
            }
            
            const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
            if (!text) {
                console.warn('Unexpected API response structure:', data);
                throw new Error('No content generated or unexpected response format from API.');
            }
            
            return text.trim();

        } catch (error) {
            console.error('Error fetching from Gemini:', error);
            // Re-throw a potentially more user-friendly message
            throw new Error(`Failed to generate content: ${error.message}`); 
        }
    }

    function generatePrompt(topic) {
        const baseInstruction = "Generate a comprehensive, well-structured, and engaging article suitable for online publication.";
        const commonRequirements = `
Requirements:
- Include an engaging title.
- Use clear headings and subheadings (Markdown format: ## Heading 2, ### Heading 3).
- Write in clear, concise paragraphs.
- Ensure factual accuracy where applicable.
- Maintain a professional yet accessible tone.
- Conclude with a summary or final thoughts.
- Aim for approximately 500-800 words unless the topic demands otherwise.
- Do NOT include any preamble like "Here is the article:" or closing remarks like "I hope this helps!". Just provide the raw article content starting with the title.
`;

        const specificInstructions = {
            '1': `Focus on the topic: "${topic}". Detail historical context, recent performance, key players/teams, statistics, expert analysis, and future predictions. Target audience: Sports fans. ${commonRequirements}`,
            '2': `Create a detailed recipe for: "${topic}". Include precise ingredients (metric/imperial), step-by-step instructions with timings, cooking tips, nutritional info (estimated), serving suggestions, and variations. Target audience: Home cooks. ${commonRequirements}`,
            '3': `Compose a travel guide for: "${topic}". Cover best times to visit, attractions (popular & hidden), accommodation, local cuisine, transport, cultural tips, safety, and sample itineraries. Target audience: Travelers. ${commonRequirements}`,
            '5': `Write a technical article on: "${topic}". Explain the core concepts, real-world applications, technical details (if applicable), comparisons, future trends, and potential challenges. Target audience: Tech enthusiasts/professionals (balance depth and readability). ${commonRequirements}`,
            '4': `Write an informative article about the custom topic: "${topic}". Ensure logical flow, supporting details/examples, balanced perspective (if needed), and clear explanations. Adapt the tone based on the topic. ${commonRequirements}`
        };

        return `${baseInstruction}\n\n${specificInstructions[currentCategory] || specificInstructions['4']}`; // Fallback to custom prompt structure
    }

    function generateFilename(topic, index) {
        // Sanitize topic for filename
        const safeTopic = topic.replace(/[^a-z0-9\s-]/gi, '').replace(/\s+/g, '_').substring(0, 50);
        return `article_${safeTopic}_${index}.md`; // Save as Markdown
    }

    function downloadZipFile(content, topic) {
        const safeTopic = topic.replace(/[^a-z0-9\s-]/gi, '').replace(/\s+/g, '_').substring(0, 30);
        const filename = `AI_Articles_${safeTopic}_${new Date().toISOString().slice(0, 10)}.zip`;
        
        const url = URL.createObjectURL(content);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);
    }

    // --- UI Updates (Progress, Status) ---
    function updateProgress(percentage) {
        const rounded = Math.min(100, Math.max(0, Math.floor(percentage)));
        progressBar.style.width = `${rounded}%`;
        progressBar.setAttribute('aria-valuenow', rounded);
    }

    function resetProgress() {
        updateProgress(0);
    }

    function showStatus(message, type = 'info') { // success, error, info
        statusBar.className = `alert alert-${type}`;
        statusBar.innerHTML = `<i class="fas ${getStatusIcon(type)}"></i> ${message}`;
        statusBar.classList.remove('hidden');
    }
    
    function clearStatus() {
         statusBar.classList.add('hidden');
         statusBar.textContent = '';
         statusBar.className = 'alert hidden';
    }

    function getStatusIcon(type) {
        switch (type) {
            case 'success': return 'fa-check-circle';
            case 'error': return 'fa-exclamation-circle';
            case 'info': return 'fa-info-circle';
            default: return 'fa-info-circle';
        }
    }
    
    function getDefaultTopic() {
          const topics = {
              '1': 'Impact of Recent Transfers on Major European Football Leagues',
              '2': 'Easy Weeknight Dinner Recipes using Pasta',
              '3': 'Top Budget-Friendly Travel Destinations in Southeast Asia for Backpackers',
              '5': 'Comparison of Leading AI Image Generation Models (DALL-E, Midjourney, Stable Diffusion)'
              // Custom '4' doesn't have a default topic
          };
          // Return the topic for the current category, or a generic default if somehow needed
          return topics[currentCategory] || 'Interesting Developments in Technology'; 
    }

    // --- Run Initialization ---
    initialize();

}); // End DOMContentLoaded