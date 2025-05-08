// search.js - Page specific JS for search.html

document.addEventListener('DOMContentLoaded', () => {
    // --- Enhanced !bang database ---
    let bangs = {
        "!g": "https://www.google.com/search?q=%s",
        "!yt": "https://www.youtube.com/results?search_query=%s",
        "!w": "https://en.wikipedia.org/wiki/Special:Search/%s",
        "!gh": "https://github.com/search?q=%s",
        "!d": "https://duckduckgo.com/?q=%s",
        "!r": "https://www.reddit.com/search/?q=%s",
        "!tw": "https://twitter.com/search?q=%s",
        "!amz": "https://www.amazon.com/s?k=%s",
        "!gm": "https://www.google.com/maps/search/%s",
        "!t": "https://www.thesaurus.com/browse/%s",
        "!tr": "https://translate.google.com/?sl=auto&tl=en&text=%s",
        "!aw": "https://wiki.archlinux.org/index.php?search=%s",
        "!so": "https://stackoverflow.com/search?q=%s",
        "!imdb": "https://www.imdb.com/find?q=%s",
        "!ud": "https://www.urbandictionary.com/define.php?term=%s"
        // More can be added here or loaded from storage
    };

    const searchInput = document.getElementById('search');
    const settingsPanel = document.getElementById('settings-panel');
    const darkModeCheckbox = document.getElementById('dark-mode');
    const stripTrackersCheckbox = document.getElementById('strip-trackers');
    const customBangInput = document.getElementById('custom-bang');
    const customUrlInput = document.getElementById('custom-url');
    const themeToggleButton = document.getElementById('theme-toggle-btn');
    const customBangListDiv = document.getElementById('custom-bang-list');

    // --- Load saved settings ---
    function loadSettings() {
        // Dark mode
        const darkModeSaved = localStorage.getItem('search-dark-mode') === 'true';
        darkModeCheckbox.checked = darkModeSaved;
        document.body.classList.toggle('search-dark-mode', darkModeSaved);
        updateThemeIcon(darkModeSaved);

        // Tracker stripping
        stripTrackersCheckbox.checked = localStorage.getItem('search-strip-trackers') === 'true';

        // Load custom !bangs from localStorage
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith('bang:')) {
                const bang = key.substring(5);
                const url = localStorage.getItem(key);
                if (bang && url) {
                    bangs[bang] = url;
                }
            }
        }
        renderCustomBangs(); // Display loaded bangs
    }

    // --- Theme Toggle ---
    function updateThemeIcon(isDarkMode) {
        if (themeToggleButton) {
             themeToggleButton.innerHTML = isDarkMode ? '<i class="fas fa-sun"></i>' : '<i class="fas fa-moon"></i>';
        }
    }

    darkModeCheckbox.addEventListener('change', (e) => {
        const isDarkMode = e.target.checked;
        localStorage.setItem('search-dark-mode', isDarkMode);
        document.body.classList.toggle('search-dark-mode', isDarkMode);
        updateThemeIcon(isDarkMode);
    });

    if(themeToggleButton) {
        themeToggleButton.addEventListener('click', () => {
             darkModeCheckbox.checked = !darkModeCheckbox.checked;
             // Manually trigger change event
             darkModeCheckbox.dispatchEvent(new Event('change'));
        });
    }

    // --- Tracker Stripping Setting ---
    stripTrackersCheckbox.addEventListener('change', (e) => {
        localStorage.setItem('search-strip-trackers', e.target.checked);
    });

    // --- Settings Panel Toggle ---
    window.toggleSettings = function() { // Make global for onclick
        if (settingsPanel) {
            const isHidden = settingsPanel.style.display === 'none' || settingsPanel.style.display === '';
            settingsPanel.style.display = isHidden ? 'block' : 'none';
        }
    }

    // --- Custom Bang Management ---
    function renderCustomBangs() {
        if (!customBangListDiv) return;
        customBangListDiv.innerHTML = ''; // Clear list
        Object.entries(bangs).forEach(([bang, url]) => {
            // Only list user-added bangs (optional, or list all)
            if (localStorage.getItem(`bang:${bang}`)) {
                const item = document.createElement('div');
                item.className = 'custom-bang-item';
                item.innerHTML = `
                    <span><strong>${bang}</strong> → ${url.substring(0, 40)}...</span>
                    <button class="remove-bang-btn" data-bang="${bang}" title="Remove bang">×</button>
                `;
                customBangListDiv.appendChild(item);
            }
        });

        // Add event listeners to remove buttons
        customBangListDiv.querySelectorAll('.remove-bang-btn').forEach(button => {
            button.addEventListener('click', removeCustomBang);
        });
    }

    function removeCustomBang(event) {
        const bangToRemove = event.target.getAttribute('data-bang');
        if (bangToRemove && bangs[bangToRemove]) {
            delete bangs[bangToRemove];
            localStorage.removeItem(`bang:${bangToRemove}`);
            renderCustomBangs(); // Re-render the list
            // Optionally show a confirmation message
        }
    }


    window.saveCustomBang = function() { // Make global for onclick
        const bang = customBangInput.value.trim();
        const url = customUrlInput.value.trim();

        if (!bang.startsWith('!')) {
             alert('Custom bang must start with !');
             return;
        }
        if (!url || !url.includes('%s')) {
             alert('URL must include %s as a placeholder for the search query.');
             return;
        }
        if(bang && url) {
            bangs[bang] = url;
            localStorage.setItem(`bang:${bang}`, url);
            renderCustomBangs(); // Update displayed list
            // alert(`Added ${bang} → ${url}`); // Optional confirmation
            customBangInput.value = '';
            customUrlInput.value = '';
        } else {
            alert('Invalid !bang or URL.');
        }
    }

    // --- Search Functions ---
    function stripTrackers(url) {
        try {
            let parsedUrl = new URL(url);
            let params = parsedUrl.searchParams;
            let paramsToDelete = [];
            params.forEach((value, key) => {
                if (key.startsWith('utm_') || key === 'fbclid' || key === 'gclid' /* Add more if needed */) {
                    paramsToDelete.push(key);
                }
            });
            paramsToDelete.forEach(key => params.delete(key));
            return parsedUrl.toString();
        } catch (e) {
            // If it's not a valid URL (e.g., just search terms), return original
            return url;
        }
    }

    window.performSearch = function() { // Make global for onclick
        let query = searchInput.value.trim();
        if (!query) return;

        let destinationUrl;
        const bangMatch = query.match(/^(!\w+)\s?(.*)?/);

        if (bangMatch) {
            const [full, bang, rest = ''] = bangMatch;
            if (bangs[bang]) {
                destinationUrl = bangs[bang].replace('%s', encodeURIComponent(rest));
            }
        }
        
        // Default search if no bang matched or no bang used
        if (!destinationUrl) {
             destinationUrl = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
        }

        // Strip trackers if enabled
        if (stripTrackersCheckbox.checked) {
            destinationUrl = stripTrackers(destinationUrl);
        }

        window.location.href = destinationUrl;
    }

    window.imFeelingLucky = function() { // Make global for onclick
        let query = searchInput.value.trim();
        if (!query) return;

        // Check for bangs first - Lucky should execute the bang directly
        const bangMatch = query.match(/^(!\w+)\s?(.*)?/);
        if (bangMatch) {
            const [full, bang, rest = ''] = bangMatch;
            if (bangs[bang]) {
                 let destinationUrl = bangs[bang].replace('%s', encodeURIComponent(rest));
                 if (stripTrackersCheckbox.checked) {
                    destinationUrl = stripTrackers(destinationUrl);
                 }
                 window.location.href = destinationUrl;
                return; // Don't proceed to Google Lucky
            }
        }
        
        // Use Google's I'm Feeling Lucky if no bang matched
        // Note: Browser security might sometimes block direct navigation from btnI
        let luckyUrl = `https://www.google.com/search?q=${encodeURIComponent(query)}&btnI=I%27m+Feeling+Lucky`;
        // No tracker stripping here as btnI handles redirection server-side
        window.location.href = luckyUrl;
    }

    // --- Event Listeners ---
    searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            performSearch();
        }
    });

    // --- Initialization ---
    loadSettings(); // Load settings when page loads

    // --- Handle URL parameters (e.g., if used as browser search engine) ---
    function handleUrlParams() {
        const urlParams = new URLSearchParams(window.location.search);
        const queryParam = urlParams.get('q');
        if (queryParam) {
            searchInput.value = queryParam;
            performSearch(); // Automatically search if 'q' parameter is present
        }
    }
    handleUrlParams();

});