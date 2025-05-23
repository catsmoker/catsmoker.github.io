document.addEventListener('DOMContentLoaded', () => {
    // --- Search Engines Configuration ---
    const searchEngines = [
        {
            id: 'google',
            name: 'Google',
            searchUrl: 'https://www.google.com/search?q=%s',
            luckyUrl: 'https://www.google.com/search?q=%s&btnI=I%27m+Feeling+Lucky',
            logoUrl: 'https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png',
            settingsLogoUrl: 'https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png'
        },
        {
            id: 'duckduckgo',
            name: 'DuckDuckGo',
            searchUrl: 'https://duckduckgo.com/?q=%s',
            logoUrl: 'https://images.seeklogo.com/logo-png/31/1/duckduckgo-logo-png_seeklogo-314219.png',
            settingsLogoUrl: 'https://duckduckgo.com/assets/logo_header.v109.svg'
        },
        {
            id: 'bing',
            name: 'Bing',
            searchUrl: 'https://www.bing.com/search?q=%s',
            logoUrl: 'https://upload.wikimedia.org/wikipedia/commons/thumb/c/c7/Bing_logo_%282016%29.svg/1000px-Bing_logo_%282016%29.svg.png',
            settingsLogoUrl: 'https://upload.wikimedia.org/wikipedia/commons/thumb/c/c7/Bing_logo_%282016%29.svg/300px-Bing_logo_%282016%29.svg.png'
        },
        {
            id: 'yahoo',
            name: 'Yahoo',
            searchUrl: 'https://search.yahoo.com/search?p=%s',
            logoUrl: 'https://s.yimg.com/pv/static/img/Yahoo_logo-202409020747.svg',
            settingsLogoUrl: 'https://s.yimg.com/pv/static/img/Yahoo_logo-202409020747.svg'
        },
        {
            id: 'brave',
            name: 'Brave Search',
            searchUrl: 'https://search.brave.com/search?q=%s',
            logoUrl: 'https://cdn.search.brave.com/serp/v3/_app/immutable/assets/brave-logo-light.BR9nBcVE.svg',
            settingsLogoUrl: 'https://brave.com/static-assets/images/brave-logo-sans-text.svg'
        },
        {
            id: 'yandex',
            name: 'yandex Search',
            searchUrl: 'https://yandex.com/search?text=%s',
            logoUrl: 'https://cdn-images-1.medium.com/v2/resize:fill:1600:480/gravity:fp:0.5:0.4/1*E0iLZoYH7JqSYRWuBmYlQA.png',
            settingsLogoUrl: 'https://cdn-images-1.medium.com/v2/resize:fill:1600:480/gravity:fp:0.5:0.4/1*E0iLZoYH7JqSYRWuBmYlQA.png'
        },
    ];
    let currentSearchEngineId = 'google'; // Default

    // --- Enhanced !bang database ---
    let bangs = {
        "!yt": "https://www.youtube.com/results?search_query=%s",
        "!w": "https://en.wikipedia.org/wiki/Special:Search/%s",
        "!gh": "https://github.com/search?q=%s",
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
    };

    const searchInput = document.getElementById('search');
    const settingsPanel = document.getElementById('settings-panel');
    const stripTrackersCheckbox = document.getElementById('strip-trackers');
    const customBangInput = document.getElementById('custom-bang');
    const customUrlInput = document.getElementById('custom-url');
    const customBangListDiv = document.getElementById('custom-bang-list');
    const mainPageLogo = document.getElementById('main-page-logo');
    const searchEngineSelectorDiv = document.getElementById('search-engine-selector');

    // --- Search Engine Selection ---
    function renderSearchEngineSelector() {
        if (!searchEngineSelectorDiv) return;
        searchEngineSelectorDiv.innerHTML = ''; // Clear existing options

        searchEngines.forEach(engine => {
            const optionDiv = document.createElement('div');
            optionDiv.className = 'engine-option';
            optionDiv.dataset.engineId = engine.id;

            const radioInput = document.createElement('input');
            radioInput.type = 'radio';
            radioInput.name = 'search_engine_pref';
            radioInput.id = `engine_radio_${engine.id}`;
            radioInput.value = engine.id;
            if (engine.id === currentSearchEngineId) {
                radioInput.checked = true;
                optionDiv.classList.add('selected');
            }

            const label = document.createElement('label');
            label.htmlFor = `engine_radio_${engine.id}`;
            
            const logoImg = document.createElement('img');
            logoImg.src = engine.settingsLogoUrl || engine.logoUrl; // Fallback to main logo if settingsLogo is not defined
            logoImg.alt = `${engine.name} logo`;
            
            const nameSpan = document.createElement('span');
            nameSpan.textContent = engine.name;

            label.appendChild(logoImg);
            label.appendChild(nameSpan);
            optionDiv.appendChild(radioInput);
            optionDiv.appendChild(label);
            
            optionDiv.addEventListener('click', () => {
                selectSearchEngine(engine.id);
            });

            searchEngineSelectorDiv.appendChild(optionDiv);
        });
    }
    
    function updateMainLogoAndDefault() {
        const selectedEngine = searchEngines.find(se => se.id === currentSearchEngineId);
        if (selectedEngine && mainPageLogo) {
            mainPageLogo.src = selectedEngine.logoUrl;
            mainPageLogo.alt = `${selectedEngine.name} Search`;
        }
        // Visually update selected state in the selector
        document.querySelectorAll('.engine-option').forEach(opt => {
            opt.classList.toggle('selected', opt.dataset.engineId === currentSearchEngineId);
            const radio = opt.querySelector('input[type="radio"]');
            if (radio) radio.checked = opt.dataset.engineId === currentSearchEngineId;
        });
    }

    window.selectSearchEngine = function(engineId) { 
        currentSearchEngineId = engineId;
        localStorage.setItem('search-engine-preference', engineId);
        updateMainLogoAndDefault();
    }


    // --- Load saved settings ---
    function loadSettings() {
        // Tracker stripping
        if (stripTrackersCheckbox) {
            stripTrackersCheckbox.checked = localStorage.getItem('search-strip-trackers') === 'true';
        }

        // Search Engine Preference
        const savedEngineId = localStorage.getItem('search-engine-preference');
        if (savedEngineId && searchEngines.some(se => se.id === savedEngineId)) {
            currentSearchEngineId = savedEngineId;
        }
        updateMainLogoAndDefault(); 
        renderSearchEngineSelector(); 

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
        renderCustomBangs();
    }

    // --- Tracker Stripping Setting ---
    if (stripTrackersCheckbox) {
        stripTrackersCheckbox.addEventListener('change', (e) => {
            localStorage.setItem('search-strip-trackers', e.target.checked);
        });
    }

    // --- Settings Panel Toggle ---
    window.toggleSettings = function() {
        if (settingsPanel) {
            const isHidden = settingsPanel.style.display === 'none' || settingsPanel.style.display === '';
            settingsPanel.style.display = isHidden ? 'block' : 'none';
        }
    }

    // --- Custom Bang Management ---
    function renderCustomBangs() {
        if (!customBangListDiv) return;
        customBangListDiv.innerHTML = '';
        Object.entries(bangs).forEach(([bang, url]) => {
            if (localStorage.getItem(`bang:${bang}`)) {
                const item = document.createElement('div');
                item.className = 'custom-bang-item';
                item.innerHTML = `
                    <span><strong>${bang}</strong> → ${url.length > 40 ? url.substring(0, 37) + '...' : url}</span>
                    <button class="remove-bang-btn" data-bang="${bang}" title="Remove bang">×</button>
                `;
                customBangListDiv.appendChild(item);
            }
        });

        customBangListDiv.querySelectorAll('.remove-bang-btn').forEach(button => {
            button.addEventListener('click', removeCustomBang);
        });
    }

    function removeCustomBang(event) {
        const bangToRemove = event.target.getAttribute('data-bang');
        if (bangToRemove && bangs[bangToRemove] && localStorage.getItem(`bang:${bangToRemove}`)) {
            delete bangs[bangToRemove];
            localStorage.removeItem(`bang:${bangToRemove}`);
            renderCustomBangs();
        }
    }

    window.saveCustomBang = function() {
        if (!customBangInput || !customUrlInput) return;
        const bang = customBangInput.value.trim();
        const url = customUrlInput.value.trim();

        if (!bang.startsWith('!')) {
             alert('Custom bang must start with !');
             return;
        }
        if (bangs[bang] && !localStorage.getItem(`bang:${bang}`)) {
            alert(`Cannot overwrite built-in bang: ${bang}. Choose a different name.`);
            return;
        }
        if (!url || !url.includes('%s')) {
             alert('URL must include %s as a placeholder for the search query.');
             return;
        }
        if(bang && url) {
            bangs[bang] = url;
            localStorage.setItem(`bang:${bang}`, url);
            renderCustomBangs(); 
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
            const trackerParams = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'fbclid', 'gclid', 'msclkid', 'mc_eid', '_hsenc', 'vero_conv', 'hsCtaTracking'];
            params.forEach((value, key) => {
                if (trackerParams.some(tracker => key.toLowerCase().startsWith(tracker.replace('_', '')) || key.toLowerCase() === tracker)) {
                    paramsToDelete.push(key);
                }
            });
            paramsToDelete.forEach(key => params.delete(key));
            return parsedUrl.toString();
        } catch (e) {
            return url;
        }
    }

    window.performSearch = function() {
        if (!searchInput) return;
        let query = searchInput.value.trim();
        if (!query) return;

        let destinationUrl;
        const bangMatch = query.match(/^(!\w+)\s?(.*)?/);

        if (bangMatch) {
            const [full, bang, rest = ''] = bangMatch;
            if (bangs[bang]) {
                destinationUrl = bangs[bang].replace('%s', encodeURIComponent(rest.trim()));
            }
        }
        
        if (!destinationUrl) {
             const selectedEngine = searchEngines.find(se => se.id === currentSearchEngineId) || searchEngines[0];
             destinationUrl = selectedEngine.searchUrl.replace('%s', encodeURIComponent(query));
        }

        if (stripTrackersCheckbox && stripTrackersCheckbox.checked) {
            destinationUrl = stripTrackers(destinationUrl);
        }
        window.location.href = destinationUrl;
    }

    window.imFeelingLucky = function() {
        // Navigate to the specified static URL
        window.location.href = 'https://catsmoker.github.io';
    }

    // --- Event Listeners ---
    if (searchInput) {
        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                performSearch();
            }
        });
    }

    // --- Initialization ---
    loadSettings(); 

    // --- Handle URL parameters (e.g., if used as browser search engine) ---
    function handleUrlParams() {
        const urlParams = new URLSearchParams(window.location.search);
        const queryParam = urlParams.get('q');
        if (queryParam && searchInput) {
            searchInput.value = queryParam;
            performSearch(); 
        }
    }
    handleUrlParams();
});
