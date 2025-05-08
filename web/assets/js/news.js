// news.js - Page specific JS for news.html

document.addEventListener('DOMContentLoaded', () => {
    // --- RSS Feed Logic (from previous combined script) ---
    const CORS_PROXY_NEWS = "https://api.allorigins.win/get?url=";
    let currentFeedNews = "http://rss.cnn.com/rss/cnn_tech.rss"; // Default

    const newsContainer = document.getElementById('rss-feed-container');
    const feedSelectorNews = document.getElementById('feed-selector');
    const refreshBtnNews = document.getElementById('refresh-btn');

    async function loadRSSFeed(feedUrl = currentFeedNews) {
        if (!newsContainer) return; // Exit if container not found

        newsContainer.innerHTML = '<div class="loading-news"><i class="fas fa-spinner fa-spin"></i> Loading news...</div>';
        try {
            const response = await fetch(`${CORS_PROXY_NEWS}${encodeURIComponent(feedUrl)}`);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();

            if (!data.contents) {
                // Handle cases where allorigins might fail or return unexpected structure
                throw new Error('Failed to fetch feed content via proxy.');
            }

            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(data.contents, "text/xml");

            // Check for parser errors
            const parserError = xmlDoc.querySelector("parsererror");
            if (parserError) {
                console.error("XML Parsing Error:", parserError.textContent);
                throw new Error('Failed to parse RSS feed.');
            }
            
            const items = xmlDoc.querySelectorAll("item");
            if (items.length === 0) {
                 // Also check channel > item for feeds structured that way
                 const channelItems = xmlDoc.querySelectorAll("channel > item");
                 if(channelItems.length > 0) {
                    items = channelItems;
                 } else {
                    newsContainer.innerHTML = '<div class="error-news">No articles found in this feed.</div>';
                    return;
                 }
            }

            let html = '';
            
            Array.from(items).slice(0, 15).forEach(item => { // Show up to 15 items
                const title = item.querySelector("title")?.textContent?.trim() || 'No title';
                const linkElement = item.querySelector("link");
                // Handle different ways links might appear (text content vs. href attribute)
                let link = '#';
                if (linkElement) {
                   link = linkElement.textContent?.trim() || linkElement.getAttribute('href') || '#';
                }
                
                // Attempt to get a better description, handle CDATA
                let description = 'No description available.';
                const descriptionNode = item.querySelector("description");
                if (descriptionNode) {
                    description = descriptionNode.textContent?.trim() || '';
                    // Basic HTML tag stripping (consider a more robust library if needed)
                    description = description.replace(/<[^>]*>/g, ' '); 
                    description = description.replace(/\s+/g, ' ').trim(); // Clean up whitespace
                }
                
                const pubDateStr = item.querySelector("pubDate")?.textContent;
                const pubDate = pubDateStr ? new Date(pubDateStr).toLocaleDateString() : 'No date';
                
                html += `
                    <div class="rss-item">
                    <h3><a href="${link}" target="_blank" rel="noopener noreferrer">${title}</a></h3>
                    <div class="rss-description">${description.substring(0, 150)}${description.length > 150 ? '...' : ''}</div>
                    <div class="rss-meta">
                        <span class="rss-date">${pubDate}</span>
                        <a href="${link}" target="_blank" rel="noopener noreferrer" class="rss-read-more">Read more <i class="fas fa-arrow-right"></i></a>
                    </div>
                    </div>
                `;
            });
            newsContainer.innerHTML = html || '<div class="error-news">No articles found.</div>';
        } catch (err) {
            console.error("RSS Error:", err);
            newsContainer.innerHTML = `<div class="error-news">Failed to load news feed. ${err.message}</div>`;
        }
    }

    if (feedSelectorNews) {
        currentFeedNews = feedSelectorNews.value; // Initialize with selected value
        feedSelectorNews.addEventListener('change', (e) => {
            currentFeedNews = e.target.value;
            loadRSSFeed(currentFeedNews);
        });
    }
    if (refreshBtnNews) {
        refreshBtnNews.addEventListener('click', () => loadRSSFeed());
    }
    
    loadRSSFeed(); // Initial load
});