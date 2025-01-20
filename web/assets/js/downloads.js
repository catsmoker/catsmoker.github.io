function filterLinks() {
    const searchTerm = document.getElementById('searchBox').value.toLowerCase();
    const sections = document.querySelectorAll('.card-container');

    sections.forEach(section => {
        const title = section.querySelector('h2').textContent.toLowerCase();
        if (searchTerm === '' || title.includes(searchTerm)) {
            section.classList.remove('hidden');
        } else {
            section.classList.add('hidden');
        }
    });
}

window.tailwind.config = {
    darkMode: 'class', // Use 'class' for dark mode
    theme: {
        extend: {
            colors: {
                border: 'hsl(var(--border))',
                input: 'hsl(var(--input))',
                ring: 'hsl(var(--ring))',
                background: 'hsl(var(--background))',
                foreground: 'hsl(var(--foreground))',
                primary: {
                    DEFAULT: 'hsl(var(--primary))',
                    foreground: 'hsl(var(--primary-foreground))'
                },
                secondary: {
                    DEFAULT: 'hsl(var(--secondary))',
                    foreground: 'hsl(var(--secondary-foreground))'
                },
                destructive: {
                    DEFAULT: 'hsl(var(--destructive))',
                    foreground: 'hsl(var(--destructive-foreground))'
                },
                muted: {
                    DEFAULT: 'hsl(var(--muted))',
                    foreground: 'hsl(var(--muted-foreground))'
                },
                accent: {
                    DEFAULT: 'hsl(var(--accent))',
                    foreground: 'hsl(var(--accent-foreground))'
                },
                popover: {
                    DEFAULT: 'hsl(var(--popover))',
                    foreground: 'hsl(var(--popover-foreground))'
                },
                card: {
                    DEFAULT: 'hsl(var(--card))',
                    foreground: 'hsl(var(--card-foreground))'
                },
            },
        },
    },
};


// Debounce function to limit the rate at which `filterLinks` is called
function debounce(func, wait) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

const debouncedFilterLinks = debounce(filterLinks, 300);

document.getElementById('searchBox').addEventListener('input', debouncedFilterLinks);

document.getElementById('gohome').addEventListener('click', function() {
    window.location.href = 'https://catsmoker.github.io'; // Navigate to the home page
});

document.getElementById('darkModeToggle').addEventListener('click', function() {
    document.body.classList.toggle('dark');
});
