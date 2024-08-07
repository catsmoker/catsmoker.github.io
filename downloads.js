function filterLinks() {
    const searchTerm = document.getElementById('searchBox').value.toLowerCase();
    const sections = document.querySelectorAll('.card-container');

    sections.forEach(section => {
        const title = section.querySelector('h2').textContent.toLowerCase();
        if (title.includes(searchTerm)) {
            section.style.display = '';
        } else {
            section.style.display = 'none';
        }
    });
}
