document.addEventListener("DOMContentLoaded", function () {
    // Smooth scroll for internal links
    document.querySelectorAll('a.nav-link[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();

            document.querySelector(this.getAttribute('href')).scrollIntoView({
                behavior: 'smooth'
            });
        });
    });

    // Collapse the navbar after clicking on a link (for mobile view)
    document.querySelectorAll('.navbar-nav .nav-link').forEach(link => {
        link.addEventListener('click', function () {
            const navbarToggler = document.querySelector('.navbar-toggler');
            const navbarCollapse = document.querySelector('.navbar-collapse');
            if (navbarToggler && window.getComputedStyle(navbarToggler).display !== 'none') {
                navbarCollapse.classList.remove('show');
            }
        });
    });

    // Highlight active menu item on scroll
    const sections = document.querySelectorAll('section[id]');
    const navLi = document.querySelectorAll('.navbar-nav .nav-item .nav-link');

    window.addEventListener('scroll', () => {
        let current = '';

        sections.forEach(section => {
            const sectionTop = section.offsetTop;
            if (scrollY >= sectionTop - 60) {  // offset to highlight a bit before reaching the section
                current = section.getAttribute('id');
            }
        });

        navLi.forEach(li => {
            li.classList.remove('active');
            if (li.getAttribute('href').includes(current)) {
                li.classList.add('active');
            }
        });
    });
});


