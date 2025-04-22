    // Only run custom cursor logic on screens wider than 767px
    if (window.innerWidth >= 767) {
      const cursorDot = document.querySelector('.cursor-dot');
      const cursorOutline = document.querySelector('.cursor-dot-outline');

      // Update cursor position on mouse move
      document.addEventListener('mousemove', (e) => {
        const x = e.clientX;
        const y = e.clientY;
        cursorDot.style.transform = `translate(${x}px, ${y}px) translate(-50%, -50%)`;
        cursorOutline.style.transform = `translate(${x}px, ${y}px) translate(-50%, -50%)`;
      });

      // Add hover effect for links
      document.querySelectorAll('a').forEach(link => {
        link.addEventListener('mouseenter', () => {
          cursorOutline.classList.add('hovered');
        });
        link.addEventListener('mouseleave', () => {
          cursorOutline.classList.remove('hovered');
        });
      });

      // Optional: Hide cursor when leaving the window
      document.addEventListener('mouseleave', () => {
        cursorDot.style.opacity = '0';
        cursorOutline.style.opacity = '0';
      });

      // Restore cursor when re-entering the window
      document.addEventListener('mouseenter', () => {
        cursorDot.style.opacity = '1';
        cursorOutline.style.opacity = '1';
      });
	  
	    document.addEventListener('mousedown', () => {
      cursorOutline.style.transform += ' scale(0.8)';
      setTimeout(() => {
      cursorOutline.style.transform = cursorOutline.style.transform.replace(' scale(0.8)', '');
      }, 100);
      });
      
      }
