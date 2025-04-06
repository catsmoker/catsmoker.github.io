document.addEventListener('DOMContentLoaded', function() {
    const seeMoreButtons = document.querySelectorAll('.see-more-btn');
    
    seeMoreButtons.forEach(button => {
      button.addEventListener('click', function() {
        const section = this.getAttribute('data-section');
        
        if (section === 'long-form') {
          const moreVideos = document.querySelector('.more-videos');
          if (moreVideos.style.display === 'none' || !moreVideos.style.display) {
            moreVideos.style.display = 'grid';
            this.textContent = 'Show Less';
          } else {
            moreVideos.style.display = 'none';
            this.textContent = 'Show More';
          }
        }
        else if (section === 'short-form') {
          const moreShorts = document.querySelector('.more-shorts');
          if (moreShorts.style.display === 'none' || !moreShorts.style.display) {
            moreShorts.style.display = 'grid';
            this.textContent = 'Show Less';
          } else {
            moreShorts.style.display = 'none';
            this.textContent = 'Show More';
          }
        }
        
        // Smooth scroll to maintain position
        this.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      });
    });
  });