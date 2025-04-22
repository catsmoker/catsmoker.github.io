document.addEventListener('DOMContentLoaded', function() {
  // Constants for class names and attributes
  const SELECTORS = {
    showMoreBtn: '.see-more-btn',
    longFormContent: '.more-videos',
    shortFormContent: '.more-shorts'
  };
  
  const DATA_ATTRS = {
    section: 'data-section'
  };
  
  const TEXT = {
    showMore: 'Show More',
    showLess: 'Show Less'
  };
  
  // Animation timing
  const ANIMATION = {
    duration: 300,
    easing: 'ease-in-out'
  };

  // Handle show more/less functionality
  document.addEventListener('click', function(e) {
    const showMoreBtn = e.target.closest(SELECTORS.showMoreBtn);
    if (!showMoreBtn) return;

    const section = showMoreBtn.getAttribute(DATA_ATTRS.section);
    let contentToToggle;

    switch (section) {
      case 'long-form':
        contentToToggle = document.querySelector(SELECTORS.longFormContent);
        break;
      case 'short-form':
        contentToToggle = document.querySelector(SELECTORS.shortFormContent);
        break;
      default:
        console.warn(`Unknown section: ${section}`);
        return;
    }

    if (!contentToToggle) {
      console.warn(`No content found for section: ${section}`);
      return;
    }

    toggleContent(contentToToggle, showMoreBtn);
  });

  /**
   * Toggles content visibility with animation and updates button text
   * @param {HTMLElement} content - The element to show/hide
   * @param {HTMLElement} button - The button that triggers the toggle
   */
  function toggleContent(content, button) {
    const isHidden = content.style.maxHeight === '0px' || 
                     !content.style.maxHeight;
    
    if (isHidden) {
      // Show content
      content.style.display = 'grid';
      content.style.overflow = 'hidden';
      content.style.maxHeight = '0';
      
      // Animate height
      const fullHeight = content.scrollHeight + 'px';
      
      content.animate(
        [{ maxHeight: '0' }, { maxHeight: fullHeight }],
        { duration: ANIMATION.duration, easing: ANIMATION.easing }
      ).onfinish = () => {
        content.style.maxHeight = 'none';
      };
      
      button.textContent = TEXT.showLess;
    } else {
      // Hide content with animation
      const contentClone = content.cloneNode(true);
      contentClone.style.position = 'absolute';
      contentClone.style.visibility = 'hidden';
      contentClone.style.maxHeight = 'none';
      document.body.appendChild(contentClone);
      
      const fullHeight = contentClone.scrollHeight + 'px';
      document.body.removeChild(contentClone);
      
      content.style.maxHeight = fullHeight;
      
      content.animate(
        [{ maxHeight: fullHeight }, { maxHeight: '0' }],
        { duration: ANIMATION.duration, easing: ANIMATION.easing }
      ).onfinish = () => {
        content.style.display = 'none';
        content.style.maxHeight = '';
      };
      
      button.textContent = TEXT.showMore;
    }

    // Smooth scroll to maintain position
    button.scrollIntoView({
      behavior: 'smooth',
      block: 'nearest',
      inline: 'nearest'
    });
  }
});
