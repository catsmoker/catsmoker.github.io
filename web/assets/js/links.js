document.addEventListener('DOMContentLoaded', function() {
  // Use event delegation for show more buttons
  document.addEventListener('click', function(e) {
    if (e.target.matches('.see-more-btn')) {
      const section = e.target.getAttribute('data-section');
      let contentToToggle;
      
      if (section === 'long-form') {
        contentToToggle = document.querySelector('.more-videos');
      } 
      else if (section === 'short-form') {
        contentToToggle = document.querySelector('.more-shorts');
      }
      
      if (contentToToggle) {
        const isHidden = contentToToggle.style.display === 'none' || 
                        !contentToToggle.style.display;
        
        contentToToggle.style.display = isHidden ? 'grid' : 'none';
        e.target.textContent = isHidden ? 'Show Less' : 'Show More';
        
        // Smooth scroll to maintain position
        e.target.scrollIntoView({
          behavior: 'smooth',
          block: 'nearest'
        });
      }
    }
  });

  // Audio element and settings
  const audio = document.getElementById('background-music');
  audio.volume = 0.3; // Default volume (30%)
  
  // Check user's previous audio preference
  const audioAllowed = localStorage.getItem('audioAllowed') === 'true';
  const audioWasPlaying = localStorage.getItem('audioPlaying') === 'true';
  
  // Play music if previously allowed and playing
  if (audioAllowed && audioWasPlaying) {
    audio.play().catch(e => {
      console.log("Autoplay blocked, waiting for user interaction");
    });
  }
  
  // Handle first user interaction
  const handleUserInteraction = () => {
    // Set preferences
    localStorage.setItem('audioAllowed', 'true');
    localStorage.setItem('audioPlaying', 'true');
    
    // Try to play audio
    audio.play().then(() => {
      console.log("Audio started after user interaction");
    }).catch(e => {
      console.error("Audio playback error:", e);
    });
    
    // Remove event listeners after first interaction
    document.removeEventListener('click', handleUserInteraction);
    document.removeEventListener('keydown', handleUserInteraction);
    document.removeEventListener('scroll', handleUserInteraction);
    document.removeEventListener('touchstart', handleUserInteraction);
  };
  
  // Add multiple interaction listeners if audio wasn't previously allowed
  if (!audioAllowed) {
    document.addEventListener('click', handleUserInteraction, { once: true });
    document.addEventListener('keydown', handleUserInteraction, { once: true });
    document.addEventListener('scroll', handleUserInteraction, { once: true });
    document.addEventListener('touchstart', handleUserInteraction, { once: true });
  }
  
  // Create audio controls UI
  function createAudioControls() {
    const controlsContainer = document.createElement('div');
    controlsContainer.className = 'audio-controls';
    controlsContainer.innerHTML = `
      <button id="audio-toggle" aria-label="Toggle music">
        <i class="fas fa-volume-up"></i>
      </button>
      <input type="range" id="audio-volume" min="0" max="1" step="0.1" 
             value="${audio.volume}" aria-label="Music volume">
    `;
    
    // Style the controls (you can also put this in your CSS)
    controlsContainer.style.position = 'fixed';
    controlsContainer.style.bottom = '20px';
    controlsContainer.style.right = '20px';
    controlsContainer.style.display = 'flex';
    controlsContainer.style.gap = '10px';
    controlsContainer.style.alignItems = 'center';
    controlsContainer.style.zIndex = '1000';
    controlsContainer.style.background = 'rgba(0,0,0,0.7)';
    controlsContainer.style.padding = '10px';
    controlsContainer.style.borderRadius = '20px';
    
    document.body.appendChild(controlsContainer);
    
    // Toggle button functionality
    const toggleBtn = document.getElementById('audio-toggle');
    toggleBtn.addEventListener('click', () => {
      audio.muted = !audio.muted;
      localStorage.setItem('audioPlaying', String(!audio.muted));
      
      if (audio.muted) {
        toggleBtn.innerHTML = '<i class="fas fa-volume-mute"></i>';
      } else {
        toggleBtn.innerHTML = '<i class="fas fa-volume-up"></i>';
        // If unmuted and paused, try to play
        if (audio.paused) {
          audio.play().catch(e => console.log("Playback error:", e));
        }
      }
    });
    
    // Volume control functionality
    const volumeControl = document.getElementById('audio-volume');
    volumeControl.addEventListener('input', (e) => {
      audio.volume = e.target.value;
      localStorage.setItem('audioVolume', e.target.value);
      
      // If volume was 0 and is increased, unmute
      if (audio.volume > 0 && audio.muted) {
        audio.muted = false;
        toggleBtn.innerHTML = '<i class="fas fa-volume-up"></i>';
      }
    });
    
    // Load saved volume if exists
    const savedVolume = localStorage.getItem('audioVolume');
    if (savedVolume) {
      audio.volume = parseFloat(savedVolume);
      volumeControl.value = savedVolume;
    }
    
    // Set initial button state
    if (audio.muted || audio.paused) {
      toggleBtn.innerHTML = '<i class="fas fa-volume-mute"></i>';
    }
  }
  
  // Create the audio controls
  createAudioControls();
  
  // Handle page visibility changes
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      // Page is hidden, pause audio
      audio.pause();
    } else if (localStorage.getItem('audioPlaying') === 'true' && !audio.muted) {
      // Page is visible again, resume if was playing
      audio.play().catch(e => console.log("Resume error:", e));
    }
  });
});
