document.addEventListener('DOMContentLoaded', function() {
  // Audio element and settings
  const audio = document.getElementById('background-music');
  audio.volume = 0.3; // Default volume (30%)
  
  // Immediately try to autoplay (will fail without user interaction)
  const tryAutoplay = () => {
    audio.play()
      .then(() => {
        console.log("Audio autoplay successful");
        localStorage.setItem('audioAllowed', 'true');
        localStorage.setItem('audioPlaying', 'true');
      })
      .catch(e => {
        console.log("Autoplay blocked, waiting for user interaction");
        setupInteractionListeners();
      });
  };
  
  tryAutoplay();
  
  // Setup interaction listeners if autoplay fails
  const setupInteractionListeners = () => {
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
    
    document.addEventListener('click', handleUserInteraction, { once: true });
    document.addEventListener('keydown', handleUserInteraction, { once: true });
    document.addEventListener('scroll', handleUserInteraction, { once: true });
    document.addEventListener('touchstart', handleUserInteraction, { once: true });
  };
  
  // Create stylish audio controls UI
  function createAudioControls() {
    const controlsContainer = document.createElement('div');
    controlsContainer.className = 'audio-controls';
    controlsContainer.innerHTML = `
      <button id="audio-toggle" aria-label="Toggle music" class="music-toggle-btn">
        <span class="music-icon">
          <svg class="sound-on" viewBox="0 0 24 24">
            <path fill="currentColor" d="M14,3.23V5.29C16.89,6.15 19,8.83 19,12C19,15.17 16.89,17.84 14,18.7V20.77C18,19.86 21,16.28 21,12C21,7.72 18,4.14 14,3.23M16.5,12C16.5,10.23 15.5,8.71 14,7.97V16C15.5,15.29 16.5,13.76 16.5,12M3,9V15H7L12,20V4L7,9H3Z"/>
          </svg>
          <svg class="sound-off" viewBox="0 0 24 24">
            <path fill="currentColor" d="M12,4L9.91,6.09L12,8.18M4.27,3L3,4.27L7.73,9H3V15H7L12,20V13.27L16.25,17.53C15.58,18.04 14.83,18.46 14,18.7V20.77C15.38,20.45 16.63,19.82 17.68,18.96L19.73,21L21,19.73L12,10.73M19,12C19,12.94 18.8,13.82 18.46,14.64L19.97,16.15C20.62,14.91 21,13.5 21,12C21,7.72 18,4.14 14,3.23V5.29C16.89,6.15 19,8.83 19,12M16.5,12C16.5,10.23 15.5,8.71 14,7.97V10.18L16.45,12.63C16.5,12.43 16.5,12.21 16.5,12Z"/>
          </svg>
        </span>
        <span class="music-pulse"></span>
      </button>
      <div class="volume-container">
        <input type="range" id="audio-volume" min="0" max="1" step="0.1" 
               value="${audio.volume}" aria-label="Music volume" class="volume-slider">
      </div>
    `;
    
    document.body.appendChild(controlsContainer);
    
    // Add CSS styles for the controls
    const style = document.createElement('style');
    style.textContent = `
.audio-controls {
  position: fixed;
  bottom: 20px;
  right: 20px;
  display: flex;
  align-items: center;
  z-index: 1000;
  background: rgba(0,0,0,0.7);
  padding: 8px;
  border-radius: 30px;
  backdrop-filter: blur(10px);
  box-shadow: 0 4px 15px rgba(0,0,0,0.2);
  transition: all 0.3s ease;
  width: 40px;
  height: 40px;
  justify-content: center;
  overflow: hidden;
}

.audio-controls:hover {
  width: 160px;
  background: rgba(0,0,0,0.8);
  justify-content: flex-start;
}

.audio-controls:hover .volume-container {
  opacity: 1;
  width: 100px;
}

.music-toggle-btn {
  background: none;
  border: none;
  width: 40px;
  height: 40px;
  border-radius: 50%;
  cursor: pointer;
  position: relative;
  padding: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  margin: 0;
}

.music-icon {
  width: 24px;
  height: 24px;
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
}

.music-icon svg {
  position: absolute;
  width: 100%;
  height: 100%;
  fill: white;
  transition: all 0.3s ease;
}

.sound-off {
  opacity: 0;
  transform: scale(0.8);
}

.sound-on {
  opacity: 1;
  transform: scale(1);
}

.music-toggle-btn.muted .sound-off {
  opacity: 1;
  transform: scale(1);
}

.music-toggle-btn.muted .sound-on {
  opacity: 0;
  transform: scale(0.8);
}

.music-pulse {
  position: absolute;
  width: 100%;
  height: 100%;
  border-radius: 50%;
  background: rgba(255,255,255,0.1);
  transform: scale(0.8);
  opacity: 0;
  transition: all 0.3s ease;
}

.music-toggle-btn:not(.muted) .music-pulse {
  animation: pulse 2s infinite;
}

@keyframes pulse {
  0% {
    transform: scale(0.8);
    opacity: 0.7;
  }
  70% {
    transform: scale(1.2);
    opacity: 0;
  }
  100% {
    transform: scale(0.8);
    opacity: 0;
  }
}

.volume-container {
  width: 0;
  opacity: 0;
  padding-left: 8px;
  transition: all 0.3s ease;
  overflow: hidden;
}

.volume-slider {
  width: 100%;
  height: 6px;
  -webkit-appearance: none;
  background: rgba(255,255,255,0.2);
  border-radius: 3px;
  outline: none;
}

.volume-slider::-webkit-slider-thumb {
  -webkit-appearance: none;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: white;
  cursor: pointer;
  transition: all 0.2s ease;
}

.volume-slider::-webkit-slider-thumb:hover {
  transform: scale(1.1);
  background: #4CAF50;
}
    `;
    document.head.appendChild(style);
    
    // Toggle button functionality
    const toggleBtn = document.getElementById('audio-toggle');
    
    const updateButtonState = () => {
      if (audio.muted || audio.paused) {
        toggleBtn.classList.add('muted');
        toggleBtn.querySelector('.music-pulse').style.animation = 'none';
      } else {
        toggleBtn.classList.remove('muted');
        toggleBtn.querySelector('.music-pulse').style.animation = 'pulse 2s infinite';
      }
    };
    
    toggleBtn.addEventListener('click', () => {
      audio.muted = !audio.muted;
      localStorage.setItem('audioPlaying', String(!audio.muted));
      updateButtonState();
      
      // If unmuted and paused, try to play
      if (!audio.muted && audio.paused) {
        audio.play().catch(e => console.log("Playback error:", e));
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
        updateButtonState();
      }
    });
    
    // Load saved volume if exists
    const savedVolume = localStorage.getItem('audioVolume');
    if (savedVolume) {
      audio.volume = parseFloat(savedVolume);
      volumeControl.value = savedVolume;
    }
    
    // Set initial button state
    updateButtonState();
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
