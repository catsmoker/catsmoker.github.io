// home.js

document.addEventListener('DOMContentLoaded', function () {
    // --- Mobile Navigation Toggle ---
    const mobileNavToggle = document.getElementById('mobileNavToggle');
    const navLinksContainer = document.querySelector('.top-navigation .nav-links');
    if (mobileNavToggle && navLinksContainer) {
        mobileNavToggle.addEventListener('click', () => {
            navLinksContainer.classList.toggle('active');
        });
        document.addEventListener('click', function (event) {
            const isClickInsideNav = navLinksContainer.contains(event.target);
            const isClickOnToggler = mobileNavToggle.contains(event.target);
            if (!isClickInsideNav && !isClickOnToggler && navLinksContainer.classList.contains('active')) {
                navLinksContainer.classList.remove('active');
            }
        });
    }

    // --- Typing Animation ---
    const typingTextSpan = document.querySelector('.profile .typing-text span');
    if (typingTextSpan) {
        const words = [
            "Designer", "Developer", "Editor", "YouTuber",
            "Programmer", "Content Creator", "Video Editor",
            "Tech Enthusiast", "Crypto Investor"
        ];
        let wordIndex = 0;
        let charIndex = 0;
        let isDeleting = false;
        const typeSpeed = 120;
        const deleteSpeed = 80;
        const delayBetweenWords = 1200;

        function typeAnimation() {
            const currentWord = words[wordIndex];
            if (isDeleting) {
                typingTextSpan.textContent = currentWord.substring(0, charIndex - 1);
                charIndex--;
            } else {
                typingTextSpan.textContent = currentWord.substring(0, charIndex + 1);
                charIndex++;
            }

            if (!isDeleting && charIndex === currentWord.length) {
                isDeleting = true;
                setTimeout(typeAnimation, delayBetweenWords);
            } else if (isDeleting && charIndex === 0) {
                isDeleting = false;
                wordIndex = (wordIndex + 1) % words.length;
                setTimeout(typeAnimation, typeSpeed);
            } else {
                setTimeout(typeAnimation, isDeleting ? deleteSpeed : typeSpeed);
            }
        }
        if (words.length > 0) typeAnimation();
    }

    // --- Show More/Less Videos ---
    const SELECTORS_VIDEOS = {
        showMoreBtn: '.see-more-btn',
        longFormContent: '.more-videos',
        shortFormContent: '.more-shorts'
    };
    const DATA_ATTRS_VIDEOS = { section: 'data-section' };
    const TEXT_VIDEOS = { showMore: 'Show More', showLess: 'Show Less' };
    const ANIMATION_VIDEOS = { duration: 350, easing: 'cubic-bezier(0.25, 0.1, 0.25, 1.0)' };

    document.addEventListener('click', function (e) {
        const showMoreBtn = e.target.closest(SELECTORS_VIDEOS.showMoreBtn);
        if (!showMoreBtn) return;

        const section = showMoreBtn.getAttribute(DATA_ATTRS_VIDEOS.section);
        let contentToToggle;
        let baseShowMoreText = TEXT_VIDEOS.showMore;

        switch (section) {
            case 'long-form':
                contentToToggle = document.querySelector(SELECTORS_VIDEOS.longFormContent);
                baseShowMoreText = "Show More Long Form";
                break;
            case 'short-form':
                contentToToggle = document.querySelector(SELECTORS_VIDEOS.shortFormContent);
                baseShowMoreText = "Show More Short Form";
                break;
            default: return;
        }
        if (!contentToToggle) return;

        toggleVideoContent(contentToToggle, showMoreBtn, baseShowMoreText);
    });

    function toggleVideoContent(content, button, baseShowMoreText) {
        const isHidden = content.style.display === 'none' || !content.style.maxHeight || content.style.maxHeight === '0px';

        if (isHidden) {
            content.style.display = 'grid';
            content.style.overflow = 'hidden';
            content.style.maxHeight = '0px';

            requestAnimationFrame(() => {
                const fullHeight = content.scrollHeight + 'px';
                content.animate(
                    [{ maxHeight: '0px' }, { maxHeight: fullHeight }],
                    ANIMATION_VIDEOS
                ).onfinish = () => {
                    content.style.maxHeight = 'none';
                    content.style.overflow = 'visible';
                };
            });
            button.textContent = TEXT_VIDEOS.showLess;
        } else {
            const currentHeight = content.scrollHeight + 'px';
            content.style.maxHeight = currentHeight;
            content.style.overflow = 'hidden';

            requestAnimationFrame(() => {
                content.animate(
                    [{ maxHeight: currentHeight }, { maxHeight: '0px' }],
                    ANIMATION_VIDEOS
                ).onfinish = () => {
                    content.style.display = 'none';
                    content.style.maxHeight = '0px';
                };
            });
            button.textContent = baseShowMoreText;
        }
    }

    // --- Crypto Address Selector ---
    const Addresses_Crypto = {
        USDT_TRC20: "TTdXcExjMTxSnM5HEpsg7mh3huPTxrmvYq",
        USDT_ERC20: "0xb813f07bce7df3c333acc33d0efe021f6c823880",
        USDT_BEP20: "0xb813f07bce7df3c333acc33d0efe021f6c823880",
        USDC_ERC20: "0xb813f07bce7df3c333acc33d0efe021f6c823880",
        USDC_BEP20: "0xb813f07bce7df3c333acc33d0efe021f6c823880"
    };
    const addressSelect_Crypto = document.getElementById('AddressSelect');
    const dynamicAddressDisplay_Crypto = document.getElementById('DynamicAddress');

    window.updateDynamicAddress = function () {
        if (addressSelect_Crypto && dynamicAddressDisplay_Crypto) {
            const selectedNetwork = addressSelect_Crypto.value;
            dynamicAddressDisplay_Crypto.innerText = Addresses_Crypto[selectedNetwork] || "Select a network";
        }
    }
    if (addressSelect_Crypto) {
        addressSelect_Crypto.addEventListener('change', updateDynamicAddress);
        updateDynamicAddress();
    }

    window.copyToClipboard = function (text, messageId) {
        navigator.clipboard.writeText(text).then(() => {
            document.querySelectorAll('.copied-message-small').forEach(msg => {
                msg.style.opacity = '0';
            });
            const copiedMessageEl = document.getElementById(messageId);
            if (copiedMessageEl) {
                copiedMessageEl.style.opacity = '1';
                setTimeout(() => {
                    copiedMessageEl.style.opacity = '0';
                }, 2000);
            }
        }).catch(err => console.error('Copy failed: ', err));
    }

    window.copyDynamicAddress = function () {
        if (dynamicAddressDisplay_Crypto) {
            copyToClipboard(dynamicAddressDisplay_Crypto.innerText, 'copiedMsgCryptoAddress');
        }
    }

    // --- Smooth Anchor Link Scroll ---
    document.querySelectorAll('.top-navigation a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                const navbarHeight = document.querySelector('.top-navigation')?.offsetHeight || 60;
                const offset = targetElement.getBoundingClientRect().top + window.pageYOffset - navbarHeight - 20;
                smoothScroll(offset, 1500); // Slower anchor scroll
                if (navLinksContainer?.classList.contains('active')) {
                    navLinksContainer.classList.remove('active');
                }
            }
        });
    });

    // --- Smooth Manual Mouse Wheel Scroll ---
    (function enableSmoothMouseScroll() {
        let isScrolling = false;
        let targetScroll = window.scrollY;
        let currentScroll = window.scrollY;

        function easeOutQuart(t) {
            return 1 - Math.pow(1 - t, 4);
        }

        function animateScroll() {
            if (!isScrolling) return;
            currentScroll += (targetScroll - currentScroll) * 0.1;
            if (Math.abs(targetScroll - currentScroll) < 0.5) {
                currentScroll = targetScroll;
                isScrolling = false;
            }
            window.scrollTo(0, currentScroll);
            if (isScrolling) requestAnimationFrame(animateScroll);
        }

        window.addEventListener('wheel', function (e) {
            e.preventDefault();
            const delta = e.deltaY;
            targetScroll += delta;
            targetScroll = Math.max(0, Math.min(targetScroll, document.body.scrollHeight - window.innerHeight));
            if (!isScrolling) {
                isScrolling = true;
                animateScroll();
            }
        }, { passive: false });
    })();

    // --- Shared Smooth Scroll Function ---
    function smoothScroll(targetY, duration) {
        const startY = window.pageYOffset;
        const diffY = targetY - startY;
        const startTime = performance.now();

        function easeOutQuart(t) {
            return 1 - Math.pow(1 - t, 4);
        }

        function scroll(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const eased = easeOutQuart(progress);
            window.scrollTo(0, startY + diffY * eased);
            if (progress < 1) requestAnimationFrame(scroll);
        }

        requestAnimationFrame(scroll);
    }

}); // End DOMContentLoaded