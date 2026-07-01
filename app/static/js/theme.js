// Theme Management - Memory and Performance Optimized
document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('themeToggle');
    const themeIcon = document.getElementById('themeIcon');
    const root = document.documentElement;

    // Function to update theme with smooth transition
    function setTheme(theme, saveToStorage = true) {
        // Disable transitions during theme switch for performance
        document.body.classList.add('no-transition');

        // Set the theme
        root.setAttribute('data-theme', theme);
        updateIcon(theme);

        // Save to localStorage if needed (only when user explicitly changes theme)
        if (saveToStorage) {
            localStorage.setItem('theme', theme);
            // Also save in session storage for initial page loads
            sessionStorage.setItem('theme', theme);
        }

        // Re-enable transitions after a short delay
        setTimeout(() => {
            document.body.classList.remove('no-transition');
        }, 10);
    }

    // Function to update the theme icon with animation
    function updateIcon(theme) {
        // Fade out icon
        themeIcon.style.transition = 'transform 0.3s ease, opacity 0.3s ease';
        themeIcon.style.opacity = '0';

        setTimeout(() => {
            if (theme === 'dark') {
                themeIcon.className = 'fas fa-sun';
                themeIcon.title = 'Switch to Light Mode';
            } else {
                themeIcon.className = 'fas fa-moon';
                themeIcon.title = 'Switch to Dark Mode';
            }

            // Fade in and scale icon
            themeIcon.style.opacity = '1';
            themeIcon.style.transform = 'scale(1.2)';

            // Reset scale after animation
            setTimeout(() => {
                themeIcon.style.transform = 'scale(1)';
            }, 200);
        }, 150);
    }

    // Check for saved theme preference
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const savedTheme = localStorage.getItem('theme');
    const sessionTheme = sessionStorage.getItem('theme');

    // Priority: saved theme > session theme > system preference > light
    if (savedTheme) {
        setTheme(savedTheme, false);
    } else if (sessionTheme) {
        setTheme(sessionTheme, false);
    } else if (prefersDark) {
        setTheme('dark', false);
    } else {
        setTheme('light', false);
    }

    // Toggle theme on button click
    themeToggle.addEventListener('click', (e) => {
        e.preventDefault();
        const current = root.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        setTheme(next);

        // Add click animation for better UX
        themeToggle.style.transform = 'scale(0.9)';
        setTimeout(() => {
            themeToggle.style.transform = 'scale(1)';
        }, 100);
    });

    // Listen for system theme changes (only if user hasn't set a preference)
    if (!localStorage.getItem('theme')) {
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
            setTheme(e.matches ? 'dark' : 'light', false);
        });
    }

    // Debug logging (only in development)
    if (typeof console !== 'undefined' && console.log) {
        console.log('Theme system initialized');
        console.log('Current theme:', root.getAttribute('data-theme'));
    }
});

// Add smooth transitions after page load
window.addEventListener('load', () => {
    document.body.style.transition = 'background-color 0.5s ease, color 0.3s ease';
});

// Prevent flash of unstyled content (FOUC)
(function() {
    document.documentElement.classList.add('theme-loading');
    document.body.classList.add('no-transition');

    window.addEventListener('load', () => {
        setTimeout(() => {
            document.documentElement.classList.remove('theme-loading');
            document.body.classList.remove('no-transition');
        }, 50);
    });
})();
