/**
 * Main Application JavaScript
 * Global functionality and utilities
 */

// Global application state
window.RansomGuardApp = {
    version: '1.0.0',
    debug: false,
    initialized: false
};

// Initialize application when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('RansomGuard Pro v' + window.RansomGuardApp.version + ' initialized');

    // Initialize tooltips
    initializeTooltips();

    // Initialize modals
    initializeModals();

    // Initialize notifications
    initializeNotifications();

    // Initialize system status updates
    initializeSystemStatus();

    window.RansomGuardApp.initialized = true;
});

// Tooltip initialization
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Modal initialization
function initializeModals() {
    // Auto-focus first input in modals
    document.addEventListener('shown.bs.modal', function(event) {
        const modal = event.target;
        const firstInput = modal.querySelector('input:not([type="hidden"]), textarea, select');
        if (firstInput) {
            firstInput.focus();
        }
    });
}

// Notification system
function initializeNotifications() {
    // Auto-dismiss flash messages after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        if (!alert.querySelector('.btn-close')) {
            setTimeout(function() {
                if (alert.parentNode) {
                    alert.remove();
                }
            }, 5000);
        }
    });
}

// System status updates
function initializeSystemStatus() {
    // Update system status every 30 seconds
    setInterval(updateSystemStatus, 30000);
}

function updateSystemStatus() {
    fetch('/api/system_status')
    .then(response => response.json())
    .then(data => {
        // Update threat level indicator
        const threatIndicator = document.querySelector('.status-indicator.bg-success');
        if (threatIndicator && data.threat_level !== 'low') {
            threatIndicator.className = 'status-indicator bg-' +
                (data.threat_level === 'high' ? 'danger' : 'warning');
        }

        // Update active scans count if display exists
        const activeScansDisplay = document.querySelector('#activeScansCount');
        if (activeScansDisplay) {
            activeScansDisplay.textContent = data.active_scans || 0;
        }
    })
    .catch(error => {
        if (window.RansomGuardApp.debug) {
            console.log('System status update failed:', error);
        }
    });
}

// Utility functions
window.RansomGuardApp.utils = {

    // Format file size
    formatFileSize: function(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },

    // Format date
    formatDate: function(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    },

    // Copy to clipboard
    copyToClipboard: function(text) {
        navigator.clipboard.writeText(text).then(function() {
            showNotification('success', 'Copied to clipboard!');
        }).catch(function(err) {
            console.error('Failed to copy: ', err);
            showNotification('error', 'Failed to copy to clipboard');
        });
    },

    // Show notification
    showNotification: function(type, message) {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-triangle' : 'info-circle'} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.body.appendChild(notification);

        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    }
};

// Global notification function for backward compatibility
function showNotification(type, message) {
    window.RansomGuardApp.utils.showNotification(type, message);
}

// Export for global use
window.showNotification = showNotification;
