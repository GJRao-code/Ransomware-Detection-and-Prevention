/**
 * Enhanced Scan Page JavaScript with Better Error Handling
 * Fixed scanning functionality and error messages
 */

let scanEventSource = null;
let scanInterval = null;
let maxProgress = 0;
let currentDisplayProgress = 0;
let targetProgress = 0;
let progressAnimationFrame = null;
let currentScanId = null; // Store current scan ID globally

function initializeScanPage() {
    console.log('Initializing scan page...');

    // Set up scan type selection
    setupScanTypeSelection();

    // Prevent form submission and handle with JavaScript
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            startScan();
        });
    }

    // Set up scan button (also prevent default if clicked directly)
    const scanButton = document.getElementById('startScanBtn');
    if (scanButton) {
        scanButton.addEventListener('click', function(e) {
            e.preventDefault();
            startScan();
        });
    }

    // Set up stop scan button
    const stopButton = document.getElementById('stopScanBtn');
    if (stopButton) {
        stopButton.addEventListener('click', stopScan);
    }
}

function setupScanTypeSelection() {
    const scanTypes = document.querySelectorAll('input[name="scan_type"]');
    const browseButton = document.getElementById('browseButton');
    const customPathGroup = document.getElementById('customPathGroup');

    scanTypes.forEach(type => {
        type.addEventListener('change', function() {
            if (this.value === 'custom') {
                if (customPathGroup) customPathGroup.style.display = 'block';
                if (browseButton) browseButton.style.display = 'inline-block';
            } else {
                if (customPathGroup) customPathGroup.style.display = 'none';
                if (browseButton) browseButton.style.display = 'none';
            }
        });
    });
}

function startScan() {
    console.log('Starting scan...');

    const scanType = document.querySelector('input[name="scan_type"]:checked')?.value || 'quick';
    const scanPath = document.getElementById('scan_path')?.value || '';

    // Validate custom scan path if selected
    if (scanType === 'custom' && !scanPath.trim()) {
        showNotification('error', 'Please specify a path for custom scan.');
        return;
    }

    // Disable scan button and show loading state
    const scanButton = document.getElementById('startScanBtn');
    const stopButton = document.getElementById('stopScanBtn');

    if (scanButton) {
        scanButton.disabled = true;
        scanButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Starting Scan...';
    }

    // Start the scan with proper error handling
    fetch('/start_scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        credentials: 'same-origin',
        body: `scan_type=${encodeURIComponent(scanType)}&scan_path=${encodeURIComponent(scanPath)}`
    })
    .then(response => {
        console.log('Scan response status:', response.status);
        if (!response.ok) {
            return response.text().then(text => {
                console.error('Error response:', text);
                throw new Error(`HTTP error! status: ${response.status}, message: ${text}`);
            });
        }
        return response.json();
    })
    .then(data => {
        console.log('Scan started:', data);

        if (data.success) {
            // Update button state
            if (scanButton) {
                scanButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Scanning...';
            }

            // Show success notification
            showNotification('success', 'Scan started successfully!');

            // Store scan ID in session storage
            sessionStorage.setItem('current_scan_id', data.scan_id);
            
            // Show loading message
            showNotification('info', 'Preparing scan...');
            
            // Redirect to scan progress page
            window.location.href = `/scan_progress/${data.scan_id}`;
        } else {
            throw new Error(data.message || 'Failed to start scan');
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
        showNotification('error', `Failed to start scan: ${error.message}`);

        // Reset button state
        if (scanButton) {
            scanButton.disabled = false;
            scanButton.innerHTML = '<i class="fas fa-play me-2"></i>Start Scan';
        }

        if (stopButton) {
            stopButton.style.display = 'none';
        }
    });
}

async function stopScan() {
    console.log('Stopping scan...');
    
    // Use global currentScanId instead of looking for hidden input
    if (!currentScanId) {
        console.error('No active scan to stop');
        showNotification('error', 'No active scan to stop');
        return;
    }
    
    const scanId = currentScanId;

    try {
        const response = await fetch(`/stop_scan/${scanId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to stop scan');
        }

        // Close connections
        if (scanEventSource) {
            scanEventSource.close();
            scanEventSource = null;
        }

        if (scanInterval) {
            clearInterval(scanInterval);
            scanInterval = null;
        }
        
        // Clear the current scan ID
        currentScanId = null;

        // Reset UI
        const scanButton = document.getElementById('startScanBtn');
        const stopButton = document.getElementById('stopScanBtn');
        const progressBar = document.getElementById('scanProgress');
        const progressText = document.getElementById('progressText');

        if (scanButton) {
            scanButton.disabled = false;
            scanButton.innerHTML = '<i class="fas fa-play me-2"></i>Start New Scan';
        }

        if (stopButton) {
            stopButton.style.display = 'none';
        }

        if (progressBar) {
            progressBar.style.width = '0%';
            progressBar.setAttribute('aria-valuenow', '0');
        }

        if (progressText) {
            progressText.textContent = 'Ready to scan';
        }

        showNotification('success', data.message || 'Scan stopped successfully');
    } catch (error) {
        console.error('Failed to stop scan:', error);
        showNotification('error', error.message || 'Failed to stop scan. Please try again.');
    }
}

function startScanMonitoring(scanId) {
    console.log('Starting scan monitoring for scan ID:', scanId);
    
    // Store the scan ID globally so stopScan can access it
    currentScanId = scanId;

    // Close any existing connections
    if (scanEventSource) {
        scanEventSource.close();
    }

    if (scanInterval) {
        clearInterval(scanInterval);
    }

    // Reset all progress variables
    maxProgress = 0;
    currentDisplayProgress = 0;
    targetProgress = 0;
    if (progressAnimationFrame) {
        cancelAnimationFrame(progressAnimationFrame);
        progressAnimationFrame = null;
    }

    // Start Server-Sent Events for real-time updates
    try {
        scanEventSource = new EventSource(`/scan_events/${scanId}`);

        scanEventSource.onopen = function() {
            console.log('Scan monitoring connected');
        };

        scanEventSource.onmessage = function(event) {
            try {
                const data = JSON.parse(event.data);
                console.log('Scan update:', data);

                if (data.type === 'progress') {
                    updateScanProgress(data);
                } else if (data.type === 'complete') {
                    handleScanComplete(data);
                } else {
                    console.log('Unknown scan event type:', data.type);
                }
            } catch (e) {
                console.error('Error parsing scan event:', e);
            }
        };

        scanEventSource.onerror = function(event) {
            console.error('Scan event source error:', event);

            // Check if the error is due to scan completion
            if (event.target.readyState === EventSource.CLOSED) {
                console.log('Scan monitoring connection closed');
                return;
            }

            showNotification('error', 'Lost connection to scan server. Please refresh the page.');

            // Reset UI
            const scanButton = document.getElementById('startScanBtn');
            if (scanButton) {
                scanButton.disabled = false;
                scanButton.innerHTML = '<i class="fas fa-play me-2"></i>Start Scan';
            }
        };

    } catch (e) {
        console.error('Error setting up scan monitoring:', e);
        showNotification('error', 'Failed to connect to scan monitoring. Please try again.');

        // Fallback to polling
        startScanPolling(scanId);
    }
}

function startScanPolling(scanId) {
    console.log('Starting scan polling for scan ID:', scanId);

    scanInterval = setInterval(() => {
        fetch(`/scan_progress/${scanId}`)
        .then(response => response.json())
        .then(data => {
            console.log('Scan poll:', data);

            if (data.status === 'completed' || data.status === 'error' || data.status === 'stopped') {
                clearInterval(scanInterval);
                handleScanComplete(data);
            } else {
                updateScanProgress(data);
            }
        })
        .catch(error => {
            console.error('Error polling scan:', error);
            clearInterval(scanInterval);
            showNotification('error', 'Lost connection to scan server.');
        });
    }, 1000);
}

function updateScanProgress(data) {
    const rawProgress = Math.min(100, Math.max(0, data.progress_percentage || data.progress || 0));

    // Set target progress (enforce monotonic)
    targetProgress = Math.max(targetProgress, rawProgress);

    // If server reports completion ensure 100%
    if (data.status === 'completed') {
        targetProgress = 100;
    }

    // Start smooth animation if not already running
    if (!progressAnimationFrame) {
        animateProgress();
    }

    // Update scan statistics
    const filesScanned = document.getElementById('filesScanned');
    const threatsFound = document.getElementById('threatsFound');

    if (filesScanned) {
        filesScanned.textContent = data.files_scanned || 0;
    }

    if (threatsFound) {
        threatsFound.textContent = data.threats_detected || 0;
    }

    // Update current file
    const currentFileName = document.getElementById('currentFileName');
    const currentFilePath = document.getElementById('currentFilePath');

    if (currentFileName && currentFilePath) {
        const filePath = data.current_file || '';
        const fileName = filePath.split(/[/\\]/).pop() || 'Initializing...';

        currentFileName.textContent = fileName;
        currentFilePath.textContent = filePath || 'Preparing file system analysis...';
    }

    // Update file scanner list
    updateFileScanner(data);
}

function animateProgress() {
    const progressBar = document.getElementById('scanProgressBar');
    const progressText = document.getElementById('scanProgressText');

    // Smoothly interpolate towards target
    const diff = targetProgress - currentDisplayProgress;
    
    if (Math.abs(diff) > 0.1) {
        // Move 10% of the remaining distance each frame (smooth easing)
        currentDisplayProgress += diff * 0.1;
        
        if (progressBar) {
            progressBar.style.width = `${currentDisplayProgress}%`;
            progressBar.setAttribute('aria-valuenow', Math.round(currentDisplayProgress));

            if (currentDisplayProgress >= 99.9) {
                progressBar.classList.remove('progress-bar-animated');
            }
        }

        if (progressText) {
            progressText.textContent = `${Math.round(currentDisplayProgress)}%`;
        }

        // Continue animation
        progressAnimationFrame = requestAnimationFrame(animateProgress);
    } else {
        // Snap to target when close enough
        currentDisplayProgress = targetProgress;
        
        if (progressBar) {
            progressBar.style.width = `${currentDisplayProgress}%`;
            progressBar.setAttribute('aria-valuenow', Math.round(currentDisplayProgress));
        }

        if (progressText) {
            progressText.textContent = `${Math.round(currentDisplayProgress)}%`;
        }

        // Stop animation
        progressAnimationFrame = null;
    }

    // Update progress circle if it exists
    const progressCircle = document.getElementById('progressCircle');
    const progressPercent = document.getElementById('progressPercent');

    if (progressCircle && progressPercent) {
        const circumference = 314; // 2 * π * 50 (radius)
        const offset = circumference - (currentDisplayProgress / 100) * circumference;
        progressCircle.style.strokeDashoffset = offset;
        progressCircle.style.transition = 'stroke-dashoffset 0.3s ease';
        progressPercent.textContent = `${Math.round(currentDisplayProgress)}%`;
    }
}

function updateFileScanner(data) {
    const fileScanner = document.getElementById('fileScanner');
    if (!fileScanner) return;

    // Add new file to the list
    if (data.current_file) {
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item scanning p-2 border-bottom';

        const fileName = data.current_file.split(/[/\\]/).pop() || 'Unknown file';
        const filePath = data.current_file;

        fileItem.innerHTML = `
            <div class="d-flex align-items-center">
                <div class="threat-indicator threat-safe"></div>
                <div class="flex-grow-1">
                    <div class="fw-semibold">${fileName}</div>
                    <div class="text-muted small">${filePath}</div>
                </div>
                <div class="text-muted">
                    <i class="fas fa-search"></i> Scanning...
                </div>
            </div>
        `;

        // Remove old items to prevent memory buildup
        const items = fileScanner.querySelectorAll('.file-item');
        if (items.length > 100) {
            items[0].remove();
        }

        fileScanner.appendChild(fileItem);

        // Scroll to bottom
        fileScanner.scrollTop = fileScanner.scrollHeight;
    }
}

function handleScanComplete(data) {
    console.log('Scan completed:', data);

    maxProgress = 100;
    updateScanProgress({ ...data, status: 'completed', progress: 100 });

    // Close connections
    if (scanEventSource) {
        scanEventSource.close();
        scanEventSource = null;
    }

    if (scanInterval) {
        clearInterval(scanInterval);
        scanInterval = null;
    }
    
    // Clear the current scan ID
    currentScanId = null;

    // Update UI
    const progressSection = document.getElementById('scanProgressSection');
    const completeSection = document.getElementById('scanComplete');

    if (progressSection) progressSection.style.display = 'none';
    if (completeSection) completeSection.style.display = 'block';

    // Update scan summary
    updateScanSummary(data);

    // Reset buttons
    const scanButton = document.getElementById('startScanBtn');
    const stopButton = document.getElementById('stopScanBtn');

    if (scanButton) {
        scanButton.disabled = false;
        scanButton.innerHTML = '<i class="fas fa-play me-2"></i>Start Scan';
    }

    if (stopButton) {
        stopButton.style.display = 'none';
    }

    // Show completion notification
    if (data.status === 'completed') {
        showNotification('success', `Scan completed! Scanned ${data.total_files || 0} files, found ${data.total_threats || 0} threats.`);
    } else if (data.status === 'error') {
        showNotification('error', 'Scan encountered an error. Please check the logs and try again.');
    } else if (data.status === 'stopped') {
        showNotification('info', 'Scan was stopped by user.');
    }
}

function updateScanSummary(data) {
    const summaryContainer = document.getElementById('scanSummary');
    if (!summaryContainer) return;

    const totalFiles = data.total_files || 0;
    const totalThreats = data.total_threats || 0;
    const scanDuration = data.end_time && data.start_time ?
        Math.round((new Date(data.end_time) - new Date(data.start_time)) / 1000) : 0;

    summaryContainer.innerHTML = `
        <div class="col-md-4">
            <div class="text-center">
                <div class="h4 text-primary mb-1">${totalFiles.toLocaleString()}</div>
                <div class="text-muted small">Files Scanned</div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="text-center">
                <div class="h4 text-danger mb-1">${totalThreats}</div>
                <div class="text-muted small">Threats Found</div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="text-center">
                <div class="h4 text-success mb-1">${scanDuration}s</div>
                <div class="text-muted small">Scan Duration</div>
            </div>
        </div>
    `;
}

// Notification container styles
const notificationStyles = document.createElement('style');
notificationStyles.textContent = `
    .notification-container {
        position: fixed;
        top: 90px;
        right: 20px;
        z-index: 9999;
        display: flex;
        flex-direction: column;
        gap: 12px;
        width: 350px;
        max-width: calc(100% - 40px);
        max-height: calc(100vh - 120px);
        overflow-y: auto;
        padding: 10px;
        pointer-events: none;
        -webkit-overflow-scrolling: touch;
    }
    
    /* Hide scrollbar but keep functionality */
    .notification-container::-webkit-scrollbar {
        width: 4px;
    }
    
    .notification-container::-webkit-scrollbar-track {
        background: transparent;
    }
    
    .notification-container::-webkit-scrollbar-thumb {
        background: rgba(0,0,0,0.1);
        border-radius: 4px;
    }
    
    .scan-notification {
        width: 100%;
        opacity: 0;
        transform: translateX(120%);
        transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        margin: 0;
        box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        pointer-events: auto;
        position: relative;
        z-index: 10000;
        background: white;
        border: none;
        border-radius: 8px;
        overflow: hidden;
        backdrop-filter: blur(10px);
    }
    
    /* Notification header with colored accent */
    .scan-notification::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        width: 4px;
        height: 100%;
        background: #0d6efd;
        z-index: 1;
    }
    
    .scan-notification.alert-success::before { background: #198754; }
    .scan-notification.alert-error::before,
    .scan-notification.alert-danger::before { background: #dc3545; }
    .scan-notification.alert-warning::before { background: #ffc107; }
    .scan-notification.alert-info::before { background: #0dcaf0; }
    
    .scan-notification .alert {
        margin: 0;
        border: 1px solid rgba(0,0,0,0.1);
        border-left: none;
        border-radius: 0 8px 8px 0;
        padding: 15px 40px 15px 20px;
        position: relative;
        background: rgba(255, 255, 255, 0.95);
        z-index: 2;
    }
    
    [data-theme="dark"] .scan-notification .alert {
        background: rgba(45, 55, 72, 0.95);
        color: #e2e8f0;
        border-color: #4a5568;
    }
    
    .scan-notification.show {
        opacity: 1;
        transform: translateX(0);
        animation: slideInRight 0.4s cubic-bezier(0.4, 0, 0.2, 1) forwards;
    }
    
    /* Close button styling */
    .scan-notification .btn-close {
        position: absolute;
        top: 12px;
        right: 12px;
        width: 20px;
        height: 20px;
        padding: 0.25rem;
        background: transparent url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='%236c757d'%3e%3cpath d='M.293.293a1 1 0 011.414 0L8 6.586 14.293.293a1 1 0 111.414 1.414L9.414 8l6.293 6.293a1 1 0 01-1.414 1.414L8 9.414l-6.293 6.293a1 1 0 01-1.414-1.414L6.586 8 .293 1.707a1 1 0 010-1.414z'/%3e%3c/svg%3e") center/0.8em auto no-repeat;
        opacity: 0.7;
        transition: all 0.2s ease;
        z-index: 3;
        border: none;
    }
    
    [data-theme="dark"] .scan-notification .btn-close {
        filter: invert(1) grayscale(100%) brightness(1.5);
    }
    
    .scan-notification .btn-close:hover {
        opacity: 1;
        transform: rotate(90deg);
    }
    
    /* Notification content */
    .scan-notification .alert-body {
        padding-right: 24px;
        word-break: break-word;
    }
    
    /* Animation */
    @keyframes slideInRight {
        from {
            transform: translateX(120%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    /* Responsive adjustments */
    @media (max-width: 768px) {
        .notification-container {
            width: calc(100% - 30px);
            right: 15px;
            top: 80px;
            max-height: calc(100vh - 100px);
        }
        
        .scan-notification {
            width: 100%;
        }
    }
    
    /* Ensure notifications don't overlap with navbar */
    @media (max-width: 991.98px) {
        .notification-container {
            top: 70px;
        }
    }
`;
document.head.appendChild(notificationStyles);

// Track active notifications
const activeNotifications = new Set();
let notificationId = 0;

function showNotification(type, message, options = {}) {
    // Create container if it doesn't exist
    let container = document.querySelector('.notification-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'notification-container';
        document.body.appendChild(container);
    }

    // Create a unique ID for this notification
    const id = `notification-${Date.now()}-${notificationId++}`;
    
    // Add icon based on type
    let icon = 'info-circle';
    if (type === 'success') icon = 'check-circle';
    else if (type === 'error' || type === 'danger') icon = 'exclamation-triangle';
    else if (type === 'warning') icon = 'exclamation-circle';

    // Create notification element
    const notification = document.createElement('div');
    notification.className = `scan-notification alert-${type}`;
    notification.id = id;
    notification.setAttribute('role', 'alert');
    notification.setAttribute('aria-live', 'polite');
    
    // Set tabindex for better accessibility
    notification.setAttribute('tabindex', '-1');
    
    // Create alert content
    notification.innerHTML = `
        <div class="alert alert-dismissible">
            <div class="d-flex align-items-center">
                <i class="fas fa-${icon} me-2"></i>
                <div class="alert-body">${message}</div>
            </div>
            <button type="button" class="btn-close" aria-label="Close"></button>
        </div>
    `;

    // Add to container at the top (newest on top)
    if (container.firstChild) {
        container.insertBefore(notification, container.firstChild);
    } else {
        container.appendChild(notification);
    }
    
    // Store notification data
    const notificationData = {
        id,
        element: notification,
        container,
        timeout: null,
        dismissTime: options.duration || 5000
    };
    
    activeNotifications.add(notificationData);
    
    // Trigger animation after a small delay to allow DOM to update
    setTimeout(() => {
        notification.classList.add('show');
        // Focus the notification for screen readers
        notification.focus();
    }, 10);

    // Set up auto-dismiss
    setupDismissal(notificationData);
    
    // Handle manual close
    const closeButton = notification.querySelector('.btn-close');
    if (closeButton) {
        closeButton.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            closeNotification(notificationData);
        });
    }
    
    // Pause dismissal on hover
    notification.addEventListener('mouseenter', () => pauseDismissal(notificationData));
    notification.addEventListener('mouseleave', () => resumeDismissal(notificationData));
    
    // Close on escape key
    notification.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeNotification(notificationData);
        }
    });
    
    return notificationData;
}

function setupDismissal(notification) {
    // Clear any existing timeout
    if (notification.timeout) {
        clearTimeout(notification.timeout);
    }
    
    // Set new timeout
    notification.timeout = setTimeout(() => {
        closeNotification(notification);
    }, notification.dismissTime);
}

function pauseDismissal(notification) {
    if (notification.timeout) {
        clearTimeout(notification.timeout);
        notification.timeout = null;
    }
}

function resumeDismissal(notification) {
    if (!notification.timeout) {
        setupDismissal(notification);
    }
}

function closeNotification(notification) {
    if (!notification || !notification.element || !notification.container) return;
    
    // Remove from active notifications
    activeNotifications.delete(notification);
    
    // Clear any pending timeout
    if (notification.timeout) {
        clearTimeout(notification.timeout);
    }
    
    // Start fade out animation
    notification.element.classList.remove('show');
    
    // Remove from DOM after animation completes
    setTimeout(() => {
        if (notification.element.parentNode === notification.container) {
            notification.container.removeChild(notification.element);
            
            // Remove container if no more notifications
            if (notification.container.children.length === 0 && notification.container.parentNode) {
                document.body.removeChild(notification.container);
            }
        }
    }, 300);
}

// Handle page unload
window.addEventListener('beforeunload', function() {
    if (scanEventSource) {
        scanEventSource.close();
    }
    if (scanInterval) {
        clearInterval(scanInterval);
    }
});

// View detailed report function
function viewReport() {
    // Redirect to analytics page to view detailed report
    window.location.href = '/analytics';
}

// Start new scan function
function startNewScan() {
    // Reset the scan form and UI
    location.reload();
}

// Export scan results (quick formats)
function exportScanResults(format) {
    showNotification('info', `Exporting scan results as ${format.toUpperCase()}...`);
    
    // Use direct download via window.location
    const url = `/export_report/scan?format=${format}`;
    
    // Create hidden iframe for download
    const iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    iframe.src = url;
    document.body.appendChild(iframe);
    
    // Show success message after a short delay
    setTimeout(() => {
        showNotification('success', `Scan results exported successfully as ${format.toUpperCase()}!`);
        // Remove iframe after download starts
        setTimeout(() => {
            document.body.removeChild(iframe);
        }, 1000);
    }, 500);
}

// Export detailed reports (comprehensive, executive, technical)
function exportReport(type) {
    showNotification('info', `Generating ${type} report...`);
    
    // Use fetch to check for errors first
    fetch(`/export_report/${type}`)
        .then(response => {
            if (!response.ok) {
                // If error, read the error message
                return response.text().then(text => {
                    throw new Error(text || 'Export failed');
                });
            }
            // If successful, trigger download via iframe
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.src = `/export_report/${type}`;
            document.body.appendChild(iframe);
            
            setTimeout(() => {
                showNotification('success', `${type.charAt(0).toUpperCase() + type.slice(1)} report exported successfully!`);
                setTimeout(() => {
                    if (iframe.parentNode) {
                        document.body.removeChild(iframe);
                    }
                }, 1000);
            }, 500);
        })
        .catch(error => {
            console.error('Export error:', error);
            showNotification('error', error.message || `Failed to generate ${type} report. Please try again.`);
        });
}
