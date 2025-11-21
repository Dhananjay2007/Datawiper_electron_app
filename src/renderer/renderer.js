// Main renderer process script
class SecureWipeDashboard {
  constructor() {
    this.currentSection = 'dashboard';
    this.devices = [];
    this.sessions = new Map();
    this.activities = [];
    
    this.init();
  }

  async init() {
    this.setupEventListeners();
    this.setupNavigation();
    this.setupModals();
    this.setupIPCListeners();
    
    // Initialize dashboard
    await this.loadDashboardData();
    
    // Auto-detect devices on startup
    setTimeout(() => this.detectDevices(), 1000);
  }

  setupEventListeners() {
    // Header buttons
    document.getElementById('detect-devices-btn')?.addEventListener('click', () => this.detectDevices());
    document.getElementById('new-session-btn')?.addEventListener('click', () => this.newSession());
    
    // Device refresh
    document.getElementById('refresh-devices')?.addEventListener('click', () => this.detectDevices());
    document.getElementById('detect-devices-first')?.addEventListener('click', () => this.detectDevices());
    
    // Wipe form
    document.getElementById('wipe-form')?.addEventListener('submit', (e) => this.handleWipeSubmit(e));
    document.getElementById('start-wipe-btn')?.addEventListener('click', () => this.startWipeProcess());
    
    // Verification
    document.getElementById('run-verification-btn')?.addEventListener('click', () => this.runVerification());
    
    // Activities
    document.getElementById('clear-activities')?.addEventListener('click', () => this.clearActivities());
  }

  setupNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const section = link.dataset.section;
        this.navigateToSection(section);
      });
    });
  }

  setupModals() {
    // Progress modal
    const progressModal = document.getElementById('progress-modal');
    const confirmModal = document.getElementById('confirmation-modal');
    
    // Close modal handlers
    document.querySelector('.close')?.addEventListener('click', () => {
      progressModal.style.display = 'none';
    });
    
    document.getElementById('cancel-wipe')?.addEventListener('click', () => {
      confirmModal.style.display = 'none';
    });
    
    document.getElementById('confirm-wipe')?.addEventListener('click', () => {
      this.confirmWipe();
    });
    
    // Close modals on outside click
    window.addEventListener('click', (e) => {
      if (e.target === progressModal) {
        progressModal.style.display = 'none';
      }
      if (e.target === confirmModal) {
        confirmModal.style.display = 'none';
      }
    });
  }

  setupIPCListeners() {
    // Listen for wipe completion
    secureWipeAPI.onWipeCompleted((event, sessionId) => {
      this.handleWipeCompleted(sessionId);
    });
    
    // Listen for wipe failure
    secureWipeAPI.onWipeFailed((event, data) => {
      this.handleWipeFailed(data.sessionId, data.error);
    });
    
    // Listen for progress updates
    secureWipeAPI.onSessionProgressUpdate((event, data) => {
      this.updateWipeProgress(data.sessionId, data.progress, data.message);
    });
    
    // Listen for log updates
    secureWipeAPI.onSessionLogUpdate((event, data) => {
      this.addLogEntry(data.sessionId, data.log);
    });
    // Listen for format result
    secureWipeAPI.onFormatResult((event, args) => {
      const { success, message } = args;
      if (success) {
        this.showToast('success', 'Format Completed', message);
        this.addActivity('success', message);
      }  else {
          this.showToast('error', 'Format Failed or Postponed', message);
          this.addActivity('error', message);
        }
      });
    secureWipeAPI.onFormatResult((event, args) => {
      this.handleFormatResult(args.success, args.message);
    });

    secureWipeAPI.onDevicesUpdated((_, devices) => {
  this.devices = devices;
  this.renderDevices();
  this.populateDeviceSelects();
  this.updateDashboardStats();
  this.showToast('info','Devices Refreshed','Device list updated after format');
});

secureWipeAPI.onWipeProcessComplete((_, { sessionId, verification }) => {
  this.showToast(
    'success',
    'Wipe Complete',
    `Drive wiped, formatted, verified: ${verification.verification_passed ? 'PASSED' : 'FAILED'}`
  );
  this.handleVerificationResult(sessionId, verification);
});

    // Menu events
    secureWipeAPI.onMenuNewSession(() => this.newSession());
    secureWipeAPI.onMenuDetectDevices(() => this.detectDevices());
    secureWipeAPI.onMenuRunVerification(() => this.runVerification());
    secureWipeAPI.onOpenReport((event, filePath) => this.openReport(filePath));
  }

  navigateToSection(sectionId) {
    // Update navigation
    document.querySelectorAll('.nav-link').forEach(link => {
      link.classList.remove('active');
    });
    document.querySelector(`[data-section="${sectionId}"]`)?.classList.add('active');
    
    // Show section
    document.querySelectorAll('.content-section').forEach(section => {
      section.classList.remove('active');
    });
    document.getElementById(`${sectionId}-section`)?.classList.add('active');
    
    this.currentSection = sectionId;
    
    // Load section-specific data
    this.loadSectionData(sectionId);
  }

  async loadSectionData(sectionId) {
    switch (sectionId) {
      case 'devices':
        if (this.devices.length === 0) {
          await this.detectDevices();
        }
        break;
      case 'wipe':
        this.populateDeviceSelects();
        break;
      case 'verification':
        this.populateDeviceSelects();
        break;
      case 'certificates':
        await this.loadCertificates();
        break;
      case 'reports':
        await this.loadReports();
        break;
    }
  }

  async detectDevices() {
    this.showLoadingSpinner(true);
    
    try {
      this.devices = await secureWipeAPI.detectDevices();
      this.renderDevices();
      this.updateDashboardStats();
      this.populateDeviceSelects();
      
      this.showToast('success', 'Success', `Detected ${this.devices.length} storage devices`);
      this.addActivity('info', `Detected ${this.devices.length} storage devices`);
      
    } catch (error) {
      console.error('Error detecting devices:', error);
      this.showToast('error', 'Error', 'Failed to detect storage devices');
      this.addActivity('error', 'Failed to detect storage devices');
    } finally {
      this.showLoadingSpinner(false);
    }
  }

  renderDevices() {
    const container = document.getElementById('devices-list');
    
    if (this.devices.length === 0) {
      container.innerHTML = `
        <div class="no-data">
          <i class="fas fa-hdd"></i>
          <p>No storage devices detected</p>
          <button id="detect-devices-retry" class="btn btn-primary">
            <i class="fas fa-sync-alt"></i>
            Try Again
          </button>
        </div>
      `;
      
      document.getElementById('detect-devices-retry')?.addEventListener('click', () => this.detectDevices());
      return;
    }
    
    container.innerHTML = this.devices.map(device => `
      <div class="device-card" data-device-id="${device.id}">
        <div class="device-header">
          <div class="device-icon">
            <i class="fas fa-${device.type === 'SSD' ? 'microchip' : 'hdd'}"></i>
          </div>
          <div class="device-info">
            <h3>${device.label || device.name}</h3>
            <p>${device.model} - ${device.vendor}</p>
          </div>
        </div>
        
        <div class="device-details">
          <div class="detail-item">
            <span class="detail-label">Size</span>
            <span class="detail-value">${device.sizeFormatted}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Interface</span>
            <span class="detail-value">${device.interface}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Type</span>
            <span class="detail-value">${device.type}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Serial</span>
            <span class="detail-value">${device.serial}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">SMART Status</span>
            <span class="detail-value ${device.smartStatus?.toLowerCase()}">${device.smartStatus}</span>
          </div>
          ${device.temperature ? `
            <div class="detail-item">
              <span class="detail-label">Temperature</span>
              <span class="detail-value">${device.temperature}°C</span>
            </div>
          ` : ''}
        </div>
        
        <div class="device-actions">
          <button class="btn btn-primary btn-sm" onclick="dashboard.selectDeviceForWipe('${device.id}')">
            <i class="fas fa-eraser"></i>
            Select for Wipe
          </button>
          <button class="btn btn-secondary btn-sm" onclick="dashboard.showDeviceDetails('${device.id}')">
            <i class="fas fa-info-circle"></i>
            Details
          </button>
        </div>
      </div>
    `).join('');
  }

  populateDeviceSelects() {
    const selects = ['device-select', 'verify-device-select'];
    
    selects.forEach(selectId => {
      const select = document.getElementById(selectId);
      if (select) {
        select.innerHTML = '<option value="">Select a device...</option>' +
          this.devices.map(device => 
            `<option value="${device.id}">${device.label || device.name} (${device.sizeFormatted})</option>`
          ).join('');
      }
    });
  }

  selectDeviceForWipe(deviceId) {
    this.navigateToSection('wipe');
    setTimeout(() => {
      const deviceSelect = document.getElementById('device-select');
      if (deviceSelect) {
        deviceSelect.value = deviceId;
      }
    }, 100);
  }

  showDeviceDetails(deviceId) {
    const device = this.devices.find(d => d.id === deviceId);
    if (!device) return;
    
    const details = `
      <div class="device-details-modal">
        <h3>${device.label || device.name}</h3>
        <table>
          <tr><td>Model:</td><td>${device.model}</td></tr>
          <tr><td>Vendor:</td><td>${device.vendor}</td></tr>
          <tr><td>Size:</td><td>${device.sizeFormatted} (${device.size} bytes)</td></tr>
          <tr><td>Interface:</td><td>${device.interface}</td></tr>
          <tr><td>Type:</td><td>${device.type}</td></tr>
          <tr><td>Serial Number:</td><td>${device.serial}</td></tr>
          <tr><td>SMART Status:</td><td>${device.smartStatus}</td></tr>
          ${device.temperature ? `<tr><td>Temperature:</td><td>${device.temperature}°C</td></tr>` : ''}
        </table>
      </div>
    `;
    
    this.showModal('Device Details', details);
  }

  async startWipeProcess() {
    const form = document.getElementById('wipe-form');
    const formData = new FormData(form);
    
    const config = {
      deviceId: formData.get('device-select') || document.getElementById('device-select').value,
      profile: formData.get('profile-select') || document.getElementById('profile-select').value,
      standard: formData.get('standard-select') || document.getElementById('standard-select').value,
      includeHpaDco: document.getElementById('include-hpa-dco').checked
    };
    
    // Validation
    if (!config.deviceId || !config.profile || !config.standard) {
      this.showToast('error', 'Validation Error', 'Please fill all required fields');
      return;
    }
    
    const device = this.devices.find(d => d.id === config.deviceId);
    if (!device) {
      this.showToast('error', 'Error', 'Selected device not found');
      return;
    }
    
    // Show confirmation modal
    this.showWipeConfirmation(config, device);
  }

  showWipeConfirmation(config, device) {
    const confirmModal = document.getElementById('confirmation-modal');
    const detailsDiv = document.getElementById('confirmation-details');
    
    detailsDiv.innerHTML = `
      <div class="wipe-confirmation-details">
        <div class="detail-row">
          <strong>Device:</strong> ${device.label || device.name}
        </div>
        <div class="detail-row">
          <strong>Size:</strong> ${device.sizeFormatted}
        </div>
        <div class="detail-row">
          <strong>Profile:</strong> ${config.profile.toUpperCase()}
        </div>
        <div class="detail-row">
          <strong>Standard:</strong> ${config.standard}
        </div>
        <div class="detail-row">
          <strong>Include HPA/DCO:</strong> ${config.includeHpaDco ? 'Yes' : 'No'}
        </div>
        <div class="detail-row">
          <strong>Confirmations Required:</strong> ${config.profile === 'citizen' ? '1' : '3'}
        </div>
      </div>
    `;
    
    this.pendingWipeConfig = { config, device };
    confirmModal.style.display = 'block';
  }

  async confirmWipe() {
    const confirmModal = document.getElementById('confirmation-modal');
    confirmModal.style.display = 'none';
    
    if (!this.pendingWipeConfig) return;
    
    const { config, device } = this.pendingWipeConfig;
    
    try {
      this.showLoadingSpinner(true);
      
      const result = await secureWipeAPI.startWipe(config);
      
      if (result.success) {
        this.sessions.set(result.sessionId, {
          id: result.sessionId,
          device,
          config,
          startTime: new Date(),
          status: 'running',
          progress: 0
        });
        
        this.showWipeProgress(result.sessionId);
        this.addActivity('info', `Started secure wipe of ${device.label || device.name}`);
        this.updateDashboardStats();
        
      } else {
        throw new Error(result.error || 'Failed to start wipe');
      }
      
    } catch (error) {
      console.error('Error starting wipe:', error);
      this.showToast('error', 'Error', `Failed to start wipe: ${error.message}`);
      this.addActivity('error', `Failed to start wipe: ${error.message}`);
    } finally {
      this.showLoadingSpinner(false);
      this.pendingWipeConfig = null;
    }
  }

  showWipeProgress(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    
    const modal = document.getElementById('progress-modal');
    const deviceInfo = document.getElementById('progress-device-info');
    const progressBar = document.querySelector('.progress-fill');
    const progressText = document.querySelector('.progress-text');
    const statusText = document.getElementById('progress-status');
    
    deviceInfo.innerHTML = `
      <h4>${session.device.label || session.device.name}</h4>
      <p>${session.device.sizeFormatted} - ${session.config.profile.toUpperCase()} Profile</p>
    `;
    
    progressBar.style.width = '0%';
    progressText.textContent = '0%';
    statusText.textContent = 'Initializing...';
    
    modal.style.display = 'block';
    
    // Start time tracking
    this.updateProgressTime(sessionId);
  }

  updateWipeProgress(sessionId, progress, message) {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    
    session.progress = progress;
    
    const progressBar = document.querySelector('.progress-fill');
    const progressText = document.querySelector('.progress-text');
    const statusText = document.getElementById('progress-status');
    
    if (progressBar) progressBar.style.width = `${progress}%`;
    if (progressText) progressText.textContent = `${progress}%`;
    if (statusText) statusText.textContent = message || 'Processing...';
    
    this.updateProgressTime(sessionId);
  }

  updateProgressTime(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    
    const timeDiv = document.getElementById('progress-time');
    if (timeDiv) {
      const elapsed = Date.now() - session.startTime;
      timeDiv.textContent = `Elapsed: ${secureWipeAPI.formatDuration(elapsed)}`;
      
      if (session.status === 'running') {
        setTimeout(() => this.updateProgressTime(sessionId), 1000);
      }
    }
  }

  addLogEntry(sessionId, log) {
    const logsContainer = document.getElementById('live-logs');
    if (!logsContainer) return;
    
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';
    logEntry.innerHTML = `
      <span class="log-timestamp">${new Date(log.timestamp).toLocaleTimeString()}</span>
      <span class="log-level ${log.level}">${log.level.toUpperCase()}</span>
      <span class="log-message">${securityUtils.sanitizeInput(log.message)}</span>
    `;
    
    logsContainer.appendChild(logEntry);
    logsContainer.scrollTop = logsContainer.scrollHeight;
  }

  handleWipeCompleted(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    
    session.status = 'completed';
    session.endTime = new Date();
    
    this.showToast('success', 'Wipe Completed', `Successfully wiped ${session.device.label || session.device.name}`);
    this.addActivity('success', `Completed secure wipe of ${session.device.label || session.device.name}`);
    
    // Auto-generate certificate and verification
    this.generateCertificateAndVerify(sessionId);
    
    this.updateDashboardStats();
  }
  handleFormatResult(success, message) {
    if (success) {
      this.showToast('success', 'Drive Format', message);
      this.addActivity('success', message);
    } else {
        this.showToast('error', 'Drive Format', message);
        this.addActivity('error', message);
        }
  }

  handleWipeFailed(sessionId, error) {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    
    session.status = 'failed';
    session.endTime = new Date();
    session.error = error;
    
    this.showToast('error', 'Wipe Failed', `Failed to wipe ${session.device.label || session.device.name}`);
    this.addActivity('error', `Failed to wipe ${session.device.label || session.device.name}: ${error}`);
    
    this.updateDashboardStats();
  }

  async generateCertificateAndVerify(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    
    try {
      // Generate certificate
      const sessionData = {
        sessionId,
        device: session.device,
        config: session.config,
        startTime: session.startTime,
        endTime: session.endTime,
        status: session.status
      };
      
      const certificate = await secureWipeAPI.generateCertificate(sessionData);
      
      if (certificate.success) {
        this.addActivity('success', `Generated certificate for ${session.device.label || session.device.name}`);
        
        // Auto-run verification
        setTimeout(async () => {
          try {
            const verificationResult = await secureWipeAPI.runVerification(session.device.id, sessionId);
            this.handleVerificationResult(sessionId, verificationResult);
          } catch (error) {
            console.error('Auto verification failed:', error);
          }
        }, 2000);
      }
      
    } catch (error) {
      console.error('Certificate generation failed:', error);
      this.addActivity('error', 'Failed to generate certificate');
    }
  }

  async runVerification() {
    const deviceSelect = document.getElementById('verify-device-select');
    const deviceId = deviceSelect.value;
    
    if (!deviceId) {
      this.showToast('error', 'Validation Error', 'Please select a device to verify');
      return;
    }
    
    const device = this.devices.find(d => d.id === deviceId);
    if (!device) {
      this.showToast('error', 'Error', 'Selected device not found');
      return;
    }
    
    try {
      this.showLoadingSpinner(true);
      this.showToast('info', 'Verification Started', 'Running PhotoRec/TestDisk verification...');
      
      const result = await secureWipeAPI.runVerification(deviceId, securityUtils.generateUUID());
      this.handleVerificationResult(null, result);
      
    } catch (error) {
      console.error('Verification error:', error);
      this.showToast('error', 'Verification Failed', error.message);
      this.addActivity('error', `Verification failed: ${error.message}`);
    } finally {
      this.showLoadingSpinner(false);
    }
  }

  handleVerificationResult(sessionId, result) {
    const resultsDiv = document.getElementById('verification-results');
    const outputDiv = document.getElementById('verification-output');
    
    if (!resultsDiv || !outputDiv) return;
    
    const passed = result.filesRecovered === 0;
    const statusClass = passed ? 'success' : 'error';
    const statusIcon = passed ? 'check-circle' : 'exclamation-triangle';
    const statusText = passed ? 'PASSED' : 'FAILED';
    
    outputDiv.innerHTML = `
      <div class="verification-result ${statusClass}">
        <div class="result-header">
          <i class="fas fa-${statusIcon}"></i>
          <h4>Verification ${statusText}</h4>
        </div>
        <div class="result-details">
          <div class="result-item">
            <strong>Files Recovered:</strong> ${result.filesRecovered || 0}
          </div>
          <div class="result-item">
            <strong>Scan Time:</strong> ${result.scanTime || 'N/A'}
          </div>
          <div class="result-item">
            <strong>Status:</strong> ${passed ? 'Wipe verified successful - no data recoverable' : 'Warning - some data may be recoverable'}
          </div>
          ${result.details ? `
            <div class="result-item">
              <strong>Details:</strong> ${result.details}
            </div>
          ` : ''}
        </div>
      </div>
    `;
    
    resultsDiv.style.display = 'block';
    
    // Add to activities
    const message = passed 
      ? 'Verification passed - no recoverable data found'
      : `Verification warning - ${result.filesRecovered} files recovered`;
    
    this.addActivity(passed ? 'success' : 'warning', message);
    
    // Navigate to verification section
    if (this.currentSection !== 'verification') {
      this.navigateToSection('verification');
    }
  }

  async loadDashboardData() {
    this.updateDashboardStats();
    this.loadRecentActivities();
  }

  updateDashboardStats() {
    const deviceCount = document.getElementById('device-count');
    const activeSessions = document.getElementById('active-sessions');
    const completedWipes = document.getElementById('completed-wipes');
    const certificatesCount = document.getElementById('certificates-count');
    
    if (deviceCount) deviceCount.textContent = this.devices.length;
    
    const activeCount = Array.from(this.sessions.values()).filter(s => s.status === 'running').length;
    if (activeSessions) activeSessions.textContent = activeCount;
    
    const completedCount = Array.from(this.sessions.values()).filter(s => s.status === 'completed').length;
    if (completedWipes) completedWipes.textContent = completedCount;
    
    // TODO: Load actual certificate count
    if (certificatesCount) certificatesCount.textContent = completedCount;
  }

  loadRecentActivities() {
    const activitiesList = document.getElementById('activities-list');
    if (!activitiesList) return;
    
    if (this.activities.length === 0) {
      activitiesList.innerHTML = `
        <div class="no-data">
          <i class="fas fa-info-circle"></i>
          <p>No recent activities</p>
        </div>
      `;
      return;
    }
    
    activitiesList.innerHTML = this.activities.slice(-10).reverse().map(activity => `
      <div class="activity-item ${activity.type}">
        <div class="activity-icon">
          <i class="fas fa-${this.getActivityIcon(activity.type)}"></i>
        </div>
        <div class="activity-content">
          <div class="activity-message">${activity.message}</div>
          <div class="activity-time">${activity.timestamp.toLocaleString()}</div>
        </div>
      </div>
    `).join('');
  }

  getActivityIcon(type) {
    const icons = {
      info: 'info-circle',
      success: 'check-circle',
      warning: 'exclamation-triangle',
      error: 'times-circle'
    };
    return icons[type] || 'info-circle';
  }

  addActivity(type, message) {
    this.activities.push({
      type,
      message,
      timestamp: new Date()
    });
    
    // Keep only last 100 activities
    if (this.activities.length > 100) {
      this.activities = this.activities.slice(-100);
    }
    
    this.loadRecentActivities();
  }

  clearActivities() {
    this.activities = [];
    this.loadRecentActivities();
    this.showToast('info', 'Activities Cleared', 'All activities have been cleared');
  }

  newSession() {
    // Reset all forms and navigate to wipe section
    const forms = document.querySelectorAll('form');
    forms.forEach(form => form.reset());
    
    this.navigateToSection('wipe');
    this.showToast('info', 'New Session', 'Ready to configure new wipe operation');
  }

  showToast(type, title, message, duration = 5000) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <div class="toast-header">
        <span class="toast-title">${title}</span>
        <span class="toast-close">&times;</span>
      </div>
      <div class="toast-message">${message}</div>
    `;
    
    // Close button
    toast.querySelector('.toast-close').addEventListener('click', () => {
      toast.remove();
    });
    
    container.appendChild(toast);
    
    // Auto remove
    setTimeout(() => {
      if (toast.parentNode) {
        toast.remove();
      }
    }, duration);
  }

  showLoadingSpinner(show) {
    const spinner = document.getElementById('loading-spinner');
    if (spinner) {
      spinner.style.display = show ? 'flex' : 'none';
    }
  }

  showModal(title, content, actions = null) {
    // Create modal dynamically
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
      <div class="modal-content">
        <div class="modal-header">
          <h3>${title}</h3>
          <span class="close">&times;</span>
        </div>
        <div class="modal-body">
          ${content}
        </div>
        ${actions ? `<div class="modal-footer">${actions}</div>` : ''}
      </div>
    `;
    
    document.body.appendChild(modal);
    
    // Close handler
    modal.querySelector('.close').addEventListener('click', () => {
      modal.remove();
    });
    
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.remove();
      }
    });
    
    modal.style.display = 'block';
    
    return modal;
  }

  async loadCertificates() {
    // TODO: Implement certificate loading
    const container = document.getElementById('certificates-list');
    if (container) {
      container.innerHTML = `
        <div class="no-data">
          <i class="fas fa-certificate"></i>
          <p>No certificates generated yet</p>
          <p><small>Certificates are automatically generated after successful wipe operations</small></p>
        </div>
      `;
    }
  }

  async loadReports() {
    // TODO: Implement report loading
    const container = document.getElementById('reports-list');
    if (container) {
      container.innerHTML = `
        <div class="no-data">
          <i class="fas fa-file-alt"></i>
          <p>No reports available</p>
          <p><small>Detailed reports are generated for each wipe operation</small></p>
        </div>
      `;
    }
  }

  async openReport(filePath) {
    try {
      // TODO: Implement report opening
      this.showToast('info', 'Report', 'Opening report...');
      await secureWipeAPI.openFile(filePath);
    } catch (error) {
      console.error('Error opening report:', error);
      this.showToast('error', 'Error', 'Failed to open report');
    }
  }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  window.dashboard = new SecureWipeDashboard();
});

// Make dashboard available globally for inline event handlers
window.dashboard = window.dashboard || {};