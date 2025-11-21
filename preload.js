const { contextBridge, ipcRenderer } = require('electron');

// Expose secure API to renderer process
contextBridge.exposeInMainWorld('secureWipeAPI', {
  // Device management
  detectDevices: () => ipcRenderer.invoke('detect-devices'),
  
  // Wipe operations
  startWipe: (config) => ipcRenderer.invoke('start-wipe', config),
  getSessionStatus: (sessionId) => ipcRenderer.invoke('get-session-status', sessionId),
  
  // Verification
  runVerification: (deviceId, sessionId) => ipcRenderer.invoke('run-verification', deviceId, sessionId),
  
  // Certificate generation
  generateCertificate: (sessionData) => ipcRenderer.invoke('generate-certificate', sessionData),
  
  // File operations
  openFile: (filePath) => ipcRenderer.invoke('open-file', filePath),
  saveReport: (reportData) => ipcRenderer.invoke('save-report', reportData),
  
  // Event listeners
  onWipeCompleted: (callback) => ipcRenderer.on('wipe-completed', callback),
  onWipeFailed: (callback) => ipcRenderer.on('wipe-failed', callback),
  onSessionProgressUpdate: (callback) => ipcRenderer.on('session-progress-update', callback),
  onSessionLogUpdate: (callback) => ipcRenderer.on('session-log-update', callback),
  onMenuNewSession: (callback) => ipcRenderer.on('menu-new-session', callback),
  onMenuDetectDevices: (callback) => ipcRenderer.on('menu-detect-devices', callback),
  onMenuRunVerification: (callback) => ipcRenderer.on('menu-run-verification', callback),
  onOpenReport: (callback) => ipcRenderer.on('open-report', callback),
  onFormatResult: (callback) => ipcRenderer.on('format-result', callback),
  onDevicesUpdated: cb => ipcRenderer.on('devices-updated', cb),
  onWipeProcessComplete: cb => ipcRenderer.on('wipe-process-complete', cb),
  // Remove listeners
  removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel),
  
  // Utility functions
  formatBytes: (bytes, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  },
  
  formatDuration: (milliseconds) => {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  },
  
  getCurrentTimestamp: () => new Date().toISOString(),
  
  // Constants
  WIPE_PROFILES: {
    CITIZEN: 'citizen',
    ENTERPRISE: 'enterprise',
    GOVERNMENT: 'government'
  },
  
  WIPE_STANDARDS: {
    NIST_800_88: 'NIST SP 800-88',
    HSE: 'HSE'
  },
  
  LOG_LEVELS: {
    INFO: 'info',
    SUCCESS: 'success',
    WARNING: 'warning',
    ERROR: 'error'
  }
});

// Expose system information
contextBridge.exposeInMainWorld('systemInfo', {
  platform: process.platform,
  arch: process.arch,
  versions: process.versions
});

// Security utilities
contextBridge.exposeInMainWorld('securityUtils', {
  generateHash: (data) => {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(data).digest('hex');
  },
  
  generateUUID: () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c == 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  },
  
  sanitizeInput: (input) => {
    if (typeof input !== 'string') return input;
    return input.replace(/[<>\"'&]/g, (match) => {
      const escapeMap = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
        '&': '&amp;'
      };
      return escapeMap[match];
    });
  }
});

console.log('Preload script loaded successfully');