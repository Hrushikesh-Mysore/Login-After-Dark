/**
 * Client-Side Genuine Device Fingerprinting & Telemetry Collector
 * Generates deterministic hardware/browser fingerprints via Canvas, WebGL, and System Entropy.
 */

class DeviceFingerprinter {
  static async getFingerprint() {
    try {
      const entropy = await this.collectEntropy();
      const rawString = JSON.stringify(entropy);
      const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rawString));
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      return {
        fingerprint: `fp_${hashHex.substring(0, 16)}`,
        entropy,
        deviceName: this.getDeviceSummary()
      };
    } catch (err) {
      console.warn("Fingerprinting fallback:", err);
      return {
        fingerprint: `fp_fallback_${Math.abs(this.simpleHash(navigator.userAgent))}`,
        entropy: {},
        deviceName: this.getDeviceSummary()
      };
    }
  }

  static async collectEntropy() {
    return {
      screen: `${screen.width}x${screen.height}x${screen.colorDepth}`,
      pixelRatio: window.devicePixelRatio || 1,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC',
      tzOffset: new Date().getTimezoneOffset(),
      language: navigator.language || navigator.userLanguage,
      platform: navigator.platform || 'Unknown',
      concurrency: navigator.hardwareConcurrency || 4,
      canvas: this.getCanvasHash(),
      webgl: this.getWebGLInfo()
    };
  }

  static getCanvasHash() {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 200;
      canvas.height = 50;
      const ctx = canvas.getContext('2d');
      if (!ctx) return 'no-canvas';

      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#06b6d4';
      ctx.fillRect(10, 10, 80, 20);
      ctx.fillStyle = '#ef4444';
      ctx.fillText('LoginAfterDark#2026', 15, 15);

      return this.simpleHash(canvas.toDataURL());
    } catch (e) {
      return 'canvas-blocked';
    }
  }

  static getWebGLInfo() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return 'no-webgl';
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      if (!debugInfo) return 'webgl-no-debug';
      const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || '';
      const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || '';
      return `${vendor} ~ ${renderer}`;
    } catch (e) {
      return 'webgl-error';
    }
  }

  static getDeviceSummary() {
    const ua = navigator.userAgent;
    const isMobile = /Mobi|Android|iPhone|iPad/i.test(ua);
    let browser = "Browser";
    if (ua.includes("Firefox")) browser = "Firefox";
    else if (ua.includes("Chrome") && !ua.includes("Edg")) browser = "Chrome";
    else if (ua.includes("Safari") && !ua.includes("Chrome")) browser = "Safari";
    else if (ua.includes("Edg")) browser = "Edge";

    let os = "OS";
    if (ua.includes("Windows")) os = "Windows";
    else if (ua.includes("Mac OS")) os = "macOS";
    else if (ua.includes("Android")) os = "Android";
    else if (ua.includes("iPhone") || ua.includes("iPad")) os = "iOS";
    else if (ua.includes("Linux")) os = "Linux";

    return `${browser} on ${os} (${isMobile ? 'Mobile' : 'Desktop'})`;
  }

  static simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(16);
  }
}

window.DeviceFingerprinter = DeviceFingerprinter;
