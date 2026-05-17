/**
 * sanitization.js - Input sanitization utilities
 * 
 * Prevents XSS attacks by sanitizing user input before
 * sending to backend or displaying in UI.
 */

/**
 * Sanitize user input to prevent XSS attacks
 * Removes potentially dangerous characters and HTML tags
 * 
 * @param {string} input - Raw user input
 * @returns {string} Sanitized input safe for use
 */
export const sanitizeInput = (input) => {
  if (typeof input !== 'string') return '';
  
  // Remove leading/trailing whitespace
  let sanitized = input.trim();
  
  // Remove HTML/script tags
  sanitized = sanitized
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
    .replace(/<on\w+\s*=/gi, '');
  
  // Escape HTML special characters
  sanitized = sanitized
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
  
  // Limit length to prevent DoS
  const MAX_INPUT_LENGTH = 2000;
  if (sanitized.length > MAX_INPUT_LENGTH) {
    sanitized = sanitized.substring(0, MAX_INPUT_LENGTH);
  }
  
  return sanitized;
};

/**
 * Validate IP address format
 * 
 * @param {string} ip - IP address string
 * @returns {boolean} True if valid IPv4 or IPv6
 */
export const isValidIP = (ip) => {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  
  if (ipv4Regex.test(ip)) {
    const parts = ip.split('.');
    return parts.every(part => parseInt(part, 10) <= 255);
  }
  
  return ipv6Regex.test(ip);
};

/**
 * Validate port number
 * 
 * @param {number} port - Port number
 * @returns {boolean} True if valid port (1-65535)
 */
export const isValidPort = (port) => {
  const num = parseInt(port, 10);
  return num >= 1 && num <= 65535 && !isNaN(num);
};

/**
 * Escape HTML special characters for safe display
 * 
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
export const escapeHtml = (text) => {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
};

/**
 * Validate API response before using
 * 
 * @param {any} response - API response to validate
 * @returns {boolean} True if response appears safe
 */
export const isValidAPIResponse = (response) => {
  // Check if response is an object
  if (typeof response !== 'object' || response === null) {
    return false;
  }
  
  // Check if response is not deeply nested (prevent prototype pollution)
  const depth = getObjectDepth(response);
  const MAX_DEPTH = 10;
  if (depth > MAX_DEPTH) {
    console.warn('API response too deeply nested, possible attack');
    return false;
  }
  
  return true;
};

/**
 * Get the depth of an object
 * 
 * @param {any} obj - Object to measure
 * @returns {number} Depth level
 */
const getObjectDepth = (obj) => {
  if (typeof obj !== 'object' || obj === null) return 0;
  
  const keys = Object.keys(obj);
  if (keys.length === 0) return 1;
  
  const depths = keys.map(key => getObjectDepth(obj[key]));
  return 1 + Math.max(...depths);
};

export default {
  sanitizeInput,
  isValidIP,
  isValidPort,
  escapeHtml,
  isValidAPIResponse,
};
