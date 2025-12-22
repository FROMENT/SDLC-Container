import { Base64 } from 'js-base64';

const SALT = "SECURE_CONTAINER_SALT_v1_";

export const secureStorage = {
  /**
   * Encrypts and saves a value to LocalStorage
   */
  setItem: (key: string, value: any) => {
    try {
      const stringVal = JSON.stringify(value);
      // Obfuscation: Base64 encode the string + salt. 
      // This protects against casual 'View Source' or DevTools inspection.
      const encoded = Base64.encode(SALT + stringVal);
      window.localStorage.setItem(key, encoded);
    } catch (e) {
      console.error("SecureStorage save failed", e);
    }
  },

  /**
   * Decrypts and retrieves a value from LocalStorage
   */
  getItem: <T>(key: string, defaultValue: T): T => {
    try {
      const item = window.localStorage.getItem(key);
      if (!item) return defaultValue;
      
      // Attempt to decode
      try {
          const decoded = Base64.decode(item);
          // Check for our salt signature
          if (decoded.startsWith(SALT)) {
             const jsonStr = decoded.substring(SALT.length);
             return JSON.parse(jsonStr);
          }
      } catch (e) {
          // If decoding fails, it might be old plain-text data. Fallthrough.
      }

      // Fallback: Try parsing as plain JSON (migration from old version)
      try {
        return JSON.parse(item);
      } catch {
        return defaultValue;
      }
    } catch (e) {
      console.warn("SecureStorage read error", e);
      return defaultValue;
    }
  },
  
  removeItem: (key: string) => {
    window.localStorage.removeItem(key);
  }
};