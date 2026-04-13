/**
 * background.js — Service worker for nur collector
 *
 * Minimal background script. Handles extension installation
 * and any future message passing between popup and content scripts.
 */

// Set default settings on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.set({
    apiEndpoint: 'https://nur.saramena.us/contribute/submit',
    autoCapture: false,
  });
});
