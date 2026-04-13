/**
 * options.js — Settings page controller for nur collector
 */

(async () => {
  const apiEndpoint = document.getElementById('api-endpoint');
  const testBtn = document.getElementById('test-connection');
  const connectionStatus = document.getElementById('connection-status');
  const autoCapture = document.getElementById('auto-capture');
  const saveBtn = document.getElementById('save-btn');
  const saveStatus = document.getElementById('save-status');

  // ── Load saved settings ────────────────────────────────────────────

  const settings = await chrome.storage.sync.get({
    apiEndpoint: 'https://nur.saramena.us/contribute/submit',
    autoCapture: false,
  });

  apiEndpoint.value = settings.apiEndpoint;
  autoCapture.checked = settings.autoCapture;

  // ── Test connection ────────────────────────────────────────────────

  testBtn.addEventListener('click', async () => {
    testBtn.disabled = true;
    connectionStatus.textContent = 'Testing...';
    connectionStatus.className = 'connection-status testing';

    try {
      const response = await fetch(apiEndpoint.value, {
        method: 'OPTIONS',
        mode: 'cors',
      });

      if (response.ok || response.status === 204 || response.status === 405) {
        connectionStatus.textContent = 'Connected';
        connectionStatus.className = 'connection-status connected';
      } else {
        connectionStatus.textContent = `Error: ${response.status}`;
        connectionStatus.className = 'connection-status error';
      }
    } catch (err) {
      connectionStatus.textContent = `Failed: ${err.message}`;
      connectionStatus.className = 'connection-status error';
    }

    testBtn.disabled = false;
  });

  // ── Save settings ──────────────────────────────────────────────────

  saveBtn.addEventListener('click', async () => {
    await chrome.storage.sync.set({
      apiEndpoint: apiEndpoint.value,
      autoCapture: autoCapture.checked,
    });

    saveStatus.textContent = 'Saved!';
    saveStatus.className = 'save-status saved';
    setTimeout(() => {
      saveStatus.textContent = '';
    }, 2000);
  });
})();
