/**
 * popup.js — Main popup controller for nur collector
 *
 * Two modes:
 *   1. Capture Page — scrape the current page only
 *   2. Full Scan — discover all nav links, walk through each page,
 *      build a complete dashboard profile
 */

(async () => {
  // ── DOM references ─────────────────────────────────────────────────

  const statusDot = document.getElementById('status-dot');
  const pageStatus = document.getElementById('page-status');
  const captureBtn = document.getElementById('capture-btn');
  const fullscanBtn = document.getElementById('fullscan-btn');
  const scanProgress = document.getElementById('scan-progress');
  const progressBar = document.getElementById('progress-bar');
  const progressText = document.getElementById('progress-text');
  const progressDetail = document.getElementById('progress-detail');
  const stopScanBtn = document.getElementById('stop-scan-btn');
  const statusMessage = document.getElementById('status-message');
  const previewPanel = document.getElementById('preview-panel');
  const previewContent = document.getElementById('preview-content');
  const rawContent = document.getElementById('raw-content');
  const toggleRawBtn = document.getElementById('toggle-raw');
  const pageCount = document.getElementById('page-count');
  const compareBtn = document.getElementById('compare-btn');
  const comparePanel = document.getElementById('compare-panel');
  const compareContent = document.getElementById('compare-content');
  const backToPreviewBtn = document.getElementById('back-to-preview');
  const submitBtn = document.getElementById('submit-btn');
  const settingsBtn = document.getElementById('settings-btn');

  // State
  let anonymizedData = null;
  let rawScanData = null; // pre-anonymization for self-assessment
  let showingRaw = false;
  let scanRunning = false;
  let scanAborted = false;
  let currentTabId = null;

  // ── Initialize: detect current page ────────────────────────────────

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTabId = tab?.id;
    if (tab && tab.url) {
      const url = new URL(tab.url);
      pageStatus.textContent = url.hostname + url.pathname;
      statusDot.classList.add('active');
    } else {
      pageStatus.textContent = 'No accessible page';
      statusDot.classList.add('inactive');
      captureBtn.disabled = true;
      fullscanBtn.disabled = true;
    }
  } catch (err) {
    pageStatus.textContent = 'Cannot access page';
    statusDot.classList.add('inactive');
    captureBtn.disabled = true;
    fullscanBtn.disabled = true;
  }

  // ── Settings ───────────────────────────────────────────────────────

  settingsBtn.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });

  // ── Single Page Capture ────────────────────────────────────────────

  captureBtn.addEventListener('click', async () => {
    captureBtn.disabled = true;
    fullscanBtn.disabled = true;
    setStatus('Capturing page data...', 'working');

    try {
      // Inject fingerprint.js first, then content.js so it can use Fingerprint
      await chrome.scripting.executeScript({
        target: { tabId: currentTabId },
        files: ['fingerprint.js'],
      });
      const results = await chrome.scripting.executeScript({
        target: { tabId: currentTabId },
        files: ['content.js'],
      });

      if (!results || !results[0] || !results[0].result) {
        setStatus('No data captured. Is this a supported page?', 'error');
        captureBtn.disabled = false;
        fullscanBtn.disabled = false;
        return;
      }

      const scrapedData = results[0].result;
      setStatus('Anonymizing data...', 'working');

      rawScanData = scrapedData;
      const { anonymized, report } = await Anonymize.anonymizeData(scrapedData);
      anonymizedData = anonymized;

      // Save scan locally for future comparison
      await Compare.saveScan(anonymized);

      renderPreview(anonymized, report, 1);
      previewPanel.classList.remove('hidden');
      submitBtn.disabled = false;
      compareBtn.disabled = false;
      setStatus(`Ready for review. ${report.length} items anonymized.`, 'success');
    } catch (err) {
      console.error('Capture error:', err);
      setStatus(`Capture failed: ${err.message}`, 'error');
    }
    captureBtn.disabled = false;
    fullscanBtn.disabled = false;
  });

  // ── Full Scan ──────────────────────────────────────────────────────

  fullscanBtn.addEventListener('click', async () => {
    if (scanRunning) return;
    scanRunning = true;
    scanAborted = false;
    captureBtn.disabled = true;
    fullscanBtn.disabled = true;
    scanProgress.classList.remove('hidden');

    try {
      // Step 1: Discover all navigation links from current page
      setProgress(0, 'Discovering dashboard pages...');

      const discoveryResults = await chrome.scripting.executeScript({
        target: { tabId: currentTabId },
        files: ['crawler.js'],
      });

      if (!discoveryResults?.[0]?.result) {
        setStatus('Could not discover pages. Try Capture Page instead.', 'error');
        resetScanUI();
        return;
      }

      const discovery = discoveryResults[0].result;
      const startUrl = discovery.current_url;
      const source = discovery.source;
      const navLinks = discovery.links || [];

      // Collect all pages to visit (nav link hrefs + current page)
      // Filter to only real href links (not click-based SPA buttons for now)
      const pagesToVisit = navLinks
        .filter(l => !l.isClick && l.href)
        .slice(0, 50); // cap at 50 pages to avoid runaway scans

      const totalPages = pagesToVisit.length + 1; // +1 for current page
      setProgress(0, `Found ${pagesToVisit.length} pages to scan`);
      setProgressDetail(`Source: ${source}`);

      // Step 2: Capture current page first
      const allPageData = [];
      allPageData.push({
        url: startUrl,
        label: 'Starting Page',
        ...discovery.page_data,
      });

      // Step 3: Navigate to each link and capture
      for (let i = 0; i < pagesToVisit.length; i++) {
        if (scanAborted) break;

        const link = pagesToVisit[i];
        const pct = Math.round(((i + 1) / totalPages) * 100);
        setProgress(pct, `Scanning: ${link.label}`);
        setProgressDetail(`Page ${i + 2} of ${totalPages}`);

        try {
          // Navigate the tab to the link
          await navigateTab(currentTabId, link.href);

          // Wait for page to load
          await waitForLoad(currentTabId);

          // Small delay for SPA rendering
          await sleep(1500);

          // Inject fingerprinting + scrape the page
          await chrome.scripting.executeScript({
            target: { tabId: currentTabId },
            files: ['fingerprint.js'],
          });
          const pageResults = await chrome.scripting.executeScript({
            target: { tabId: currentTabId },
            files: ['content.js'],
          });

          if (pageResults?.[0]?.result) {
            allPageData.push({
              url: link.href,
              label: link.label,
              ...pageResults[0].result,
            });
          }
        } catch (err) {
          console.warn(`Failed to capture ${link.label}: ${err.message}`);
          // Continue to next page
        }
      }

      // Step 4: Navigate back to starting page
      if (!scanAborted) {
        setProgress(95, 'Returning to starting page...');
        try {
          await navigateTab(currentTabId, startUrl);
          await waitForLoad(currentTabId);
        } catch { /* best effort */ }
      }

      // Step 5: Merge all page data into a single dashboard profile
      setProgress(98, 'Building dashboard profile...');
      const mergedProfile = mergeDashboardProfile(source, allPageData);

      // Step 6: Anonymize the merged profile
      setProgress(99, 'Anonymizing...');
      const { anonymized, report } = await Anonymize.anonymizeData(mergedProfile);
      anonymizedData = anonymized;

      // Step 7: Show results
      scanProgress.classList.add('hidden');
      renderPreview(anonymized, report, allPageData.length);
      previewPanel.classList.remove('hidden');
      submitBtn.disabled = false;

      rawScanData = mergedProfile;

      // Save scan locally
      await Compare.saveScan(anonymized);

      const label = scanAborted ? 'Scan stopped early.' : 'Full scan complete.';
      setStatus(`${label} ${allPageData.length} pages captured. ${report.length} items anonymized.`, 'success');
      compareBtn.disabled = false;

    } catch (err) {
      console.error('Full scan error:', err);
      setStatus(`Scan failed: ${err.message}`, 'error');
    }

    resetScanUI();
  });

  // Stop scan button
  stopScanBtn.addEventListener('click', () => {
    scanAborted = true;
    setProgress(100, 'Stopping scan...');
  });

  // ── Tab Navigation Helpers ─────────────────────────────────────────

  function navigateTab(tabId, url) {
    return chrome.tabs.update(tabId, { url });
  }

  function waitForLoad(tabId) {
    return new Promise((resolve) => {
      const listener = (id, changeInfo) => {
        if (id === tabId && changeInfo.status === 'complete') {
          chrome.tabs.onUpdated.removeListener(listener);
          resolve();
        }
      };
      chrome.tabs.onUpdated.addListener(listener);
      // Timeout after 15 seconds
      setTimeout(() => {
        chrome.tabs.onUpdated.removeListener(listener);
        resolve();
      }, 15000);
    });
  }

  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ── Merge Dashboard Profile ────────────────────────────────────────

  /**
   * Merge data from multiple pages into a single dashboard profile.
   * Deduplicates metrics, modules, tables and builds a page map.
   */
  function mergeDashboardProfile(source, pages) {
    const allTables = [];
    const allMetrics = [];
    const allModules = [];
    const allSnippets = [];
    const allFingerprints = [];
    const allIntegrations = [];
    const pageMap = [];
    const seenMetricKeys = new Set();
    const seenModuleNames = new Set();
    const seenSnippets = new Set();
    const seenIntegrations = new Set();

    for (const page of pages) {
      // Track which pages we visited
      pageMap.push({
        label: page.label || page.page_title || 'Unknown',
        path: page.page_path || '',
      });

      // Merge tables (tag with source page)
      if (page.tables) {
        for (const table of page.tables) {
          allTables.push({
            page: page.label || page.page_title || page.page_path,
            ...table,
          });
        }
      }

      // Merge metrics (deduplicate by label)
      if (page.metrics) {
        for (const m of page.metrics) {
          const key = `${m.label}:${m.value}`;
          if (!seenMetricKeys.has(key)) {
            seenMetricKeys.add(key);
            allMetrics.push({ ...m, page: page.label || page.page_path });
          }
        }
      }

      // Merge active modules (deduplicate by name)
      if (page.active_modules) {
        for (const m of page.active_modules) {
          if (!seenModuleNames.has(m.name)) {
            seenModuleNames.add(m.name);
            allModules.push(m);
          }
        }
      }

      // Merge text snippets
      const snippets = page.text_snippets || page.raw_text_snippets || [];
      for (const s of snippets) {
        if (!seenSnippets.has(s)) {
          seenSnippets.add(s);
          allSnippets.push(s);
        }
      }

      // Collect fingerprints per page
      if (page.fingerprint) {
        allFingerprints.push({
          page: page.label || page.page_path,
          simhash: page.fingerprint.simhash,
          feature_vector: page.fingerprint.feature_vector,
          url_pattern: page.fingerprint.url_pattern,
        });

        // Merge integrations from fingerprints
        if (page.fingerprint.integrations) {
          for (const int of page.fingerprint.integrations) {
            if (int.vendor !== '__platform__' && !seenIntegrations.has(int.vendor)) {
              seenIntegrations.add(int.vendor);
              allIntegrations.push(int);
            }
          }
        }
      }
    }

    return {
      source,
      scan_type: 'full_dashboard',
      captured_at: new Date().toISOString(),
      pages_scanned: pages.length,
      page_map: pageMap,
      tables: allTables.slice(0, 100),
      metrics: allMetrics.slice(0, 200),
      active_modules: allModules.slice(0, 200),
      raw_text_snippets: allSnippets.slice(0, 100),
      navigation: pageMap.map(p => p.label),
      fingerprints: allFingerprints,
      integrations: allIntegrations,
    };
  }

  // ── Toggle raw JSON view ───────────────────────────────────────────

  toggleRawBtn.addEventListener('click', () => {
    showingRaw = !showingRaw;
    if (showingRaw) {
      rawContent.classList.remove('hidden');
      previewContent.classList.add('hidden');
      toggleRawBtn.textContent = 'Formatted';
    } else {
      rawContent.classList.add('hidden');
      previewContent.classList.remove('hidden');
      toggleRawBtn.textContent = 'Raw JSON';
    }
  });

  // ── Submit ─────────────────────────────────────────────────────────

  submitBtn.addEventListener('click', async () => {
    if (!anonymizedData) return;
    submitBtn.disabled = true;
    setStatus('Submitting to nur...', 'working');

    try {
      const settings = await chrome.storage.sync.get({
        apiEndpoint: 'https://nur.saramena.us/contribute/submit',
      });

      // Determine which endpoint to use based on data type
      let endpoint = settings.apiEndpoint; // default: /contribute/submit
      if (anonymizedData.scan_type === 'full_dashboard' ||
          anonymizedData.scan_type === 'full' ||
          anonymizedData.scan_type === 'single' ||
          anonymizedData.fingerprints ||
          anonymizedData.fingerprint ||
          anonymizedData.page_fingerprints ||
          anonymizedData.active_modules) {
        endpoint = settings.apiEndpoint.replace(/\/contribute\/submit$/, '/contribute/dashboard-scan');
      }

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          data: anonymizedData,
          extension_version: chrome.runtime.getManifest().version,
          submitted_at: new Date().toISOString(),
        }),
      });

      if (response.ok) {
        setStatus('Submitted successfully. Thank you!', 'success');
      } else {
        const errText = await response.text();
        setStatus(`Submission failed (${response.status}): ${errText}`, 'error');
        submitBtn.disabled = false;
      }
    } catch (err) {
      setStatus(`Submission failed: ${err.message}`, 'error');
      submitBtn.disabled = false;
    }
  });

  // ── UI Helpers ─────────────────────────────────────────────────────

  function setStatus(message, type) {
    statusMessage.textContent = message;
    statusMessage.className = `status-message status-${type}`;
  }

  function setProgress(pct, text) {
    progressBar.style.width = `${pct}%`;
    progressText.textContent = text;
  }

  function setProgressDetail(text) {
    progressDetail.textContent = text;
  }

  function resetScanUI() {
    scanRunning = false;
    captureBtn.disabled = false;
    fullscanBtn.disabled = false;
  }

  /**
   * Render the anonymized data in a human-readable preview.
   */
  function renderPreview(data, report, pagesCaptured) {
    let html = '';

    // Source info
    html += `<div class="preview-section">`;
    html += `<div class="preview-label">Source</div>`;
    html += `<div class="preview-value safe">${esc(data.source || '')}</div>`;
    if (data.scan_type === 'full_dashboard') {
      html += `<div class="preview-label">Scan Type</div>`;
      html += `<div class="preview-value safe">Full Dashboard Scan</div>`;
    }
    html += `<div class="preview-label">Captured</div>`;
    html += `<div class="preview-value safe">${esc(data.captured_at || '')}</div>`;
    html += `</div>`;

    // Page map (for full scans)
    if (data.page_map && data.page_map.length > 0) {
      html += `<div class="preview-section">`;
      html += `<div class="preview-label">Pages Scanned (${data.page_map.length})</div>`;
      data.page_map.forEach((p) => {
        html += `<div class="preview-value safe">${esc(p.label)} <span class="page-path">${esc(p.path)}</span></div>`;
      });
      html += `</div>`;
    }

    // Active modules — the shelfware detection data
    if (data.active_modules && data.active_modules.length > 0) {
      html += `<div class="preview-section">`;
      html += `<div class="preview-label">Modules Detected (${data.active_modules.length})</div>`;
      const active = data.active_modules.filter(m => m.status === 'active');
      const inactive = data.active_modules.filter(m => m.status === 'inactive');
      if (active.length > 0) {
        html += `<div class="preview-sublabel">${active.length} active</div>`;
        active.forEach(m => {
          html += `<div class="preview-value module-active">${esc(m.name || m)}</div>`;
        });
      }
      if (inactive.length > 0) {
        html += `<div class="preview-sublabel">${inactive.length} inactive / locked</div>`;
        inactive.forEach(m => {
          html += `<div class="preview-value module-inactive">${esc(m.name || m)}</div>`;
        });
      }
      html += `</div>`;
    }

    // Metrics
    if (data.metrics && data.metrics.length > 0) {
      html += `<div class="preview-section">`;
      html += `<div class="preview-label">Metrics (${data.metrics.length})</div>`;
      data.metrics.slice(0, 20).forEach(m => {
        html += `<div class="preview-value"><span class="metric-label">${esc(m.label)}</span>: <span class="metric-value">${esc(m.value)}</span></div>`;
      });
      if (data.metrics.length > 20) {
        html += `<div class="preview-more">... and ${data.metrics.length - 20} more metrics</div>`;
      }
      html += `</div>`;
    }

    // Tables
    if (data.tables && data.tables.length > 0) {
      html += `<div class="preview-section">`;
      html += `<div class="preview-label">Tables (${data.tables.length})</div>`;
      data.tables.slice(0, 5).forEach((table, i) => {
        const pageLabel = table.page ? ` (${table.page})` : '';
        html += `<div class="preview-table-label">Table ${i + 1}${pageLabel}: ${table.headers?.length || 0} cols, ${table.rows?.length || 0} rows</div>`;
        if (table.headers?.length > 0) {
          html += `<div class="preview-value safe">Headers: ${table.headers.map(esc).join(' | ')}</div>`;
        }
        (table.rows || []).slice(0, 3).forEach(row => {
          html += `<div class="preview-value">${row.map(esc).join(' | ')}</div>`;
        });
        if ((table.rows?.length || 0) > 3) {
          html += `<div class="preview-more">... and ${table.rows.length - 3} more rows</div>`;
        }
      });
      if (data.tables.length > 5) {
        html += `<div class="preview-more">... and ${data.tables.length - 5} more tables</div>`;
      }
      html += `</div>`;
    }

    // Text snippets
    if (data.raw_text_snippets && data.raw_text_snippets.length > 0) {
      html += `<div class="preview-section">`;
      html += `<div class="preview-label">Text Snippets (${data.raw_text_snippets.length})</div>`;
      data.raw_text_snippets.slice(0, 10).forEach(s => {
        html += `<div class="preview-value">${esc(s)}</div>`;
      });
      if (data.raw_text_snippets.length > 10) {
        html += `<div class="preview-more">... and ${data.raw_text_snippets.length - 10} more</div>`;
      }
      html += `</div>`;
    }

    // Fingerprint data
    if (data.fingerprint) {
      const fp = data.fingerprint;
      html += `<div class="preview-section">`;
      html += `<div class="preview-label">Structural Fingerprint</div>`;
      html += `<div class="preview-value safe">SimHash: <span class="metric-value">${esc(fp.simhash)}</span></div>`;
      html += `<div class="preview-value safe">URL Pattern: ${esc(fp.url_pattern)}</div>`;
      html += `<div class="preview-value safe">Skeleton: ${fp.skeleton_node_count} nodes, depth ${fp.skeleton_depth}</div>`;

      // Feature vector highlights
      if (fp.feature_vector) {
        const fv = fp.feature_vector;
        const highlights = [];
        if (fv.table_count > 0) highlights.push(`${fv.table_count} tables`);
        if (fv.canvas_count > 0) highlights.push(`${fv.canvas_count} charts`);
        if (fv.card_count > 0) highlights.push(`${fv.card_count} cards`);
        if (fv.metric_count > 0) highlights.push(`${fv.metric_count} metric widgets`);
        if (fv.form_count > 0) highlights.push(`${fv.form_count} forms`);
        if (fv.api_indicator_count > 0) highlights.push(`${fv.api_indicator_count} integration indicators`);
        if (highlights.length > 0) {
          html += `<div class="preview-value safe">Structure: ${highlights.join(', ')}</div>`;
        }
      }

      // Integrations detected
      if (fp.integrations && fp.integrations.length > 0) {
        html += `<div class="preview-sublabel">Integrations Detected (${fp.integrations.length})</div>`;
        fp.integrations.forEach(int => {
          if (int.vendor === '__platform__') {
            html += `<div class="preview-value safe">Integration page found at ${esc(int.path || '')}</div>`;
          } else {
            const statusClass = int.status === 'connected' ? 'module-active' :
                                int.status === 'disconnected' ? 'module-inactive' : '';
            html += `<div class="preview-value ${statusClass}">${esc(int.vendor)} [${int.status}] (${esc(int.context)})</div>`;
          }
        });
      }
      html += `</div>`;
    }

    // Anonymization report
    if (report && report.length > 0) {
      html += `<div class="preview-section anonymization-report">`;
      html += `<div class="preview-label">Anonymization Report</div>`;
      const typeCounts = {};
      report.forEach(r => { typeCounts[r.type] = (typeCounts[r.type] || 0) + 1; });
      Object.entries(typeCounts).forEach(([type, count]) => {
        html += `<div class="preview-value stripped">${count}x ${type} stripped/anonymized</div>`;
      });
      html += `</div>`;
    }

    previewContent.innerHTML = html;
    rawContent.textContent = JSON.stringify(data, null, 2);
    pageCount.textContent = pagesCaptured > 1 ? `${pagesCaptured} pages` : '';
  }

  // ── Compare / Utilization Report ─────────────────────────────────

  compareBtn.addEventListener('click', async () => {
    if (!anonymizedData) return;

    // First, try to get peer aggregate from nur API
    const vendor = anonymizedData.source;
    let peerData = null;

    try {
      const settings = await chrome.storage.sync.get({
        apiEndpoint: 'https://nur.saramena.us/contribute/submit',
      });
      const baseUrl = settings.apiEndpoint.replace(/\/contribute\/submit$/, '');
      const response = await fetch(`${baseUrl}/api/compare/${encodeURIComponent(vendor)}`, {
        headers: { 'Content-Type': 'application/json' },
      });
      if (response.ok) {
        peerData = await response.json();
      }
    } catch {
      // No peer data available — fall back to self-assessment
    }

    // Show comparison or self-assessment
    previewPanel.classList.add('hidden');
    comparePanel.classList.remove('hidden');

    if (peerData && peerData.total_scans > 0) {
      const report = Compare.compare(anonymizedData, peerData);
      compareContent.innerHTML = Compare.renderComparison(report);
    } else {
      // No peer data yet — show self-assessment
      const assessment = Compare.selfAssess(anonymizedData);
      compareContent.innerHTML = Compare.renderSelfAssessment(assessment);
    }
  });

  backToPreviewBtn.addEventListener('click', () => {
    comparePanel.classList.add('hidden');
    previewPanel.classList.remove('hidden');
  });

  function esc(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
})();
