/**
 * compare.js — Dashboard comparison engine for nur collector
 *
 * Compares a user's scan against aggregate peer data to answer:
 *   "What am I NOT using that my peers ARE using?"
 *
 * Like a burp-style diff, but for vendor feature utilization.
 * Shows gaps, unused modules, and features peers find valuable.
 */

const Compare = (() => {

  /**
   * Compare a user's scan against aggregate peer data.
   *
   * @param {Object} userScan - The user's dashboard scan (anonymized)
   * @param {Object} peerAggregate - Aggregate data from nur API
   *   Expected format:
   *   {
   *     vendor: "crowdstrike.com",
   *     total_scans: 47,
   *     modules: [
   *       { name: "Endpoint Detection", adoption_pct: 95, avg_status: "active" },
   *       { name: "Spotlight (Vuln Mgmt)", adoption_pct: 62, avg_status: "active" },
   *       ...
   *     ],
   *     metrics_seen: [
   *       { label: "Total Detections", seen_by_pct: 88 },
   *       ...
   *     ],
   *     pages_seen: [
   *       { path: "/dashboards/overview", visited_by_pct: 100 },
   *       { path: "/investigate/events", visited_by_pct: 73 },
   *       ...
   *     ]
   *   }
   *
   * @returns {Object} Comparison report
   */
  function compare(userScan, peerAggregate) {
    const report = {
      vendor: userScan.source || peerAggregate.vendor || 'Unknown',
      scanned_at: userScan.captured_at,
      peer_count: peerAggregate.total_scans || 0,
      summary: {},
      modules: { using: [], not_using: [], inactive: [], unique_to_you: [] },
      metrics: { seen: [], missing: [] },
      pages: { visited: [], not_visited: [] },
      recommendations: [],
    };

    // ── Module comparison ──────────────────────────────────────────

    const userModuleNames = new Set();
    const userActiveModules = new Set();
    const userInactiveModules = new Set();

    if (userScan.active_modules) {
      for (const m of userScan.active_modules) {
        const name = (typeof m === 'string') ? m : m.name;
        const status = (typeof m === 'string') ? 'active' : m.status;
        userModuleNames.add(normalizeModuleName(name));
        if (status === 'active') {
          userActiveModules.add(normalizeModuleName(name));
        } else {
          userInactiveModules.add(normalizeModuleName(name));
        }
      }
    }

    if (peerAggregate.modules) {
      for (const peerModule of peerAggregate.modules) {
        const normalized = normalizeModuleName(peerModule.name);
        const adoption = peerModule.adoption_pct || 0;

        if (userActiveModules.has(normalized)) {
          // You're using it — good
          report.modules.using.push({
            name: peerModule.name,
            your_status: 'active',
            peer_adoption: adoption,
          });
        } else if (userInactiveModules.has(normalized)) {
          // You have it but it's inactive/locked
          report.modules.inactive.push({
            name: peerModule.name,
            your_status: 'inactive',
            peer_adoption: adoption,
          });
        } else {
          // You don't have it at all
          report.modules.not_using.push({
            name: peerModule.name,
            peer_adoption: adoption,
          });
        }
      }

      // Check for modules you have that peers don't
      for (const name of userModuleNames) {
        const peerNames = new Set(
          peerAggregate.modules.map(m => normalizeModuleName(m.name))
        );
        if (!peerNames.has(name)) {
          report.modules.unique_to_you.push({ name });
        }
      }

      // Sort not_using by peer adoption (highest first = biggest gaps)
      report.modules.not_using.sort((a, b) => b.peer_adoption - a.peer_adoption);
      report.modules.inactive.sort((a, b) => b.peer_adoption - a.peer_adoption);
    }

    // ── Metrics comparison ─────────────────────────────────────────

    const userMetricLabels = new Set();
    if (userScan.metrics) {
      for (const m of userScan.metrics) {
        userMetricLabels.add(normalizeLabel(m.label));
      }
    }

    if (peerAggregate.metrics_seen) {
      for (const pm of peerAggregate.metrics_seen) {
        const normalized = normalizeLabel(pm.label);
        if (userMetricLabels.has(normalized)) {
          report.metrics.seen.push({
            label: pm.label,
            seen_by_pct: pm.seen_by_pct,
          });
        } else {
          report.metrics.missing.push({
            label: pm.label,
            seen_by_pct: pm.seen_by_pct,
          });
        }
      }
      report.metrics.missing.sort((a, b) => b.seen_by_pct - a.seen_by_pct);
    }

    // ── Page/section comparison ────────────────────────────────────

    const userPaths = new Set();
    if (userScan.page_map) {
      for (const p of userScan.page_map) {
        userPaths.add(normalizePath(p.path));
      }
    }

    if (peerAggregate.pages_seen) {
      for (const pp of peerAggregate.pages_seen) {
        const normalized = normalizePath(pp.path);
        if (userPaths.has(normalized)) {
          report.pages.visited.push({
            path: pp.path,
            visited_by_pct: pp.visited_by_pct,
          });
        } else {
          report.pages.not_visited.push({
            path: pp.path,
            visited_by_pct: pp.visited_by_pct,
          });
        }
      }
      report.pages.not_visited.sort((a, b) => b.visited_by_pct - a.visited_by_pct);
    }

    // ── Summary ────────────────────────────────────────────────────

    const totalPeerModules = peerAggregate.modules?.length || 0;
    const youUse = report.modules.using.length;
    const youMiss = report.modules.not_using.length;
    const youInactive = report.modules.inactive.length;

    report.summary = {
      modules_you_use: youUse,
      modules_you_dont_use: youMiss,
      modules_inactive: youInactive,
      total_peer_modules: totalPeerModules,
      utilization_pct: totalPeerModules > 0
        ? Math.round((youUse / totalPeerModules) * 100)
        : 0,
      peer_count: peerAggregate.total_scans || 0,
    };

    // ── Recommendations ────────────────────────────────────────────

    // High-adoption modules you're not using
    const highAdoptionGaps = report.modules.not_using
      .filter(m => m.peer_adoption >= 60);
    if (highAdoptionGaps.length > 0) {
      report.recommendations.push({
        type: 'high_adoption_gap',
        message: `${highAdoptionGaps.length} modules used by 60%+ of peers that you don't have`,
        modules: highAdoptionGaps.map(m => `${m.name} (${m.peer_adoption}% of peers)`),
      });
    }

    // Modules you're paying for but not using (inactive)
    if (report.modules.inactive.length > 0) {
      report.recommendations.push({
        type: 'shelfware',
        message: `${report.modules.inactive.length} modules you have but aren't using`,
        modules: report.modules.inactive.map(m => `${m.name} (${m.peer_adoption}% of peers use it)`),
      });
    }

    // Pages peers visit that you didn't
    const missedPages = report.pages.not_visited.filter(p => p.visited_by_pct >= 50);
    if (missedPages.length > 0) {
      report.recommendations.push({
        type: 'missed_sections',
        message: `${missedPages.length} dashboard sections visited by 50%+ of peers that you haven't explored`,
        pages: missedPages.map(p => `${p.path} (${p.visited_by_pct}% of peers)`),
      });
    }

    return report;
  }

  // ── Normalization helpers ──────────────────────────────────────────

  function normalizeModuleName(name) {
    return (name || '').toLowerCase().trim().replace(/\s+/g, ' ');
  }

  function normalizeLabel(label) {
    return (label || '').toLowerCase().trim().replace(/\s+/g, ' ');
  }

  function normalizePath(path) {
    return (path || '').toLowerCase().replace(/\/+$/, '').replace(/\/\[.*?\]/g, '');
  }

  // ── Local scan storage ─────────────────────────────────────────────

  /**
   * Save a scan locally for later comparison.
   */
  async function saveScan(scan) {
    const key = `scan_${scan.source}_${Date.now()}`;
    const scans = await getScans(scan.source);
    scans.push({ key, timestamp: Date.now(), data: scan });

    // Keep last 10 scans per vendor
    const trimmed = scans.slice(-10);
    await chrome.storage.local.set({ [`scans_${scan.source}`]: trimmed });
    return key;
  }

  /**
   * Get all saved scans for a vendor.
   */
  async function getScans(source) {
    const result = await chrome.storage.local.get(`scans_${source}`);
    return result[`scans_${source}`] || [];
  }

  /**
   * Compare two local scans (your own scans over time).
   * Shows what changed: new modules, removed modules, metric changes.
   */
  function diffScans(scanA, scanB) {
    const diff = {
      added_modules: [],
      removed_modules: [],
      status_changes: [],
      metric_changes: [],
    };

    const modulesA = new Map();
    const modulesB = new Map();

    for (const m of (scanA.active_modules || [])) {
      const name = typeof m === 'string' ? m : m.name;
      const status = typeof m === 'string' ? 'active' : m.status;
      modulesA.set(normalizeModuleName(name), { name, status });
    }
    for (const m of (scanB.active_modules || [])) {
      const name = typeof m === 'string' ? m : m.name;
      const status = typeof m === 'string' ? 'active' : m.status;
      modulesB.set(normalizeModuleName(name), { name, status });
    }

    // Added in B that weren't in A
    for (const [key, val] of modulesB) {
      if (!modulesA.has(key)) {
        diff.added_modules.push(val);
      } else {
        const prev = modulesA.get(key);
        if (prev.status !== val.status) {
          diff.status_changes.push({
            name: val.name,
            from: prev.status,
            to: val.status,
          });
        }
      }
    }

    // Removed in B that were in A
    for (const [key, val] of modulesA) {
      if (!modulesB.has(key)) {
        diff.removed_modules.push(val);
      }
    }

    return diff;
  }

  /**
   * Generate a utilization summary from a scan (without peer data).
   * Uses the scan's own active/inactive module data.
   */
  function selfAssess(scan) {
    const modules = scan.active_modules || [];
    const active = modules.filter(m => (typeof m === 'string') || m.status === 'active');
    const inactive = modules.filter(m => typeof m !== 'string' && m.status === 'inactive');

    return {
      vendor: scan.source,
      total_modules_detected: modules.length,
      active_count: active.length,
      inactive_count: inactive.length,
      utilization_pct: modules.length > 0
        ? Math.round((active.length / modules.length) * 100)
        : 0,
      active_modules: active.map(m => typeof m === 'string' ? m : m.name),
      inactive_modules: inactive.map(m => m.name),
      pages_scanned: scan.pages_scanned || 1,
      metrics_captured: (scan.metrics || []).length,
      tables_captured: (scan.tables || []).length,
    };
  }

  // ── Render comparison as HTML ──────────────────────────────────────

  function renderComparison(report) {
    let html = '';

    // Summary header
    html += `<div class="compare-summary">`;
    html += `<div class="compare-vendor">${esc(report.vendor)}</div>`;
    html += `<div class="compare-stat">`;
    html += `<span class="compare-big-number">${report.summary.utilization_pct}%</span>`;
    html += `<span class="compare-stat-label">feature utilization vs peers</span>`;
    html += `</div>`;
    html += `<div class="compare-meta">`;
    html += `Compared against ${report.summary.peer_count} peer scans`;
    html += `</div>`;
    html += `</div>`;

    // Modules you're using (collapsed by default)
    if (report.modules.using.length > 0) {
      html += `<div class="compare-section">`;
      html += `<div class="compare-section-header good">`;
      html += `${report.modules.using.length} modules you're using`;
      html += `</div>`;
      report.modules.using.forEach(m => {
        html += `<div class="compare-item good">`;
        html += `${esc(m.name)} <span class="compare-peer-pct">${m.peer_adoption}% of peers</span>`;
        html += `</div>`;
      });
      html += `</div>`;
    }

    // SHELFWARE: Modules you have but aren't using
    if (report.modules.inactive.length > 0) {
      html += `<div class="compare-section">`;
      html += `<div class="compare-section-header warning">`;
      html += `${report.modules.inactive.length} modules you have but aren't using (shelfware)`;
      html += `</div>`;
      report.modules.inactive.forEach(m => {
        html += `<div class="compare-item warning">`;
        html += `${esc(m.name)} <span class="compare-peer-pct">${m.peer_adoption}% of peers use this</span>`;
        html += `</div>`;
      });
      html += `</div>`;
    }

    // GAPS: Modules peers use that you don't have
    if (report.modules.not_using.length > 0) {
      html += `<div class="compare-section">`;
      html += `<div class="compare-section-header gap">`;
      html += `${report.modules.not_using.length} modules peers use that you don't have`;
      html += `</div>`;
      report.modules.not_using.forEach(m => {
        const bar = m.peer_adoption;
        html += `<div class="compare-item gap">`;
        html += `<div class="compare-item-name">${esc(m.name)}</div>`;
        html += `<div class="compare-bar-container">`;
        html += `<div class="compare-bar" style="width: ${bar}%"></div>`;
        html += `<span class="compare-bar-label">${bar}% adoption</span>`;
        html += `</div>`;
        html += `</div>`;
      });
      html += `</div>`;
    }

    // Recommendations
    if (report.recommendations.length > 0) {
      html += `<div class="compare-section">`;
      html += `<div class="compare-section-header reco">Recommendations</div>`;
      report.recommendations.forEach(r => {
        html += `<div class="compare-reco">`;
        html += `<div class="compare-reco-msg">${esc(r.message)}</div>`;
        const items = r.modules || r.pages || [];
        items.slice(0, 5).forEach(item => {
          html += `<div class="compare-reco-item">${esc(item)}</div>`;
        });
        if (items.length > 5) {
          html += `<div class="compare-more">... and ${items.length - 5} more</div>`;
        }
        html += `</div>`;
      });
      html += `</div>`;
    }

    return html;
  }

  function renderSelfAssessment(assessment) {
    let html = '';

    html += `<div class="compare-summary">`;
    html += `<div class="compare-vendor">${esc(assessment.vendor)}</div>`;
    html += `<div class="compare-stat">`;
    html += `<span class="compare-big-number">${assessment.utilization_pct}%</span>`;
    html += `<span class="compare-stat-label">of detected features active</span>`;
    html += `</div>`;
    html += `<div class="compare-meta">`;
    html += `${assessment.total_modules_detected} modules detected across ${assessment.pages_scanned} pages`;
    html += `</div>`;
    html += `</div>`;

    if (assessment.active_modules.length > 0) {
      html += `<div class="compare-section">`;
      html += `<div class="compare-section-header good">${assessment.active_count} active</div>`;
      assessment.active_modules.forEach(name => {
        html += `<div class="compare-item good">${esc(name)}</div>`;
      });
      html += `</div>`;
    }

    if (assessment.inactive_modules.length > 0) {
      html += `<div class="compare-section">`;
      html += `<div class="compare-section-header warning">${assessment.inactive_count} inactive / shelfware</div>`;
      assessment.inactive_modules.forEach(name => {
        html += `<div class="compare-item warning">${esc(name)}</div>`;
      });
      html += `</div>`;
    }

    html += `<div class="compare-section">`;
    html += `<div class="compare-section-header">Data captured</div>`;
    html += `<div class="compare-item">${assessment.metrics_captured} metrics</div>`;
    html += `<div class="compare-item">${assessment.tables_captured} tables</div>`;
    html += `</div>`;

    if (assessment.inactive_count > 0) {
      html += `<div class="compare-section">`;
      html += `<div class="compare-section-header reco">Submit to nur to see how peers use these modules</div>`;
      html += `</div>`;
    }

    return html;
  }

  function esc(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
  }

  return {
    compare,
    diffScans,
    selfAssess,
    saveScan,
    getScans,
    renderComparison,
    renderSelfAssessment,
  };
})();
