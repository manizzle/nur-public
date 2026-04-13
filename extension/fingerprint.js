/**
 * fingerprint.js — Structural DOM fingerprinting for nur collector
 *
 * Creates privacy-preserving fingerprints of dashboard pages by:
 * 1. Stripping ALL text/data content from the DOM
 * 2. Keeping only the structural skeleton (tags, classes, element counts)
 * 3. Computing a SimHash for fuzzy matching across users
 * 4. Extracting a fixed-length feature vector (counts only — no PII possible)
 *
 * Two users on the same CrowdStrike "Endpoint Detection" page will produce
 * nearly identical fingerprints even though their data is completely different.
 *
 * These fingerprints are:
 * - Inherently anonymized (structure only, no content)
 * - Directly aggregatable with Pedersen commitments
 * - Usable for blind category discovery (same hash from 3+ orgs = quorum)
 */

const Fingerprint = (() => {

  // ── Structural Skeleton Extraction ────────────────────────────────

  /**
   * Extract the structural skeleton of a DOM subtree.
   * Strips all text content. Keeps tag names, meaningful class names,
   * and child structure up to a configurable depth.
   *
   * @param {Element} root - The root element to fingerprint
   * @param {number} maxDepth - How deep to traverse (default 8)
   * @returns {Object} Structural skeleton
   */
  function extractSkeleton(root, maxDepth = 8) {
    return _walk(root, 0, maxDepth);
  }

  function _walk(el, depth, maxDepth) {
    if (!el || depth > maxDepth) return null;
    if (el.nodeType !== Node.ELEMENT_NODE) return null;

    // Skip script, style, svg internals, hidden elements
    const tag = el.tagName.toLowerCase();
    if (['script', 'style', 'noscript', 'link', 'meta'].includes(tag)) return null;

    // Extract meaningful class names (strip dynamic/hash classes)
    const classes = _extractMeaningfulClasses(el);

    // Count children by type instead of recursing into huge lists
    const children = Array.from(el.children);
    let childSkeletons;

    if (children.length > 20) {
      // For large lists (table rows, list items), summarize instead of enumerating
      const typeCounts = {};
      children.forEach(c => {
        const ct = c.tagName.toLowerCase();
        typeCounts[ct] = (typeCounts[ct] || 0) + 1;
      });
      childSkeletons = [{ _summary: true, counts: typeCounts, total: children.length }];
    } else {
      childSkeletons = children
        .map(c => _walk(c, depth + 1, maxDepth))
        .filter(Boolean);
    }

    return {
      tag,
      classes,
      role: el.getAttribute('role') || undefined,
      childCount: children.length,
      children: childSkeletons.length > 0 ? childSkeletons : undefined,
    };
  }

  /**
   * Extract class names that are meaningful (not dynamic hashes).
   * Filters out: CSS module hashes, Tailwind utilities, random strings.
   * Keeps: semantic names like "dashboard-card", "nav-sidebar", "metric-widget".
   */
  function _extractMeaningfulClasses(el) {
    if (!el.className || typeof el.className !== 'string') return [];

    return el.className
      .trim()
      .split(/\s+/)
      .filter(cls => {
        // Skip empty
        if (!cls) return false;
        // Skip CSS module hashes (e.g., "header_a1b2c3", "styles__card--xyz")
        if (/[_-][a-zA-Z0-9]{5,}$/.test(cls)) return false;
        // Skip pure hex/hash classes
        if (/^[a-f0-9]{6,}$/i.test(cls)) return false;
        // Skip very short meaningless classes
        if (cls.length < 3) return false;
        // Skip Tailwind-style utilities (flex, p-4, text-sm, etc.)
        if (/^(flex|grid|p-|m-|text-|bg-|border-|rounded|w-|h-|gap-|space-|items-|justify-)/.test(cls)) return false;
        return true;
      })
      .slice(0, 3); // Keep max 3 meaningful classes
  }

  // ── Feature Vector Extraction ─────────────────────────────────────

  /**
   * Extract a fixed-length numeric feature vector from the current page.
   * These counts are inherently anonymized — no PII possible in element counts.
   * Directly committable with Pedersen commitments and aggregatable with running sums.
   *
   * @returns {Object} Feature vector with named dimensions
   */
  function extractFeatureVector() {
    const body = document.body;
    if (!body) return _emptyVector();

    return {
      // Layout structure
      table_count: body.querySelectorAll('table').length,
      form_count: body.querySelectorAll('form').length,
      input_count: body.querySelectorAll('input, select, textarea').length,
      button_count: body.querySelectorAll('button').length,

      // Data visualization
      canvas_count: body.querySelectorAll('canvas').length,  // charts
      svg_count: body.querySelectorAll('svg').length,        // vector graphics/icons
      iframe_count: body.querySelectorAll('iframe').length,   // embedded content

      // Navigation structure
      nav_count: body.querySelectorAll('nav, [role="navigation"]').length,
      nav_link_count: body.querySelectorAll('nav a, [role="navigation"] a').length,
      tab_count: body.querySelectorAll('[role="tab"], [class*="tab-item"]').length,
      menu_count: body.querySelectorAll('[role="menu"], [class*="dropdown-menu"]').length,

      // Dashboard widgets
      card_count: _countByClassPattern(['card', 'widget', 'panel', 'tile']),
      metric_count: _countByClassPattern(['metric', 'stat', 'kpi', 'counter', 'gauge']),
      alert_count: body.querySelectorAll('[role="alert"], [class*="alert"], [class*="notification"]').length,
      modal_count: body.querySelectorAll('[role="dialog"], [class*="modal"]').length,

      // Content structure
      heading_count: body.querySelectorAll('h1, h2, h3, h4').length,
      list_count: body.querySelectorAll('ul, ol').length,
      image_count: body.querySelectorAll('img').length,

      // Interactive elements
      toggle_count: body.querySelectorAll('[class*="toggle"], [class*="switch"], input[type="checkbox"]').length,
      search_count: body.querySelectorAll('input[type="search"], [class*="search"]').length,

      // Depth / complexity
      max_dom_depth: _measureMaxDepth(body, 0, 20),
      total_elements: body.querySelectorAll('*').length,

      // Integration indicators
      api_indicator_count: _countByClassPattern(['integration', 'connector', 'api', 'webhook', 'plugin', 'addon', 'extension']),
      data_source_count: _countByClassPattern(['source', 'datasource', 'data-source', 'feed', 'input-source', 'log-source']),
      connection_status_count: _countByClassPattern(['connected', 'disconnected', 'status-indicator', 'health-check']),
    };
  }

  function _emptyVector() {
    return {
      table_count: 0, form_count: 0, input_count: 0, button_count: 0,
      canvas_count: 0, svg_count: 0, iframe_count: 0,
      nav_count: 0, nav_link_count: 0, tab_count: 0, menu_count: 0,
      card_count: 0, metric_count: 0, alert_count: 0, modal_count: 0,
      heading_count: 0, list_count: 0, image_count: 0,
      toggle_count: 0, search_count: 0,
      max_dom_depth: 0, total_elements: 0,
      api_indicator_count: 0, data_source_count: 0, connection_status_count: 0,
    };
  }

  function _countByClassPattern(patterns) {
    let count = 0;
    const selector = patterns.map(p => `[class*="${p}"]`).join(', ');
    try {
      count = document.querySelectorAll(selector).length;
    } catch { /* invalid selector edge case */ }
    return count;
  }

  function _measureMaxDepth(el, current, limit) {
    if (!el || current >= limit) return current;
    let max = current;
    for (const child of el.children) {
      const d = _measureMaxDepth(child, current + 1, limit);
      if (d > max) max = d;
    }
    return max;
  }

  // ── Integration Detection ─────────────────────────────────────────

  /**
   * Detect integrations/connections visible on the current page.
   * Looks for integration status indicators, connected services,
   * API endpoints, data sources, and webhook configurations.
   *
   * Returns anonymized integration fingerprints — vendor names kept
   * (they're public), but connection details stripped.
   */
  function detectIntegrations() {
    const integrations = [];
    const seen = new Set();

    // Known vendor/product name patterns to look for in integration contexts
    const vendorPatterns = [
      'splunk', 'crowdstrike', 'sentinel', 'microsoft', 'palo alto', 'fortinet',
      'cisco', 'okta', 'ping', 'sailpoint', 'cyberark', 'hashicorp', 'vault',
      'aws', 'azure', 'gcp', 'google cloud', 'datadog', 'elastic', 'kibana',
      'jira', 'servicenow', 'slack', 'teams', 'pagerduty', 'opsgenie',
      'qualys', 'tenable', 'rapid7', 'snyk', 'veracode', 'checkmarx',
      'zscaler', 'netskope', 'cloudflare', 'akamai', 'imperva',
      'carbon black', 'vmware', 'tanium', 'wiz', 'orca', 'lacework',
      'prisma', 'proofpoint', 'mimecast', 'abnormal', 'knowbe4',
      'darktrace', 'vectra', 'exabeam', 'securonix', 'sumo logic',
      'chronicle', 'siemplify', 'phantom', 'demisto', 'xsoar',
      'syslog', 'snmp', 'ldap', 'saml', 'oauth', 'oidc', 'scim',
      's3', 'kafka', 'rabbitmq', 'redis', 'postgres', 'mysql',
    ];

    // Search in integration-related page sections
    const integrationSelectors = [
      '[class*="integration"]', '[class*="connector"]',
      '[class*="plugin"]', '[class*="addon"]', '[class*="extension"]',
      '[class*="data-source"]', '[class*="datasource"]',
      '[class*="connection"]', '[class*="linked"]',
      '[class*="api-key"]', '[class*="webhook"]',
      '[class*="source"]', '[class*="destination"]',
    ];

    const integrationEls = document.querySelectorAll(integrationSelectors.join(', '));

    integrationEls.forEach(el => {
      const text = el.textContent.toLowerCase();

      // Check for status indicators
      const statusEl = el.querySelector(
        '[class*="status"], [class*="badge"], [class*="indicator"], [class*="connected"], [class*="active"]'
      );
      let status = 'unknown';
      if (statusEl) {
        const statusText = statusEl.textContent.toLowerCase();
        const statusClass = (statusEl.className || '').toLowerCase();
        if (/connected|active|enabled|success|running|healthy/i.test(statusText + statusClass)) {
          status = 'connected';
        } else if (/disconnected|inactive|disabled|error|failed|unhealthy/i.test(statusText + statusClass)) {
          status = 'disconnected';
        }
      }

      // Match vendor names
      for (const vendor of vendorPatterns) {
        if (text.includes(vendor) && !seen.has(vendor)) {
          seen.add(vendor);
          integrations.push({
            vendor: vendor,
            status: status,
            context: _getIntegrationContext(el),
          });
        }
      }
    });

    // Also check navigation for integration-related pages
    const navLinks = document.querySelectorAll('nav a, [class*="sidebar"] a, [class*="menu"] a');
    navLinks.forEach(link => {
      const text = link.textContent.toLowerCase();
      const href = (link.getAttribute('href') || '').toLowerCase();
      if (/integrat|connect|plugin|addon|extension|api|webhook|source/i.test(text + href)) {
        if (!seen.has('__has_integration_page__')) {
          seen.add('__has_integration_page__');
          integrations.push({
            vendor: '__platform__',
            status: 'has_integration_page',
            context: 'navigation',
            path: href,
          });
        }
      }
    });

    return integrations;
  }

  /**
   * Get anonymized context about an integration element.
   * Captures the type of integration (API, webhook, data source, etc.)
   * without capturing any connection details.
   */
  function _getIntegrationContext(el) {
    const classes = (el.className || '').toLowerCase();
    if (/webhook/.test(classes)) return 'webhook';
    if (/api/.test(classes)) return 'api';
    if (/data.?source|log.?source/.test(classes)) return 'data_source';
    if (/siem|log/.test(classes)) return 'siem_integration';
    if (/soar|orchestrat/.test(classes)) return 'soar_integration';
    if (/sso|saml|auth/.test(classes)) return 'auth_integration';
    if (/ticket|itsm|incident/.test(classes)) return 'ticketing_integration';
    if (/notification|alert/.test(classes)) return 'notification_integration';
    return 'general';
  }

  // ── SimHash for Fuzzy Matching ────────────────────────────────────

  /**
   * Compute a SimHash of the structural skeleton.
   * SimHash produces similar hashes for similar inputs — two users on
   * the same CrowdStrike page get nearly identical hashes even with
   * different data, browser sizes, or minor UI variations.
   *
   * Uses 64-bit SimHash via two 32-bit halves (JS doesn't have 64-bit ints).
   *
   * @param {Object} skeleton - Structural skeleton from extractSkeleton()
   * @returns {string} Hex string of the SimHash
   */
  function computeSimHash(skeleton) {
    // Convert skeleton to shingles (structural n-grams)
    const shingles = _skeletonToShingles(skeleton);

    // SimHash: weighted bit voting
    const bits = 64;
    const votes = new Array(bits).fill(0);

    for (const shingle of shingles) {
      const hash = _fnv1a64(shingle);
      for (let i = 0; i < bits; i++) {
        const byteIndex = Math.floor(i / 8);
        const bitIndex = i % 8;
        if ((hash[byteIndex] >> bitIndex) & 1) {
          votes[i] += 1;
        } else {
          votes[i] -= 1;
        }
      }
    }

    // Convert votes to bits
    const result = new Uint8Array(8);
    for (let i = 0; i < bits; i++) {
      if (votes[i] > 0) {
        const byteIndex = Math.floor(i / 8);
        const bitIndex = i % 8;
        result[byteIndex] |= (1 << bitIndex);
      }
    }

    return Array.from(result).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Convert a skeleton to structural shingles (n-grams of the tree path).
   * Each shingle is a string like "div.card > h3 > span" representing
   * a structural path in the DOM.
   */
  function _skeletonToShingles(skeleton, parentPath = '', shingles = []) {
    if (!skeleton) return shingles;

    const nodeId = skeleton.tag +
      (skeleton.classes?.length > 0 ? '.' + skeleton.classes.join('.') : '') +
      (skeleton.role ? `[${skeleton.role}]` : '');

    const path = parentPath ? `${parentPath} > ${nodeId}` : nodeId;

    // Add this path as a shingle
    shingles.push(path);

    // Add child count as a shingle (structural fingerprint)
    if (skeleton.childCount > 0) {
      shingles.push(`${path}#${skeleton.childCount}`);
    }

    // Recurse into children
    if (skeleton.children) {
      for (const child of skeleton.children) {
        if (child._summary) {
          // Summarized children — add count signature
          const sig = Object.entries(child.counts)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([tag, count]) => `${tag}*${count}`)
            .join('+');
          shingles.push(`${path} > [${sig}]`);
        } else {
          _skeletonToShingles(child, path, shingles);
        }
      }
    }

    return shingles;
  }

  /**
   * FNV-1a hash producing 8 bytes (64-bit).
   * Fast, good distribution, no crypto overhead needed here since
   * this is structural data that's already content-free.
   */
  function _fnv1a64(str) {
    // FNV-1a 64-bit as two 32-bit halves
    let h1 = 0x811c9dc5;
    let h2 = 0xcbf29ce4;

    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      h1 ^= c;
      h2 ^= c;
      // Multiply by FNV prime 0x01000193 (split across halves)
      h1 = Math.imul(h1, 0x01000193);
      h2 = Math.imul(h2, 0x00000100) ^ Math.imul(h1, 0x93);
    }

    const result = new Uint8Array(8);
    result[0] = h1 & 0xff;
    result[1] = (h1 >> 8) & 0xff;
    result[2] = (h1 >> 16) & 0xff;
    result[3] = (h1 >> 24) & 0xff;
    result[4] = h2 & 0xff;
    result[5] = (h2 >> 8) & 0xff;
    result[6] = (h2 >> 16) & 0xff;
    result[7] = (h2 >> 24) & 0xff;
    return result;
  }

  /**
   * Compute Hamming distance between two SimHashes.
   * Lower distance = more structurally similar pages.
   * Threshold of ~10 bits (out of 64) = same page, different data.
   *
   * @param {string} hashA - Hex string
   * @param {string} hashB - Hex string
   * @returns {number} Number of differing bits (0-64)
   */
  function hammingDistance(hashA, hashB) {
    const a = _hexToBytes(hashA);
    const b = _hexToBytes(hashB);
    let dist = 0;
    for (let i = 0; i < 8; i++) {
      let xor = a[i] ^ b[i];
      while (xor) {
        dist += xor & 1;
        xor >>= 1;
      }
    }
    return dist;
  }

  function _hexToBytes(hex) {
    const bytes = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  // ── Full Page Fingerprint ─────────────────────────────────────────

  /**
   * Generate a complete fingerprint for the current page.
   * This is the main entry point called from the content script.
   *
   * Returns everything needed for secure aggregation:
   * - simhash: for fuzzy matching / blind category discovery
   * - feature_vector: for Pedersen-committable numeric aggregation
   * - integrations: detected vendor connections
   */
  function fingerprintPage() {
    const skeleton = extractSkeleton(document.body);
    const simhash = computeSimHash(skeleton);
    const featureVector = extractFeatureVector();
    const integrations = detectIntegrations();

    // URL fingerprint (structure only, no IDs)
    const urlPath = window.location.pathname
      .replace(/\/[0-9a-fA-F\-]{8,}/g, '/:id')
      .replace(/\/\d+/g, '/:num');

    return {
      simhash,
      url_pattern: urlPath,
      source: window.location.hostname,
      feature_vector: featureVector,
      integrations,
      skeleton_depth: _getSkeletonDepth(skeleton),
      skeleton_node_count: _countSkeletonNodes(skeleton),
    };
  }

  function _getSkeletonDepth(skeleton, depth = 0) {
    if (!skeleton || !skeleton.children) return depth;
    let max = depth;
    for (const child of skeleton.children) {
      if (!child._summary) {
        const d = _getSkeletonDepth(child, depth + 1);
        if (d > max) max = d;
      }
    }
    return max;
  }

  function _countSkeletonNodes(skeleton) {
    if (!skeleton) return 0;
    let count = 1;
    if (skeleton.children) {
      for (const child of skeleton.children) {
        if (child._summary) {
          count += child.total;
        } else {
          count += _countSkeletonNodes(child);
        }
      }
    }
    return count;
  }

  return {
    extractSkeleton,
    extractFeatureVector,
    detectIntegrations,
    computeSimHash,
    hammingDistance,
    fingerprintPage,
  };
})();
