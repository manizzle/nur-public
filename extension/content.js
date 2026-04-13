/**
 * content.js — Page scraper for nur collector
 *
 * Injected into the active tab when the user clicks "Capture Page".
 * Extracts structured data from security dashboard pages:
 * tables, metrics, navigation, active modules, and text snippets.
 *
 * Returns a structured JSON object to the popup for anonymization.
 */

(() => {
  /**
   * Extract all HTML tables on the page.
   * Returns array of { headers: string[], rows: string[][] }
   */
  function scrapeTables() {
    const tables = [];
    document.querySelectorAll('table').forEach((table) => {
      const headers = [];
      const rows = [];

      // Extract headers from <thead> or first <tr>
      const headerRow = table.querySelector('thead tr') || table.querySelector('tr');
      if (headerRow) {
        headerRow.querySelectorAll('th, td').forEach((cell) => {
          headers.push(cell.textContent.trim());
        });
      }

      // Extract body rows
      const bodyRows = table.querySelectorAll('tbody tr');
      const rowSource = bodyRows.length > 0 ? bodyRows : table.querySelectorAll('tr');

      rowSource.forEach((tr, idx) => {
        // Skip header row if we already captured it
        if (idx === 0 && !table.querySelector('thead') && headers.length > 0) return;

        const cells = [];
        tr.querySelectorAll('td, th').forEach((cell) => {
          cells.push(cell.textContent.trim());
        });
        if (cells.length > 0) {
          rows.push(cells);
        }
      });

      if (headers.length > 0 || rows.length > 0) {
        tables.push({ headers, rows: rows.slice(0, 100) }); // cap at 100 rows
      }
    });
    return tables;
  }

  /**
   * Extract dashboard metric widgets.
   * Looks for common CSS patterns used by security dashboards.
   */
  function scrapeMetrics() {
    const metrics = [];
    const seen = new Set();

    // Common selectors for dashboard widgets/cards/metrics
    const metricSelectors = [
      '.metric', '.widget', '.card', '.stat', '.kpi',
      '[class*="metric"]', '[class*="widget"]', '[class*="stat"]',
      '[class*="kpi"]', '[class*="dashboard-card"]',
      '[class*="summary-card"]', '[class*="count"]',
      '[data-testid*="metric"]', '[data-testid*="stat"]',
      '.number-card', '.info-card', '.data-card',
    ];

    const selector = metricSelectors.join(', ');

    document.querySelectorAll(selector).forEach((el) => {
      // Look for a large number (the metric value)
      const numbers = el.querySelectorAll(
        'span, div, p, h1, h2, h3, h4, strong, b, [class*="value"], [class*="number"], [class*="count"]'
      );

      let value = '';
      let label = '';

      // Find the most prominent number in the widget
      numbers.forEach((n) => {
        const text = n.textContent.trim();
        if (/^\$?[\d,]+\.?\d*[KkMmBb%]?$/.test(text) && text.length < 20) {
          if (!value || text.length > value.length) {
            value = text;
          }
        }
      });

      // Get the label (usually smaller text near the number)
      const labelCandidates = el.querySelectorAll(
        'label, [class*="label"], [class*="title"], [class*="name"], [class*="desc"], h3, h4, h5, p, span'
      );
      labelCandidates.forEach((l) => {
        const text = l.textContent.trim();
        if (text && text !== value && text.length < 100 && text.length > 1) {
          if (!label) label = text;
        }
      });

      // Fallback: use the full text content
      if (!label && !value) {
        const fullText = el.textContent.trim();
        if (fullText.length < 200) {
          label = fullText;
        }
      }

      const key = `${label}:${value}`;
      if (!seen.has(key) && (label || value)) {
        seen.add(key);
        metrics.push({ label: label || '(unlabeled)', value: value || '(no value)' });
      }
    });

    return metrics.slice(0, 50); // cap at 50 metrics
  }

  /**
   * Extract navigation/sidebar items.
   * Helps understand what modules/features are available.
   */
  function scrapeNavigation() {
    const navItems = [];
    const seen = new Set();

    // Look for nav elements, sidebars, menus
    const navSelectors = [
      'nav a', 'nav button',
      '[class*="sidebar"] a', '[class*="sidebar"] button',
      '[class*="menu"] a', '[class*="menu"] button',
      '[class*="nav"] a', '[class*="nav"] button',
      '[role="navigation"] a', '[role="menu"] a',
      '.sidebar a', '#sidebar a',
    ];

    const selector = navSelectors.join(', ');

    document.querySelectorAll(selector).forEach((el) => {
      const text = el.textContent.trim();
      if (text && text.length < 100 && text.length > 1 && !seen.has(text)) {
        seen.add(text);
        navItems.push(text);
      }
    });

    return navItems.slice(0, 100);
  }

  /**
   * Detect active vs inactive modules.
   * Looks for disabled states, "upgrade" badges, grayed-out elements.
   */
  function scrapeActiveModules() {
    const modules = [];

    // Look for elements that indicate feature/module status
    const allNavLinks = document.querySelectorAll(
      'nav a, [class*="sidebar"] a, [class*="menu"] a, [role="navigation"] a'
    );

    allNavLinks.forEach((el) => {
      const text = el.textContent.trim();
      if (!text || text.length > 100) return;

      const classes = el.className.toLowerCase();
      const parentClasses = (el.parentElement?.className || '').toLowerCase();

      // Check for inactive/disabled indicators
      const isDisabled = el.hasAttribute('disabled') ||
        classes.includes('disabled') || classes.includes('inactive') ||
        classes.includes('locked') || classes.includes('upgrade') ||
        parentClasses.includes('disabled') || parentClasses.includes('inactive');

      // Check for "upgrade" or "premium" badges nearby
      const badge = el.querySelector('[class*="badge"], [class*="tag"], [class*="label"]');
      const hasPremiumBadge = badge &&
        /upgrade|premium|pro|enterprise|locked/i.test(badge.textContent);

      // Check for grayed-out appearance
      const style = window.getComputedStyle(el);
      const isGrayed = parseFloat(style.opacity) < 0.5;

      const status = (isDisabled || hasPremiumBadge || isGrayed) ? 'inactive' : 'active';

      modules.push({ name: text, status });
    });

    // Deduplicate
    const seen = new Set();
    return modules.filter((m) => {
      if (seen.has(m.name)) return false;
      seen.add(m.name);
      return true;
    }).slice(0, 100);
  }

  /**
   * Extract notable text snippets from the page.
   * Captures headings, alert messages, and key-value pairs.
   */
  function scrapeTextSnippets() {
    const snippets = [];
    const seen = new Set();

    // Headings
    document.querySelectorAll('h1, h2, h3').forEach((el) => {
      const text = el.textContent.trim();
      if (text && text.length < 200 && !seen.has(text)) {
        seen.add(text);
        snippets.push(text);
      }
    });

    // Alert/notification messages
    document.querySelectorAll(
      '[class*="alert"], [class*="notification"], [class*="warning"], [class*="error"], [class*="banner"], [role="alert"]'
    ).forEach((el) => {
      const text = el.textContent.trim();
      if (text && text.length < 500 && !seen.has(text)) {
        seen.add(text);
        snippets.push(text);
      }
    });

    // Key-value pairs (definition lists, label+value pairs)
    document.querySelectorAll('dl').forEach((dl) => {
      const dts = dl.querySelectorAll('dt');
      const dds = dl.querySelectorAll('dd');
      for (let i = 0; i < Math.min(dts.length, dds.length); i++) {
        const text = `${dts[i].textContent.trim()}: ${dds[i].textContent.trim()}`;
        if (!seen.has(text)) {
          seen.add(text);
          snippets.push(text);
        }
      }
    });

    return snippets.slice(0, 50);
  }

  // ── Main scrape function ───────────────────────────────────────────────

  function scrape() {
    // Build the page URL info (anonymize: domain only + clean path)
    let source = '';
    let pagePath = '';
    try {
      const url = new URL(window.location.href);
      source = url.hostname;
      pagePath = url.pathname;
    } catch {
      source = window.location.hostname;
      pagePath = window.location.pathname;
    }

    // Structural fingerprint (if Fingerprint module is available)
    let fingerprint = null;
    if (typeof Fingerprint !== 'undefined') {
      try {
        fingerprint = Fingerprint.fingerprintPage();
      } catch { /* fingerprint.js not loaded — skip */ }
    }

    return {
      source,
      page_path: pagePath,
      captured_at: new Date().toISOString(),
      page_title: document.title,
      tables: scrapeTables(),
      metrics: scrapeMetrics(),
      navigation: scrapeNavigation(),
      active_modules: scrapeActiveModules(),
      raw_text_snippets: scrapeTextSnippets(),
      fingerprint,
    };
  }

  // If called via chrome.scripting.executeScript, return the result
  return scrape();
})();
