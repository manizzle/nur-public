/**
 * crawler.js — Full dashboard crawler for nur collector
 *
 * Walks through an entire vendor dashboard (CrowdStrike, Splunk, Sentinel, etc.)
 * by discovering navigation links and visiting each one in sequence.
 * Captures structured data from every page, then merges into a complete
 * dashboard profile.
 *
 * Runs as a content script injected repeatedly by popup.js.
 */

(() => {
  /**
   * Discover all navigable links in the dashboard.
   * Finds sidebar, nav, menu links and tabs that lead to different views.
   * Returns unique, same-origin links with their labels.
   */
  function discoverLinks() {
    const links = [];
    const seenHrefs = new Set();
    const origin = window.location.origin;

    // Selectors for dashboard navigation elements
    const selectors = [
      'nav a[href]',
      '[class*="sidebar"] a[href]',
      '[class*="menu"] a[href]',
      '[class*="nav"] a[href]',
      '[role="navigation"] a[href]',
      '[role="menu"] a[href]',
      '[role="menuitem"]',
      '.sidebar a[href]',
      '#sidebar a[href]',
      // Tab-style navigation
      '[role="tab"]',
      '[class*="tab"] a[href]',
      '[class*="tab-item"]',
      // Breadcrumb and sub-navigation
      '[class*="subnav"] a[href]',
      '[class*="breadcrumb"] a[href]',
    ];

    const selector = selectors.join(', ');

    document.querySelectorAll(selector).forEach((el) => {
      const label = el.textContent.trim();
      if (!label || label.length > 100 || label.length < 2) return;

      let href = el.getAttribute('href') || '';

      // Handle relative URLs
      try {
        const url = new URL(href, origin);
        href = url.href;

        // Only same-origin links
        if (url.origin !== origin) return;

        // Skip anchors, javascript:, mailto:, etc.
        if (href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('#')) return;

        // Skip logout, signout, download links
        if (/logout|signout|sign-out|download|export|\.pdf|\.csv/i.test(href)) return;
        if (/logout|signout|sign-out/i.test(label)) return;

      } catch {
        return; // Invalid URL, skip
      }

      if (!seenHrefs.has(href)) {
        seenHrefs.add(href);
        links.push({ label, href });
      }
    });

    // Also find clickable elements that act as navigation (SPAs)
    document.querySelectorAll(selector.replace(/a\[href\]/g, 'button')).forEach((el) => {
      const label = el.textContent.trim();
      if (!label || label.length > 60 || label.length < 2) return;
      // Skip action buttons (save, delete, submit, cancel, etc.)
      if (/save|delete|remove|cancel|submit|close|confirm|ok|yes|no/i.test(label)) return;
      if (/logout|sign.?out/i.test(label)) return;

      // Use a pseudo-href based on label for deduplication
      const pseudoHref = `__click__:${label}`;
      if (!seenHrefs.has(pseudoHref)) {
        seenHrefs.add(pseudoHref);
        links.push({ label, href: pseudoHref, isClick: true, selector: buildSelector(el) });
      }
    });

    return links;
  }

  /**
   * Build a CSS selector for an element so we can find it again.
   */
  function buildSelector(el) {
    if (el.id) return `#${el.id}`;
    const parts = [];
    let current = el;
    for (let i = 0; i < 3 && current && current !== document.body; i++) {
      let sel = current.tagName.toLowerCase();
      if (current.id) {
        sel = `#${current.id}`;
        parts.unshift(sel);
        break;
      }
      if (current.className && typeof current.className === 'string') {
        const classes = current.className.trim().split(/\s+/).slice(0, 2).join('.');
        if (classes) sel += `.${classes}`;
      }
      const parent = current.parentElement;
      if (parent) {
        const siblings = Array.from(parent.children).filter(c => c.tagName === current.tagName);
        if (siblings.length > 1) {
          const idx = siblings.indexOf(current);
          sel += `:nth-of-type(${idx + 1})`;
        }
      }
      parts.unshift(sel);
      current = current.parentElement;
    }
    return parts.join(' > ');
  }

  /**
   * Scrape the current page (same logic as content.js but returns more metadata).
   */
  function scrapePage() {
    // Tables
    const tables = [];
    document.querySelectorAll('table').forEach((table) => {
      const headers = [];
      const rows = [];
      const headerRow = table.querySelector('thead tr') || table.querySelector('tr');
      if (headerRow) {
        headerRow.querySelectorAll('th, td').forEach(c => headers.push(c.textContent.trim()));
      }
      const bodyRows = table.querySelectorAll('tbody tr');
      const rowSource = bodyRows.length > 0 ? bodyRows : table.querySelectorAll('tr');
      rowSource.forEach((tr, idx) => {
        if (idx === 0 && !table.querySelector('thead') && headers.length > 0) return;
        const cells = [];
        tr.querySelectorAll('td, th').forEach(c => cells.push(c.textContent.trim()));
        if (cells.length > 0) rows.push(cells);
      });
      if (headers.length > 0 || rows.length > 0) {
        tables.push({ headers, rows: rows.slice(0, 100) });
      }
    });

    // Metrics
    const metrics = [];
    const seenMetrics = new Set();
    const metricSelectors = [
      '.metric', '.widget', '.card', '.stat', '.kpi',
      '[class*="metric"]', '[class*="widget"]', '[class*="stat"]',
      '[class*="kpi"]', '[class*="dashboard-card"]',
      '[class*="summary-card"]', '[class*="count"]',
      '[data-testid*="metric"]', '[data-testid*="stat"]',
    ].join(', ');

    document.querySelectorAll(metricSelectors).forEach((el) => {
      const numbers = el.querySelectorAll('span, div, p, h1, h2, h3, h4, strong, b, [class*="value"], [class*="number"]');
      let value = '';
      let label = '';
      numbers.forEach(n => {
        const text = n.textContent.trim();
        if (/^\$?[\d,]+\.?\d*[KkMmBb%]?$/.test(text) && text.length < 20) {
          if (!value || text.length > value.length) value = text;
        }
      });
      const labelCandidates = el.querySelectorAll('label, [class*="label"], [class*="title"], [class*="name"], h3, h4, h5, p, span');
      labelCandidates.forEach(l => {
        const text = l.textContent.trim();
        if (text && text !== value && text.length < 100 && text.length > 1 && !label) label = text;
      });
      if (!label && !value) {
        const fullText = el.textContent.trim();
        if (fullText.length < 200) label = fullText;
      }
      const key = `${label}:${value}`;
      if (!seenMetrics.has(key) && (label || value)) {
        seenMetrics.add(key);
        metrics.push({ label: label || '(unlabeled)', value: value || '(no value)' });
      }
    });

    // Active modules
    const modules = [];
    const seenModules = new Set();
    document.querySelectorAll('nav a, [class*="sidebar"] a, [class*="menu"] a, [role="navigation"] a').forEach(el => {
      const text = el.textContent.trim();
      if (!text || text.length > 100 || seenModules.has(text)) return;
      seenModules.add(text);
      const classes = (el.className || '').toLowerCase();
      const parentClasses = (el.parentElement?.className || '').toLowerCase();
      const isDisabled = el.hasAttribute('disabled') ||
        classes.includes('disabled') || classes.includes('inactive') ||
        classes.includes('locked') || parentClasses.includes('disabled');
      const badge = el.querySelector('[class*="badge"], [class*="tag"]');
      const hasPremiumBadge = badge && /upgrade|premium|pro|enterprise|locked/i.test(badge.textContent);
      const style = window.getComputedStyle(el);
      const isGrayed = parseFloat(style.opacity) < 0.5;
      modules.push({ name: text, status: (isDisabled || hasPremiumBadge || isGrayed) ? 'inactive' : 'active' });
    });

    // Headings and alerts
    const snippets = [];
    const seenSnippets = new Set();
    document.querySelectorAll('h1, h2, h3').forEach(el => {
      const text = el.textContent.trim();
      if (text && text.length < 200 && !seenSnippets.has(text)) {
        seenSnippets.add(text);
        snippets.push(text);
      }
    });
    document.querySelectorAll('[class*="alert"], [class*="notification"], [class*="warning"], [role="alert"]').forEach(el => {
      const text = el.textContent.trim();
      if (text && text.length < 500 && !seenSnippets.has(text)) {
        seenSnippets.add(text);
        snippets.push(text);
      }
    });

    // Key-value pairs from DL elements
    document.querySelectorAll('dl').forEach(dl => {
      const dts = dl.querySelectorAll('dt');
      const dds = dl.querySelectorAll('dd');
      for (let i = 0; i < Math.min(dts.length, dds.length); i++) {
        const text = `${dts[i].textContent.trim()}: ${dds[i].textContent.trim()}`;
        if (!seenSnippets.has(text)) { seenSnippets.add(text); snippets.push(text); }
      }
    });

    return {
      page_title: document.title,
      page_path: window.location.pathname,
      tables: tables.slice(0, 20),
      metrics: metrics.slice(0, 50),
      active_modules: modules.slice(0, 100),
      text_snippets: snippets.slice(0, 50),
    };
  }

  // Determine what mode we're in based on what the popup asked for
  const mode = document.currentScript?.dataset?.mode || 'discover';

  if (mode === 'discover') {
    return {
      type: 'discovery',
      current_url: window.location.href,
      source: window.location.hostname,
      links: discoverLinks(),
      page_data: scrapePage(),
    };
  } else {
    return {
      type: 'page_capture',
      current_url: window.location.href,
      source: window.location.hostname,
      page_data: scrapePage(),
    };
  }
})();
