/**
 * anonymize.js — Client-side data anonymization for nur collector
 *
 * All anonymization runs locally in the extension. Nothing leaves the browser
 * until the user explicitly reviews and approves the anonymized output.
 *
 * Mirrors the logic in nur's Python anonymize.py but runs in pure JS.
 */

const Anonymize = (() => {
  // ── Pattern definitions ──────────────────────────────────────────────

  // Email addresses
  const EMAIL_RE = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;

  // Phone numbers (US/international formats)
  const PHONE_RE = /(?:\+?\d{1,3}[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}/g;

  // IPv4 addresses
  const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

  // IPv6 addresses (simplified — catches most common forms)
  const IPV6_RE = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g;

  // Internal hostnames (*.internal, *.local, *.corp, *.lan, *.private)
  const INTERNAL_HOST_RE = /\b[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)*\.(?:internal|local|corp|lan|private|intranet)\b/gi;

  // URLs with tokens, session IDs, or auth params
  const TOKEN_PARAM_RE = /[?&](token|session|sid|auth|key|api_key|access_token|refresh_token|csrf|nonce|secret)=[^&\s]*/gi;

  // UUIDs (commonly used as user/org/account identifiers)
  const UUID_RE = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;

  // Generic account/user IDs (alphanumeric strings that look like IDs)
  const ACCOUNT_ID_RE = /\b(?:user|account|org|tenant|customer|acct)[_\-]?(?:id)?[:\s]*[a-zA-Z0-9\-_]{6,}\b/gi;

  // Dollar amounts
  const DOLLAR_RE = /\$[\d,]+(?:\.\d{2})?/g;

  // User/device/host counts (e.g., "1,234 users", "5000 endpoints")
  const COUNT_RE = /\b([\d,]+)\s*(?:users?|devices?|endpoints?|hosts?|agents?|seats?|licenses?|nodes?|machines?|workstations?|servers?)\b/gi;

  // ── Helper functions ─────────────────────────────────────────────────

  /**
   * SHA-256 hash of a string, returned as hex.
   * Uses the Web Crypto API (available in extension contexts).
   */
  async function sha256(str) {
    const data = new TextEncoder().encode(str);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const bytes = new Uint8Array(hash);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Truncated hash for display: first 8 chars.
   */
  async function shortHash(str) {
    const full = await sha256(str);
    return full.slice(0, 8);
  }

  /**
   * Bucket a dollar amount into a range.
   * Input: raw dollar string like "$45,000.00"
   * Output: range string like "$10K-$50K"
   */
  function bucketDollars(dollarStr) {
    const num = parseFloat(dollarStr.replace(/[$,]/g, ''));
    if (isNaN(num)) return '[AMOUNT]';
    if (num < 10000) return '$0-$10K';
    if (num < 50000) return '$10K-$50K';
    if (num < 100000) return '$50K-$100K';
    if (num < 250000) return '$100K-$250K';
    if (num < 500000) return '$250K-$500K';
    return '$500K+';
  }

  /**
   * Bucket a user/device count into a range.
   * Input: number
   * Output: range string like "100-500"
   */
  function bucketCount(num) {
    if (num < 10) return '1-10';
    if (num < 50) return '10-50';
    if (num < 100) return '50-100';
    if (num < 500) return '100-500';
    if (num < 1000) return '500-1K';
    if (num < 5000) return '1K-5K';
    if (num < 10000) return '5K-10K';
    if (num < 50000) return '10K-50K';
    return '50K+';
  }

  /**
   * Strip query parameters from a URL, keeping only the path structure.
   */
  function cleanUrl(url) {
    try {
      const u = new URL(url);
      return u.origin + u.pathname;
    } catch {
      // If not a valid URL, strip everything after ? or #
      return url.replace(/[?#].*$/, '');
    }
  }

  /**
   * Remove time components from date strings, keeping just the date.
   * Matches ISO 8601 and common formats.
   */
  function stripTimes(text) {
    // ISO 8601: keep date, drop time
    return text.replace(
      /(\d{4}-\d{2}-\d{2})[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?/g,
      '$1'
    );
  }

  // ── Main anonymization ───────────────────────────────────────────────

  /**
   * Anonymize a single string value.
   * Returns { text, replacements } where replacements tracks what was changed.
   */
  async function anonymizeText(text) {
    if (typeof text !== 'string') return { text: String(text), replacements: [] };

    const replacements = [];
    let result = text;

    // 1. Emails → [EMAIL]
    const emails = result.match(EMAIL_RE) || [];
    for (const email of emails) {
      replacements.push({ type: 'email', original: email });
    }
    result = result.replace(EMAIL_RE, '[EMAIL]');

    // 2. Internal hostnames → [INTERNAL_HOST] (before general IPs)
    const hosts = result.match(INTERNAL_HOST_RE) || [];
    for (const host of hosts) {
      replacements.push({ type: 'internal_host', original: host });
    }
    result = result.replace(INTERNAL_HOST_RE, '[INTERNAL_HOST]');

    // 3. IP addresses → [IP]
    const ipv4s = result.match(IPV4_RE) || [];
    for (const ip of ipv4s) {
      replacements.push({ type: 'ipv4', original: ip });
    }
    result = result.replace(IPV4_RE, '[IP]');

    const ipv6s = result.match(IPV6_RE) || [];
    for (const ip of ipv6s) {
      replacements.push({ type: 'ipv6', original: ip });
    }
    result = result.replace(IPV6_RE, '[IP]');

    // 4. Phone numbers → [PHONE]
    const phones = result.match(PHONE_RE) || [];
    for (const phone of phones) {
      replacements.push({ type: 'phone', original: phone });
    }
    result = result.replace(PHONE_RE, '[PHONE]');

    // 5. Dollar amounts → bucketed ranges
    result = result.replace(DOLLAR_RE, (match) => {
      const bucketed = bucketDollars(match);
      replacements.push({ type: 'dollar', original: match, bucketed });
      return bucketed;
    });

    // 6. User/device counts → bucketed ranges
    result = result.replace(COUNT_RE, (match, numStr) => {
      const num = parseInt(numStr.replace(/,/g, ''), 10);
      const bucketed = bucketCount(num);
      const label = match.replace(numStr, '').trim();
      replacements.push({ type: 'count', original: match, bucketed });
      return `${bucketed} ${label}`;
    });

    // 7. UUIDs → hashed
    const uuids = result.match(UUID_RE) || [];
    for (const uuid of uuids) {
      const hashed = await shortHash(uuid);
      replacements.push({ type: 'uuid', original: uuid, hashed });
      result = result.replace(uuid, `[ID:${hashed}]`);
    }

    // 8. Account/user IDs → hashed
    const accountIds = result.match(ACCOUNT_ID_RE) || [];
    for (const id of accountIds) {
      const hashed = await shortHash(id);
      replacements.push({ type: 'account_id', original: id, hashed });
      result = result.replace(id, `[ID:${hashed}]`);
    }

    // 9. URL token parameters → stripped
    result = result.replace(TOKEN_PARAM_RE, (match) => {
      replacements.push({ type: 'token_param', original: match });
      return '';
    });

    // 10. Strip times from dates (keep dates)
    result = stripTimes(result);

    return { text: result, replacements };
  }

  /**
   * Anonymize an array of strings (e.g., table cells).
   */
  async function anonymizeArray(arr) {
    const results = [];
    const allReplacements = [];
    for (const item of arr) {
      if (typeof item === 'string') {
        const { text, replacements } = await anonymizeText(item);
        results.push(text);
        allReplacements.push(...replacements);
      } else if (Array.isArray(item)) {
        const { data, replacements } = await anonymizeArray(item);
        results.push(data);
        allReplacements.push(...replacements);
      } else {
        results.push(item);
      }
    }
    return { data: results, replacements: allReplacements };
  }

  /**
   * Anonymize a full scraped data object.
   * This is the main entry point called from popup.js.
   *
   * Returns { anonymized, report } where report details all replacements made.
   */
  async function anonymizeData(scrapedData) {
    const report = [];
    const anonymized = JSON.parse(JSON.stringify(scrapedData)); // deep clone

    // Anonymize source URL
    if (anonymized.source) {
      // Keep just the domain
      try {
        const u = new URL('https://' + anonymized.source);
        anonymized.source = u.hostname;
      } catch { /* keep as-is */ }
    }

    // Anonymize page path — strip IDs from path segments
    if (anonymized.page_path) {
      anonymized.page_path = anonymized.page_path
        .replace(/\/[0-9a-fA-F\-]{8,}/g, '/[ID]')  // hex IDs
        .replace(/\/\d+/g, '/[NUM]');                 // numeric IDs
    }

    // Anonymize tables
    if (anonymized.tables) {
      for (const table of anonymized.tables) {
        if (table.headers) {
          const { data, replacements } = await anonymizeArray(table.headers);
          table.headers = data;
          report.push(...replacements);
        }
        if (table.rows) {
          const newRows = [];
          for (const row of table.rows) {
            const { data, replacements } = await anonymizeArray(row);
            newRows.push(data);
            report.push(...replacements);
          }
          table.rows = newRows;
        }
      }
    }

    // Anonymize metrics
    if (anonymized.metrics) {
      for (const metric of anonymized.metrics) {
        if (metric.label) {
          const { text, replacements } = await anonymizeText(metric.label);
          metric.label = text;
          report.push(...replacements);
        }
        if (metric.value) {
          const { text, replacements } = await anonymizeText(String(metric.value));
          metric.value = text;
          report.push(...replacements);
        }
      }
    }

    // Anonymize navigation items
    if (anonymized.navigation) {
      const { data, replacements } = await anonymizeArray(anonymized.navigation);
      anonymized.navigation = data;
      report.push(...replacements);
    }

    // Anonymize active modules
    if (anonymized.active_modules) {
      const { data, replacements } = await anonymizeArray(anonymized.active_modules);
      anonymized.active_modules = data;
      report.push(...replacements);
    }

    // Anonymize raw text snippets
    if (anonymized.raw_text_snippets) {
      const newSnippets = [];
      for (const snippet of anonymized.raw_text_snippets) {
        const { text, replacements } = await anonymizeText(snippet);
        newSnippets.push(text);
        report.push(...replacements);
      }
      anonymized.raw_text_snippets = newSnippets;
    }

    return { anonymized, report };
  }

  // Public API
  return {
    anonymizeData,
    anonymizeText,
    // Exposed for testing
    _bucketDollars: bucketDollars,
    _bucketCount: bucketCount,
    _cleanUrl: cleanUrl,
  };
})();
