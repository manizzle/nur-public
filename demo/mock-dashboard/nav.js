/* Inject shared sidebar nav into every page. Runs at top of body
 * before extension scrape so the DOM is complete. */
document.write(`
<aside class="sidebar">
  <div class="sidebar-brand">
    <div class="logo">F</div>
    <div class="name">Falcon Sentinel</div>
  </div>
  <nav class="sidebar-nav" role="navigation">
    <div class="nav-section">
      <div class="nav-section-title">Operate</div>
      <a href="index.html"${location.pathname.endsWith('index.html')||location.pathname.endsWith('/')?' class="active"':''}>Overview</a>
      <a href="detections.html"${location.pathname.endsWith('detections.html')?' class="active"':''}>Detections</a>
      <a href="hunting.html" class="inactive">Threat Hunting <span class="badge-upgrade">Pro</span></a>
      <a href="response.html" class="inactive">Response Workflows <span class="badge-upgrade">Pro</span></a>
      <a href="cases.html"${location.pathname.endsWith('cases.html')?' class="active"':''}>Cases &amp; Incidents</a>
    </div>
    <div class="nav-section">
      <div class="nav-section-title">Investigate</div>
      <a href="forensics.html" class="disabled">Forensic Recorder <span class="badge-locked">Locked</span></a>
      <a href="malware.html"${location.pathname.endsWith('malware.html')?' class="active"':''}>Malware Analysis</a>
      <a href="memory.html" class="disabled">Memory Inspector <span class="badge-locked">Locked</span></a>
      <a href="timeline.html" class="inactive">Timeline View <span class="badge-upgrade">Premium</span></a>
    </div>
    <div class="nav-section">
      <div class="nav-section-title">Configure</div>
      <a href="modules.html"${location.pathname.endsWith('modules.html')?' class="active"':''}>Modules</a>
      <a href="integrations.html"${location.pathname.endsWith('integrations.html')?' class="active"':''}>Integrations</a>
      <a href="policies.html"${location.pathname.endsWith('policies.html')?' class="active"':''}>Policies</a>
      <a href="users.html"${location.pathname.endsWith('users.html')?' class="active"':''}>Users &amp; Roles</a>
      <a href="audit.html" class="inactive">Audit Log <span class="badge-upgrade">Pro</span></a>
    </div>
    <div class="nav-section">
      <div class="nav-section-title">Account</div>
      <a href="billing.html"${location.pathname.endsWith('billing.html')?' class="active"':''}>Billing &amp; Licenses</a>
      <a href="settings.html"${location.pathname.endsWith('settings.html')?' class="active"':''}>Settings</a>
    </div>
  </nav>
</aside>
`);
