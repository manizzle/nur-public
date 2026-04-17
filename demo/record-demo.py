"""
Record a 60-second demo of the nur extension scanning a dashboard.

Loads the mock dashboard, injects an overlay that simulates the
extension popup, animates the scan flow, records as MP4, converts
to GIF.

Usage:
    cd nur-public/demo
    python3 -m http.server 8765 &   # serve mock dashboard
    python3 record-demo.py          # produces nur-demo.gif
"""
import subprocess
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

HERE = Path(__file__).parent
OUT_DIR = HERE / "_recording"
OUT_DIR.mkdir(exist_ok=True)
MOCK_URL = "http://localhost:8765/index.html"

OVERLAY_CSS = """
  @font-face {
    font-family: 'Inter';
    src: local('Inter'), local('-apple-system'), local('BlinkMacSystemFont');
  }
  .nur-popup {
    position: fixed;
    top: 16px; right: 16px;
    width: 360px;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 12px;
    box-shadow: 0 20px 40px rgba(0,0,0,0.5);
    font-family: -apple-system, BlinkMacSystemFont, 'Inter', sans-serif;
    color: #f1f5f9;
    z-index: 99999;
    opacity: 0;
    transform: translateY(-8px);
    transition: opacity 0.3s, transform 0.3s;
  }
  .nur-popup.show { opacity: 1; transform: translateY(0); }
  .nur-popup header {
    padding: 14px 18px;
    border-bottom: 1px solid #1e293b;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .nur-popup header .logo {
    width: 28px; height: 28px;
    background: linear-gradient(135deg, #22c55e, #16a34a);
    border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    color: #042f1a;
    font-weight: 800;
  }
  .nur-popup header .name { font-weight: 700; font-size: 14px; }
  .nur-popup header .sub { font-size: 11px; color: #94a3b8; margin-top: 1px; }
  .nur-popup .body { padding: 18px; }
  .nur-popup .btn {
    width: 100%;
    padding: 12px 16px;
    background: #22c55e;
    color: #042f1a;
    border: none;
    border-radius: 8px;
    font-weight: 700;
    font-size: 14px;
    cursor: pointer;
    transition: background 0.15s;
  }
  .nur-popup .btn:hover { background: #16a34a; }
  .nur-popup .btn.secondary {
    background: #1e293b;
    color: #f1f5f9;
    margin-top: 8px;
  }
  .nur-popup .progress {
    background: #1e293b;
    height: 6px;
    border-radius: 3px;
    overflow: hidden;
    margin-top: 14px;
  }
  .nur-popup .progress-bar {
    background: #22c55e;
    height: 100%;
    width: 0%;
    transition: width 0.2s linear;
  }
  .nur-popup .log {
    margin-top: 12px;
    font-size: 11px;
    color: #94a3b8;
    font-family: ui-monospace, monospace;
    min-height: 48px;
    line-height: 1.5;
  }
  .nur-popup .log div { opacity: 0; transition: opacity 0.15s; }
  .nur-popup .log div.show { opacity: 1; }
  .nur-popup .report { margin-top: 6px; }
  .nur-popup .report .headline {
    font-size: 22px; font-weight: 800;
    color: #fca5a5;
    margin-bottom: 4px;
  }
  .nur-popup .report .sub-headline {
    font-size: 12px;
    color: #94a3b8;
    margin-bottom: 16px;
  }
  .nur-popup .stat-row {
    display: flex; justify-content: space-between;
    padding: 8px 0;
    border-top: 1px solid #1e293b;
    font-size: 12px;
  }
  .nur-popup .stat-row .k { color: #94a3b8; }
  .nur-popup .stat-row .v { color: #f1f5f9; font-weight: 600; font-feature-settings: 'tnum'; }
  .nur-popup .stat-row .v.danger { color: #fca5a5; }
  .nur-popup .stat-row .v.ok { color: #86efac; }
  .nur-cursor {
    position: fixed;
    width: 18px; height: 18px;
    border-radius: 50%;
    background: rgba(34,197,94,0.45);
    border: 2px solid #22c55e;
    pointer-events: none;
    z-index: 100000;
    transition: top 0.5s cubic-bezier(.2,.6,.2,1), left 0.5s cubic-bezier(.2,.6,.2,1), transform 0.1s;
    transform: translate(-50%, -50%);
  }
  .nur-cursor.click { transform: translate(-50%, -50%) scale(0.7); }
  .nur-caption {
    position: fixed;
    bottom: 20px; left: 50%;
    transform: translateX(-50%);
    background: rgba(15, 23, 42, 0.92);
    color: #f1f5f9;
    padding: 10px 20px;
    border-radius: 8px;
    font-family: -apple-system, BlinkMacSystemFont, 'Inter', sans-serif;
    font-size: 13px;
    font-weight: 500;
    z-index: 99999;
    opacity: 0;
    transition: opacity 0.3s;
  }
  .nur-caption.show { opacity: 1; }
"""

POPUP_HTML = """
<div class="nur-popup" id="nur-popup">
  <header>
    <div class="logo">n</div>
    <div>
      <div class="name">nur</div>
      <div class="sub">scan security dashboards</div>
    </div>
  </header>
  <div class="body">
    <div id="nur-stage-buttons">
      <button class="btn" id="nur-scan-btn">Full Scan</button>
      <button class="btn secondary">Capture Page</button>
    </div>
    <div id="nur-stage-progress" style="display:none;">
      <div style="font-size:12px; color:#94a3b8; margin-bottom:6px;">Scanning dashboard…</div>
      <div class="progress"><div class="progress-bar" id="nur-progress"></div></div>
      <div class="log" id="nur-log">
        <div>discovering pages…</div>
        <div>anonymizing client-side…</div>
        <div>building feature vector…</div>
        <div>computing SimHash fingerprints…</div>
      </div>
    </div>
    <div id="nur-stage-report" style="display:none;">
      <div class="report">
        <div class="headline">$84,000/yr</div>
        <div class="sub-headline">in shelfware across your Falcon Sentinel stack</div>
        <div class="stat-row"><span class="k">Modules scanned</span><span class="v">28</span></div>
        <div class="stat-row"><span class="k">Active</span><span class="v ok">9</span></div>
        <div class="stat-row"><span class="k">Unused</span><span class="v danger">19</span></div>
        <div class="stat-row"><span class="k">Integrations connected</span><span class="v">3 / 14</span></div>
        <div class="stat-row"><span class="k">Pages scanned</span><span class="v">5</span></div>
        <div class="stat-row"><span class="k">Data left your browser</span><span class="v ok">0 bytes PII</span></div>
      </div>
    </div>
  </div>
</div>
<div class="nur-cursor" id="nur-cursor" style="top:-50px; left:-50px;"></div>
<div class="nur-caption" id="nur-caption"></div>
"""


def run_demo():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1400, "height": 900},
            record_video_dir=str(OUT_DIR),
            record_video_size={"width": 1400, "height": 900},
        )
        page = context.new_page()
        page.goto(MOCK_URL, wait_until="domcontentloaded")
        page.wait_for_timeout(500)

        # Inject overlay
        page.evaluate(f"""() => {{
          const style = document.createElement('style');
          style.textContent = `{OVERLAY_CSS}`;
          document.head.appendChild(style);
          const wrapper = document.createElement('div');
          wrapper.innerHTML = `{POPUP_HTML}`;
          document.body.appendChild(wrapper);
        }}""")

        # 0–2s: caption → "A real security dashboard. You've been paying for it for months."
        page.evaluate("""() => {
          const c = document.getElementById('nur-caption');
          c.textContent = 'A real security dashboard. You know most of it is shelfware.';
          c.classList.add('show');
        }""")
        page.wait_for_timeout(2500)

        # 2–4s: cursor moves to top-right area, popup appears
        page.evaluate("""() => {
          const cur = document.getElementById('nur-cursor');
          cur.style.top = '40px';
          cur.style.left = '1360px';
          document.getElementById('nur-caption').classList.remove('show');
        }""")
        page.wait_for_timeout(700)
        page.evaluate("""() => {
          document.getElementById('nur-cursor').classList.add('click');
        }""")
        page.wait_for_timeout(300)
        page.evaluate("""() => {
          document.getElementById('nur-cursor').classList.remove('click');
          document.getElementById('nur-popup').classList.add('show');
        }""")
        page.wait_for_timeout(1500)

        # 4–6s: caption + cursor moves to Full Scan button
        page.evaluate("""() => {
          const c = document.getElementById('nur-caption');
          c.textContent = 'Install the extension. Click scan. That\\'s it.';
          c.classList.add('show');
        }""")
        page.wait_for_timeout(1200)
        page.evaluate("""() => {
          const btn = document.getElementById('nur-scan-btn').getBoundingClientRect();
          const cur = document.getElementById('nur-cursor');
          cur.style.top = (btn.top + btn.height / 2) + 'px';
          cur.style.left = (btn.left + btn.width / 2) + 'px';
        }""")
        page.wait_for_timeout(800)
        page.evaluate("""() => {
          document.getElementById('nur-cursor').classList.add('click');
          document.getElementById('nur-caption').classList.remove('show');
        }""")
        page.wait_for_timeout(200)

        # 6–14s: scan progress
        page.evaluate("""() => {
          document.getElementById('nur-cursor').classList.remove('click');
          document.getElementById('nur-stage-buttons').style.display = 'none';
          document.getElementById('nur-stage-progress').style.display = 'block';
        }""")

        # Animate progress + scroll the dashboard behind it
        for pct, log_idx, scroll_y in [
            (15, 0, 0),
            (30, 0, 300),
            (48, 1, 700),
            (66, 2, 1200),
            (82, 3, 1800),
            (100, 3, 2200),
        ]:
            page.evaluate(f"""() => {{
              document.getElementById('nur-progress').style.width = '{pct}%';
              const logs = document.querySelectorAll('#nur-log div');
              logs.forEach((el, i) => {{ if (i <= {log_idx}) el.classList.add('show'); }});
              window.scrollTo({{top: {scroll_y}, behavior: 'smooth'}});
            }}""")
            page.wait_for_timeout(1200)

        page.wait_for_timeout(500)

        # 14–16s: show report
        page.evaluate("""() => {
          document.getElementById('nur-stage-progress').style.display = 'none';
          document.getElementById('nur-stage-report').style.display = 'block';
          window.scrollTo({top: 0, behavior: 'smooth'});
          const c = document.getElementById('nur-caption');
          c.textContent = '19 of 28 modules unused. $84k/yr of shelfware. In 60 seconds.';
          c.classList.add('show');
        }""")
        page.wait_for_timeout(3500)

        # 16–20s: second caption — the pitch
        page.evaluate("""() => {
          const c = document.getElementById('nur-caption');
          c.classList.remove('show');
        }""")
        page.wait_for_timeout(400)
        page.evaluate("""() => {
          const c = document.getElementById('nur-caption');
          c.textContent = 'Open source. Runs in your browser. github.com/manizzle/nur-public';
          c.classList.add('show');
        }""")
        page.wait_for_timeout(3500)

        # Close context to finalize video
        page.close()
        video_path = page.video.path() if page.video else None
        context.close()
        browser.close()

        return video_path


def convert_to_gif(video_path: Path, gif_path: Path, fps: int = 15, width: int = 900):
    subprocess.run([
        "ffmpeg", "-y", "-i", str(video_path),
        "-vf", f"fps={fps},scale={width}:-1:flags=lanczos",
        "-loop", "0",
        str(gif_path),
    ], check=True, capture_output=True)


if __name__ == "__main__":
    print("Recording demo...")
    video = run_demo()
    if not video:
        raise SystemExit("no video produced")
    video_path = Path(video)
    print(f"Video: {video_path}")

    gif_path = HERE / "nur-demo.gif"
    print(f"Converting to GIF → {gif_path}")
    convert_to_gif(video_path, gif_path)
    print(f"Done. GIF size: {gif_path.stat().st_size // 1024} KB")
