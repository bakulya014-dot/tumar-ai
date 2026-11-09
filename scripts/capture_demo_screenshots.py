"""Capture genuine screenshots of the running Tumar.AI app for the demo.

Drives a headless Chromium browser (Edge or Chrome) over the DevTools
protocol against the REAL running servers — nothing is mocked. Each
analysis shown is a live call through the Trust Engine, so these
screenshots cost a few AI requests.

Prerequisites (both started separately, see docs/DEMO_SCRIPT.md):
    streamlit run app.py --server.port 8501
    uvicorn api.main:app --port 8000

    python scripts/capture_demo_screenshots.py --out docs/demo-screenshots

A manifest.json is written next to the images recording the git
commit, branch, whether the working tree was clean, app/API versions
and the time of capture, so every image can be traced to the code that
produced it.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import websockets

ROOT = Path(__file__).resolve().parent.parent
BROWSERS = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
)
PORT = 9333
WIDTH, HEIGHT = 1366, 900

PHISHING_RU = (
    "СРОЧНО! Ваша карта Kaspi заблокирована из-за подозрительной операции. "
    "Перейдите http://kaspi-secure-verify.xyz/unlock и назовите код из СМС, "
    "иначе средства будут заморожены через 30 минут."
)
LEGIT_EN = "Hi team, the meeting moved to 3pm tomorrow in room 204. Please bring the Q3 slides."
SCAM_KK = (
    "Құттықтаймыз! Сіз 500 000 теңге ұтып алдыңыз. "
    "Сыйлықты алу үшін бізге SMS кодты жіберіңіз."
)


class Page:
    def __init__(self, ws):
        self.ws = ws
        self._id = 0

    async def send(self, method: str, **params):
        self._id += 1
        my_id = self._id
        await self.ws.send(json.dumps({"id": my_id, "method": method, "params": params}))
        while True:
            message = json.loads(await self.ws.recv())
            if message.get("id") == my_id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message.get("result", {})

    async def js(self, expression: str):
        result = await self.send(
            "Runtime.evaluate", expression=expression, awaitPromise=True, returnByValue=True
        )
        return result.get("result", {}).get("value")

    async def goto(self, url: str, settle: float = 6.0):
        await self.send("Page.navigate", url=url)
        await asyncio.sleep(settle)

    async def wait_for_text(self, text: str, timeout: float = 90.0) -> bool:
        deadline = time.monotonic() + timeout
        needle = json.dumps(text)
        while time.monotonic() < deadline:
            if await self.js(f"document.body.innerText.includes({needle})"):
                return True
            await asyncio.sleep(1.0)
        return False

    async def wait_idle(self, timeout: float = 120.0):
        """Wait until Streamlit stops running (no 'Running...' / spinner)."""
        deadline = time.monotonic() + timeout
        await asyncio.sleep(1.5)
        while time.monotonic() < deadline:
            busy = await self.js(
                "!!document.querySelector('[data-testid=\"stStatusWidget\"]') || "
                "!!document.querySelector('[data-testid=\"stSpinner\"]')"
            )
            if not busy:
                await asyncio.sleep(1.5)
                return
            await asyncio.sleep(1.0)

    async def click_text(self, text: str, selector: str = "button, a, [role=button]") -> bool:
        needle = json.dumps(text)
        return bool(await self.js(f"""
            (() => {{
              const els = [...document.querySelectorAll({json.dumps(selector)})];
              const el = els.find(e => e.innerText && e.innerText.trim().includes({needle}));
              if (!el) return false;
              el.scrollIntoView({{block: 'center'}});
              el.click();
              return true;
            }})()"""))

    async def type_into(self, selector: str, text: str):
        await self.js(f"document.querySelector({json.dumps(selector)}).focus()")
        await self.send("Input.insertText", text=text)
        await asyncio.sleep(0.3)
        await self.js(f"document.querySelector({json.dumps(selector)}).blur()")

    async def scroll_to_text(self, text: str):
        needle = json.dumps(text)
        await self.js(f"""
            (() => {{
              const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT);
              let best = null;
              while (walker.nextNode()) {{
                const n = walker.currentNode;
                if (n.children.length === 0 && n.innerText && n.innerText.includes({needle})) {{ best = n; break; }}
              }}
              if (best) best.scrollIntoView({{block: 'start'}});
            }})()""")
        await asyncio.sleep(1.0)

    async def shot(self, path: Path, full_page: bool = False):
        params = {"format": "png"}
        if full_page:
            metrics = await self.send("Page.getLayoutMetrics")
            size = metrics["cssContentSize"]
            params["clip"] = {"x": 0, "y": 0, "width": WIDTH, "height": min(size["height"], 6000), "scale": 1}
            params["captureBeyondViewport"] = True
        data = await self.send("Page.captureScreenshot", **params)
        path.write_bytes(base64.b64decode(data["data"]))
        print("saved", path.name)


async def open_page() -> Page:
    # The browser starts with one about:blank tab; attach to it. (Newer
    # Chromium only creates tabs via PUT /json/new, so we avoid that.)
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json", timeout=10) as r:
        targets = [t for t in json.load(r) if t.get("type") == "page"]
    ws = await websockets.connect(targets[0]["webSocketDebuggerUrl"], max_size=50 * 2**20)
    page = Page(ws)
    await page.send("Page.enable")
    await page.send("Runtime.enable")
    await page.send(
        "Emulation.setDeviceMetricsOverride", width=WIDTH, height=HEIGHT, deviceScaleFactor=1, mobile=False
    )
    return page


async def enter_as_guest(page: Page, app: str, lang: str = "en", guest_label: str = "Try without an account"):
    await page.goto(f"{app}/?lang={lang}", settle=8)
    if not await page.click_text(guest_label):
        raise RuntimeError("guest button not found")
    await page.wait_idle()
    await asyncio.sleep(3)


async def open_nav(page: Page, label: str):
    # Sidebar links only: dashboard cards repeat the same labels.
    if not await page.click_text(label, '[data-testid="stSidebarNav"] a, a[data-testid="stSidebarNavLink"]'):
        raise RuntimeError(f"nav link {label!r} not found")
    await page.wait_idle()
    await asyncio.sleep(2)


async def analyze_message(page: Page, text: str, button: str):
    await page.type_into("textarea", text)
    await asyncio.sleep(1.0)
    if not await page.click_text(button, '[data-testid="stMain"] button, section.main button, button[kind="primary"]'):
        raise RuntimeError("analyze button not found")
    await page.wait_idle(timeout=150)
    await asyncio.sleep(2)


async def capture(app: str, api: str, out: Path, qr_png: Path | None, force: bool = False) -> list[dict]:
    shots: list[dict] = []

    def record(name: str, what: str, live: bool):
        shots.append({"file": name, "shows": what, "live_analysis": live})

    def done(name: str) -> bool:
        return not force and (out / name).exists()

    page = await open_page()

    # 1. Landing
    if not done("01-landing-page.png"):
        await page.goto(f"{app}/?lang=en", settle=9)
        await page.shot(out / "01-landing-page.png")
    record("01-landing-page.png", "Public landing page, English", False)

    # 2. Dashboard
    if not done("02-dashboard-home.png"):
        await enter_as_guest(page, app)
        await page.shot(out / "02-dashboard-home.png")
    record("02-dashboard-home.png", "Home dashboard after entering as a guest", False)

    # 3. Phishing analysis (Russian Kaspi phishing, live AI + heuristics)
    if not done("03-phishing-analysis-result.png"):
        await enter_as_guest(page, app)
        await open_nav(page, "Scam Analyzer")
        await analyze_message(page, PHISHING_RU, "Analyze message")
        await page.scroll_to_text("Analyze message")
        await page.shot(out / "03-phishing-analysis-result.png")
        await page.shot(out / "03b-phishing-analysis-full.png", full_page=True)
    record("03-phishing-analysis-result.png", "Live analysis of a Russian-language Kaspi phishing SMS", True)
    record("03b-phishing-analysis-full.png", "Same result, full page including evidence", True)

    # 4. Legitimate message
    if not done("04-legitimate-message-result.png"):
        await enter_as_guest(page, app)
        await open_nav(page, "Scam Analyzer")
        await analyze_message(page, LEGIT_EN, "Analyze message")
        await page.scroll_to_text("Analyze message")
        await page.shot(out / "04-legitimate-message-result.png")
    record("04-legitimate-message-result.png", "Live analysis of an ordinary work message", True)

    # 5. Kazakh interface + Kazakh scam
    if not done("05-kazakh-analysis-result.png"):
        await enter_as_guest(page, app, lang="kk", guest_label="Тіркелмей көру")
        await open_nav(page, "Хабарламаны талдау")
        try:
            await analyze_message(page, SCAM_KK, "Хабарламаны талдау")
        except RuntimeError:
            await page.shot(out / "_debug-kazakh-step.png")
            raise
        await page.scroll_to_text("Хабарламаны талдау")
        await page.shot(out / "05-kazakh-analysis-result.png")
    record("05-kazakh-analysis-result.png", "Kazakh interface, live analysis of a Kazakh prize scam", True)

    # 6. Screenshot scanner with a QR code (optional)
    if qr_png and qr_png.exists() and not done("06-screenshot-scanner-qr.png"):
        await enter_as_guest(page, app)
        await open_nav(page, "Screenshot Scanner")
        doc = await page.send("DOM.getDocument")
        node = await page.send("DOM.querySelector", nodeId=doc["root"]["nodeId"], selector="input[type=file]")
        await page.send("DOM.setFileInputFiles", files=[str(qr_png)], nodeId=node["nodeId"])
        await asyncio.sleep(4)
        await page.click_text("Analyze screenshot")
        await page.wait_idle(timeout=150)
        await page.scroll_to_text("Risk level")
        await page.shot(out / "06-screenshot-scanner-qr.png")
    if (out / "06-screenshot-scanner-qr.png").exists():
        record("06-screenshot-scanner-qr.png", "Screenshot Scanner decoding a QR code that points to a look-alike domain", True)

    # 7. API documentation and health
    if not done("07-api-docs-swagger.png"):
        await page.goto(f"{api}/docs", settle=6)
        await page.shot(out / "07-api-docs-swagger.png")
    record("07-api-docs-swagger.png", "Interactive API documentation (FastAPI /docs)", False)
    if not done("07b-api-health-response.png"):
        await page.goto(f"{api}/v1/health", settle=2)
        await page.shot(out / "07b-api-health-response.png")
    record("07b-api-health-response.png", "Raw /v1/health response", False)

    # 8, 9. Architecture and evaluation pages rendered from docs/
    for name, html, what in (
        ("08-system-architecture.png", ROOT / "docs" / "architecture.html", "System architecture diagram (docs/architecture.html)"),
        ("09-test-and-evaluation-results.png", ROOT / "docs" / "evaluation-results.html", "Real test-suite and offline evaluation output (docs/evaluation-results.html)"),
    ):
        if html.exists():
            if not done(name):
                await page.goto(html.as_uri(), settle=2)
                await page.shot(out / name, full_page=True)
            record(name, what, False)

    await page.ws.close()
    return shots


def _git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    except Exception:
        return ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", default="http://localhost:8501")
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--out", default=str(ROOT / "docs" / "demo-screenshots"))
    parser.add_argument("--qr", default="", help="PNG with a QR code for the Screenshot Scanner shot")
    parser.add_argument("--force", action="store_true", help="recapture shots that already exist")
    args = parser.parse_args()

    browser = next((b for b in BROWSERS if os.path.exists(b)), None) or shutil.which("chromium")
    if not browser:
        print("No Chromium-based browser found; see docs/demo-screenshots/README.md for manual steps.")
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    profile = tempfile.mkdtemp(prefix="tumar-shots-")
    proc = subprocess.Popen([
        browser, "--headless=new", f"--remote-debugging-port={PORT}", f"--user-data-dir={profile}",
        "--no-first-run", "--no-default-browser-check", "--disable-extensions",
        f"--window-size={WIDTH},{HEIGHT}", "about:blank",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json/version", timeout=1)
                break
            except OSError:
                time.sleep(0.25)
        shots = asyncio.run(capture(args.app, args.api, out, Path(args.qr) if args.qr else None, args.force))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(profile, ignore_errors=True)

    status = _git("status", "--porcelain")
    manifest = {
        "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_commit": _git("rev-parse", "--short", "HEAD"),
        "git_branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "working_tree_clean": not status,
        "app_version": "v0.1.0 (Streamlit app, i18n app.version_caption)",
        "api_version": "0.2.0",
        "app_url": args.app,
        "api_url": args.api,
        "viewport": f"{WIDTH}x{HEIGHT}",
        "browser": Path(browser).name + " (headless)",
        "screenshots": shots,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{len(shots)} screenshots, manifest written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
