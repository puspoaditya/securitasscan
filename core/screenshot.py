"""
core/screenshot.py - Web page screenshot using Playwright headless Chromium
"""

import base64
import os
import time

def take_screenshot(url: str, width: int = 1280, height: int = 800, full_page: bool = True) -> dict:
    """
    Capture a screenshot of the given URL.
    Returns base64-encoded PNG and metadata.
    """
    if not url.startswith("http"):
        url = "https://" + url

    result = {
        "url": url,
        "screenshot_b64": None,
        "title": None,
        "final_url": None,
        "load_time_ms": None,
        "error": None,
    }

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"],
            )
            context = browser.new_context(
                viewport={"width": width, "height": height},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                ignore_https_errors=True,
            )
            page = context.new_page()

            t0 = time.time()
            try:
                page.goto(url, wait_until="networkidle", timeout=20000)
            except PWTimeout:
                # Fallback: just wait for DOM
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    pass

            load_ms = int((time.time() - t0) * 1000)

            result["title"] = page.title()
            result["final_url"] = page.url
            result["load_time_ms"] = load_ms

            png_bytes = page.screenshot(full_page=full_page, type="png")
            result["screenshot_b64"] = base64.b64encode(png_bytes).decode("utf-8")

            context.close()
            browser.close()

    except ImportError:
        result["error"] = "Playwright not installed. Run: pip install playwright && playwright install chromium"
    except Exception as e:
        result["error"] = str(e)

    return result
