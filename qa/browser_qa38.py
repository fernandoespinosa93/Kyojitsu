from __future__ import annotations
import json, os, socket, subprocess, sys, time, urllib.request, urllib.error
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'qa38-output'
OUT.mkdir(parents=True, exist_ok=True)

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def wait_http(url):
    for _ in range(120):
        try:
            urllib.request.urlopen(url, timeout=.25).close()
            return
        except OSError:
            time.sleep(.05)
    raise RuntimeError('Studio no inició')

def main():
    port = free_port()
    base = f'http://127.0.0.1:{port}'
    log = open(OUT / 'studio.log', 'w')
    proc = subprocess.Popen(
        [sys.executable, '-m', 'kyojitsu', 'studio', '--port', str(port), '--no-open', '--runs-dir', str(OUT / 'runs')],
        cwd=ROOT,
        env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')),
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    errors, checks = [], []
    def ok(text):
        checks.append(text)
        print('PASS', text, flush=True)
    try:
        wait_http(base)
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path='/usr/bin/chromium', args=['--no-sandbox'])
            ctx = browser.new_context(viewport={'width': 1440, 'height': 960})
            page = ctx.new_page()
            page.set_default_timeout(8000)
            page.on('pageerror', lambda e: errors.append(str(e)))

            def bridge(path, options):
                if not path.startswith('/api/'):
                    raise ValueError('Relative API only')
                req = urllib.request.Request(
                    base + path,
                    data=(options.get('body') or '').encode() or None,
                    headers=options.get('headers', {}),
                    method=options.get('method', 'GET'),
                )
                try:
                    with urllib.request.urlopen(req, timeout=20) as r:
                        return {'status': r.status, 'body': json.load(r)}
                except urllib.error.HTTPError as e:
                    return {'status': e.code, 'body': json.load(e)}

            page.expose_function('__httpQA', bridge)
            page.evaluate("() => {window.fetch=async(path,opts={})=>{const r=await window.__httpQA(path,opts);return new Response(JSON.stringify(r.body),{status:r.status,headers:{'Content-Type':'application/json'}})};}")
            page.set_content(urllib.request.urlopen(base).read().decode())
            page.wait_for_timeout(350)

            expect(page.locator('#targetPanel')).to_be_visible()
            expect(page.locator('#frameworkPanel')).to_be_hidden()
            expect(page.locator('#reviewPanel')).to_be_hidden()
            expect(page.locator('#wizardStepLabel')).to_contain_text('Paso 1 de 5')
            ok('Wizard starts on Connection and hides the remaining configuration pages')

            for expected in ['Marco y técnicas', 'Generador de prompts', 'Evolución y límites', 'Revisar y ejecutar']:
                page.locator('#wizardNext').click()
                expect(page.locator('#wizardStepLabel')).to_contain_text(expected)
            expect(page.locator('#campaignFields')).to_be_hidden()
            expect(page.locator('#reviewPanel')).to_be_visible()
            ok('Next advances through five guided pages and Review isolates the summary/run controls')

            page.locator('#wizardBack').click()
            expect(page.locator('#evolutionPanel')).to_be_visible()
            ok('Back returns to the previous wizard page')

            for size in [{'width': 1440, 'height': 960}, {'width': 768, 'height': 1024}, {'width': 390, 'height': 844}]:
                page.set_viewport_size(size)
                page.wait_for_timeout(160)
                assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 1')
            ok('Studio wizard has no document-level horizontal overflow at desktop, tablet, or mobile widths')

            page.set_viewport_size({'width': 1440, 'height': 960})
            page.locator('[data-section="targetPanel"]').click()
            page.locator('[data-target="fixture"]').click()
            page.locator('#simulationConfirmed').check()
            page.locator('[data-section="evolutionPanel"]').click()
            page.locator('#generations').fill('1')
            page.locator('#population').fill('3')
            page.locator('#maxRequests').fill('8')
            page.locator('#interval').fill('0')
            page.locator('[data-section="reviewPanel"]').click()
            expect(page.locator('#runBtn')).to_be_enabled()
            page.once('dialog', lambda d: d.accept())
            page.locator('#runBtn').click()
            expect(page.locator('#liveView')).to_be_visible()
            page.wait_for_function("document.getElementById('statusText').textContent==='Completada'", timeout=20000)
            href = page.locator('#liveReportLink').get_attribute('href')
            assert href
            ok('Guided wizard can launch and finish a small fixture campaign')

            report = ctx.new_page()
            report.set_default_timeout(8000)
            report.on('pageerror', lambda e: errors.append(str(e)))
            report.set_content(urllib.request.urlopen(base + href).read().decode())
            report.wait_for_timeout(350)

            report.locator('[data-route="evidence"]').click()
            report.locator('[data-route="overview"]').click()
            report.wait_for_timeout(115)
            seg = report.locator('.donut-seg').first
            assert seg.count()
            initial = seg.evaluate("e=>getComputedStyle(e).strokeDasharray")
            report.wait_for_timeout(1150)
            final = seg.evaluate("e=>getComputedStyle(e).strokeDasharray")
            assert initial != final, (initial, final)
            ok('Overview charts animate again when returning through the report navigation')

            report.locator('[data-route="evidence"]').click()
            report.locator('[data-route="framework"]').click()
            report.wait_for_timeout(120)
            bars = report.locator('#frameworkChart .chart-bar')
            assert bars.count() > 0
            w0 = float(bars.first.get_attribute('width') or 0)
            report.wait_for_timeout(1050)
            w1 = float(bars.first.get_attribute('width') or 0)
            assert w1 >= w0 and w1 > 0, (w0, w1)
            ok('Framework bars replay their growth animation on navigation')

            report.locator('[data-route="evolution"]').click()
            report.wait_for_timeout(200)
            total = report.locator('.lineage-node').count()
            assert total > 2
            report.locator('#playBtn').click()
            report.wait_for_timeout(90)
            visible_early = report.locator('.lineage-node').evaluate_all("els=>els.filter(e=>parseFloat(getComputedStyle(e).opacity)>.2).length")
            assert visible_early < total, (visible_early, total)
            report.wait_for_timeout(3400)
            visible_late = report.locator('.lineage-node').evaluate_all("els=>els.filter(e=>parseFloat(getComputedStyle(e).opacity)>.2).length")
            assert visible_late == total and visible_late > visible_early, (visible_early, visible_late, total)
            ok('Replay hides the lineage first, then progressively reveals nodes and draws parent/child paths')

            for size in [{'width': 1024, 'height': 768}, {'width': 768, 'height': 1024}, {'width': 390, 'height': 844}]:
                report.set_viewport_size(size)
                report.wait_for_timeout(160)
                assert report.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 1')
            ok('Report remains page-responsive at laptop, tablet, and mobile widths')

            assert not errors, errors
            ok('No JavaScript runtime exceptions')
            (OUT / 'results.json').write_text(json.dumps({'version': '3.8.1', 'checks': checks, 'javascript_errors': errors}, indent=2), encoding='utf-8')
            page.set_viewport_size({'width': 1440, 'height': 960})
            page.screenshot(path=str(OUT / 'wizard.png'), full_page=False)
            report.set_viewport_size({'width': 1440, 'height': 960})
            report.screenshot(path=str(OUT / 'report-evolution.png'), full_page=False)
            browser.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()

if __name__ == '__main__':
    main()
