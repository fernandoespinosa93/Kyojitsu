from __future__ import annotations
import json, os, socket, subprocess, sys, time, urllib.request, urllib.error
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'qa381-output'
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
            ctx = browser.new_context(viewport={'width': 1440, 'height': 960}, reduced_motion='no-preference')
            page = ctx.new_page()
            page.set_default_timeout(10000)
            page.on('pageerror', lambda e: errors.append(str(e)))

            # The execution environment blocks browser localhost directly. Keep the real Python
            # backend and bridge only fetch calls while rendering the exact HTML returned by Studio.
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
            page.wait_for_timeout(300)

            expect(page.locator('#targetPanel')).to_be_visible()
            # Main config panel now uses the same available width as the wizard shell.
            widths = page.evaluate("""() => ({
              layout: document.querySelector('#configView .layout').getBoundingClientRect().width,
              panel: document.querySelector('#targetPanel').getBoundingClientRect().width
            })""")
            assert abs(widths['layout'] - widths['panel']) < 2, widths
            ok('Configuration panels use the full wizard width')

            next_width = page.locator('#wizardNext').evaluate('e=>e.getBoundingClientRect().width')
            assert next_width < 220, next_width
            ok('Step 1 Next button stays compact')

            # Create a small fixture run through the guided flow.
            page.locator('[data-target="fixture"]').click()
            page.locator('#simulationConfirmed').check()
            page.locator('[data-section="evolutionPanel"]').click()
            page.locator('#generations').fill('3')
            page.locator('#population').fill('8')
            page.locator('#maxRequests').fill('28')
            page.locator('#interval').fill('0')
            page.locator('[data-section="reviewPanel"]').click()
            expect(page.locator('#runBtn')).to_be_enabled()
            page.once('dialog', lambda d: d.accept())
            page.locator('#runBtn').click()
            expect(page.locator('#liveView')).to_be_visible()
            page.wait_for_function("document.getElementById('statusText').textContent==='Completada'", timeout=25000)
            href = page.locator('#liveReportLink').get_attribute('href')
            assert href
            ok('Fixture campaign completes through Studio')

            report = ctx.new_page()
            report.set_default_timeout(10000)
            report.on('pageerror', lambda e: errors.append(str(e)))
            report.set_content(urllib.request.urlopen(base + href).read().decode())
            report.wait_for_timeout(250)

            # Donut: animation should be in progress shortly after re-entering Overview.
            report.locator('[data-route="evidence"]').click()
            report.locator('[data-route="overview"]').click()
            report.wait_for_timeout(320)
            seg = report.locator('.donut-seg').first
            assert seg.count()
            running = seg.evaluate('e=>e.getAnimations().some(a=>a.playState==="running")')
            assert running, 'donut animation not running'
            report.wait_for_timeout(1250)
            ok('Result donut animates progressively when Overview appears')

            # Coverage bars use transform animation and should visibly grow.
            report.locator('[data-route="evidence"]').click()
            report.locator('[data-route="overview"]').click()
            report.wait_for_timeout(330)
            coverage = report.locator('#coverageChart .chart-bar').first
            if coverage.count():
                early = coverage.evaluate('e=>e.getBoundingClientRect().width')
                report.wait_for_timeout(1100)
                late = coverage.evaluate('e=>e.getBoundingClientRect().width')
                assert late > early + 5, (early, late)
            ok('Coverage bars visibly grow on view entry')

            # Framework bars in both panels should be animated.
            report.locator('[data-route="framework"]').click()
            report.wait_for_timeout(330)
            fbar = report.locator('#frameworkChart .chart-bar').first
            tbar = report.locator('#techniqueChart .chart-bar').first
            if fbar.count():
                assert fbar.evaluate('e=>e.getAnimations().some(a=>a.playState==="running")')
            if tbar.count():
                assert tbar.evaluate('e=>e.getAnimations().some(a=>a.playState==="running")')
            ok('Category and technique charts animate on framework view entry')

            # Lineage story: every visual starts hidden on click, then G0 appears before G1,
            # and edge paths visibly draw before the full graph is complete.
            report.locator('[data-route="evolution"]').click()
            report.wait_for_timeout(220)
            total_nodes = report.locator('.lineage-node').count()
            assert total_nodes > 4
            report.locator('#playBtn').click()
            report.wait_for_timeout(45)
            visible0 = report.locator('.lineage-node').evaluate_all("els=>els.filter(e=>parseFloat(getComputedStyle(e).opacity)>.25).length")
            assert visible0 == 0, visible0
            report.wait_for_timeout(620)
            g0 = report.locator('.lineage-node[data-generation="0"]').evaluate_all("els=>els.filter(e=>parseFloat(getComputedStyle(e).opacity)>.25).length")
            later_gens = report.locator('.lineage-node:not([data-generation="0"])').evaluate_all("els=>els.filter(e=>parseFloat(getComputedStyle(e).opacity)>.25).length")
            assert g0 > 0 and later_gens == 0, (g0, later_gens)
            report.wait_for_timeout(900)
            edge = report.locator('.lineage-edge-reveal[data-generation="1"]').first
            assert edge.count()
            edge_anim = edge.evaluate('e=>e.getAnimations().some(a=>a.playState==="running" || a.playState==="finished")')
            assert edge_anim
            partial = report.locator('.lineage-node').evaluate_all("els=>els.filter(e=>parseFloat(getComputedStyle(e).opacity)>.25).length")
            assert 0 < partial < total_nodes, (partial, total_nodes)
            report.wait_for_function("""() => [...document.querySelectorAll('.lineage-node')].every(e => parseFloat(getComputedStyle(e).opacity) > .8)""", timeout=12000)
            ok('Replay tells the G0→Gn lineage story with staged nodes and animated edges')

            # Dotted design is present in computed pseudo-element background.
            dots = report.locator('#originStage').evaluate("e=>getComputedStyle(e,'::before').backgroundImage")
            assert 'radial-gradient' in dots, dots
            ok('Lineage panel preserves the dotted background')

            # Responsive sanity.
            for size in [{'width': 1280, 'height': 800}, {'width': 768, 'height': 1024}, {'width': 390, 'height': 844}]:
                report.set_viewport_size(size)
                report.wait_for_timeout(120)
                assert report.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 1')
            ok('Report remains page-responsive on desktop, tablet and mobile')

            assert not errors, errors
            ok('No JavaScript runtime exceptions')
            (OUT / 'results.json').write_text(json.dumps({'version': '3.8.1', 'checks': checks, 'javascript_errors': errors}, indent=2), encoding='utf-8')
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
