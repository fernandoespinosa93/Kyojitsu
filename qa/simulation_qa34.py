"""Visual QA for the explicitly-labelled local simulation. No external service used."""
from __future__ import annotations
import json, os, socket, subprocess, sys, time, urllib.request, urllib.error
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
ROOT=Path(__file__).resolve().parents[1]

def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def main():
    out=Path('/mnt/data/kyojitsu34/simulation34');out.mkdir(parents=True,exist_ok=True)
    port=free_port();base=f'http://127.0.0.1:{port}'
    proc=subprocess.Popen([sys.executable,'-m','kyojitsu','studio','--port',str(port),'--no-open','--runs-dir',str(out/'runs')],env=dict(os.environ,PYTHONPATH=str(ROOT/'src')),stdout=open(out/'studio.log','w'),stderr=subprocess.STDOUT)
    checks=[]
    try:
        for _ in range(100):
            try:urllib.request.urlopen(base,timeout=.2).close();break
            except OSError:time.sleep(.05)
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path='/usr/bin/chromium',args=['--no-sandbox'])
            page=browser.new_page(viewport={'width':1600,'height':1000});page.set_default_timeout(8000)
            def bridge(path,options):
                req=urllib.request.Request(base+path,data=(options.get('body') or '').encode() or None,headers=options.get('headers',{}),method=options.get('method','GET'))
                try:
                    with urllib.request.urlopen(req,timeout=20) as r:return {'status':r.status,'body':json.load(r)}
                except urllib.error.HTTPError as e:return {'status':e.code,'body':json.load(e)}
            page.expose_function('__httpQA',bridge)
            page.set_content(urllib.request.urlopen(base).read().decode())
            page.evaluate("() => {window.fetch=async(path,opts={})=>{const r=await window.__httpQA(path,opts);return new Response(JSON.stringify(r.body),{status:r.status,headers:{'Content-Type':'application/json'}})};}")
            page.reload if False else None
            # set_content executes scripts before fetch patch, so request catalog manually and then use UI.
            page.evaluate("fetch('/api/catalog').then(r=>r.json()).then(x=>{window.__qaCatalog=x})")
            page.wait_for_timeout(300)
            page.locator('[data-target="fixture"]').click();page.locator('#simulationConfirmed').check()
            page.locator('#generations').fill('1');page.locator('#population').fill('6');page.locator('#maxRequests').fill('8');page.locator('#interval').fill('0.15')
            page.evaluate('() => { window.confirm=()=>true; }')
            page.locator('#runBtn').click();expect(page.locator('#liveView')).to_be_visible();page.wait_for_function("Number(document.getElementById('liveEvaluated').textContent)>0",timeout=8000)
            expect(page.locator('#liveMode')).to_contain_text('Simulación de laboratorio');checks.append('simulation clearly labelled')
            expect(page.locator('#flowParticles')).to_be_visible();assert page.locator('#flowParticles').evaluate('(e)=>e.width')>100;checks.append('particle canvas visible and sized after live view opens')
            page.evaluate("() => document.querySelectorAll('.toast').forEach(e=>e.remove())")
            page.screenshot(path=str(out/'simulation.png'),animations='allow',timeout=5000);checks.append('simulation screenshot rendered')
            page.locator('#stopBtn').click();page.wait_for_timeout(300);checks.append('simulation exposes cancellation control')
            browser.close()
        (out/'simulation-results.json').write_text(json.dumps({'checks':checks,'passed':len(checks),'external_services_tested':False},indent=2),encoding='utf-8')
        print('\n'.join('PASS '+x for x in checks))
    finally:
        proc.terminate();proc.wait(timeout=5)
if __name__=='__main__':main()
