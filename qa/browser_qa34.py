"""Optional browser regression test; no external credentials or services used."""
from __future__ import annotations
import argparse,json,os,re,socket,subprocess,sys,threading,time,urllib.request,urllib.error
from pathlib import Path
from http.server import ThreadingHTTPServer
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests')]
from test_rest32 import TestEndpoint,TOKEN
from test_release34 import ProviderHandler
from playwright.sync_api import sync_playwright,expect

def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,default=ROOT/'qa-output34');ap.add_argument('--http-bridge',action='store_true');args=ap.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    checks=[];errors=[]
    def check(text):checks.append(text);print('PASS',text,flush=True)
    guard=ThreadingHTTPServer(('127.0.0.1',0),TestEndpoint);threading.Thread(target=guard.serve_forever,daemon=True).start()
    generator=ThreadingHTTPServer(('127.0.0.1',0),ProviderHandler);threading.Thread(target=generator.serve_forever,daemon=True).start()
    port=free_port();base=f'http://127.0.0.1:{port}';apiurl=f'http://127.0.0.1:{guard.server_port}/slow';genurl=f'http://127.0.0.1:{generator.server_port}/v1/chat/completions'
    proc=subprocess.Popen([sys.executable,'-m','kyojitsu','studio','--port',str(port),'--no-open','--runs-dir',str(args.output/'runs')],env=dict(os.environ,PYTHONPATH=str(ROOT/'src')),stdout=open(args.output/'studio.log','w'),stderr=subprocess.STDOUT)
    guard_closed=False
    try:
        for _ in range(100):
            try:urllib.request.urlopen(base,timeout=.2).close();break
            except OSError:time.sleep(.05)
        with sync_playwright() as p:
            browser=p.chromium.launch(executable_path='/usr/bin/chromium',args=['--no-sandbox'])
            context=browser.new_context(viewport={'width':1600,'height':1050},device_scale_factor=1)
            page=context.new_page();page.set_default_timeout(8000);page.on('pageerror',lambda e:(errors.append(str(e)),print('BROWSER ERROR:',str(e),flush=True)))
            page.on('console',lambda m:print('CONSOLE:',m.type,m.text,flush=True))
            if args.http_bridge:
                def bridge(path,options):
                    if not path.startswith('/api/'):raise ValueError('Relative API only')
                    req=urllib.request.Request(base+path,data=(options.get('body') or '').encode() or None,headers=options.get('headers',{}),method=options.get('method','GET'))
                    try:
                        with urllib.request.urlopen(req,timeout=20) as r:return {'status':r.status,'body':json.load(r)}
                    except urllib.error.HTTPError as e:return {'status':e.code,'body':json.load(e)}
                page.expose_function('__httpQA',bridge)
                page.evaluate("() => {window.fetch=async(path,opts={})=>{const r=await window.__httpQA(path,opts);return new Response(JSON.stringify(r.body),{status:r.status,headers:{'Content-Type':'application/json'}})};}")
                page.set_content(urllib.request.urlopen(base).read().decode())
            else:page.goto(base)
            page.wait_for_timeout(400)
            page.screenshot(path=str(args.output/'startup-debug.png'))
            expect(page.locator('#sumTechniques')).to_have_text('1')
            expect(page.locator('#runBtn')).to_be_disabled();expect(page.locator('#generatorMode')).to_have_value('rules')
            expect(page.locator('.brand-logo').first).to_be_visible();check('REST default with no URL; rules local explicitly selected; run disabled; Kyojitsu logo visible')
            expect(page.locator('#navToggle')).to_have_attribute('aria-expanded','true')
            before=page.locator('.rail').bounding_box()['width'];page.locator('#navToggle').click()
            expect(page.locator('#navToggle')).to_have_attribute('aria-expanded','false');page.wait_for_timeout(250);assert page.locator('.rail').bounding_box()['width']<before
            page.locator('#navToggle').click();check('Hamburger expands and collapses entire sidebar')
            page.locator('#promptPath').fill('question');page.locator('#applyPromptBtn').click()
            expect(page.locator('#bodyJson')).to_have_value(re.compile('"question"'))
            body=json.loads(page.locator('#bodyJson').input_value());assert body=={'question':'{{prompt}}'}
            check('Fresh application: new question field created, previous placeholder removed')
            page.set_viewport_size({'width':768,'height':1024});page.wait_for_timeout(250)
            page.screenshot(path=str(args.output/'tablet.png'),timeout=5000,animations='disabled');assert page.evaluate('document.scrollingElement.scrollLeft')==0
            check('Tablet configuration renders without document horizontal scroll')
            page.set_viewport_size({'width':1600,'height':1050});page.wait_for_timeout(200)
            if page.locator('#navToggle').get_attribute('aria-expanded')=='false':page.locator('#navToggle').click()
            page.locator('#answerPath').fill('response.text');page.locator('#applyPromptBtn').click()
            assert 'response' not in json.loads(page.locator('#bodyJson').input_value())
            check('Response field does not mutate request JSON')
            page.locator('#promptPath').fill('messages[0].content');page.locator('#applyPromptBtn').click()
            expect(page.locator('#bodyJson')).to_have_value(re.compile('messages'))
            assert json.loads(page.locator('#bodyJson').input_value())['messages'][0]['content']=='{{prompt}}'
            check('Nested arrays in input field work without a preexisting structure')
            for sec in ['evolutionPanel','generatorPanel','frameworkPanel','targetPanel']:
                page.locator(f'[data-section="{sec}"]').click();assert page.locator('.rail').bounding_box()['y']==0
                assert page.evaluate('document.scrollingElement.scrollTop')==0
            check('Fixed sidebar and content-only scroll across configuration sections')
            page.locator('[data-section="evolutionPanel"]').click();page.locator('label[for="elite"] .help').hover()
            expect(page.locator('#tooltip')).to_contain_text('25 %');page.mouse.move(5,5)
            check('Evolution help explains selection fraction in plain language')
            page.locator('[data-section="targetPanel"]').click()
            if not page.locator('#curlInput').is_visible():page.locator('#curlDetails summary').click()
            curl=f"curl '{apiurl}' -H 'Authorization: Bearer {TOKEN}' --data-raw '{{\"input\":{{\"question\":\"hola\"}},\"tenant\":\"lab\"}}'"
            page.locator('#curlInput').fill(curl);page.locator('#importCurlBtn').click()
            expect(page.locator('#endpointUrl')).to_have_value(apiurl);expect(page.locator('#curlInput')).to_have_value('')
            expect(page.locator('#promptPath')).to_have_value('input.question');check('cURL imports nested body and authentication without executing shell')
            page.locator('#answerPath').fill('wrong');page.locator('#authorized').check();page.locator('#testBtn').click()
            expect(page.locator('#testMessage')).to_contain_text('no contiene');expect(page.locator('#runBtn')).to_be_disabled()
            check('Wrong response field fails contract test, not silently accepted')
            page.locator('#answerPath').fill('result.text')
            if not page.locator('#blockedPath').is_visible():page.locator('#instrumentDetails summary').click()
            page.locator('#blockedPath').fill('guard.blocked');page.locator('#stagePath').fill('guard.stage');page.locator('#strictInstrumentation').check()
            page.locator('#testBtn').click();expect(page.locator('#sumConnection')).to_have_text('Validada');expect(page.locator('#runBtn')).to_be_enabled()
            check('Actual local HTTP request validates nested answer and guardrail signals')
            page.locator('#endpointUrl').fill(apiurl+'?changed=1');expect(page.locator('#runBtn')).to_be_disabled();page.locator('#endpointUrl').fill(apiurl)
            page.locator('#testBtn').click();expect(page.locator('#runBtn')).to_be_enabled();check('Connection edits invalidate old preflight')
            page.locator('[data-section="generatorPanel"]').click();page.locator('#generatorMode').select_option('openai_compatible');page.locator('#generatorUrl').fill(genurl);page.locator('#generatorApiKey').fill(ProviderHandler.key)
            page.locator('#generatorConsent').check();page.locator('#discoverModelsBtn').click();expect(page.locator('#generatorProviderStatus')).to_contain_text('modelo')
            page.locator('#generatorModel').fill('openai-lab');page.locator('#testGeneratorBtn').click();expect(page.locator('#generatorTestResult')).to_contain_text('JSON válido')
            check('Temporary API key discovers models dynamically and validates the generator contract')
            page.screenshot(path=str(args.output/'studio-generator.png'))
            page.locator('#generations').fill('1');page.locator('#population').fill('3');page.locator('#interval').fill('0.35');page.locator('#maxRequests').fill('10')
            page.locator('#runBtn').click();expect(page.locator('#liveView')).to_be_visible();expect(page.locator('#generatorApiKey')).to_have_value('')
            expect(page.locator('#liveFlow')).to_have_class(re.compile('running'))
            page.wait_for_function("Number(document.getElementById('liveEvaluated').textContent)>0")
            page.screenshot(path=str(args.output/'live-model-http.png'))
            check('Live animation, particles and evidence receive actual engine events; temporary generator key is cleared')
            page.wait_for_function("document.getElementById('statusText').textContent==='Completada'",timeout=25000)
            expect(page.locator('#liveReportLink')).to_be_visible();href=page.locator('#liveReportLink').get_attribute('href')
            assert page.locator('#liveRows').inner_text().count('llm:')>0
            check('Model-generated G0 and G1 complete; provenance visible in evidence table')
            report=context.new_page();report.set_default_timeout(8000);report.on('pageerror',lambda e:errors.append(str(e)))
            if args.http_bridge:report.set_content(urllib.request.urlopen(base+href).read().decode())
            else:report.goto(base+href)
            expect(report.locator('#confirmedCount')).to_have_text('0');expect(report.locator('#conclusion')).to_contain_text('no')
            check('Executive summary shows no confirmed success without independent evidence')
            report.screenshot(path=str(args.output/'executive.png'))
            for size in [{'width':1600,'height':1050},{'width':1024,'height':768},{'width':768,'height':1024}]:
                report.set_viewport_size(size)
                for route in ['framework','evidence','evolution','overview']:
                    if report.locator('#navToggle').get_attribute('aria-expanded')=='false':report.locator('#navToggle').click()
                    report.locator(f'[data-route="{route}"]').click();expect(report.locator(f'section.rview[data-view="{route}"]')).to_be_visible()
                    report.locator('#mainScroll').evaluate('(e)=>e.scrollTop=e.scrollHeight');report.mouse.move(size['width']-40,size['height']-50);report.mouse.wheel(0,-500)
                    assert report.locator('.rail').bounding_box()['y']==0
                    assert report.evaluate('document.scrollingElement.scrollLeft')==0
            check('All report views navigate and scroll at desktop, laptop and tablet widths')
            report.set_viewport_size({'width':1600,'height':1050})
            if report.locator('#navToggle').get_attribute('aria-expanded')=='false':report.locator('#navToggle').click()
            report.locator('[data-route="evidence"]').click();report.locator('#evidenceRows tr').first.click()
            expect(report.locator('#detail')).to_be_visible();expect(report.locator('#detailPrompt')).not_to_be_empty();expect(report.locator('#detailReason')).not_to_be_empty();report.locator('#closeDetail').click()
            check('Evidence inspector shows request, response, classification and review limits')
            report.locator('[data-route="evolution"]').click();assert report.locator('.lineage-edge-reveal').count()>0;report.locator('#playBtn').click();report.wait_for_timeout(3200);report.locator('#playBtn').click();report.locator('#previousCase').click()
            expect(report.locator('#replayStep')).to_contain_text('Caso');check('Recorded-case replay supports play, pause, previous and next')
            report.locator('[data-route="framework"]').click();report.locator('#frameworkTabs button').last.click();report.screenshot(path=str(args.output/'framework.png'))
            check('Framework matrix shows actual tests, findings and out-of-scope categories')
            with urllib.request.urlopen(base+href.rsplit('/',1)[0]+'/executive.pdf') as r:
                assert r.headers['Content-Type'].startswith('application/pdf');assert r.read(8).startswith(b'%PDF')
            check('Executive PDF is served as real PDF, not a print-only placeholder')
            page.locator('#backBtn').click();page.locator('#generatorMode').select_option('rules');page.locator('#testBtn').click();expect(page.locator('#runBtn')).to_be_enabled()
            guard.shutdown();guard.server_close();guard_closed=True
            page.locator('#runBtn').click();page.wait_for_function("document.getElementById('statusText').textContent==='Fall\u00f3'",timeout=15000)
            expect(page.locator('#liveEvaluated')).to_have_text('0');expect(page.locator('#liveReportLink')).to_be_hidden()
            check('Stopped endpoint fails revalidation: zero evaluations, no fabricated report or fixture fallback')
            assert not errors,errors
            check('No JavaScript runtime exceptions')
            print('CLOSING BROWSER',flush=True)
            browser.close()
            print('BROWSER CLOSED',flush=True)
        (args.output/'browser-results.json').write_text(json.dumps({'version':'3.8.1','browser':'Chromium on Linux','navigation':'in-memory HTML with local HTTP bridge' if args.http_bridge else 'native localhost HTTP','checks':checks,'passed':len(checks),'javascript_errors':errors,'external_services_tested':False},indent=2))
    finally:
        proc.terminate();proc.wait(timeout=5)
        if not guard_closed:guard.shutdown();guard.server_close()
        generator.shutdown();generator.server_close()

if __name__=='__main__':main()
