#!/usr/bin/env python3
"""Real Chromium checks against a disposable local preview/launcher fixture."""
import json
from pathlib import Path
import ssl
import sys
from urllib import request
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright


def main():
    if sys.argv[1] == '--probe':
        with sync_playwright() as engine:
            path = Path(engine.chromium.executable_path)
            print(json.dumps({'available':path.is_file(),'executable':str(path)}))
        return
    config = json.loads(Path(sys.argv[1]).read_text())
    api_tls = ssl.create_default_context(cafile=config['ca'])
    api_tls.load_cert_chain(config['cert'], config['key'])
    api = request.build_opener(request.ProxyHandler({}), request.HTTPSHandler(context=api_tls))

    def delete(path):
        req = request.Request(config['api'] + path, method='DELETE', headers={'Authorization':'Bearer token-a'})
        with api.open(req, timeout=3) as response:
            assert response.status in (200, 204)

    first, second = config['grants']
    with sync_playwright() as engine:
        browser = engine.chromium.launch(headless=True,
            args=['--no-sandbox', '--no-proxy-server', '--disable-background-networking',
                  '--ignore-certificate-errors-spki-list=' + config['preview_spki'],
                  '--host-resolver-rules=MAP *.preview.test 127.0.0.1'])
        try:
            # Pin only this disposable preview leaf for Chromium. Production TLS
            # validity/CA/hostname checks are separately exercised by Go clients.
            context = browser.new_context()
            print('BROWSER version',browser.version,flush=True)
            page = context.new_page()
            def describe(target):
                value = urlsplit(target)
                return value.hostname + value.path if value.hostname else value.path
            page.on('request', lambda req: print('BROWSER request',req.method,describe(req.url),flush=True))
            def observed(res):
                headers = res.all_headers()
                safe = {key:headers.get(key) for key in ['content-type','content-length','transfer-encoding','content-encoding','content-disposition','origin-agent-cluster']}
                print('BROWSER response',res.status,describe(res.url),safe,flush=True)
            page.on('response', observed)
            page.on('requestfailed', lambda req: print('BROWSER failed',describe(req.url),req.failure,flush=True))
            page.on('download', lambda item: print('BROWSER unexpected download',item.suggested_filename,flush=True))
            page.on('framenavigated', lambda frame: print('BROWSER frame',describe(frame.url),flush=True))
            page.on('crash', lambda _: print('BROWSER renderer crashed',flush=True))
            page.on('websocket', lambda socket: print('BROWSER WebSocket',describe(socket.url),flush=True))
            page.goto('data:text/html,<body>browser baseline</body>', wait_until='load', timeout=5000)
            assert page.locator('body').inner_text() == 'browser baseline'
            page.goto(config['direct_app'], wait_until='load', timeout=5000)
            assert page.locator('body').inner_text() == 'preview browser fixture'
            print('BROWSER baseline data and direct application rendered',flush=True)
            page.goto(first['bootstrap_url'], wait_until='load', timeout=10000)
            assert page.url == first['origin'] + '/'
            assert page.locator('body').inner_text() == 'preview browser fixture'
            cookie = next(c for c in context.cookies(first['origin']) if c['name'] == '__Host-osv-preview')
            assert cookie['httpOnly'] and cookie['secure'] and cookie['sameSite'] == 'Lax'
            assert not cookie['domain'].startswith('.')
            visible = page.evaluate('document.cookie')
            assert 'app=alive' in visible and '__Host-osv-preview' not in visible and 'wide=' not in visible
            page.evaluate("document.cookie='__Host-osv-preview=wrong; Secure; Path=/'")
            assert next(c for c in context.cookies(first['origin']) if c['name'] == '__Host-osv-preview')['value'] == cookie['value']
            print('PASS browser one-use redirect host-only HttpOnly cookie and overwrite rejection', flush=True)
            result = page.evaluate("""async () => {
              const response = await fetch('/echo', {headers:{Authorization:'Bearer token-a'}});
              return await response.json();
            }""")
            assert not result['authorization'] and '__Host-osv-preview' not in result['cookie']
            result = page.evaluate("""async () => await (await fetch('/echo', {
              headers:{Authorization:'Bearer application-jwt'}})).json()""")
            assert result['authorization'] == 'Bearer application-jwt'
            print('PASS browser app authentication preserved without control credentials', flush=True)
            page.evaluate("""async () => await new Promise((resolve,reject) => {
              const socket = window.previewSocket = new WebSocket('wss://' + location.host + '/ws');
              socket.binaryType='arraybuffer';
              socket.onopen=()=>{const value=new Uint8Array(200000);for(let i=0;i<value.length;i++)value[i]=i%256;socket.send(value);};
              socket.onerror=()=>reject(new Error('websocket failed'));
              let received=false;
              socket.onmessage=event=>{const value=new Uint8Array(event.data);if(value.length!==200000||value.some((v,i)=>v!==i%256))reject(new Error('binary mismatch'));else {received=true;resolve(true);}};
              socket.onclose=()=>{window.previewSocketClosed=true;if(!received)reject(new Error('closed before binary echo'));};
            })""")
            print('PASS browser WebSocket 200000 byte binary duplex', flush=True)
            other = context.new_page()
            other.goto(second['bootstrap_url'], wait_until='load')
            assert other.url == second['origin'] + '/'
            page.evaluate("origin => {const frame=document.createElement('iframe');frame.id='other';frame.src=origin;document.body.append(frame);}", second['origin'])
            page.wait_for_function("""() => {try {document.getElementById('other').contentWindow.document.body;return false;}catch(e){return e.name==='SecurityError';}}""")
            assert page.evaluate("""() => {try {document.getElementById('other').contentWindow.document.body;return false;}catch(e){return e.name==='SecurityError';}}""")
            page.evaluate("() => {try {document.domain='preview.test';}catch{}}")
            assert page.evaluate("""() => {try {document.getElementById('other').contentWindow.document.body;return false;}catch(e){return e.name==='SecurityError';}}""")
            assert page.evaluate("""async origin => {try {await fetch(origin+'/echo',{credentials:'include'});return false;}catch{return true;}}""",second['origin'])
            print('PASS browser cross-origin DOM domain-relaxation and credentialed fetch denied', flush=True)
            delete('/v2/sessions/' + first['session_id'] + '/previews/' + first['id'])
            page.wait_for_function('window.previewSocketClosed === true', timeout=3000)
            assert page.reload(wait_until='load').status == 404
            assert other.reload(wait_until='load').status == 200
            print('PASS browser revoke closes WebSocket and only its own origin', flush=True)
            delete('/v2/sessions/' + second['session_id'])
            assert other.reload(wait_until='load').status == 404
            print('PASS browser session close revokes remaining origin', flush=True)
            context.close()
        finally:
            browser.close()


if __name__ == '__main__':
    main()
