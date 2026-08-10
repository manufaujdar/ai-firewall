"""Small local operator console for exercising the scan API."""

CONSOLE_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Firewall local console</title><style>
body{font:16px system-ui;max-width:900px;margin:2rem auto;padding:0 1rem;color:#18212b}textarea,input,button{font:inherit}textarea{width:100%;min-height:10rem}input{width:100%;padding:.6rem}button{padding:.7rem 1rem;margin:.7rem .5rem .7rem 0}pre{background:#f3f5f7;padding:1rem;overflow:auto}.note{border-left:4px solid #b35c00;padding:.7rem;background:#fff6e8}label{display:block;margin-top:1rem;font-weight:600}
</style></head><body><h1>AI Firewall local console</h1>
<p class="note">Local synthetic testing only. Do not paste real credentials, patient data, payment data, or private prompts. The key stays in this page's memory and is not saved.</p>
<label for="key">Local firewall API key</label><input id="key" type="password" autocomplete="off">
<label for="payload">JSON value to inspect</label><textarea id="payload">{"prompt":"Contact synthetic.user@example.com"}</textarea>
<button id="scan">Scan</button><button id="policy">Show policy summary</button><pre id="result" aria-live="polite">Ready.</pre>
<script>
const out=document.querySelector('#result');const headers=()=>({'content-type':'application/json','x-ai-firewall-api-key':document.querySelector('#key').value});
async function show(response){let value;try{value=await response.json()}catch{value={error:'Non-JSON response'}}out.textContent=JSON.stringify({status:response.status,...value},null,2)}
document.querySelector('#scan').onclick=async()=>{try{const payload=JSON.parse(document.querySelector('#payload').value);await show(await fetch('/v1/scan',{method:'POST',headers:headers(),body:JSON.stringify({payload})}))}catch(error){out.textContent=String(error)}};
document.querySelector('#policy').onclick=async()=>{try{await show(await fetch('/v1/policy',{headers:headers()}))}catch(error){out.textContent=String(error)}};
</script></body></html>"""
