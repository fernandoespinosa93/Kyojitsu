(()=>{
'use strict';
const TOKEN='__KYOJITSU_CSRF__';
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const val=id=>$('#'+id).value.trim(), check=id=>$('#'+id).checked;
let detectedSignals={};
let catalog=null, targetType='generic', selectedFrameworks=new Set(['owasp_llm_2025','mitre_atlas']);
let selectedCategories=new Set(['LLM01']), selectedTechniques=new Set(['direct_prompt_injection']);
let connectionToken=null, tokenExpires=0, testing=false, isRunning=false, importedBody=null;
let seenSeq=0, seenJob=null, pollBusy=false, lastState='idle', activeSince=null, activeCandidate=null;
let recentRows=[], traceLocked=false, lastTerminalHandled=null, launching=false, requestEpoch=0;
const WIZARD=[
 {id:'targetPanel',label:'Conexión',hint:'Configura el endpoint, la autenticación y prueba el contrato real.'},
 {id:'frameworkPanel',label:'Marco y técnicas',hint:'Define el alcance: framework, categorías y técnicas que realmente quieres evaluar.'},
 {id:'generatorPanel',label:'Generador de prompts',hint:'Elige reglas locales o un modelo generador independiente del guardrail.'},
 {id:'evolutionPanel',label:'Evolución y límites',hint:'Define rondas, población y límites antes de ejecutar.'},
 {id:'reviewPanel',label:'Revisar y ejecutar',hint:'Revisa el resumen, valida la API si hace falta y lanza la campaña.'}
];
let wizardStep='targetPanel';
const labels={guardrail_blocked:'Bloqueo confirmado; etapa desconocida',text_blocked:'Bloqueo indicado en texto',signal_conflict:'Señales contradictorias',input_blocked:'Bloqueo de entrada',output_blocked:'Bloqueo de salida',model_refusal:'Rechazo del modelo',accepted_unverified:'Aceptado sin verificar',attack_success:'\u00c9xito confirmado',attack_failure:'Fallo confirmado',transport_error:'Error de conexi\u00f3n',target_error:'Error HTTP',invalid_response:'Contrato inv\u00e1lido'};
const outcomeClass=o=>['attack_success','transport_error','target_error','invalid_response'].includes(o)?'bad':(['input_blocked','output_blocked','guardrail_blocked','attack_failure'].includes(o)?'good':(['model_refusal','text_blocked','signal_conflict'].includes(o)?'warn':(o==='accepted_unverified'?'unverified':'')));
const colors={guardrail_blocked:'#76ba95',text_blocked:'#dfb760',signal_conflict:'#dfb760',input_blocked:'#76ba95',output_blocked:'#76ba95',model_refusal:'#dfb760',accepted_unverified:'#b88be8',attack_success:'#ed8985',attack_failure:'#76ba95',transport_error:'#ed8985',target_error:'#ed8985',invalid_response:'#ed8985'};
const HELP={
 endpointUrl:'URL completa del recurso que recibe el prompt. No es la p\u00e1gina web ni la URL de salud. Kyojitsu llamar\u00e1 esta direcci\u00f3n desde el equipo que ejecuta Python.',
 targetName:'Nombre para reconocer la API en el reporte. No cambia el destino de las solicitudes.',
 httpMethod:'Método de solicitud que espera tu API. Usa el mismo que en tu ejemplo cURL: normalmente POST.',
 timeout:'Cu\u00e1ntos segundos esperar por cada respuesta. Un timeout es un error t\u00e9cnico, nunca un ataque exitoso.',
 curlInput:'Pega cURL con un body JSON, headers y autenticaci\u00f3n. Se convierte en configuraci\u00f3n sin ejecutar comandos ni leer archivos. Preferible: Copiar como cURL (bash).',
 bodyJson:'El JSON que espera tu API. Kyojitsu reemplaza {{prompt}} por el texto de cada prueba. Mant\u00e9n los dem\u00e1s campos que tu API necesite.',
 headersJson:'Metadatos que acompa\u00f1an cada petici\u00f3n: Content-Type, Authorization, API key o Cookie. No incluyas Content-Length ni Host.',
 promptPath:'Ruta al campo de texto dentro del JSON de solicitud. Ejemplos: prompt, input.text o messages.0.content. Aplicar campo inserta {{prompt}} en esa posici\u00f3n.',
 answerPath:'Ruta al texto dentro del JSON que devuelve la API. Ejemplos: answer, data.response o choices.0.message.content. Usa las sugerencias del test real.',
 blockedPath:'Ruta a true/false que indique un bloqueo del guardrail. D\u00e9jala vac\u00eda si tu API no ofrece esta se\u00f1al; no se inventa telemetr\u00eda interna.',
 stagePath:'Ruta a la etapa que inform\u00f3 tu API. Los valores output u output_blocked distinguen un bloqueo de salida. No se adivina la etapa.',
 reasonPath:'Ruta al motivo del bloqueo o evaluaci\u00f3n. Es informaci\u00f3n de apoyo, no demuestra por s\u00ed sola un ataque exitoso.',
 successPath:'Ruta a un booleano generado por un evaluador confiable de tu laboratorio. No debe ser una afirmaci\u00f3n libre del propio modelo.',
 strictInstrumentation:'Si se activa, una respuesta sin el campo de bloqueo booleano se marca como inv\u00e1lida. Solo act\u00edvalo si tu API est\u00e1 instrumentada.',
 authorized:'Permiso expl\u00edcito para probar este endpoint. Tambi\u00e9n es obligatorio para el test benigno, que env\u00eda credenciales y consume una solicitud real.',
 policyOracleConfirmed:'Solo activa esta opci\u00f3n si la pol\u00edtica del laboratorio proh\u00edbe esos marcadores. Sin esa regla, el eco de un token no confirma un ataque.',
 simulationConfirmed:'Este modo no se conecta a ning\u00fan guardrail ni requiere servicios externos. Sus resultados son ficticios y solo sirven para probar la aplicaci\u00f3n.',
 generations:'G0 es el conjunto inicial. Un valor de 3 intenta crear G1, G2 y G3 a partir de los resultados anteriores. Los l\u00edmites pueden detener el proceso antes.',
 population:'M\u00e1ximo de candidatos adversariales por generaci\u00f3n. Los controles benignos se miden aparte en G0.',
 elite:'Fracci\u00f3n de candidatos mejor puntuados que se usa como base de la siguiente generaci\u00f3n. 0.25 significa el 25 %.',
 seedsPerTechnique:'Cu\u00e1ntos ejemplos iniciales crear por t\u00e9cnica. Las siguientes generaciones los transforman, sin entrenar una GAN neuronal.',
 maxRequests:'L\u00edmite de evaluaciones del motor, incluidos controles benignos. Los tests manuales y una revalidaci\u00f3n previa son solicitudes adicionales. No es un presupuesto monetario.',
 interval:'Pausa entre evaluaciones, adem\u00e1s del tiempo de respuesta. Limita la carga sobre tu API. No altera ni inventa resultados.',
 randomSeed:'N\u00famero para repetir las decisiones pseudoaleatorias de selecci\u00f3n y mutaci\u00f3n. Un LLM externo puede responder distinto aun con la misma semilla.',
 benign:'Agrega consultas normales para medir bloqueos de contenido permitido. Se necesitan para estimar falsos positivos.',
 secretIndicators:'Marcadores ficticios colocados en el laboratorio. Ver uno en una salida solo prueba una violaci\u00f3n si la pol\u00edtica del target proh\u00edbe revelarlo.',
 techSearch:'Filtra por nombre, descripci\u00f3n o identificador OWASP/ATLAS. Filtrar no cambia las t\u00e9cnicas que ya seleccionaste.'
};
function setupHelp(){
 for(const [id,description] of Object.entries(HELP)){
  const control=$('#'+id); if(!control)continue;
  control.dataset.help=description;
  let label=$(`label[for="${id}"]`)||control.closest('label');
  if(label){label.dataset.help=description;const b=document.createElement('button');b.type='button';b.className='help';b.textContent='?';b.setAttribute('aria-label','Ayuda: '+id);b.dataset.help=description;label.appendChild(b);}
 }
}
let helpTarget=null;
function hideHelp(){ $('#tooltip').hidden=true;if(helpTarget)helpTarget.removeAttribute('aria-describedby');helpTarget=null; }
function showHelp(el){if(!el)return; const tip=$('#tooltip');tip.textContent=el.dataset.help;tip.hidden=false;const r=el.getBoundingClientRect();let x=Math.min(r.left,innerWidth-tip.offsetWidth-12), y=r.bottom+9;if(y+tip.offsetHeight>innerHeight-10)y=Math.max(10,r.top-tip.offsetHeight-9);tip.style.left=Math.max(10,x)+'px';tip.style.top=y+'px';el.setAttribute('aria-describedby','tooltip');helpTarget=el;}
document.addEventListener('pointerover',e=>{const el=e.target.closest('[data-help]');if(el)showHelp(el)});
document.addEventListener('pointerout',e=>{if(helpTarget&&!helpTarget.contains(e.relatedTarget))hideHelp()});
document.addEventListener('focusin',e=>{const el=e.target.closest('[data-help]');if(el)showHelp(el)});
document.addEventListener('focusout',hideHelp);$('#mainScroll').addEventListener('scroll',hideHelp);
document.addEventListener('click',e=>{if(e.target.closest('.help')){e.preventDefault();e.stopPropagation();showHelp(e.target.closest('.help'));}});
let toastTimer;
function notify(message){$('#toast').textContent=message;$('#toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('#toast').hidden=true,10000);addEvent(message,'bad')}
async function api(path,body){const headers={};if(body!==undefined){headers['Content-Type']='application/json';headers['X-Kyojitsu-Token']=TOKEN}const res=await fetch(path,{method:body===undefined?'GET':'POST',headers,body:body===undefined?undefined:JSON.stringify(body),cache:'no-store'});const data=await res.json().catch(()=>({error:'El servidor no devolvi\u00f3 JSON.'}));if(!res.ok)throw new Error(data.error||`HTTP ${res.status}`);return data;}
function setStatus(text,kind=''){ $('#statusText').textContent=text;$('#statusBadge').className='badge '+kind; }
function jsonField(id){try{const x=JSON.parse(val(id));if(!x||typeof x!=='object'||Array.isArray(x))throw Error('Se requiere un objeto');return x}catch(e){throw new Error(`JSON inv\u00e1lido en ${id==='bodyJson'?'solicitud':'headers'}: ${e.message}`)}}
function config(){
 const target=targetType==='fixture'?{type:'fixture'}:{type:'generic',profile:{name:val('targetName')||'API REST',url:val('endpointUrl'),method:val('httpMethod'),headers:jsonField('headersJson'),body_template:jsonField('bodyJson'),response:{answer_path:val('answerPath'),blocked_path:val('blockedPath')||null,stage_path:val('stagePath')||null,reason_path:val('reasonPath')||null,success_path:val('successPath')||null},blocked_http_statuses:[],strict_instrumentation:check('strictInstrumentation'),policy_oracle_confirmed:check('policyOracleConfirmed'),timeout_seconds:Number(val('timeout'))}};
 return {name:val('targetName')||'Campa\u00f1a',target,authorization_confirmed:targetType==='generic'&&check('authorized'),simulation_confirmed:targetType==='fixture'&&check('simulationConfirmed'),connection_token:connectionToken,generator:{mode:val('generatorMode'),url:val('generatorUrl'),model:val('generatorModel'),api_key:val('generatorApiKey'),api_key_env:'',max_calls:Number(val('generatorMaxCalls')),timeout_seconds:Number(val('generatorTimeout')),share_test_data_confirmed:check('generatorConsent')},selection:{frameworks:[...selectedFrameworks],category_ids:[...selectedCategories],technique_ids:[...selectedTechniques],seeds_per_technique:Number(val('seedsPerTechnique')),include_benign_controls:val('benign')==='true',secret_indicators:val('secretIndicators').split(/\r?\n/).map(s=>s.trim()).filter(Boolean)},evolution:{generations:Number(val('generations')),population_size:Number(val('population')),elite_fraction:Number(val('elite')),random_seed:Number(val('randomSeed')),request_interval_seconds:Number(val('interval')),max_prompt_chars:6000,benign_control_limit:100},limits:{max_requests:Number(val('maxRequests'))}};
}
function validConnection(){return connectionToken&&Date.now()<tokenExpires}
function invalidate(){connectionToken=null;tokenExpires=0;$('#sumConnection').textContent='Sin validar';$('#sumConnection').className='badge warn';if(!isRunning)setStatus('Sin validar','warn');updateControls()}
function updateControls(){
 const validated=targetType==='fixture'?check('simulationConfirmed'):validConnection();
 $('#runBtn').disabled=isRunning||testing||!validated||!selectedTechniques.size;
 $('#runBtn').textContent=targetType==='fixture'?'Iniciar simulaci\u00f3n':'Iniciar campa\u00f1a';
 $('#campaignFields').disabled=isRunning||testing;
 $('#preflightBtn').disabled=isRunning||testing||targetType==='fixture';
 $('#testBtn').disabled=isRunning||testing;
 $('#planBtn').disabled=isRunning||!selectedTechniques.size;
 $('#stopBtn').disabled=!isRunning;
 $('#runHint').textContent=isRunning?'Hay una campa\u00f1a activa. Sigue el flujo en Ejecuci\u00f3n en vivo.':!selectedTechniques.size?'Selecciona al menos una t\u00e9cnica.':!validated?(targetType==='fixture'?'Confirma que deseas una simulaci\u00f3n.':'Valida la conexi\u00f3n para habilitar la campa\u00f1a.'):(targetType==='fixture'?'Datos sint\u00e9ticos, sin llamadas a tu API.':'La conexi\u00f3n se revalidar\u00e1 justo antes de ejecutar.');
}
function wizardIndex(id){const i=WIZARD.findIndex(x=>x.id===id);return i<0?0:i}
function updateWizard(id){wizardStep=WIZARD[wizardIndex(id)].id;const index=wizardIndex(wizardStep),review=wizardStep==='reviewPanel';$('#configView').dataset.step=wizardStep;$('#campaignFields').hidden=review;$('#reviewPanel').hidden=!review;$('#configView .layout').classList.toggle('review-step',review);$('#wizardControls').classList.toggle('first-step',index===0);['targetPanel','frameworkPanel','generatorPanel','evolutionPanel'].forEach(pid=>{$('#'+pid).hidden=review||pid!==wizardStep});$$('[data-wizard-step]').forEach((b,i)=>{const bi=wizardIndex(b.dataset.wizardStep);b.classList.toggle('active',bi===index);b.classList.toggle('done',bi<index);b.setAttribute('aria-current',bi===index?'step':'false')});$('#wizardBack').hidden=index===0;$('#wizardNext').hidden=index===WIZARD.length-1;$('#wizardNext').textContent=index===WIZARD.length-2?'Revisar campaña':'Siguiente';$('#wizardStepLabel').textContent=`Paso ${index+1} de ${WIZARD.length} · ${WIZARD[index].label}`;$('#wizardStepHint').textContent=WIZARD[index].hint;$('#crumb').textContent=WIZARD[index].label;$$('.navbtn').forEach(b=>b.classList.toggle('active',b.dataset.section===wizardStep));$('#mainScroll').scrollTo({top:0,behavior:'auto'});}
function showConfig(section){hideHelp();$('#configView').hidden=false;$('#liveView').hidden=true;updateWizard(section||wizardStep||'targetPanel');}
function showLive(){hideHelp();$('#configView').hidden=true;$('#liveView').hidden=false;$('#crumb').textContent='Ejecuci\u00f3n en vivo';$$('.navbtn').forEach(b=>b.classList.toggle('active',b.hasAttribute('data-live')));$('#mainScroll').scrollTo({top:0,behavior:'auto'});requestAnimationFrame(resizeParticleCanvas)}
$$('[data-section]').forEach(b=>b.addEventListener('click',()=>{showConfig(b.dataset.section);collapseNarrow()}));
$$('[data-wizard-step]').forEach(b=>b.addEventListener('click',()=>showConfig(b.dataset.wizardStep)));
$('#wizardBack').onclick=()=>{const i=wizardIndex(wizardStep);if(i>0)showConfig(WIZARD[i-1].id)};
$('#wizardNext').onclick=()=>{const i=wizardIndex(wizardStep);if(i<WIZARD.length-1)showConfig(WIZARD[i+1].id)};
$$('[data-live]').forEach(b=>b.addEventListener('click',showLive));$('#liveNavBtn').onclick=showLive;$('#backBtn').onclick=()=>showConfig(wizardStep||'reviewPanel');
function setTarget(type){targetType=type;invalidate();$$('[data-target]').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.target===type)));$('#restFields').hidden=type==='fixture';$('#fixtureFields').hidden=type!=='fixture';$('#targetChip').textContent=type==='fixture'?'SIMULACI\u00d3N':'API REST';$('#targetChip').className='badge '+(type==='fixture'?'warn':'');$('#configMode').className='modebanner '+(type==='fixture'?'sim':'');$('#configMode').innerHTML=type==='fixture'?'<strong>Simulaci\u00f3n local</strong><span>No se har\u00e1n llamadas HTTP. Los resultados ser\u00e1n sint\u00e9ticos.</span>':'<strong>API REST</strong><span>Sin simulaci\u00f3n autom\u00e1tica. Se requiere una conexi\u00f3n validada antes de iniciar.</span>';updateSummary()}
$$('[data-target]').forEach(b=>b.onclick=()=>setTarget(b.dataset.target));
$('#restFields').addEventListener('input',e=>{if(e.target.id==='bodyJson')importedBody=null;invalidate()});$('#restFields').addEventListener('change',invalidate);$('#simulationConfirmed').onchange=updateControls;
$('#importCurlBtn').onclick=async()=>{try{const r=await api('/api/import-curl',{curl:val('curlInput')});const p=r.profile;$('#endpointUrl').value=p.url;$('#httpMethod').value=p.method;$('#headersJson').value=JSON.stringify(p.headers,null,2);$('#bodyJson').value=JSON.stringify(p.body_template,null,2);$('#promptPath').value=r.prompt_path||'';$('#promptPaths').innerHTML=r.prompt_paths.map(s=>`<option value="${esc(s)}"></option>`).join('');importedBody=r.original_body;$('#curlWarnings').textContent=r.warnings.join(' ');$('#curlInput').value='';invalidate();addEvent('cURL adaptado. No se ejecut\u00f3 el comando. Revisa los campos y confirma autorizaci\u00f3n.','info');$('#authorized').checked=false;updateControls()}catch(e){notify(e.message)}};
$('#applyPromptBtn').onclick=async()=>{const button=$('#applyPromptBtn');button.disabled=true;try{const path=val('promptPath'),source=$('#bodyJson').value;const r=await api('/api/prompt-path',{body:jsonField('bodyJson'),path});if(val('promptPath')!==path||$('#bodyJson').value!==source)throw Error('El campo o JSON cambió durante la operación. Pulsa Aplicar de nuevo.');$('#bodyJson').value=JSON.stringify(r.body_template,null,2);invalidate();$('#pathNotice').textContent='Campo de entrada aplicado. Se crearon los niveles que faltaban. La respuesta se configura por separado.';addEvent('JSON de solicitud actualizado; vuelve a probar la API.','info')}catch(e){notify(e.message)}finally{button.disabled=false}};
async function testConnection(){
 if(isRunning||testing)return;
 try{if(!check('authorized'))throw Error('Confirma que tienes autorizaci\u00f3n antes de enviar el saludo a la API.');const c=config();invalidate();testing=true;updateControls();setStatus('Probando API','warn');$('#testResult').hidden=false;$('#testResult').className='testbox';$('#testMessage').textContent='Enviando una solicitud benigna con el contrato configurado...';$('#testFacts').textContent='';$('#testPreview').textContent='Esperando respuesta.';
 const r=await api('/api/test-target',c),h=r.health;detectedSignals=h.signal_suggestions||{};$('#signalSuggestions').hidden=!Object.keys(detectedSignals).length;$('#signalSuggestionText').textContent='Campos encontrados: '+Object.entries(detectedSignals).map(([k,v])=>k+' = '+v).join(', ')+'. Aplicarlos requiere repetir la prueba.';$('#testFacts').textContent=`HTTP ${h.http_status??'sin respuesta'} | ${Number(h.latency_ms||0).toFixed(0)} ms | ${h.reachable?'Endpoint alcanzado':'Sin conexi\u00f3n'}`;$('#testMessage').textContent=h.message;$('#testPreview').textContent=h.response_preview||'No hay un JSON de respuesta disponible.';$('#answerPaths').innerHTML=(h.answer_paths||[]).map(s=>`<option value="${esc(s)}"></option>`).join('');$('#testResult').className='testbox '+(r.ok?'good':'error');
 if(r.ok){connectionToken=r.connection_token;tokenExpires=Date.now()+r.valid_for_seconds*1000;$('#sumConnection').textContent='Validada';$('#sumConnection').className='badge good';setStatus('API validada','good');addEvent(`Test aprobado: HTTP ${h.http_status}; ${h.latency_ms} ms.`,'good');if(h.simulation)addEvent('La API se identifica como mock de laboratorio, no como un LLM real.','warn');}else{setStatus('Test no aprobado','bad');addEvent(h.message,'bad');}
 }catch(e){notify(e.message);setStatus('Test no aprobado','bad');$('#testResult').hidden=false;$('#testResult').className='testbox error';$('#testMessage').textContent=e.message;}finally{testing=false;updateControls()}
}
$('#testBtn').onclick=testConnection;$('#preflightBtn').onclick=testConnection;
function tag(s,cls=''){return `<span class="tag ${cls}">${esc(s)}</span>`}
function categoryScope(t){const maps=t.mappings.filter(m=>selectedFrameworks.has(m.framework));return !!maps.length&&(!selectedCategories.size||maps.some(m=>m.category_ids.some(c=>selectedCategories.has(c))))}
function techVisible(t){if(!categoryScope(t))return false;const q=val('techSearch').toLowerCase();return !q||JSON.stringify([t.id,t.name,t.description,t.mappings]).toLowerCase().includes(q)}
function prune(){const cats=new Set(catalog.frameworks.filter(f=>selectedFrameworks.has(f.id)).flatMap(f=>f.categories.map(c=>c.id)));selectedCategories=new Set([...selectedCategories].filter(c=>cats.has(c)));selectedTechniques=new Set([...selectedTechniques].filter(id=>catalog.techniques.some(t=>t.id===id&&categoryScope(t))))}
function renderFrameworks(){
 $('#frameworkCards').innerHTML=catalog.frameworks.map(f=>`<label class="framework-card ${selectedFrameworks.has(f.id)?'active':''}"><input type="checkbox" data-fw="${esc(f.id)}" ${selectedFrameworks.has(f.id)?'checked':''}><span><b>${esc(f.name)}</b><small>${esc(f.version||'Cat\u00e1logo incluido')} | ${esc(f.description||'Taxonom\u00eda de evaluaci\u00f3n')}</small></span></label>`).join('');
 $$('[data-fw]').forEach(c=>c.onchange=()=>{c.checked?selectedFrameworks.add(c.dataset.fw):selectedFrameworks.delete(c.dataset.fw);prune();renderFrameworks();renderCategories();renderTechniques();updateSummary()});
}
function renderCategories(){const cats=catalog.frameworks.filter(f=>selectedFrameworks.has(f.id)).flatMap(f=>f.categories);$('#categoryList').innerHTML=cats.map(c=>`<label class="cat ${c.prompt_testable?'':'disabled'}" data-help="${esc(c.description)}"><input type="checkbox" data-cat="${esc(c.id)}" ${selectedCategories.has(c.id)?'checked':''} ${c.prompt_testable?'':'disabled'}><span><b>${esc(c.id)} ${esc(c.name)}</b><small>${esc(c.prompt_testable?c.description:'Requiere evaluaci\u00f3n de infraestructura; no se cubre con prompts.')}</small></span></label>`).join('');$$('[data-cat]').forEach(c=>c.onchange=()=>{c.checked?selectedCategories.add(c.dataset.cat):selectedCategories.delete(c.dataset.cat);prune();renderTechniques();updateSummary()})}
function renderTechniques(){const rows=catalog.techniques.filter(techVisible);$('#techRows').innerHTML=rows.map(t=>{const maps=t.mappings.filter(m=>selectedFrameworks.has(m.framework)).map(m=>tag((m.framework.startsWith('owasp')?'OWASP ':'ATLAS ')+(m.technique_id||m.category_ids.join(', ')))).join(' ');return `<tr><td><input aria-label="${esc(t.name)}" type="checkbox" data-tech="${esc(t.id)}" ${selectedTechniques.has(t.id)?'checked':''}></td><td><div class="tech-name">${esc(t.name)}</div><div class="tech-desc">${esc(t.description)}</div></td><td><div class="maps">${maps}</div></td><td>${tag(t.capability,t.capability)}<div class="maps">${tag(t.oracle.includes('manual')?'Revisi\u00f3n necesaria':t.oracle==='canary'?'Marcador ficticio':t.oracle==='secret'?'Texto restringido':'Criterio de prueba',t.oracle.includes('manual')?'manual':'')}</div></td></tr>`}).join('')||'<tr><td colspan="4" class="empty">No hay t\u00e9cnicas para este filtro.</td></tr>';$$('[data-tech]').forEach(c=>c.onchange=()=>{c.checked?selectedTechniques.add(c.dataset.tech):selectedTechniques.delete(c.dataset.tech);updateSummary()})}
$('#techSearch').oninput=renderTechniques;$('#selectVisibleBtn').onclick=()=>{catalog.techniques.filter(techVisible).forEach(t=>selectedTechniques.add(t.id));renderTechniques();updateSummary()};$('#clearTechBtn').onclick=()=>{selectedTechniques.clear();renderTechniques();updateSummary()};
function updateSummary(){if(!catalog)return;$('#sumMode').textContent=targetType==='fixture'?'Simulaci\u00f3n':'API REST';$('#sumFrameworks').textContent=selectedFrameworks.size;$('#sumCategories').textContent=selectedCategories.size||'Todas';$('#sumTechniques').textContent=selectedTechniques.size;$('#sumSeeds').textContent=selectedTechniques.size*(Number(val('seedsPerTechnique'))+(val('benign')==='true'?1:0));$('#sumRequests').textContent=val('maxRequests');if(targetType==='fixture'){$('#sumConnection').textContent='No aplica';$('#sumConnection').className='badge warn'}updateControls()}
$('#evolutionPanel').addEventListener('input',updateSummary);$('#evolutionPanel').addEventListener('change',updateSummary);
$('#planBtn').onclick=async()=>{try{const p=await api('/api/plan',config());$('#planContent').innerHTML=`<p>${p.seeds.length} semillas | ${p.techniques.length} t\u00e9cnicas. Los l\u00edmites y la selecci\u00f3n pueden reducir lo que finalmente se eval\u00faa.</p><pre>${esc(p.coverage.map(c=>`${c.technique_name}: ${(c.external_technique_ids||[]).concat(c.control_ids||[]).join(', ')}`).join('\n'))}</pre>`;$('#planDialog').showModal()}catch(e){notify(e.message)}};$('#closePlanBtn').onclick=()=>$('#planDialog').close();
function addEvent(message,kind='info',when=Date.now()){
 const box=$('#events');box.querySelector('.empty')?.remove();const row=document.createElement('div');row.className='event';const time=document.createElement('time');time.textContent=new Date(when).toLocaleTimeString('es-MX',{hour12:false});const text=document.createElement('span');text.className=kind;text.textContent=message;row.append(time,text);const atBottom=box.scrollHeight-box.scrollTop-box.clientHeight<50;box.appendChild(row);while(box.children.length>160)box.firstChild.remove();if(atBottom)box.scrollTop=box.scrollHeight;$('#eventCount').textContent=`${box.children.length} eventos`;
}
function liveMode(mode,url=''){const sim=mode==='fixture'||mode==='simulation';$('#liveView').classList.toggle('simulation-mode',sim);$('#liveMode').className='modebanner '+(sim?'sim':'');$('#liveMode').innerHTML=sim?'<strong>Simulaci\u00f3n de laboratorio</strong><span>Resultados sint\u00e9ticos. No demuestran la efectividad de un guardrail real.</span>':`<strong>API REST</strong><span>${esc(url||'Conexi\u00f3n real; resultados observados por solicitud.')} | Sin acceso al interior de la API salvo las se\u00f1ales que la API devuelva.</span>`}
function phase(name,text,kind=''){pulseFlow(name);const nodes=$$('[data-phase]');nodes.forEach(n=>{n.classList.remove('active','good','bad','warn');if(n.dataset.phase===name){n.classList.add('active');if(kind)n.classList.add(kind)}});$('#livePhase').textContent=text;$('#livePhase').className='badge '+(kind||'');$('#liveFlow').classList.toggle('running',isRunning)}
function showTrace(e){$('#currentCandidate').textContent=e.candidate_id||'Sin candidato';$('#livePrompt').textContent=e.prompt||'Sin texto registrado.';$('#liveAnswer').textContent=e.answer||e.reason||(e.type==='candidate_started'?'Esperando respuesta real del endpoint.':'Respuesta vac\u00eda o no disponible.');$('#currentOutcome').textContent=labels[e.outcome]||'En curso';$('#currentOutcome').className='badge '+(e.outcome?outcomeClass(e.outcome):'neutral');}
function renderRows(){const rows=recentRows.slice(-150).reverse();$('#liveRows').innerHTML=rows.map((e,i)=>`<tr data-candidate="${esc(e.candidate_id)}" class="${i===0?'row-enter':''}"><td class="mono">G${e.generation}<br>${esc(e.candidate_id.slice(-9))}</td><td>${esc(e.technique_id||'control benigno')}</td><td class="mono" style="color:${String(e.operator).startsWith('llm:')?'var(--violet)':'var(--muted)'}">${esc(e.operator||'semilla')}</td><td><span class="badge ${outcomeClass(e.outcome)}">${esc(labels[e.outcome]||e.outcome)}</span></td><td class="mono">${e.http_status??'n/a'}</td><td class="mono">${Number(e.latency_ms||0).toFixed(0)} ms</td><td class="mono">${Number(e.fitness).toFixed(3)}</td></tr>`).join('');$$('[data-candidate]').forEach(tr=>tr.onclick=()=>{const e=recentRows.find(r=>r.candidate_id===tr.dataset.candidate);if(e){traceLocked=true;showTrace(e);$('#liveCaption').textContent='Inspeccionando una solicitud anterior. Pulsa el t\u00edtulo Prompt enviado para volver al seguimiento.'}});renderLineage();}
$('#currentCandidate').parentElement.onclick=()=>{traceLocked=false;const last=recentRows[recentRows.length-1];if(last)showTrace(last);$('#liveCaption').textContent='Seguimiento del candidato actual.'};
function renderLineage(){const rows=recentRows.slice(-60),gens=[...new Set(rows.map(e=>e.generation))].sort((a,b)=>a-b),pos=new Map();let svg='';for(let g=0;g<gens.length;g++){const gen=gens[g],group=rows.filter(e=>e.generation===gen),x=80+(gens.length===1?420:g*840/(gens.length-1));svg+=`<text x="${x}" y="20" text-anchor="middle">G${gen}</text>`;group.forEach((e,i)=>pos.set(e.candidate_id,{x,y:40+(i+.5)*124/group.length}));}let edge=0;for(const e of rows){const p=pos.get(e.candidate_id),parent=pos.get(e.parent_id);if(parent)svg+=`<path class="lineage-edge" style="--delay:${Math.min(edge++,18)*35}ms" d="M${parent.x} ${parent.y} C${(p.x+parent.x)/2} ${parent.y},${(p.x+parent.x)/2} ${p.y},${p.x} ${p.y}"/>`;}let node=0;for(const e of rows){const p=pos.get(e.candidate_id);svg+=`<circle class="lineage-node" style="--delay:${Math.min(node++,25)*28}ms" cx="${p.x}" cy="${p.y}" r="4.5" fill="${colors[e.outcome]||'#b88be8'}"><title>${esc(e.technique_id)}: ${esc(labels[e.outcome]||e.outcome)}</title></circle>`;}$('#liveLineage').innerHTML=svg;}
let particleRAF=0,particlePhase='prepare',particleBurst=0,particleBurstAt=0;
function resizeParticleCanvas(){const c=$('#flowParticles'),host=$('#liveFlow');if(!c||!host)return;const r=host.getBoundingClientRect(),d=Math.min(devicePixelRatio||1,2);c.width=Math.max(1,Math.floor(r.width*d));c.height=Math.max(1,Math.floor(r.height*d));c.style.width=r.width+'px';c.style.height=r.height+'px';c._d=d;}
function flowPoints(){const host=$('#liveFlow');if(!host)return[];const hr=host.getBoundingClientRect();return $$('.fnode .orb').map(o=>{const r=o.getBoundingClientRect();return{x:r.left-hr.left+r.width/2,y:r.top-hr.top+r.height/2}})}
function flowSample(pts,u,lane=0){const scaled=Math.max(0,Math.min(.999999,u))*(pts.length-1),seg=Math.min(pts.length-2,Math.floor(scaled)),t=scaled-seg,a=pts[seg],b=pts[seg+1],amp=(lane%2?1:-1)*(8+(lane%4)*3),bend=Math.sin(t*Math.PI)*amp;return{x:a.x+(b.x-a.x)*t,y:a.y+(b.y-a.y)*t+bend,seg,t}}
function drawParticles(ts){const c=$('#flowParticles');if(!c)return;const ctx=c.getContext('2d'),d=c._d||1,pts=flowPoints(),w=c.width/d,h=c.height/d;ctx.setTransform(d,0,0,d,0,0);ctx.clearRect(0,0,w,h);if(pts.length<2){particleRAF=requestAnimationFrame(drawParticles);return}const reduced=matchMedia('(prefers-reduced-motion: reduce)').matches,running=isRunning&&!reduced,motionActive=!reduced&&(isRunning||recentRows.length>0),palette=['#a35ee8','#e056c9','#c99bf2','#8f63d8'];
// Four low-contrast energy ribbons. They move continuously without blurring the panel itself.
for(let lane=0;lane<4;lane++){ctx.beginPath();const steps=70;for(let j=0;j<=steps;j++){const u=j/steps,scaled=u*(pts.length-1),seg=Math.min(pts.length-2,Math.floor(Math.min(scaled,pts.length-1.000001))),local=scaled-seg,a=pts[seg],b=pts[seg+1],base=a.y+(b.y-a.y)*local,amp=(lane-1.5)*11+Math.sin(ts*.0012+lane)*6,y=base+Math.sin(u*Math.PI*5+ts*.0015+lane*1.3)*amp,x=a.x+(b.x-a.x)*local;if(!j)ctx.moveTo(x,y);else ctx.lineTo(x,y)}ctx.lineWidth=lane===1||lane===2?1.15:.75;ctx.strokeStyle=lane===1?'rgba(224,86,201,.38)':lane===2?'rgba(201,155,242,.31)':'rgba(163,94,232,.19)';ctx.stroke()}
const count=targetType==='fixture'?96:66,speed=targetType==='fixture'?.00042:.00031;for(let i=0;i<count;i++){const u=(ts*speed+i/count+particleBurst*.023)%1,p=flowSample(pts,u,i),tail=flowSample(pts,(u-.010+1)%1,i),col=palette[i%palette.length],alpha=motionActive?(running?.64:.34)+.24*Math.sin((u+i)*Math.PI*2):.10;ctx.beginPath();ctx.moveTo(tail.x,tail.y);ctx.lineTo(p.x,p.y);ctx.globalAlpha=Math.max(.12,alpha*.45);ctx.strokeStyle=col;ctx.lineWidth=.75+(i%3)*.25;ctx.stroke();ctx.beginPath();ctx.globalAlpha=Math.max(.18,alpha);ctx.fillStyle=col;ctx.shadowBlur=motionActive?(running?8:4):0;ctx.shadowColor=col;ctx.arc(p.x,p.y,1+(i%4)*.34,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;ctx.globalAlpha=1}
const phaseIndex={prepare:0,send:1,wait:2,score:3,select:4}[particlePhase]??0,active=pts[phaseIndex];if(active&&motionActive){for(let ring=0;ring<2;ring++){const radius=33+ring*13+Math.sin(ts*.002+ring)*3;ctx.beginPath();ctx.globalAlpha=.13-ring*.035;ctx.strokeStyle=ring?'#a35ee8':'#e056c9';ctx.lineWidth=1;ctx.arc(active.x,active.y,radius,0,Math.PI*2);ctx.stroke()}for(let i=0;i<22;i++){const a=ts*.0017+i*Math.PI*2/22,r=31+(i%4)*7,x=active.x+Math.cos(a*(i%3?1:-1))*r,y=active.y+Math.sin(a*1.08)*r;ctx.beginPath();ctx.globalAlpha=.16+.42*((Math.sin(a+i)+1)/2);ctx.fillStyle=palette[i%palette.length];ctx.arc(x,y,.9+(i%4)*.28,0,Math.PI*2);ctx.fill()}ctx.globalAlpha=1;const age=ts-particleBurstAt;if(age>=0&&age<900){const k=age/900,r=18+k*72;ctx.beginPath();ctx.globalAlpha=(1-k)*.55;ctx.strokeStyle='#e056c9';ctx.lineWidth=1.3;ctx.arc(active.x,active.y,r,0,Math.PI*2);ctx.stroke();for(let i=0;i<28;i++){const a=i*Math.PI*2/28+(particleBurst%7)*.17,rr=12+k*(38+(i%5)*8),x=active.x+Math.cos(a)*rr,y=active.y+Math.sin(a)*rr;ctx.beginPath();ctx.globalAlpha=(1-k)*(.35+(i%3)*.12);ctx.fillStyle=palette[i%palette.length];ctx.arc(x,y,1.1+(i%3)*.35,0,Math.PI*2);ctx.fill()}ctx.globalAlpha=1}}
particleRAF=requestAnimationFrame(drawParticles)}
function pulseFlow(name){particlePhase=name;particleBurst++;particleBurstAt=performance.now();const host=$('#liveFlow');if(host){host.dataset.phase=name;host.classList.remove('pulse');void host.offsetWidth;host.classList.add('pulse')}}
window.addEventListener('resize',resizeParticleCanvas);setTimeout(()=>{resizeParticleCanvas();if(!matchMedia('(prefers-reduced-motion: reduce)').matches)particleRAF=requestAnimationFrame(drawParticles)},50);
function processEvent(e){
 let msg=e.type,kind='info';
 if(e.type==='preflight_started'){msg='Revalidando el endpoint antes de ejecutar.';phase('send','Revalidando','warn');liveMode(e.target_type);}
 if(e.type==='preflight_passed'){msg='Contrato validado para esta ejecuci\u00f3n.';kind='good';liveMode(e.health?.simulation?'simulation':(e.health?.url?'generic':'fixture'),e.health?.url||'');}
 if(e.type==='generator_started'){msg='Generador LLM: llamada '+e.call+' al modelo '+e.model+'.';phase('prepare','Generando con LLM');$('#liveGeneratorSource').textContent='Generador LLM: '+e.model;$('#liveGeneratorCalls').textContent=e.call+' llamadas al generador';if(!activeCandidate&&!traceLocked){$('#currentCandidate').textContent='Generando variantes';$('#livePrompt').textContent='Kyojitsu está creando nuevas variantes con el modelo generador. Todavía no se ha enviado un caso a la API evaluada.';$('#liveAnswer').textContent='Esperando a que el generador devuelva variantes válidas antes de comenzar las evaluaciones.';$('#currentOutcome').textContent='Generando';$('#currentOutcome').className='badge gen';$('#liveCaption').textContent='Fase de generación: aún no hay una solicitud activa contra el endpoint evaluado.';}}
 if(e.type==='generator_completed'){msg='LLM: '+e.count+' variantes recibidas y validadas.';kind='good';if(!activeCandidate&&!traceLocked){$('#livePrompt').textContent=`${e.count} variantes nuevas recibidas del generador. Preparando el primer envío.`;$('#liveAnswer').textContent='La API evaluada todavía no ha respondido porque aún no se ha enviado el siguiente caso.';$('#currentOutcome').textContent='Variantes listas';$('#currentOutcome').className='badge good';}}
 if(e.type==='run_started'){msg='Motor iniciado: '+e.run_id;$('#liveSubtitle').textContent=e.run_id;}
 if(e.type==='generation_started'){msg=`G${e.generation}: ${e.population} candidatos listos.`;$('#liveGeneration').textContent='G'+e.generation;$('#livePopulation').textContent=e.population+' candidatos';phase('prepare','Preparando variantes');}
 if(e.type==='candidate_started'){msg=`G${e.generation}: enviando ${e.candidate_id}.`;activeSince=e.time*1000;activeCandidate=e.candidate_id;phase('wait','Esperando respuesta');if(!traceLocked)showTrace(e);$('#liveCaption').textContent='Solicitud en curso. No se infieren pasos internos del modelo o del guardrail.';$('#waitLabel').textContent='petici\u00f3n en curso';}
 if(e.type==='candidate_evaluated'){msg=`G${e.generation}: ${labels[e.outcome]||e.outcome}; HTTP ${e.http_status??'n/a'}; ${Math.round(e.latency_ms||0)} ms.`;kind=outcomeClass(e.outcome)||'info';activeSince=null;activeCandidate=null;phase('score',labels[e.outcome]||e.outcome,outcomeClass(e.outcome));if(!traceLocked)showTrace(e);$('#liveCaption').textContent='Respuesta de la API recibida. Puntuación de selección calculada localmente.';$('#liveLatency').textContent=`${Math.round(e.latency_ms||0)} ms | ${e.instrumentation==='inferred'?'Sin se\u00f1al estructurada del guardrail':e.instrumentation==='synthetic'?'Simulaci\u00f3n':'Se\u00f1al del endpoint'}`;$('#waitLabel').textContent='respuesta recibida';recentRows.push(e);if(recentRows.length>200)recentRows.shift();renderRows();}
 if(e.type==='generation_completed'){msg=`G${e.generation}: ${e.evaluated} evaluados; ${e.elites} seleccionados.`;phase('select','Seleccionando variantes');}
 if(e.type==='population_ready'){msg=`G${e.generation}: ${e.population} variantes nuevas generadas.`;phase('prepare','Nueva generaci\u00f3n');}
 if(e.type==='run_finished'){msg='Motor finalizado: '+(e.status==='budget_exhausted'?'límite de evaluaciones alcanzado':e.status);kind=e.status==='completed'?'good':'warn';}
 if(e.type==='cancel_requested'){msg=e.message;kind='warn';}
 if(e.type==='error'){msg=e.message;kind='bad';phase('wait','Error de ejecuci\u00f3n','bad');}
 if(e.type==='artifacts_ready'){msg='Evidencia y reporte guardados.';kind='good';}
 addEvent(msg,kind,e.time*1000);
}
function resetLive(){recentRows=[];seenSeq=0;traceLocked=false;activeSince=null;$('#events').innerHTML='';$('#liveRows').innerHTML='<tr><td colspan="7" class="empty">Preparando ejecuci\u00f3n...</td></tr>';$('#liveLineage').innerHTML='';$('#liveBypass').textContent='\u2014';$('#liveEvaluated').textContent='0';$('#liveErrors').textContent='0';$('#liveGeneration').textContent='\u2014';$('#reportLink').hidden=true;$('#liveReportLink').hidden=true;}
async function startRun(){if(isRunning)return;try{if(targetType==='fixture'&&!confirm('Esta ejecución generará resultados simulados y NO probará tu API. ¿Continuar?'))return;const c=config();launching=true;requestEpoch++;isRunning=true;updateControls();resetLive();const r=await api('/api/run',c);if($('#generatorApiKey')){$('#generatorApiKey').value='';invalidateGenerator('Clave retirada de la interfaz');}launching=false;seenJob=r.job_id;lastState='running';lastTerminalHandled=null;setStatus(targetType==='fixture'?'Simulando':'Ejecutando');liveMode(targetType);$('#liveSubtitle').textContent=r.job_id;showLive();phase('send','Revalidando endpoint');poll()}catch(e){launching=false;isRunning=false;updateControls();notify(e.message);setStatus('No iniciada','bad')}}
$('#runBtn').onclick=startRun;
$('#stopBtn').onclick=async()=>{try{await api('/api/cancel',{});$('#stopBtn').disabled=true;$('#liveCaption').textContent='Cancelaci\u00f3n solicitada: esperando a que termine la petici\u00f3n en curso.'}catch(e){notify(e.message)}};
async function poll(){if(pollBusy||launching)return;const epoch=requestEpoch;pollBusy=true;try{const s=await api('/api/status?after='+seenSeq);if(epoch!==requestEpoch||launching)return;if(!s.job_id)return;if(s.job_id!==seenJob){seenJob=s.job_id;resetLive();lastTerminalHandled=null;return;}
 isRunning=s.state==='running';(s.events||[]).forEach(e=>{if(e.seq>seenSeq){processEvent(e);seenSeq=e.seq;}});$('#liveEvaluated').textContent=s.evaluated;$('#liveLimit').textContent='L\u00edmite: '+s.max_requests;$('#liveErrors').textContent=s.errors;$('#liveBypass').textContent=s.bypass_rate==null?'\u2014':s.bypass_rate.toFixed(2)+'%';$('#liveBypassNote').textContent=s.bypass_denominator?`${s.bypass_denominator} candidatos adversariales con se\u00f1al`:'Faltan se\u00f1ales para calcular el porcentaje';$('#progressBar').style.width=s.progress+'%';$('#liveFlow').classList.toggle('running',isRunning);
 if(s.source)liveMode(s.source.simulation?'simulation':s.source.mode,s.source.url||'');
 if(isRunning){setStatus('Ejecutando');}
 else if(lastTerminalHandled!==s.job_id+':'+s.state){lastTerminalHandled=s.job_id+':'+s.state;activeSince=null;const finished=s.state==='completed';setStatus(finished?'Completada':s.state==='failed'?'Fall\u00f3':s.state==='cancelled'?'Cancelada':'Detenida',finished?'good':s.state==='failed'?'bad':'warn');$('#livePhase').textContent=finished?'Finalizada':s.state==='failed'?'Fall\u00f3':'Detenida';$('#livePhase').className='badge '+(finished?'good':'warn');$('#liveCaption').textContent=s.error||(finished?'Todas las evaluaciones planificadas que permitieron los l\u00edmites han terminado.':'Ejecuci\u00f3n detenida; revisa la evidencia parcial.');if(s.report_url){for(const id of ['reportLink','liveReportLink']){$('#'+id).href=s.report_url;$('#'+id).hidden=false}}if(s.state==='failed')notify(s.error||'La ejecuci\u00f3n fall\u00f3.');}
 lastState=s.state;updateControls();
 }catch(e){if(isRunning){setStatus('Sin conexi\u00f3n al Studio','bad');$('#liveCaption').textContent='Se perdi\u00f3 contacto con Python. No se conocen nuevos resultados.';$('#liveFlow').classList.remove('running');}}
 finally{pollBusy=false}}
setInterval(poll,300);
setInterval(()=>{if(activeSince&&isRunning)$('#liveLatency').textContent=((Date.now()-activeSince)/1000).toFixed(1)+' s esperando';if(connectionToken&&Date.now()>=tokenExpires)invalidate();},200);

Object.assign(HELP, {
 "httpMethod":"Método HTTP que usa tu API para recibir la solicitud. En la mayoría de las APIs de chat será POST. Usa el mismo que en un cURL que ya funcione.",
 "promptPath":"Ruta dentro del JSON donde Kyojitsu debe colocar cada prompt. Ejemplos: question, input.text o messages[0].content. Si la ruta no existe, el botón la crea.",
 "answerPath":"Ruta dentro del JSON de respuesta donde aparece el texto que devolvió la aplicación. Ejemplos: answer o choices[0].message.content. Se comprueba con una llamada real de prueba.",
 "blockedPath":"Campo true/false que indica si el guardrail bloqueó el caso. Si tu API no lo devuelve, Kyojitsu no inventará esa señal y el porcentaje de bypass puede quedar como no observable.",
 "stagePath":"Campo opcional que indica en qué etapa ocurrió el bloqueo. Por ejemplo input antes del modelo u output después del modelo. Déjalo vacío si tu API no lo informa.",
 "reasonPath":"Campo opcional con el motivo del bloqueo o de la decisión. Sirve como evidencia adicional, pero por sí solo no confirma un ataque exitoso.",
 "successPath":"Campo true/false calculado por tu propia aplicación o por un evaluador confiable que confirme que se logró el objetivo de la prueba. Déjalo vacío si no existe.",
 "strictInstrumentation":"Actívalo solo si TODAS las respuestas de tu API siempre incluyen el campo booleano de bloqueo. Si falta en una respuesta, el caso se marcará como problema de formato.",
 "authorized":"Confirma que tienes permiso para probar este endpoint. Kyojitsu realizará solicitudes reales y puede generar consumo o registros en el sistema objetivo.",
 "policyOracleConfirmed":"Actívalo solo si tu laboratorio ya tiene una regla que prohíbe revelar estos textos ficticios. Kyojitsu no crea esa regla automáticamente.",
 "simulationConfirmed":"La simulación no se conecta a un guardrail. Sirve para ensayar la interfaz y la presentación con datos sintéticos.",
 "generations":"Número de rondas de mejora después del conjunto inicial G0. Por ejemplo, 3 ejecuta G0 y puede crear G1, G2 y G3, siempre que no se alcance antes el límite total.",
 "population":"Cantidad máxima de prompts adversariales que se intentan conservar por ronda. Un valor mayor explora más variantes, pero también puede consumir más solicitudes.",
 "elite":"Proporción de los casos con mejor señal que se toma como base para crear la siguiente ronda. 0.25 significa 25 %. No representa el porcentaje de ataques exitosos.",
 "seedsPerTechnique":"Cantidad de casos iniciales que se preparan para cada técnica seleccionada. Por ejemplo, 2 casos x 3 técnicas = 6 casos iniciales antes de agregar controles permitidos.",
 "maxRequests":"Tope de evaluaciones que Kyojitsu enviará a la API objetivo durante esta campaña. Las llamadas al modelo generador se cuentan por separado.",
 "interval":"Pausa entre una solicitud y la siguiente. Ayuda a evitar sobrecargar la API objetivo. 0.5 equivale a medio segundo.",
 "randomSeed":"Número usado para repetir las decisiones pseudoaleatorias locales. Ayuda a reproducir una campaña, aunque un LLM remoto puede generar textos diferentes en cada ejecución.",
 "benign":"Incluye preguntas normales que deberían permitirse. Sirven para detectar falsos positivos: situaciones donde el guardrail bloquea contenido legítimo.",
 "secretIndicators":"Opcional y avanzado. Textos ficticios cuya divulgación tu laboratorio ya considera prohibida. Nunca uses contraseñas, tokens ni datos reales.",
 "techSearch":"Filtra por nombre, descripción o identificador OWASP/MITRE. El filtro visual no cambia lo que ya seleccionaste.",
 "generatorMode":"Reglas locales crea variantes mediante transformaciones programadas. Anthropic, Gemini o una API compatible usan un LLM externo para redactar variantes nuevas a partir de la técnica y del feedback observado. Ningún modo entrena una GAN.",
 "generatorUrl":"Endpoint que usa Kyojitsu para pedir nuevas variantes al LLM generador. Es independiente de la API que estás evaluando.",
 "generatorApiKey":"Clave temporal para validar el proveedor y ejecutar esta campaña. No se escribe en reportes, SQLite ni archivos de configuración; el navegador la borra al iniciar y el servidor la elimina al terminar.",
 "generatorModel":"Modelo que redactará las variantes. Pulsa Validar clave y cargar modelos para consultar dinámicamente los modelos disponibles para tu credencial.",
 "generatorMaxCalls":"Tope de llamadas al LLM generador durante la campaña. Este límite controla la generación de variantes; no es el mismo que el número de pruebas enviadas al guardrail.",
 "generatorTimeout":"Tiempo máximo que Kyojitsu esperará cada respuesta del modelo generador. Si vence, se registra el error y no se sustituye silenciosamente por reglas locales.",
 "generatorConsent":"Confirma que tienes autorización para enviar al proveedor de generación los casos de prueba y feedback resumido de la campaña.",
 "discoverModelsBtn":"Valida la clave temporal consultando al proveedor y carga los modelos que esa credencial puede usar. No realiza una campaña.",
 "testGeneratorBtn":"Envía una única solicitud de generación de prueba al modelo seleccionado para comprobar el contrato de respuesta. Puede generar consumo en el proveedor."
});
setupHelp();
let navExpanded=true;
try{navExpanded=localStorage.getItem('kyojitsu-nav-35')!=='closed'}catch(e){}
function setNav(){document.documentElement.classList.toggle('nav-expanded',navExpanded);$('#navToggle').setAttribute('aria-expanded',String(navExpanded));$('#navToggle').setAttribute('aria-label',navExpanded?'Plegar menú':'Desplegar menú');hideHelp();}
function collapseNarrow(){if(innerWidth<900&&navExpanded){navExpanded=false;setNav();}}
window.addEventListener('resize',collapseNarrow);
setNav();collapseNarrow();$('#navToggle').onclick=()=>{navExpanded=!navExpanded;setNav();try{localStorage.setItem('kyojitsu-nav-35',navExpanded?'open':'closed')}catch(e){}};
$('#applySignalsBtn').onclick=()=>{for(const [k,v] of Object.entries(detectedSignals)){const id={blocked:'blockedPath',stage:'stagePath',reason:'reasonPath'}[k];if(id)$('#'+id).value=v;}invalidate();$('#testMessage').textContent='Mapeo actualizado. Repite Probar API para validarlo.';};
const PROVIDERS={
 rules:{generation:'No aplica',models:'No aplica',url:'',label:'Reglas locales'},
 anthropic:{generation:'https://api.anthropic.com/v1/messages',models:'https://api.anthropic.com/v1/models',url:'https://api.anthropic.com/v1/messages',label:'Anthropic'},
 gemini:{generation:'https://generativelanguage.googleapis.com/v1beta/interactions',models:'https://generativelanguage.googleapis.com/v1beta/models',url:'https://generativelanguage.googleapis.com/v1beta/interactions',label:'Google Gemini'},
 openai_compatible:{generation:'Endpoint compatible con OpenAI',models:'Derivado de /v1/models',url:'https://api.openai.com/v1/chat/completions',label:'API compatible con OpenAI'}
};
let providerValidated=false,discoveredGeneratorModels=[];
function invalidateGenerator(message='Clave sin validar'){
 providerValidated=false;discoveredGeneratorModels=[];
 const s=$('#generatorProviderStatus'); if(s){s.textContent=message;s.className='badge neutral'}
 const list=$('#generatorModels'); if(list)list.innerHTML='';
}
function geminiUrlForModel(model){
 const found=discoveredGeneratorModels.find(m=>m.id===model);
 if(found?.generation_url)return found.generation_url;
 if(/^gemini-(?:1|2)(?:\.|-)/.test(model||''))return `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
 return PROVIDERS.gemini.url;
}
function syncGeminiTransport(){
 if(val('generatorMode')!=='gemini')return;
 const model=val('generatorModel').trim();if(!model)return;
 const next=geminiUrlForModel(model);
 $('#generatorUrl').value=next;$('#providerGenerationUrl').textContent=next;
 const found=discoveredGeneratorModels.find(m=>m.id===model);
 if(found?.transport)$('#generatorTestResult').textContent=`Transporte seleccionado para ${model}: ${found.transport}.`;
}
function setGenerator(){
 const mode=val('generatorMode'),llm=mode!=='rules',meta=PROVIDERS[mode]||PROVIDERS.openai_compatible;
 $('#generatorFields').hidden=!llm;
 $$('.fnode[data-phase=prepare]').forEach(e=>e.classList.toggle('generated',llm));
 $('#generatorBadge').textContent=llm?'Generación con LLM':'Reglas locales';$('#generatorBadge').className='badge '+(llm?'gen':'neutral');
 $('#generatorDescription').textContent=llm?'Un modelo independiente redacta nuevas variantes usando la técnica elegida y feedback resumido de rondas anteriores.':'Transformaciones programadas y selección adaptativa, sin enviar datos a un LLM externo.';
 $('#liveGeneratorSource').textContent=llm?'Generación: '+meta.label:'Generación: reglas locales adaptativas';
 $('#providerGenerationUrl').textContent=meta.generation;$('#providerModelsUrl').textContent=meta.models;
 if(llm){const current=val('generatorUrl');const known=Object.values(PROVIDERS).map(x=>x.url).filter(Boolean);if(!current||known.includes(current))$('#generatorUrl').value=meta.url;}
 invalidateGenerator();
}
$('#generatorMode').onchange=setGenerator;
['generatorUrl','generatorApiKey'].forEach(id=>$('#'+id).addEventListener('input',()=>invalidateGenerator()));
$('#generatorModel').addEventListener('change',syncGeminiTransport);$('#generatorModel').addEventListener('input',()=>{if(val('generatorMode')==='gemini')syncGeminiTransport()});
$('#discoverModelsBtn').onclick=async()=>{
 const b=$('#discoverModelsBtn');try{b.disabled=true;const st=$('#generatorProviderStatus');st.textContent='Validando…';st.className='badge warn';const out=await api('/api/generator-models',{generator:config().generator});
  const models=out.models||[];discoveredGeneratorModels=models;$('#generatorModels').innerHTML=models.map(m=>`<option value="${esc(m.id)}">${esc(m.name||m.id)}${m.transport?' · '+esc(m.transport):''}</option>`).join('');
  if(models.length&&!val('generatorModel'))$('#generatorModel').value=models[0].id;
  providerValidated=true;st.textContent=`${models.length} modelos disponibles`;st.className='badge good';
  if(out.generation_url){$('#providerGenerationUrl').textContent=out.generation_url;if(val('generatorMode')!=='openai_compatible')$('#generatorUrl').value=out.generation_url;}
  if(val('generatorMode')==='gemini'&&val('generatorModel'))syncGeminiTransport();
  if(out.models_url)$('#providerModelsUrl').textContent=out.models_url;$('#generatorTestResult').textContent=out.message||'Clave validada y modelos cargados.';addEvent(out.message||'Proveedor de generación validado.','good');
 }catch(e){invalidateGenerator('Validación fallida');$('#generatorTestResult').textContent=e.message;notify(e.message)}finally{b.disabled=false;}
};
$('#testGeneratorBtn').onclick=async()=>{const b=$('#testGeneratorBtn');try{b.disabled=true;$('#generatorTestResult').textContent='Solicitando una variante segura de prueba…';const out=await api('/api/test-generator',{generator:config().generator});$('#generatorTestResult').textContent=out.message||'Generador validado.';addEvent(out.message||'Generador validado.','good')}catch(e){$('#generatorTestResult').textContent=e.message;notify(e.message)}finally{b.disabled=false;}};
setGenerator();
showConfig('targetPanel');

(async()=>{catalog=await api('/api/catalog');prune();renderFrameworks();renderCategories();renderTechniques();updateSummary();await poll();})().catch(e=>{notify(e.message);setStatus('Error de cat\u00e1logo','bad')});
})();
