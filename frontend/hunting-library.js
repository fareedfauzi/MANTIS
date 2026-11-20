(() => {
    const pane=document.getElementById('hunting-library-pane'); if(!pane) return;
    const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const cleanTitle=value=>String(value||'').replace(/^\s*[A-Za-z]{0,2}\d{1,3}(?:[.)]|[-–:])\s+/, '');
    const base=location.protocol==='file:'?'http://127.0.0.1:9999':location.origin;
    let repos=[], items=[], facets={}, total=0, offset=0, selected=null, poll=null;
    pane.innerHTML=`<div class="hl-layout"><header class="hl-hero"><div><div class="hl-kicker">THREAT INTELLIGENCE / HUNTING</div><h1>Threat Hunting Library</h1><p>Search original hunting queries from public GitHub repositories. Classification is labeled when inferred.</p></div><div class="hl-hero-actions"><button id="hl-open-converter" type="button" class="btn-secondary"><i class="fa-solid fa-arrow-right-arrow-left" aria-hidden="true"></i> Native Query Converter</button><button id="hl-sync-all" class="btn-primary">Sync all repositories</button></div></header>
      <div class="hl-grid"><main><section class="hl-card hl-search"><div class="hl-search-line"><input id="hl-q" placeholder="Search query, malware, actor, behavior or ATT&CK ID" aria-label="Search queries"><button id="hl-search" class="btn-primary">Search</button></div>
      <div class="hl-filters"><select id="hl-language" aria-label="Language"><option value="">All languages</option></select><select id="hl-platform" aria-label="Platform"><option value="">All platforms</option></select><select id="hl-category" aria-label="Category"><option value="">All categories</option></select><select id="hl-repo" aria-label="Repository"><option value="">All repositories</option></select></div></section>
      <div class="hl-results-head"><span id="hl-count">Loading...</span><span>Original queries · GitHub attribution</span></div><div id="hl-results" class="hl-results"></div>
      <div class="hl-pages"><button id="hl-prev" class="btn-secondary">Previous</button><span id="hl-page"></span><button id="hl-next" class="btn-secondary">Next</button></div></main>
      <aside><section class="hl-card"><div class="hl-side-head"><h2>Repositories</h2><span id="hl-running"></span></div><div id="hl-repos"></div>
      <form id="hl-add-form"><label for="hl-add">Add public repository</label><div><input id="hl-add" placeholder="owner/repo" required><button class="btn-secondary">Add</button></div></form><div id="hl-status" role="status"></div></section></aside></div>
      <div id="hl-detail" class="hl-overlay" hidden><div class="hl-detail" role="dialog" aria-modal="true" aria-labelledby="hl-detail-title"><button id="hl-close" class="hl-close" type="button" aria-label="Close query details"><i class="fa-solid fa-xmark" aria-hidden="true"></i></button><div id="hl-detail-content"></div></div></div>
      <div id="hl-converter" class="hl-overlay" hidden><div class="hl-converter" role="dialog" aria-modal="true" aria-labelledby="hl-converter-title"><button id="hl-converter-close" type="button" class="hl-close" aria-label="Close converter"><i class="fa-solid fa-xmark" aria-hidden="true"></i></button><header class="hl-converter-intro"><span class="hl-section-kicker">THREAT HUNTING LIBRARY</span><h2 id="hl-converter-title">Native Query Converter</h2><p>Translate a hunting query between SIEM and EDR platforms using MANTIS AI. Review the output against your own schema before running it.</p></header>
      <div class="hl-converter-body"><div class="hl-converter-settings"><label for="hl-source">Source platform<select id="hl-source"><option value="">Select source platform</option></select></label><label for="hl-target">Target platform<select id="hl-target"><option value="">Select target platform</option></select></label></div>
      <div class="hl-converter-editors"><label for="hl-native-input">Original query<textarea id="hl-native-input" spellcheck="false" placeholder="Paste a SIEM or EDR hunting query..."></textarea></label><label for="hl-native-output">Converted query<textarea id="hl-native-output" spellcheck="false" readonly placeholder="Converted query will appear here."></textarea></label></div>
      <div id="hl-converter-status" role="status" aria-live="polite"></div><div class="hl-converter-actions"><button type="button" id="hl-copy-output" class="btn-secondary" disabled><i class="fa-regular fa-copy" aria-hidden="true"></i> Copy output</button><button type="button" id="hl-run-converter" class="btn-primary"><i class="fa-solid fa-arrow-right-arrow-left" aria-hidden="true"></i> Convert query</button></div></div></div></div></div>`;
    const $=id=>document.getElementById(id);
    async function api(path, options){const res=await fetch(base+'/api/hunting-library'+path,options);let data;try{data=await res.json()}catch(_){throw Error('Invalid server response')}if(!res.ok)throw Error(data.detail||`HTTP ${res.status}`);return data}
    const post=(path,body={})=>api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const setStatus=(msg,error=false)=>{$('hl-status').textContent=msg;$('hl-status').classList.toggle('hl-error',error)};
    let platforms=[], converterReturnFocus=null, converterGeneration=0;
    const converterStatus=(msg,error=false)=>{const status=$('hl-converter-status');status.textContent=msg;status.classList.toggle('hl-error',error)};
    function inferSource(language,platform){
        const lang=String(language||'').toUpperCase(), name=String(platform||'');
        if(/Splunk/i.test(name)||lang==='SPL')return 'splunk';
        if(/Defender/i.test(name))return 'defender';
        if(/SentinelOne/i.test(name))return 'sentinelone_dv';
        if(/Sentinel/i.test(name))return 'sentinel';
        if(/CrowdStrike/i.test(name))return 'crowdstrike';
        if(/QRadar/i.test(name)||lang==='AQL')return 'qradar';
        if(/Chronicle|SecOps/i.test(name)||lang.startsWith('YARA-L'))return 'secops';
        if(/Sumo Logic/i.test(name))return 'sumologic';
        if(/CloudWatch/i.test(name))return 'cloudwatch';
        if(lang==='EQL')return 'elastic_eql';
        if(lang==='PPL')return 'elastic_ppl';
        if(/Elastic/i.test(name)&&lang==='KQL')return 'elastic_kql';
        if(/Elastic/i.test(name)&&/DSL/i.test(lang))return 'elastic_dsl';
        return '';
    }
    async function loadConverterOptions(){
        try{
            platforms=await api('/platforms');
            for(const id of ['hl-source','hl-target']){
                const select=$(id),old=select.value;
                select.replaceChildren(new Option('Select '+(id==='hl-source'?'source':'target')+' platform',''),
                    ...platforms.map(p=>new Option(p.name+' · '+p.language,p.id)));
                select.value=old;
            }
        }catch(e){converterStatus(e.message,true)}
    }
    async function openConverter(query='',language='',platform=''){
        const generation=++converterGeneration;
        converterReturnFocus=$('hl-detail').hidden?document.activeElement:
            pane.querySelector('#hl-results [data-index="'+items.indexOf(selected)+'"]');
        $('hl-detail').hidden=true;
        $('hl-converter').hidden=false;
        $('hl-native-input').value=query;
        $('hl-native-output').value='';
        $('hl-copy-output').disabled=true;
        converterStatus('');
        $('hl-source').value='';$('hl-target').value='';
        $('hl-source').focus();
        await loadConverterOptions();
        if($('hl-converter').hidden||generation!==converterGeneration)return;
        const candidate=inferSource(language,platform);
        if(platforms.some(p=>p.id===candidate))$('hl-source').value=candidate;
        $('hl-target').value=platforms.find(p=>p.id!==candidate)?.id||'';
        if(query&&!candidate)converterStatus('Source platform is uncertain. Select the correct platform before converting.');
        if(!query)$('hl-native-input').focus();
    }
    function closeConverter(){
        if($('hl-converter').hidden)return;
        converterGeneration++;
        $('hl-converter').hidden=true;
        if(converterReturnFocus?.isConnected)converterReturnFocus.focus();
    }
    $('hl-open-converter').onclick=()=>openConverter();
    $('hl-converter-close').onclick=closeConverter;
    $('hl-converter').onclick=e=>{if(e.target===$('hl-converter'))closeConverter()};
    $('hl-converter').onkeydown=e=>{
        if(e.key==='Escape'){e.preventDefault();closeConverter();return}
        if(e.key!=='Tab')return;
        const controls=[...$('hl-converter').querySelectorAll('button:not([disabled]),select,input,textarea')];
        if(e.shiftKey&&document.activeElement===controls[0]){e.preventDefault();controls.at(-1).focus()}
        else if(!e.shiftKey&&document.activeElement===controls.at(-1)){e.preventDefault();controls[0].focus()}
    };
    const invalidateConversion=()=>{converterGeneration++;$('hl-native-output').value='';$('hl-copy-output').disabled=true;converterStatus('')};
    $('hl-native-input').oninput=invalidateConversion;
    for(const id of ['hl-source','hl-target']){
        $(id).addEventListener('change',invalidateConversion);
    }
    $('hl-run-converter').onclick=async()=>{
        const query=$('hl-native-input').value,source=$('hl-source').value,target=$('hl-target').value;
        if(!query.trim()||!source||!target){converterStatus('Enter a query and select both platforms.',true);return}
        if(source===target){converterStatus('Choose a different target platform.',true);return}
        const generation=converterGeneration,button=$('hl-run-converter');button.disabled=true;converterStatus('Converting query...');
        try{
            const data=await post('/convert',{query,source,target});
            if(generation!==converterGeneration)return;
            if(!data.revised_query)throw Error('Conversion returned no query');
            $('hl-native-output').value=data.revised_query;
            $('hl-copy-output').disabled=false;
            converterStatus('Conversion complete. Verify fields and syntax against your environment.');
        }catch(e){if(generation===converterGeneration)converterStatus(e.message,true)}finally{button.disabled=false}
    };
    $('hl-copy-output').onclick=async()=>{
        try{await navigator.clipboard.writeText($('hl-native-output').value);converterStatus('Converted query copied.')}
        catch(e){converterStatus('Copy failed: '+e.message,true)}
    };
    async function loadRepos(){
        try { repos=await api('/repos');
            $('hl-repos').innerHTML=repos.map(r=>`<div class="hl-repo" data-repo="${esc(r.name)}">
                <div class="hl-repo-info"><strong>${esc(r.name)}</strong><small>${esc(r.license||'License unknown')} · ${esc(r.count)} source queries</small>
                <small>${esc(r.state)}${r.last_sync?' · '+esc(r.last_sync.slice(0,10)):''}</small>
                ${r.error?`<details class="hl-repo-error"><summary>Sync failed · view reason</summary><p>${esc(r.error)}</p></details>`:''}</div>
                <div class="hl-repo-actions"><button data-action="sync" class="btn-secondary" title="Synchronize ${esc(r.name)}"><i class="fa-solid fa-rotate" aria-hidden="true"></i> Sync</button>
                <button data-action="history" class="btn-secondary">History</button><button data-action="remove" class="btn-secondary" title="Remove ${esc(r.name)}"><i class="fa-solid fa-trash-can" aria-hidden="true"></i> Remove</button></div></div>`).join('');
            const select=$('hl-repo'),value=select.value;select.innerHTML='<option value="">All repositories</option>'+repos.map(r=>`<option value="${esc(r.name)}">${esc(r.name)}</option>`).join('');select.value=value;
            const running=repos.some(r=>r.state==='running');$('hl-running').textContent=running?'Syncing…':'';
            clearTimeout(poll);if(running)poll=setTimeout(async()=>{await loadRepos();await loadQueries()},4000);
        }catch(e){setStatus(e.message,true)}
    }
    function populate(id,values,label){const select=$(id),value=select.value;select.innerHTML=`<option value="">All ${label}</option>`+(values||[]).map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join('');select.value=value;}
    async function loadQueries(){
        const params=new URLSearchParams({q:$('hl-q').value.trim(),language:$('hl-language').value,platform:$('hl-platform').value,category:$('hl-category').value,repo:$('hl-repo').value,limit:'40',offset:String(offset)});
        try {const data=await api('/queries?'+params);items=data.items;facets=data.facets;total=data.total;
            populate('hl-language',facets.language,'languages');populate('hl-platform',facets.platform,'platforms');populate('hl-category',facets.category,'categories');
            $('hl-count').textContent=`${total.toLocaleString()} unique queries`;$('hl-page').textContent=`${total?offset+1:0}–${Math.min(offset+40,total)} of ${total}`;
            $('hl-prev').disabled=offset===0;$('hl-next').disabled=offset+40>=total;
            $('hl-results').innerHTML=items.map((q,i)=>{const source=q.sources[0]||{};return `<article class="hl-item" data-index="${i}" tabindex="0"><div class="hl-item-top"><span class="hl-language">${esc(q.language)}</span><span>${esc(q.platform)}</span></div><h3>${esc(cleanTitle(source.title)||'Untitled query')}</h3><p>${esc(source.description||q.query.slice(0,180))}</p><div class="hl-item-foot"><span>${esc(q.category)}</span><span>${q.sources.length} source${q.sources.length!==1?'s':''}</span></div></article>`}).join('')||'<div class="hl-empty">No queries found. Synchronize a repository or adjust the filters.</div>';
        }catch(e){$('hl-results').innerHTML=`<div class="hl-empty">${esc(e.message)}</div>`}
    }
    function detail(index) {
        selected=items[index]; if(!selected)return;
        const q=selected, src=q.sources[0]||{}, count=q.sources.length;
        const meta=(label,value,basis)=>
            "<div class='hl-meta-item'><span class='hl-meta-label'>"+label+"</span><strong>"+esc(value||'Not specified')+"</strong><span class='hl-basis "+(basis==='verified'?'hl-basis-verified':basis==='inferred'?'hl-basis-inferred':'')+"'>"+(basis==='verified'?'From source':basis==='inferred'?'Inferred':'Unspecified')+"</span></div>";
        const sources=q.sources.map(s=>{
            const safe=/^https:\/\/github\.com\//i.test(s.url||'')?s.url:'';
            const title=esc(s.repo)+' / '+esc(s.path);
            return "<div class='hl-source'><div class='hl-source-title'><i class='fa-brands fa-github' aria-hidden='true'></i>"+
                (safe?"<a href='"+esc(safe)+"' target='_blank' rel='noopener noreferrer'>"+title+" <i class='fa-solid fa-arrow-up-right-from-square' aria-hidden='true'></i></a>":"<span>"+title+"</span>")+
                "</div><div class='hl-source-facts'>"+(s.author?"<span>Author: "+esc(s.author)+"</span>":'')+
                (s.updated?"<span>Repository updated "+esc(s.updated.slice(0,10))+"</span>":'')+
                ((s.mitre||[]).length?"<span>ATT&CK: "+s.mitre.map(esc).join(', ')+"</span>":'')+
                (s.tags?"<span>Tags: "+esc(s.tags)+"</span>":'')+"</div></div>";
        }).join('');
        $('hl-detail-content').innerHTML=
            "<div class='hl-detail-intro'><div class='hl-detail-eyebrow'><span class='hl-language'>"+esc(q.language)+"</span><span class='hl-detail-separator'></span><span>Hunting query</span><span class='hl-detail-separator'></span><span>"+count+" source"+(count===1?'':'s')+"</span></div>"+
            "<h2 id='hl-detail-title'>"+esc(cleanTitle(src.title)||'Untitled query')+"</h2>"+(src.description?"<p>"+esc(src.description)+"</p>":'')+"</div>"+
            "<div class='hl-meta'>"+meta('Platform',q.platform,q.platform_basis)+meta('Category',q.category,q.category_basis)+meta('Required telemetry',q.telemetry,q.telemetry_basis)+"</div>"+
            "<section class='hl-query-section' aria-label='Original query'><div class='hl-code-head'><div><span class='hl-section-kicker'>ORIGINAL QUERY</span><h3>Source query</h3></div><div class='hl-query-actions'><button id='hl-copy' type='button' class='btn-secondary'><i class='fa-regular fa-copy' aria-hidden='true'></i> Copy query</button><button id='hl-convert' type='button' class='btn-primary'><i class='fa-solid fa-arrow-right-arrow-left' aria-hidden='true'></i> Convert query</button></div></div><pre class='hl-query-code'><code id='hl-code'></code></pre></section>"+
            "<section class='hl-attribution' aria-label='Sources and attribution'><div class='hl-attribution-head'><span class='hl-section-kicker'>PROVENANCE</span><h3>Sources and attribution <span>"+count+"</span></h3></div><div class='hl-sources'>"+sources+"</div></section>";
        $('hl-code').textContent=q.query;
        if(window.hljs){try{window.hljs.highlightElement($('hl-code'))}catch(_){}}
        $('hl-detail').hidden=false;
        $('hl-close').focus();
        $('hl-copy').onclick=async()=>{
            const button=$('hl-copy');
            try {
                await navigator.clipboard.writeText(q.query);
                button.innerHTML="<i class='fa-solid fa-check' aria-hidden='true'></i> Copied";
                setTimeout(()=>{if(button.isConnected)button.innerHTML="<i class='fa-regular fa-copy' aria-hidden='true'></i> Copy query"},1800);
            } catch(_) { button.textContent='Copy failed'; }
        };
        $('hl-convert').onclick=()=>openConverter(q.query,q.language,q.platform);
    }
    $('hl-results').onclick=e=>{const card=e.target.closest('[data-index]');if(card)detail(Number(card.dataset.index))};
    $('hl-results').onkeydown=e=>{if(e.key==='Enter'){const card=e.target.closest('[data-index]');if(card)detail(Number(card.dataset.index))}};
    const closeDetail=()=>{if($('hl-detail').hidden)return;$('hl-detail').hidden=true;const card=pane.querySelector('#hl-results [data-index="'+items.indexOf(selected)+'"]');card?.focus()};
    $('hl-close').onclick=closeDetail;
    $('hl-detail').onclick=e=>{if(e.target===$('hl-detail'))closeDetail()};
    $('hl-detail').onkeydown=e=>{if(e.key==='Escape'){e.preventDefault();closeDetail()}if(e.key==='Tab'){const controls=[$('hl-close'),$('hl-copy'),$('hl-convert')].filter(Boolean);if(e.shiftKey&&document.activeElement===controls[0]){e.preventDefault();controls.at(-1).focus()}else if(!e.shiftKey&&document.activeElement===controls.at(-1)){e.preventDefault();controls[0].focus()}}};
    $('hl-search').onclick=()=>{offset=0;loadQueries()};$('hl-q').onkeydown=e=>{if(e.key==='Enter'){offset=0;loadQueries()}};
    ['hl-language','hl-platform','hl-category','hl-repo'].forEach(id=>$(id).onchange=()=>{offset=0;loadQueries()});
    $('hl-prev').onclick=()=>{offset=Math.max(0,offset-40);loadQueries()};$('hl-next').onclick=()=>{offset+=40;loadQueries()};
    $('hl-add-form').onsubmit=async e=>{e.preventDefault();try{const data=await post('/repos',{repo:$('hl-add').value});$('hl-add').value='';await loadRepos();await post('/repos/'+data.repo+'/sync');window.showStartupProgress?.();setStatus('Repository added; synchronization started.');await loadRepos()}catch(err){setStatus(err.message,true)}};
    $('hl-sync-all').onclick=async()=>{try{await post('/sync');window.showStartupProgress?.();setStatus('Synchronization started.');await loadRepos()}catch(e){setStatus(e.message,true)}};
    $('hl-repos').onclick=async e=>{const btn=e.target.closest('[data-action]');if(!btn)return;const repo=btn.closest('[data-repo]').dataset.repo;
        try{if(btn.dataset.action==='remove'){if(!confirm(`Remove ${repo} and its source references?`))return;await api('/repos/'+repo,{method:'DELETE'});await loadQueries()}
            else if(btn.dataset.action==='sync'){await post('/repos/'+repo+'/sync');window.showStartupProgress?.();setStatus(`Synchronizing ${repo}...`)}
            else{const rows=await api('/repos/'+repo+'/history');setStatus(rows.length?rows.map(r=>`${r.finished.slice(0,16)} ${r.state}: ${r.detail}`).join(' | '):'No sync history yet.')}
            await loadRepos();}catch(err){setStatus(err.message,true)}
    };
    window.initHuntingLibrary=async()=>{await loadRepos();await loadQueries()};
})();
