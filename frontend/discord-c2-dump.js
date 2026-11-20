/* Discord C2 evidence explorer. Credentials are not persisted by the browser. */
(() => {
  const pane=document.getElementById('discord-c2-pane'); if(!pane) return;
  const base=location.protocol==='file:'?'http://127.0.0.1:9999':location.origin;
  const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const $=id=>document.getElementById(id), qs=o=>new URLSearchParams(o).toString();
  let guild=null, page=0, last=[], jobId=null;
  const ICON_SEARCH='<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>';
  pane.innerHTML=`<div class="dc">
  <header class="dc-top">
    <div class="dc-brand"><span class="dc-logo"><i class="fa-brands fa-discord"></i></span>
      <div><h1>Discord C2 Dump</h1><p>Collect accessible guild evidence and investigate it locally.</p></div></div>
    <span class="dc-badge"><i class="fa-solid fa-lock"></i> Read-only Discord API</span>
  </header>

  <section class="dc-panel">
    <div class="dc-panel-head"><div><h2>Connect to a guild</h2><p>Enter a recovered bot token and guild ID. The token is used for the active collection and is never stored.</p></div></div>
    <div class="dc-connect">
      <label class="dc-field"><span>Bot token</span><input id="dc-token" type="password" autocomplete="off" spellcheck="false" placeholder="Recovered bot token"></label>
      <label class="dc-field dc-field-narrow"><span>Guild ID</span><input id="dc-guild" inputmode="numeric" autocomplete="off" placeholder="Discord server ID"></label>
      <button id="dc-inspect" class="dc-btn dc-btn-primary">Inspect guild</button>
    </div>
    <div id="dc-info" class="dc-status" role="status"></div>
  </section>

  <section id="dc-collect-card" class="dc-panel" hidden>
    <div class="dc-panel-head">
      <div><h2>Channel inventory</h2><p>Message history and pins are collected from readable channels. Voice, stage and category entries provide context.</p></div>
      <span id="dc-guild-label" class="dc-chip"></span>
    </div>
    <div class="dc-toolbar">
      <button id="dc-all" class="dc-btn dc-btn-ghost">Select readable</button>
      <button id="dc-none" class="dc-btn dc-btn-ghost">Clear</button>
    </div>
    <div id="dc-channels" class="dc-channels"></div>
    <div class="dc-footer">
      <div class="dc-options">
        <label class="dc-switch"><input id="dc-download" type="checkbox" checked><span class="dc-switch-track"></span><span>Download attachments</span></label>
        <label class="dc-inline">Max file size <input id="dc-maxmb" type="number" min="1" max="100" value="25"><small>MB</small></label>
      </div>
      <div class="dc-footer-actions">
        <div id="dc-collection-status" class="dc-status" role="status"></div>
        <button id="dc-cancel" class="dc-btn dc-btn-ghost" hidden>Cancel</button>
        <button id="dc-collect" class="dc-btn dc-btn-primary">Start collection</button>
      </div>
    </div>
    <div id="dc-coverage" class="dc-coverage"></div>
  </section>

  <section id="dc-names-card" class="dc-panel" hidden>
    <div class="dc-panel-head"><div><h2>Guild names</h2><p>Roles, emojis and channels. Matches highlight URLs, IPs and hashes.</p></div></div>
    <div class="dc-search"><span class="dc-search-icon">${ICON_SEARCH}</span><input id="dc-name-search" placeholder="Search names, URLs, IPs or hashes"><button id="dc-name-button" class="dc-btn dc-btn-ghost">Search</button></div>
    <div id="dc-names" class="dc-names"></div>
  </section>

  <section class="dc-panel">
    <div class="dc-panel-head"><div><h2>Collected messages</h2><p>Filter the local evidence store.</p></div>
      <button id="dc-export" class="dc-btn dc-btn-ghost"><i class="fa-solid fa-file-arrow-down"></i> Export page</button></div>
    <div class="dc-filters">
      <div class="dc-search dc-search-grow"><span class="dc-search-icon">${ICON_SEARCH}</span><input id="dc-search" placeholder="Search messages and attachment text"></div>
      <input id="dc-filter-guild" class="dc-input-sm" placeholder="Guild ID">
      <input id="dc-filter-channel" class="dc-input-sm" placeholder="Channel ID">
      <label class="dc-switch"><input id="dc-pinned" type="checkbox"><span class="dc-switch-track"></span><span>Pinned only</span></label>
      <button id="dc-search-btn" class="dc-btn dc-btn-primary">Search</button>
    </div>
    <div id="dc-results" class="dc-results"></div>
    <div class="dc-pager"><span id="dc-count" class="dc-count"></span><div class="dc-pager-btns"><button id="dc-prev" class="dc-btn dc-btn-ghost">Previous</button><button id="dc-next" class="dc-btn dc-btn-ghost">Next</button></div></div>
  </section>
  </div>`;
  function status(id,value,error=false){const el=$(id);el.textContent=value;el.classList.toggle('dc-error',error);}
  async function api(path,options){const response=await fetch(base+'/api/discord-c2'+path,options);let body;try{body=await response.json();}catch(_){throw Error('Invalid server response');}if(!response.ok)throw Error(typeof body.detail==='string'?body.detail:'HTTP '+response.status);return body;}
  const post=(path,data)=>api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
  const creds=()=>({token:$('dc-token').value.trim(),guild_id:$('dc-guild').value.trim()});
  async function coverage(){if(!guild)return;const rows=await api('/channels?'+qs({guild_id:guild.id}));const map=new Map(rows.map(c=>[c.id,c]));pane.querySelectorAll('#dc-channels label[data-channel]').forEach(el=>{const c=map.get(el.dataset.channel);if(c)el.querySelector('.dc-state').textContent=c.state+' · '+c.history_count+' history · '+c.pins_count+' pins';});$('dc-coverage').innerHTML=rows.filter(c=>c.error).map(c=>'<p class="dc-gap"><i class="fa-solid fa-triangle-exclamation"></i> '+esc(c.name)+': '+esc(c.error)+'</p>').join('');}
  async function names(){if(!guild)return;const rows=await api('/names?'+qs({guild_id:guild.id,search:$('dc-name-search').value.trim()}));$('dc-names').innerHTML=rows.map(n=>'<div class="dc-name"><div class="dc-name-top"><span class="dc-kind">'+esc(n.kind)+'</span><strong>'+esc(n.name)+'</strong></div><code>'+esc(n.id)+'</code>'+(n.matches.length?'<em>'+esc(n.matches.join(' · '))+'</em>':'')+'</div>').join('')||'<p class="dc-empty">No matching names.</p>';}
  $('dc-inspect').onclick=async()=>{const btn=$('dc-inspect');btn.disabled=true;status('dc-info','Inspecting guild, channels, threads and names…');try{const data=await post('/inspect',creds());guild=data.guild;$('dc-guild-label').textContent=guild.name+' · '+data.channels.length+' entries';$('dc-channels').innerHTML=data.channels.map(c=>'<label data-channel="'+esc(c.id)+'" class="dc-chan'+(c.collectable?'':' dc-unreadable')+'"><input type="checkbox" value="'+esc(c.id)+'" '+(c.collectable?'checked':'disabled')+'><span class="dc-chan-body"><span class="dc-chan-name">'+esc(c.name)+'</span><span class="dc-chan-type">'+esc(c.type_label)+'</span></span><span class="dc-state"></span></label>').join('')||'<p class="dc-empty">No channels returned.</p>';$('dc-collect-card').hidden=false;$('dc-names-card').hidden=false;$('dc-filter-guild').value=guild.id;const issues=data.warnings.map(w=>(w.channel||w.scope)+': '+w.error).join('; ');status('dc-info','Bot '+(data.bot.username||data.bot.id)+' · '+data.channels.filter(c=>c.collectable).length+' message channels or threads · '+data.names.roles+' roles · '+data.names.emojis+' emojis.'+(issues?' Gaps: '+issues:''),!!issues);await Promise.all([coverage(),names(),load()]);}catch(e){status('dc-info',e.message,true);}finally{btn.disabled=false;}};
  $('dc-all').onclick=()=>pane.querySelectorAll('#dc-channels input:not(:disabled)').forEach(c=>c.checked=true);
  $('dc-none').onclick=()=>pane.querySelectorAll('#dc-channels input').forEach(c=>c.checked=false);
  async function poll(){if(!jobId)return;try{const job=await api('/jobs/'+jobId), problems=Array.isArray(job.error)?job.error.map(e=>(e.channel||e.scope)+': '+e.error).join('; '):job.error;status('dc-collection-status',job.state+' · '+job.channel_done+'/'+(job.channel_ids.length||job.channels.filter(c=>[0,5,10,11,12].includes(c.type)).length)+' channels · '+job.read_count+' history messages'+(problems?' · '+problems:''),['failed','partial','interrupted'].includes(job.state));await Promise.all([coverage(),load()]);if(['queued','running'].includes(job.state))setTimeout(poll,2000);else{$('dc-collect').disabled=false;$('dc-cancel').hidden=true;jobId=null;}}catch(e){status('dc-collection-status',e.message,true);setTimeout(poll,4000);}}
  $('dc-collect').onclick=async()=>{const selected=[...pane.querySelectorAll('#dc-channels input:checked')].map(c=>c.value);if(!selected.length)return status('dc-collection-status','Select at least one readable channel.',true);$('dc-collect').disabled=true;status('dc-collection-status','Starting collection…');try{const result=await post('/collect',{...creds(),channel_ids:selected,download_attachments:$('dc-download').checked,max_attachment_mb:Number($('dc-maxmb').value)});$('dc-token').value='';jobId=result.id;$('dc-cancel').hidden=false;page=0;await poll();}catch(e){$('dc-collect').disabled=false;status('dc-collection-status',e.message,true);}};
  $('dc-cancel').onclick=async()=>{if(jobId){await post('/jobs/'+jobId+'/cancel',{});status('dc-collection-status','Cancellation requested; finishing the current request.');}};
  $('dc-name-button').onclick=()=>names().catch(e=>status('dc-names',e.message,true));
  $('dc-name-search').onkeydown=e=>{if(e.key==='Enter')names();};
  async function load(){const params=qs({guild_id:$('dc-filter-guild').value.trim(),channel_id:$('dc-filter-channel').value.trim(),search:$('dc-search').value.trim(),pinned:$('dc-pinned').checked,limit:100,offset:page*100});try{const data=await api('/messages?'+params);last=data.items;$('dc-count').textContent=data.total?((page*100+1)+'–'+Math.min((page+1)*100,data.total)+' of '+data.total):'0 messages';$('dc-prev').disabled=page===0;$('dc-next').disabled=(page+1)*100>=data.total;$('dc-results').innerHTML=data.items.map(m=>{const files=m.attachments.map(a=>'<li><span class="dc-file"><i class="fa-regular fa-file"></i>'+esc(a.filename)+'</span><span class="dc-meta">'+esc(a.size)+' bytes · '+esc(a.state||'not downloaded')+(a.error?' · '+esc(a.error):'')+'</span>'+(a.state==='downloaded'?'<a href="'+base+'/api/discord-c2/attachments/'+encodeURIComponent(a.id)+'">Download local copy</a><span class="dc-meta dc-mono">SHA256 '+esc(a.sha256)+'</span>':'')+(a.text?'<details><summary>Extracted text</summary><pre>'+esc(a.text)+'</pre></details>':'')+'</li>').join('');const author=(m.author_name||m.author_id||'Unknown');return '<article class="dc-msg"><div class="dc-msg-head"><span class="dc-avatar">'+esc(author.charAt(0).toUpperCase())+'</span><div class="dc-msg-who"><strong>'+esc(author)+'</strong>'+(m.pinned?'<span class="dc-tag">Pinned</span>':'')+'<span class="dc-meta">#'+esc(m.channel_name)+' · '+esc(m.guild_name)+'</span></div><time class="dc-meta">'+esc(m.timestamp)+'</time></div><pre class="dc-msg-body">'+esc(m.content||'(no text content)')+'</pre>'+(files||m.urls.length||m.hashes.length||m.embeds.length?'<details class="dc-artifacts"><summary>Artifacts and embeds</summary>'+(files?'<ul class="dc-files">'+files+'</ul>':'')+(m.urls.length?'<p class="dc-kv"><span>URLs</span>'+m.urls.map(esc).join(' · ')+'</p>':'')+(m.hashes.length?'<p class="dc-kv"><span>Hashes</span>'+m.hashes.map(esc).join(' · ')+'</p>':'')+(m.embeds.length?'<pre>'+esc(JSON.stringify(m.embeds,null,2))+'</pre>':'')+'</details>':'')+'<div class="dc-msg-foot">Message ID '+esc(m.id)+'</div></article>';}).join('')||'<div class="dc-empty">No collected messages match this search.</div>';}catch(e){status('dc-count',e.message,true);}}
  $('dc-search-btn').onclick=()=>{page=0;load();};$('dc-search').onkeydown=e=>{if(e.key==='Enter'){page=0;load();}};$('dc-pinned').onchange=()=>{page=0;load();};$('dc-prev').onclick=()=>{page=Math.max(0,page-1);load();};$('dc-next').onclick=()=>{page++;load();};
  $('dc-export').onclick=()=>{if(!last.length)return status('dc-count','No messages on this page to export.',true);const url=URL.createObjectURL(new Blob([JSON.stringify(last,null,2)],{type:'application/json'})),link=document.createElement('a');link.href=url;link.download='discord-c2-messages.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
  window.initDiscordC2Dump=()=>{if(guild){coverage();names();}load();};
})();
