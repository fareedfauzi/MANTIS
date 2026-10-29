let ktipThreatActorsData = [];
let ktipThreatActorsLoaded = false;
let ktipTaFilteredData = [];
let ktipTaSelectedRegions = new Set();
let ktipTaSelectedSectors = new Set();

async function initKtipThreatActors() {
    if (ktipThreatActorsLoaded) return;

    const tipKey = KEY_STORE.tip();
    const grid = document.getElementById('ktip-ta-grid');
    
    if (!tipKey) {
        grid.innerHTML = '<div style="color:var(--accent); padding:20px; border: 1px solid var(--accent); border-radius: 4px; background: rgba(255,100,100,0.1);">Please configure your Kaspersky TIP API Key in Settings to view Threat Actors.</div>';
        return;
    }

    ktipThreatActorsLoaded = true;
    grid.innerHTML = '<div style="color:var(--text-muted); padding:20px;"><i class="fa-solid fa-circle-notch mantis-spin"></i> Loading Kaspersky Threat Actor Profiles...</div>';

    try {
        const cachedData = localStorage.getItem('ktip_ta_cache');
        const cachedTime = localStorage.getItem('ktip_ta_cache_time');
        const cacheAge = cachedTime ? (Date.now() - parseInt(cachedTime)) : Infinity;
        
        let data;
        
        // Cache for 24 hours (86400000 ms)
        if (cachedData && cacheAge < 86400000) {
            data = JSON.parse(cachedData);
        } else {
            const res = await fetch('/api/ktip/actors', {
                headers: { 'x-tip-key': tipKey }
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || `Failed to fetch: ${res.status}`);
            }
            data = await res.json();
            
            try {
                localStorage.setItem('ktip_ta_cache', JSON.stringify(data));
                localStorage.setItem('ktip_ta_cache_time', Date.now().toString());
            } catch (storageError) {
                console.warn('Could not save to cache (quota exceeded?)', storageError);
            }
        }
        
        if (data.items) {
            ktipThreatActorsData = data.items;
        } else {
            ktipThreatActorsData = [];
        }
        
        ktipTaFilteredData = [...ktipThreatActorsData];

        populateKtipTAFilters();
        renderKtipTACards();

        // Setup Search
        document.getElementById('ktip-ta-search').addEventListener('input', () => {
            applyKtipTAFilters();
        });

        document.getElementById('ktip-ta-reset-filters').addEventListener('click', () => {
            document.getElementById('ktip-ta-search').value = '';
            ktipTaSelectedRegions.clear();
            ktipTaSelectedSectors.clear();
            document.querySelectorAll('#ktip-ta-filter-region input[type="checkbox"], #ktip-ta-filter-sector input[type="checkbox"]').forEach(cb => cb.checked = false);
            applyKtipTAFilters();
        });

    } catch (e) {
        ktipThreatActorsLoaded = false;
        grid.innerHTML = `<div style="color:var(--accent); padding:20px; border: 1px solid var(--accent); border-radius: 4px; background: rgba(255,100,100,0.1);">Error loading Kaspersky Threat Actors: ${esc(e.message)}</div>`;
    }
}

function populateKtipTAFilters() {
    const regionSet = new Set();
    const sectorSet = new Set();

    ktipThreatActorsData.forEach(actor => {
        if (actor.geo && actor.geo.regions) {
            actor.geo.regions.forEach(r => regionSet.add(r.name));
        }
        if (actor.industries) {
            actor.industries.forEach(i => sectorSet.add(i.name));
        }
    });

    const regionFilter = document.getElementById('ktip-ta-filter-region');
    const sectorFilter = document.getElementById('ktip-ta-filter-sector');

    regionFilter.innerHTML = '';
    sectorFilter.innerHTML = '';

    Array.from(regionSet).sort().forEach(r => {
        const label = document.createElement('label');
        label.style.display = 'flex';
        label.style.alignItems = 'center';
        label.style.gap = '8px';
        label.style.cursor = 'pointer';
        label.style.color = 'var(--text-color)';
        
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.value = r;
        cb.addEventListener('change', (e) => {
            if (e.target.checked) ktipTaSelectedRegions.add(r);
            else ktipTaSelectedRegions.delete(r);
            applyKtipTAFilters();
        });
        
        label.appendChild(cb);
        label.appendChild(document.createTextNode(r));
        regionFilter.appendChild(label);
    });

    Array.from(sectorSet).sort().forEach(s => {
        const label = document.createElement('label');
        label.style.display = 'flex';
        label.style.alignItems = 'center';
        label.style.gap = '8px';
        label.style.cursor = 'pointer';
        label.style.color = 'var(--text-color)';
        
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.value = s;
        cb.addEventListener('change', (e) => {
            if (e.target.checked) ktipTaSelectedSectors.add(s);
            else ktipTaSelectedSectors.delete(s);
            applyKtipTAFilters();
        });
        
        label.appendChild(cb);
        label.appendChild(document.createTextNode(s));
        sectorFilter.appendChild(label);
    });
}

function applyKtipTAFilters() {
    const term = document.getElementById('ktip-ta-search').value.toLowerCase();
    
    ktipTaFilteredData = ktipThreatActorsData.filter(actor => {
        // Search term
        const nameMatch = actor.name && actor.name.toLowerCase().includes(term);
        const aliasMatch = actor.aliases && actor.aliases.some(a => a.toLowerCase().includes(term));
        const matchesTerm = nameMatch || aliasMatch;

        // Region Filter
        let matchesRegion = true;
        if (ktipTaSelectedRegions.size > 0) {
            if (!actor.geo || !actor.geo.regions) matchesRegion = false;
            else matchesRegion = actor.geo.regions.some(r => ktipTaSelectedRegions.has(r.name));
        }

        // Sector Filter
        let matchesSector = true;
        if (ktipTaSelectedSectors.size > 0) {
            if (!actor.industries) matchesSector = false;
            else matchesSector = actor.industries.some(i => ktipTaSelectedSectors.has(i.name));
        }

        return matchesTerm && matchesRegion && matchesSector;
    });

    renderKtipTACards();
}

function renderKtipTACards() {
    const grid = document.getElementById('ktip-ta-grid');
    grid.innerHTML = '';
    
    document.getElementById('ktip-ta-count-actors').textContent = ktipTaFilteredData.length;

    ktipTaFilteredData.forEach(actor => {
        const card = document.createElement('div');
        card.style.background = 'rgba(255,255,255,0.02)';
        card.style.border = '1px solid var(--border)';
        card.style.borderRadius = '6px';
        card.style.padding = '15px';
        card.style.cursor = 'pointer';
        card.style.transition = 'all 0.2s';
        card.style.display = 'flex';
        card.style.flexDirection = 'column';
        
        card.onmouseover = () => card.style.background = 'rgba(255,255,255,0.05)';
        card.onmouseout = () => card.style.background = 'rgba(255,255,255,0.02)';
        
        card.addEventListener('click', () => openKtipTAModal(actor.id));

        const header = document.createElement('div');
        header.style.display = 'flex';
        header.style.justifyContent = 'space-between';
        header.style.alignItems = 'flex-start';
        header.style.marginBottom = '10px';
        
        const title = document.createElement('div');
        title.style.color = 'var(--accent)';
        title.style.fontWeight = 'bold';
        title.style.fontSize = '1.1rem';
        title.textContent = actor.name;
        
        header.appendChild(title);
        
        const aliases = document.createElement('div');
        aliases.style.color = 'var(--text-muted)';
        aliases.style.fontSize = '0.8rem';
        aliases.style.marginBottom = '15px';
        aliases.style.flex = '1';
        aliases.innerHTML = actor.aliases && actor.aliases.length > 0 ? `<strong>AKA:</strong> ${esc(actor.aliases.slice(0,3).join(', '))}${actor.aliases.length > 3 ? '...' : ''}` : '<em>No known aliases</em>';

        const footer = document.createElement('div');
        footer.style.marginTop = 'auto';
        footer.style.display = 'flex';
        footer.style.gap = '10px';
        footer.style.fontSize = '0.75rem';
        
        if (actor.geo && actor.geo.countries && actor.geo.countries.length > 0) {
            const cTag = document.createElement('span');
            cTag.style.background = 'rgba(255, 255, 255, 0.1)';
            cTag.style.padding = '3px 6px';
            cTag.style.borderRadius = '3px';
            cTag.innerHTML = `<i class="fa-solid fa-earth-americas"></i> ${esc(actor.geo.countries[0].code)}${actor.geo.countries.length > 1 ? '+' : ''}`;
            footer.appendChild(cTag);
        }

        if (actor.industries && actor.industries.length > 0) {
            const sTag = document.createElement('span');
            sTag.style.background = 'rgba(74, 158, 255, 0.1)';
            sTag.style.color = '#4a9eff';
            sTag.style.padding = '3px 6px';
            sTag.style.borderRadius = '3px';
            sTag.innerHTML = `<i class="fa-solid fa-bullseye"></i> ${esc(actor.industries[0].name)}${actor.industries.length > 1 ? '+' : ''}`;
            footer.appendChild(sTag);
        }

        card.appendChild(header);
        card.appendChild(aliases);
        card.appendChild(footer);
        grid.appendChild(card);
    });
}

async function openKtipTAModal(actorId) {
    const tipKey = KEY_STORE.tip();
    const modal = document.getElementById('ktip-ta-modal-overlay');
    modal.style.display = 'flex';
    
    // reset contents
    document.getElementById('ktip-ta-modal-title').textContent = 'Loading...';
    document.getElementById('ktip-ta-modal-aka').textContent = '';
    document.getElementById('ktip-ta-modal-sectors').textContent = '';
    document.getElementById('ktip-ta-modal-regions').textContent = '';
    document.getElementById('ktip-ta-modal-countries').textContent = '';
    document.getElementById('ktip-ta-modal-desc').innerHTML = '';
    document.getElementById('ktip-ta-modal-ttps').innerHTML = '';
    document.getElementById('ktip-ta-modal-cves').innerHTML = '';
    document.getElementById('ktip-ta-modal-software').innerHTML = '';
    document.getElementById('ktip-ta-modal-reports').innerHTML = '';
    document.getElementById('ktip-ta-modal-samples').innerHTML = 'Loading samples...';
    document.getElementById('ktip-ta-modal-uuid').textContent = actorId;
    document.getElementById('ktip-ta-modal-updated').textContent = '';

    try {
        const [profileRes, samplesRes] = await Promise.all([
            fetch(`/api/ktip/actors/${encodeURIComponent(actorId)}`, { headers: { 'x-tip-key': tipKey } }),
            fetch(`/api/ktip/actors/${encodeURIComponent(actorId)}/samples`, { headers: { 'x-tip-key': tipKey } })
        ]);

        if (profileRes.ok) {
            const actor = await profileRes.json();
            
            document.getElementById('ktip-ta-modal-title').textContent = actor.name || 'Unknown';
            document.getElementById('ktip-ta-modal-aka').textContent = actor.aliases ? actor.aliases.join(', ') : 'None';
            document.getElementById('ktip-ta-modal-updated').textContent = actor.updatedAt || actor.createdAt || '';
            
            document.getElementById('ktip-ta-modal-sectors').innerHTML = actor.industries ? actor.industries.map(i => `<span style="display:inline-block; margin:2px 4px; padding:2px 6px; background:rgba(255,255,255,0.1); border-radius:3px;">${esc(i.name)}</span>`).join('') : 'Unknown';
            
            if (actor.geo) {
                document.getElementById('ktip-ta-modal-regions').innerHTML = actor.geo.regions ? actor.geo.regions.map(r => `<span style="display:inline-block; margin:2px 4px; padding:2px 6px; background:rgba(255,255,255,0.1); border-radius:3px;">${esc(r.name)}</span>`).join('') : 'Unknown';
                document.getElementById('ktip-ta-modal-countries').innerHTML = actor.geo.countries ? actor.geo.countries.map(c => `<span style="display:inline-block; margin:2px 4px; padding:2px 6px; background:rgba(255,255,255,0.1); border-radius:3px;"><img src="https://flagcdn.com/24x18/${c.code.toLowerCase()}.png" style="width:16px;vertical-align:middle;border-radius:2px;margin-right:4px;" onerror="this.style.display='none'"> ${esc(c.code)}</span>`).join('') : 'Unknown';
            }
            
            document.getElementById('ktip-ta-modal-desc').textContent = actor.description || 'No description available.';
            
            // TTPs
            const ttpsContainer = document.getElementById('ktip-ta-modal-ttps');
            if (actor.ttps && actor.ttps.length > 0) {
                actor.ttps.forEach(ttp => {
                    const div = document.createElement('div');
                    div.style.background = 'rgba(255,255,255,0.05)';
                    div.style.padding = '8px';
                    div.style.borderRadius = '4px';
                    div.style.fontSize = '0.8rem';
                    div.innerHTML = `<strong style="color:var(--accent);">${esc(ttp.tacticId)}</strong> / <strong>${esc(ttp.techniqueId)}</strong><br/><span style="color:var(--text-muted);">${esc(ttp.details || '')}</span>`;
                    ttpsContainer.appendChild(div);
                });
            } else {
                ttpsContainer.textContent = "No TTPs available.";
            }

            // CVEs
            const cvesContainer = document.getElementById('ktip-ta-modal-cves');
            if (actor.cves && actor.cves.length > 0) {
                actor.cves.forEach(cve => {
                    const span = document.createElement('span');
                    span.style.background = 'rgba(255,100,100,0.1)';
                    span.style.color = '#ff6464';
                    span.style.padding = '4px 8px';
                    span.style.borderRadius = '4px';
                    span.style.fontSize = '0.85rem';
                    span.textContent = cve.id;
                    cvesContainer.appendChild(span);
                });
            } else {
                cvesContainer.textContent = "No CVEs available.";
            }

            // Software
            const swContainer = document.getElementById('ktip-ta-modal-software');
            if (actor.softwares && actor.softwares.length > 0) {
                actor.softwares.forEach(sw => {
                    const span = document.createElement('span');
                    span.style.background = 'rgba(255,255,255,0.1)';
                    span.style.padding = '4px 8px';
                    span.style.borderRadius = '4px';
                    span.style.fontSize = '0.85rem';
                    span.textContent = sw.name;
                    swContainer.appendChild(span);
                });
            } else {
                swContainer.textContent = "No software available.";
            }

            // Reports
            const repContainer = document.getElementById('ktip-ta-modal-reports');
            if (actor.reports && actor.reports.length > 0) {
                actor.reports.forEach(rep => {
                    const div = document.createElement('div');
                    div.style.background = 'rgba(74, 158, 255, 0.05)';
                    div.style.borderLeft = '3px solid #4a9eff';
                    div.style.padding = '8px 12px';
                    div.style.fontSize = '0.85rem';
                    div.innerHTML = `<strong>${esc(rep.name)}</strong> <span style="color:var(--text-muted); font-size: 0.7rem;">(${esc(rep.id)})</span>`;
                    repContainer.appendChild(div);
                });
            } else {
                repContainer.textContent = "No reports available.";
            }
        }

        if (samplesRes.ok) {
            const samplesData = await samplesRes.json();
            const samplesContainer = document.getElementById('ktip-ta-modal-samples');
            samplesContainer.innerHTML = '';
            
            if (samplesData.items && samplesData.items.length > 0) {
                const table = document.createElement('table');
                table.style.width = '100%';
                table.style.borderCollapse = 'collapse';
                table.innerHTML = `
                    <tr style="border-bottom: 1px solid rgba(255,255,255,0.1); text-align: left; font-size: 0.8rem; color: var(--text-muted);">
                        <th style="padding: 5px;">MD5</th>
                        <th style="padding: 5px;">Similarity</th>
                        <th style="padding: 5px;">Last Seen</th>
                    </tr>
                `;
                samplesData.items.forEach(sample => {
                    const tr = document.createElement('tr');
                    tr.style.borderBottom = '1px solid rgba(255,255,255,0.05)';
                    tr.style.fontSize = '0.85rem';
                    tr.innerHTML = `
                        <td style="padding: 5px; font-family: monospace; color: #4a9eff;">${esc(sample.md5)}</td>
                        <td style="padding: 5px;">${esc(sample.similarity.toString())}%</td>
                        <td style="padding: 5px;">${esc(sample.lastSeen ? new Date(sample.lastSeen).toLocaleDateString() : 'Unknown')}</td>
                    `;
                    table.appendChild(tr);
                });
                samplesContainer.appendChild(table);
            } else {
                samplesContainer.textContent = "No related samples found.";
            }
        } else {
            document.getElementById('ktip-ta-modal-samples').textContent = "Failed to load related samples.";
        }
    } catch (e) {
        console.error(e);
        document.getElementById('ktip-ta-modal-title').textContent = "Error loading profile";
        document.getElementById('ktip-ta-modal-desc').textContent = e.message;
    }
}

document.getElementById('ktip-ta-modal-close').addEventListener('click', () => {
    document.getElementById('ktip-ta-modal-overlay').style.display = 'none';
});
