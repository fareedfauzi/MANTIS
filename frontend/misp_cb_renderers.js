    const renderMispGalaxy = (data) => {
        if (!data || !data.results || data.results.length === 0) return '<em>No MISP Galaxy data found</em>';
        let html = '';
        data.results.forEach(item => {
            html += `<div style="background: rgba(0,0,0,0.2); padding: 10px; margin-bottom: 10px; border-left: 3px solid #ff4757; border-radius: 4px;">`;
            html += `<strong style="color: #ff4757; font-size: 1.1em;">${esc(item.value)}</strong> <span style="opacity: 0.6; font-size: 0.8em; margin-left: 10px;">Cluster: ${esc(item.cluster)}</span><br>`;
            if (item.description) html += `<p style="margin: 8px 0; font-size: 0.9em; opacity: 0.9;">${esc(item.description)}</p>`;
            if (item.synonyms && item.synonyms.length > 0) {
                html += `<div style="margin-top: 5px;"><span style="color: #ccc; font-size: 0.8em;">Aliases:</span> `;
                item.synonyms.forEach(syn => {
                    html += `<span style="display: inline-block; background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 3px; font-size: 0.8em; margin: 2px;">${esc(syn)}</span>`;
                });
                html += `</div>`;
            }
            html += `</div>`;
        });
        return html;
    };
    
    const renderCyberBriefing = (data) => {
        return renderRawJson(data); // Default to raw JSON for now since we don't have sample output
    };
