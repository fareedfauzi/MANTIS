# Drawing Tools

The drawing tools create diagrams, charts and documents in the browser and export them. Nothing is uploaded to a third-party service to render.

Sidebar (under Drawer and Viewer): **Diagram** (`diagram-draw`), **Flow Chart** (`flowchart-draw`), **Mindmap** (`mindmap-draw`), **Map Chart** (`mapchart-draw`), **Chart Creator** (`chart-creator`), **Mermaid Viewer** (`mermaid-draw`), **Markdown Viewer** (`markdown-draw`).

## Diagram, Flow Chart and Mindmap

Build diagrams visually. Each has its own canvas and save format.

- Use the canvas tools to add nodes and connectors and lay them out.
- Use the export options in the pane toolbar to save the result. Check the pane's buttons for the formats it offers.

## Mermaid Viewer

Paste Mermaid source to render a flowchart, sequence diagram or similar.

- Invalid syntax is reported instead of a diagram; fix the source and render again.
- **Export SVG** saves a vector copy of the rendered diagram.
- Use it to preview the diagrams in [MANTIS AI](mantis-ai.md) case exports.

### Tutorial: render an attack chain

1. Open **Mermaid Viewer** and paste:

   ```mermaid
   flowchart LR
     A[Phishing email] --> B[Macro document]
     B --> C[Stager on 192.0.2.10]
     C --> D[Credential theft]
   ```

2. Check the render. Fix any parser error shown in place of the diagram.
3. Click **Export SVG** to save it for a report.

## Markdown Viewer

Edit and preview Markdown. Export with **Download Markdown** or **Save as PDF**.

## Map Chart

A world map that colours countries by a value. Enter country values in the pane and export the rendered map from its toolbar.

## Chart Creator

Build charts from a small data table: choose the chart type, set the labels and values, then export from the pane toolbar.

## Export notes

- Export runs in the browser; no data leaves the machine for rendering.
- **Save as PDF** prints the current document; use your browser's print dialog to choose the destination.
- Keep exported images free of sensitive data before sharing.
