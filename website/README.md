# MANTIS Website

Static Astro landing page for [MANTIS](https://github.com/fareedfauzi/MANTIS), built for deployment to GitHub Pages at `https://fareedfauzi.github.io/MANTIS/`.

## Development

```bash
pnpm install
pnpm dev
```

The development server is available at `http://localhost:4321/MANTIS/`.

## Production build

```bash
pnpm build
pnpm preview
```

Astro writes the static site to `website/dist/`.

## GitHub Pages deployment

The repository workflow at `.github/workflows/deploy-website.yml` builds and deploys the site whenever changes to `website/` land on `main`, or when it is started manually.

In **Repository settings → Pages**, set **Source** to **GitHub Actions**. The workflow does not require a separate Pages branch.

## Source accuracy

Copy, integrations, commands, licensing, and screenshots are based on the root MANTIS README and documentation. Product images in `public/images/` are the official screenshots embedded in the upstream repository. External integrations may require their own API keys, subscriptions, or services.
