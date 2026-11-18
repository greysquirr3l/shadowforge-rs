# shadowforge-rs documentation site

The documentation site for shadowforge-rs, built with [Astro](https://astro.build) and
[Starlight](https://starlight.astro.build), and deployed to GitHub Pages.

Live URL: <https://greysquirr3l.github.io/shadowforge-rs/>

## Where this lives

The site is a separate project from the Rust workspace, in `site/`. It has its own
`package.json` and its own lockfile — `cargo` never sees it. The Rust crate does not depend
on it either; nothing in `crates/shadowforge` references anything under `site/`.

The source content is authored as MDX under `site/src/content/docs/`, one directory per
section. The sidebar in `astro.config.mjs` lists the content collection explicitly: same
group labels, same order, same nesting, one entry per published page.

## Diagrams

Diagrams are authored as Mermaid in `site/src/diagrams/*.mmd` and rendered to SVG by
[Pele](https://pele.run) — a dependency-free Mermaid renderer — into
`site/src/diagrams/generated/`.

```sh
pnpm run diagrams      # re-render every .mmd source
```

The render step runs automatically before `dev` and `build`. Each SVG is inlined into the page
by `src/components/Diagram.astro`, which is required for the light/dark theming: Pele emits
its `svg.pele` rule with CSS variables, and that only applies to inline markup.

## Develop

```sh
pnpm install
pnpm run dev           # http://localhost:4321/shadowforge-rs/
pnpm run build         # static output into dist/
pnpm exec astro check  # type and template diagnostics
```

`pnpm run preview` serves the built `dist/` locally.

## Deploy

Deployment targets the `greysquirr3l.github.io` user-pages repository. The script clones it
next to this project if it is not already there, rsyncs `dist/` into the `shadowforge-rs/`
subdirectory, commits, and pushes.

```sh
pnpm run deploy:dry    # build, rsync, stage locally — do not commit or push
pnpm run deploy        # build, rsync, commit, push
```

Configuration lives in the `deploy-docs` block of `package.json`: the pages repo path, the
subdirectory, the live URL, and the source repo used in the commit message.

`deploy:dry` stages the change without committing it, so a preview cannot leave a commit
behind that blocks the next real deploy. `deploy` compares the body Pages serves against the
local build rather than checking only for HTTP 200, so a CDN still serving the previous
deploy is not mistaken for a successful one.

### Pages source conflict

If the live URL returns 404 with "Site not found", the Pages source on the *source* repository
is shadowing the user-pages site. This is a one-time repository setting: set the source
repository's Pages source to "GitHub Actions" (or disable Pages there), then re-run the
deploy. The deploy script prints the exact `gh api` command when it detects this case.

## Layout

```
site/
├── astro.config.mjs          # Starlight config: title, theme, sidebar
├── public/                   # favicon.svg, llm.txt
├── scripts/
│   ├── render-diagrams.mjs   # Mermaid -> SVG via Pele
│   ├── deploy-docs.sh        # rsync into the user-pages repo and push
│   └── deploy-docs.test.sh   # regression tests for deploy-docs.sh
├── src/
│   ├── assets/               # logo artwork
│   ├── components/           # Logo.astro, Diagram.astro
│   ├── content/docs/         # the MDX content
│   ├── diagrams/             # .mmd sources and generated/ SVGs
│   └── styles/custom.css     # theme overrides
```
