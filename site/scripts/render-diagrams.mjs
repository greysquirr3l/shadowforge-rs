#!/usr/bin/env node
/**
 * Render the Mermaid sources in `src/diagrams/*.mmd` to SVG with Pele.
 *
 * Pele is a dependency-free Mermaid renderer: it parses the diagram and
 * emits SVG directly, with no headless browser and no JavaScript bundle
 * shipped to the reader. Colours are emitted as `var(--pele-*)` custom
 * properties, so one set of SVG files follows the site's light/dark theme
 * — see the `--pele-*` block in `src/styles/custom.css`.
 *
 * Output goes to `src/diagrams/generated/*.svg`. The files are written
 * before every build, so a fresh `pnpm install && pnpm build` produces a
 * complete site without a separate asset step.
 *
 * Each diagram gets a unique `idPrefix`. Pele uses the prefix for the
 * internal ids of markers, clip paths and gradients; two diagrams sharing
 * a prefix on one page produce colliding ids, and the second copy renders
 * with the first copy's arrowheads.
 */
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { render, register } from 'pele/core';
import flowchart from 'pele/diagrams/flowchart';

// Only the diagram types actually used here are registered, which keeps the
// renderer small. Add another `register(...)` call when a new diagram type
// is introduced.
register(flowchart);

const scriptDir = dirname(fileURLToPath(import.meta.url));
const siteDir = join(scriptDir, '..');
const sourceDir = join(siteDir, 'src', 'diagrams');
const outputDir = join(sourceDir, 'generated');

/**
 * Stable, collision-free id prefix for a diagram.
 *
 * @param {string} name
 * @returns {string}
 */
const idPrefixFor = (name) => `sf-${name.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`;

/**
 * Accessible names for the rendered diagrams. Kept beside the renderer so
 * the title travels with the SVG wherever it is used.
 *
 * @param {string} name
 * @returns {string}
 */
function titleFor(name) {
	switch (name) {
		case 'hexagonal-architecture':
			return 'Hexagonal architecture: the interface, application and adapter layers depend inward on a pure domain layer.';
		case 'embed-pipeline':
			return 'Embed pipeline: key generation, key encapsulation, payload encryption, sharding, embedding into a cover, optional profile hardening, and distribution.';
		case 'extract-pipeline':
			return 'Extract pipeline: gathering covers, reading each embedded payload, reconstructing missing shares, decrypting, verifying, and returning the recovered payload.';
		default:
			return name.replace(/[-_]/g, ' ');
	}
}

async function main() {
	if (!existsSync(sourceDir)) {
		throw new Error(`diagram source directory not found: ${sourceDir}`);
	}

	await mkdir(outputDir, { recursive: true });

	const entries = (await readdir(sourceDir, { withFileTypes: true }))
		.filter((entry) => entry.isFile() && entry.name.endsWith('.mmd'))
		.map((entry) => entry.name)
		.sort();

	if (entries.length === 0) {
		throw new Error(`no .mmd sources found in ${sourceDir}`);
	}

	for (const file of entries) {
		const name = file.replace(/\.mmd$/, '');
		const source = await readFile(join(sourceDir, file), 'utf8');
		const idPrefix = idPrefixFor(name);

		const result = render(source, {
			idPrefix,
			responsive: true,
			fontFamily: 'var(--pele-font, sans-serif)',
			fontFamilyMono: 'var(--pele-font-mono, monospace)',
		});

		// Pele emits an SVG without a <title>, so a screen reader announces
		// it as an unlabelled graphic. The title is injected here so the
		// diagram carries its own accessible name.
		const title = titleFor(name);
		const svg = result.svg
			.replace('<svg ', `<svg role="img" aria-labelledby="${idPrefix}-title" `)
			.replace(/(<svg[^>]*>)/, `$1<title id="${idPrefix}-title">${title}</title>`);

		await writeFile(join(outputDir, `${name}.svg`), `${svg}\n`, 'utf8');
		console.log(`rendered ${file} -> generated/${name}.svg`);
	}

	console.log(`${entries.length} diagram(s) rendered.`);
}

await main();
