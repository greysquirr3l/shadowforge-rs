// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// shadowforge-rs documentation site.
// Industrial, monochrome. The wordmark and the forge glyph carry the brand;
// signal amber is reserved for warnings and cautions in prose.
export default defineConfig({
  site: 'https://greysquirr3l.github.io/shadowforge-rs/',
  base: '/shadowforge-rs',
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: 'shadowforge-rs',
      description:
        'Quantum-resistant steganography toolkit for journalists, whistleblowers, and dissidents operating against nation-state adversaries.',
      logo: {
        src: './src/assets/shadowforge_roundel.png',
        alt: 'shadowforge-rs',
        replacesTitle: false,
      },
      favicon: '/favicon.svg',
      customCss: ['./src/styles/custom.css'],
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/greysquirr3l/shadowforge-rs',
        },
      ],
      components: {
        SiteTitle: './src/components/Logo.astro',
      },
      editLink: {
        baseUrl: 'https://github.com/greysquirr3l/shadowforge-rs/edit/main/site/',
      },
      lastUpdated: false,
      // The sidebar lists the content collection explicitly: same group
      // titles, same order, same nesting, one entry per published page.
      sidebar: [
        { label: 'Introduction', items: ['introduction'] },
        {
          label: 'User Guide',
          items: [
            { label: 'Installation', slug: 'guide/installation' },
            { label: 'Quick Start', slug: 'guide/quickstart' },
            { label: 'Shell Completions', slug: 'guide/completions' },
          ],
        },
        {
          label: 'CLI Reference',
          items: [
            { label: 'Overview', slug: 'cli/overview' },
            { label: 'keygen', slug: 'cli/keygen' },
            { label: 'embed', slug: 'cli/embed' },
            { label: 'extract', slug: 'cli/extract' },
            { label: 'embed-distributed', slug: 'cli/embed-distributed' },
            { label: 'extract-distributed', slug: 'cli/extract-distributed' },
            { label: 'analyse', slug: 'cli/analyse' },
            {
              label: 'Countermeasures',
              items: [
                { label: 'scrub', slug: 'cli/scrub' },
                { label: 'dead-drop', slug: 'cli/dead-drop' },
                { label: 'time-lock', slug: 'cli/time-lock' },
                { label: 'watermark', slug: 'cli/watermark' },
                { label: 'corpus', slug: 'cli/corpus' },
              ],
            },
          ],
        },
        {
          label: 'Threat Model',
          items: [
            { label: 'Overview', slug: 'threats/overview' },
            { label: 'Automated Steganalysis', slug: 'threats/steganalysis' },
            { label: 'Compelled Decryption', slug: 'threats/compelled-decryption' },
            { label: 'Traffic Analysis', slug: 'threats/traffic-analysis' },
            { label: 'Endpoint Compromise', slug: 'threats/endpoint-compromise' },
            { label: 'Legal & Jurisdictional Pressure', slug: 'threats/legal-pressure' },
            { label: 'Stylometric Identification', slug: 'threats/stylometry' },
            { label: 'Residual Risks', slug: 'threats/residual-risks' },
          ],
        },
        {
          label: 'Operational Security',
          items: [{ label: 'Overview', slug: 'opsec/overview' }],
        },
        {
          label: 'Architecture',
          items: [
            { label: 'Design Philosophy', slug: 'architecture/design' },
            { label: 'Bounded Contexts', slug: 'architecture/bounded-contexts' },
            { label: 'Embed Pipeline', slug: 'architecture/embed-pipeline' },
            { label: 'Extract Pipeline', slug: 'architecture/extract-pipeline' },
            { label: 'Cryptographic Design', slug: 'architecture/crypto' },
            { label: 'Security Policy', slug: 'architecture/security-policy' },
          ],
        },
        {
          label: 'Contributing',
          items: [
            { label: 'Development Setup', slug: 'contributing/setup' },
            { label: 'Testing Standards', slug: 'contributing/testing' },
            { label: 'Code Style', slug: 'contributing/style' },
            { label: 'Release Process', slug: 'contributing/release' },
          ],
        },
      ],
    }),
  ],
});
