// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// Project is published to GitHub Pages as a project site at
// https://exonical.github.io/rootseal. `site` + `base` make Astro emit the
// correct absolute URLs and asset paths. Override via the SITE/BASE env vars
// if the repo or owner is renamed.
const site = process.env.SITE ?? 'https://exonical.github.io';
const base = process.env.BASE ?? '/rootseal';

// https://astro.build/config
export default defineConfig({
  site,
  base,
  integrations: [
    starlight({
      title: 'Rootseal',
      description:
        'TPM-attested, Vault-backed unlocking of LUKS/root volumes — a modern replacement for Clevis+Tang.',
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/Exonical/rootseal',
        },
      ],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'Introduction', slug: 'introduction' },
            { label: 'Quick start (local stack)', slug: 'quick-start' },
          ],
        },
        {
          label: 'Concepts',
          items: [
            { label: 'Architecture', slug: 'concepts/architecture' },
            { label: 'Unlock flow', slug: 'concepts/unlock-flow' },
            { label: 'Security model', slug: 'concepts/security-model' },
          ],
        },
        {
          label: 'Operations',
          items: [
            { label: 'Installation (RPM)', slug: 'operations/installation' },
            { label: 'Configuration', slug: 'operations/configuration' },
            { label: 'Enrollment', slug: 'operations/enrollment' },
            { label: 'TPM attestation', slug: 'operations/tpm-attestation' },
            { label: 'Vault integration', slug: 'operations/vault' },
            { label: 'FIPS 140-3 builds', slug: 'operations/fips' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'CLI reference', slug: 'reference/cli' },
            { label: 'gRPC API', slug: 'reference/api' },
          ],
        },
      ],
    }),
  ],
});
