<script setup lang="ts">
import { ExternalLink } from 'lucide-vue-next'
</script>

<template>
  <a class="write" href="https://exegol.com/" target="_blank" rel="sponsored noopener">
    <span class="write__external" aria-hidden="true">
      <ExternalLink :size="14" :stroke-width="2" />
    </span>
    <p class="write__title">By the creator of this site</p>
    <p class="write__desc">
      Professional environments for
      <br />
      pentesting, red team, ctf
    </p>
    <div class="write__brand">
      <img class="write__logo" src="/images/Exegol_Logo_DarkVersion_Horizontal.svg" alt="Exegol"/>
    </div>
  </a>
</template>

<style scoped>
.write {
  --write-pad-x: clamp(1rem, 3.5vw, 1.75rem);
  --write-pad-top: clamp(0.85rem, 2.5vw, 1.2rem);
  --write-pad-bottom: clamp(1rem, 3vw, 1.4rem);
  --write-gap-tight: 0.5rem;
  --write-gap-loose: 1rem;
  --write-fs-desc: 0.6875rem;
  --write-logo-max-h: 2.375rem;

  position: relative;
  display: block;
  width: 100%;
  margin: 1rem 0;
  padding: var(--write-pad-top) var(--write-pad-x) var(--write-pad-bottom);
  box-sizing: border-box;
  border-radius: 12px;
  text-decoration: none;
  color: inherit;
  text-align: left;
  background: var(--vp-c-bg-soft);
  border: none;
  transition: background-color 0.2s ease;
}

.write:hover {
  background: var(--vp-c-bg-alt);
}

.write:focus-visible {
  outline: 2px solid var(--vp-c-brand-1);
  outline-offset: 3px;
}

.write__external {
  position: absolute;
  top: 0.55rem;
  right: 0.55rem;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--vp-c-text-3);
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.2s ease, color 0.2s ease;
}

.write:hover .write__external,
.write:focus-visible .write__external {
  opacity: 1;
  color: var(--vp-c-text-2);
}

.write__title {
  display: block;
  width: 100%;
  min-width: 0;
  margin: 0 0 var(--write-gap-tight);
  box-sizing: border-box;
  font-family: var(--vp-font-family-base);
  font-size: 14px;
  font-weight: 600;
  line-height: 1.25;
  letter-spacing: -0.02em;
  color: var(--vp-c-text-1);
  white-space: nowrap;
  text-align: left;
}

.write__desc {
  margin: 0 0 var(--write-gap-loose);
  font-size: var(--write-fs-desc);
  font-weight: 400;
  line-height: 1.45;
  color: var(--vp-c-text-2);
}

.write__brand {
  display: flex;
  justify-content: center;
  align-items: center;
  line-height: 0;
}

.write__logo {
  display: block;
  width: auto;
  max-width: min(100%, 10.5rem);
  max-height: var(--write-logo-max-h);
  height: auto;
  object-fit: contain;
  object-position: center;
  margin-inline: auto;
  transform-origin: center;
  transition: transform 0.25s ease;
}

.write:hover .write__logo {
  transform: scale(1.06);
}

/* Tablette + mobile : même grille (texte à gauche, logo à droite) */
@media (max-width: 1279px) {
  .write {
    --write-pad-x: clamp(1rem, 4.2vw, 1.65rem);
    --write-pad-top: clamp(1rem, 2.8vw, 1.35rem);
    --write-pad-bottom: clamp(1.1rem, 3.2vw, 1.55rem);
    --write-fs-desc: 0.75rem;
    --write-logo-max-h: 5.5rem;

    display: grid;
    grid-template-columns: minmax(0, 1fr) min(11.5rem, 34vw);
    grid-template-rows: auto auto;
    column-gap: 1.125rem;
    row-gap: 0.2rem;
    align-items: center;

    margin-top: 1.25rem;
    border-radius: 14px;
    -webkit-tap-highlight-color: color-mix(in srgb, var(--vp-c-brand-1) 22%, transparent);
  }

  .write__logo {
    max-width: min(100%, 18rem);
  }

  .write__title {
    grid-column: 1;
    grid-row: 1;
    align-self: end;
    margin-bottom: 0.15rem;
    white-space: normal;
    text-wrap: balance;
  }

  .write__desc {
    grid-column: 1;
    grid-row: 2;
    align-self: start;
    margin-bottom: 0;
    text-align: left;
  }

  .write__brand {
    grid-column: 2;
    grid-row: 1 / span 2;
    justify-content: center;
  }

  .write:active {
    background: var(--vp-c-bg-alt);
  }
}
</style>
