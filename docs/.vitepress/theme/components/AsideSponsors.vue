<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { useSponsor } from '../composables/sponsors'
import { useData } from 'vitepress'

const { data } = useSponsor()
const { page } = useData()

const currentCategory = computed(() => page.value.frontmatter.category || '')
const userCountry = ref(null)

function countryFromQuery(): string | null {
  if (typeof window === 'undefined') return null
  const value = new URLSearchParams(window.location.search).get('country')
  return value ? value.toUpperCase() : null
}

type GeoEndpoint = { url: string; parse: (data: Record<string, unknown>) => string | null }

const GEO_ENDPOINTS: GeoEndpoint[] = [
  {
    url: 'https://get.geojs.io/v1/ip/country.json',
    parse: (data) => (typeof data.country === 'string' ? data.country : null),
  },
  {
    url: 'https://api.country.is/',
    parse: (data) => (typeof data.country === 'string' ? data.country : null),
  },
]

async function detectCountry(): Promise<string> {
  for (const endpoint of GEO_ENDPOINTS) {
    try {
      const response = await fetch(endpoint.url)
      if (!response.ok) continue
      const data = await response.json()
      const code = endpoint.parse(data)
      if (code && /^[a-z]{2}$/i.test(code)) return code.toUpperCase()
    } catch {
      // try next provider (CORS / network blocks are common in prod)
    }
  }
  // Non-FR fallback so EXT partners stay visible when every geo API is blocked
  return 'US'
}

const fetchUserCountry = async () => {
  const override = countryFromQuery()
  if (override) {
    userCountry.value = override
    return
  }

  userCountry.value = await detectCountry()
}

onMounted(() => {
  fetchUserCountry()
})

/** Flat list of visible aside ads (banner tier excluded). */
const ads = computed(() => {
  if (userCountry.value === null || !data?.value) return []

  return data.value
    .filter((group) => group.tier !== 'Banner Sponsors')
    .flatMap((group) =>
      group.items.filter(
        (item) =>
          item.categories.includes(currentCategory.value) &&
          (item.country.includes(userCountry.value) || item.country.includes('ALL'))
      )
    )
})
</script>

<template>
  <div class="context-stack" :class="{ 'context-stack--empty': !ads.length }">
    <a
      v-for="(ad, index) in ads"
      :key="ad.name"
      class="context-card"
      :href="ad.url"
      target="_blank"
      rel="sponsored noopener"
    >
      <p v-if="index === 0" class="context-card__label">Ad partner</p>
      <img class="context-card__logo" :src="ad.img" :alt="ad.name" />
    </a>
  </div>
</template>

<style scoped>
.context-stack {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  width: 100%;
}

.context-stack--empty {
  display: none;
}

.context-card {
  --context-card-pad-x: clamp(1rem, 3.5vw, 1.75rem);

  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 0.5rem;
  width: 100%;
  box-sizing: border-box;
  padding: 0.85rem var(--context-card-pad-x) 1rem;
  border-radius: 12px;
  text-decoration: none;
  color: inherit;
  background: var(--vp-c-bg-soft);
  transition: background-color 0.2s ease;
  -webkit-tap-highlight-color: color-mix(in srgb, var(--vp-c-brand-1) 22%, transparent);
}

.context-card:hover,
.context-card:active {
  background: var(--vp-c-bg-alt);
}

.context-card:focus-visible {
  outline: 2px solid var(--vp-c-brand-1);
  outline-offset: 3px;
}

.context-card__label {
  margin: 0;
  font-family: var(--vp-font-family-base);
  font-size: 14px;
  font-weight: 600;
  line-height: 1.25;
  letter-spacing: -0.02em;
  color: var(--vp-c-text-1);
}

.context-card__logo {
  display: block;
  width: auto;
  max-width: min(100%, 140px);
  max-height: 48px;
  height: auto;
  margin-inline: auto;
  object-fit: contain;
  transition: transform 0.25s ease, filter 0.25s ease;
}

.context-card:hover .context-card__logo,
.context-card:active .context-card__logo {
  transform: scale(1.06);
}

@media (max-width: 1279px) {
  .context-card {
    --context-card-pad-x: clamp(1rem, 4.2vw, 1.65rem);
    padding-top: clamp(1rem, 2.8vw, 1.35rem);
    padding-bottom: clamp(1.1rem, 3.2vw, 1.55rem);
    border-radius: 14px;
  }

  .context-card__logo {
    max-width: min(100%, 11rem);
    max-height: 3.25rem;
  }
}
</style>

<style>
/* Light: colored. Dark: grayscale until hover/active. */
.context-card__logo {
  filter: none;
}

.dark .context-card__logo {
  filter: grayscale(1);
}

.dark .context-card:hover .context-card__logo,
.dark .context-card:active .context-card__logo {
  filter: none;
}
</style>
