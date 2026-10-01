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
  <div class="aside-ads" :class="{ 'aside-ads--empty': !ads.length }">
    <a
      v-for="(ad, index) in ads"
      :key="ad.name"
      class="aside-ad"
      :href="ad.url"
      target="_blank"
      rel="sponsored noopener"
    >
      <p v-if="index === 0" class="aside-ad__label">Ad partner</p>
      <img class="aside-ad__logo" :src="ad.img" :alt="ad.name" />
    </a>
  </div>
</template>

<style scoped>
.aside-ads {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  width: 100%;
}

.aside-ads--empty {
  display: none;
}

.aside-ad {
  --aside-ad-pad-x: clamp(1rem, 3.5vw, 1.75rem);

  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 0.5rem;
  width: 100%;
  box-sizing: border-box;
  padding: 0.85rem var(--aside-ad-pad-x) 1rem;
  border-radius: 12px;
  text-decoration: none;
  color: inherit;
  background: var(--vp-c-bg-soft);
  transition: background-color 0.2s ease;
  -webkit-tap-highlight-color: color-mix(in srgb, var(--vp-c-brand-1) 22%, transparent);
}

.aside-ad:hover,
.aside-ad:active {
  background: var(--vp-c-bg-alt);
}

.aside-ad:focus-visible {
  outline: 2px solid var(--vp-c-brand-1);
  outline-offset: 3px;
}

.aside-ad__label {
  margin: 0;
  font-family: var(--vp-font-family-base);
  font-size: 14px;
  font-weight: 600;
  line-height: 1.25;
  letter-spacing: -0.02em;
  color: var(--vp-c-text-1);
}

.aside-ad__logo {
  display: block;
  width: auto;
  max-width: min(100%, 140px);
  max-height: 48px;
  height: auto;
  margin-inline: auto;
  object-fit: contain;
  transition: transform 0.25s ease, filter 0.25s ease;
}

.aside-ad:hover .aside-ad__logo,
.aside-ad:active .aside-ad__logo {
  transform: scale(1.06);
}

@media (max-width: 1279px) {
  .aside-ad {
    --aside-ad-pad-x: clamp(1rem, 4.2vw, 1.65rem);
    padding-top: clamp(1rem, 2.8vw, 1.35rem);
    padding-bottom: clamp(1.1rem, 3.2vw, 1.55rem);
    border-radius: 14px;
  }

  .aside-ad__logo {
    max-width: min(100%, 11rem);
    max-height: 3.25rem;
  }
}
</style>

<style>
/* Light: colored. Dark: grayscale until hover/active. */
.aside-ad__logo {
  filter: none;
}

.dark .aside-ad__logo {
  filter: grayscale(1);
}

.dark .aside-ad:hover .aside-ad__logo,
.dark .aside-ad:active .aside-ad__logo {
  filter: none;
}
</style>
