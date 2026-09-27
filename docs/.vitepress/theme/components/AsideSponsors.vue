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

const fetchUserCountry = async () => {
  const override = countryFromQuery()
  if (override) {
    userCountry.value = override
    return
  }

  try {
    const response = await fetch('https://api.country.is/')
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    const result = await response.json()
    // api.country.is returns { ip, country } (ISO 3166-1 alpha-2)
    userCountry.value = result.country || 'FR'
  } catch (error) {
    console.error('Erreur lors de la récupération du pays:', error)
    userCountry.value = 'FR'
  }
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
  <div v-if="ads.length" class="aside-ads">
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
}

.aside-ad:hover {
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

.aside-ad:hover .aside-ad__logo {
  transform: scale(1.06);
}
</style>

<style>
/* Light: colored. Dark: grayscale until hover. */
.aside-ad__logo {
  filter: none;
}

.dark .aside-ad__logo {
  filter: grayscale(1);
}

.dark .aside-ad:hover .aside-ad__logo {
  filter: none;
}
</style>
