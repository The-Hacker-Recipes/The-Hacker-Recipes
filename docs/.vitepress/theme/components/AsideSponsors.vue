<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { VPDocAsideSponsors } from 'vitepress/theme'
import { useSponsor } from '../composables/sponsors'
import { useData } from 'vitepress'

const { data } = useSponsor()
const { page } = useData()

const currentCategory = computed(() => page.value.frontmatter.category || '')
const userCountry = ref(null)

const fetchUserCountry = async () => {
  try {
    const response = await fetch('https://api.country.is/')
    const result = await response.json()
    userCountry.value = result.country_code || 'FR' // Défaut à FR si inconnu
  } catch (error) {
    console.error('Erreur lors de la récupération du pays:', error)
    userCountry.value = 'FR' 
  }
}

onMounted(() => {
  fetchUserCountry()
})

const sponsors = computed(() => {
  if (userCountry.value === null) {
    return null; // Attendre la récupération du pays
  }

  return (
    data?.value
      .filter((sponsor) => sponsor.tier !== 'Banner Sponsors')
      .map((sponsor) => {
        return {
          size: sponsor.size === 'big' ? 'mini' : 'xmini',
          items: sponsor.items.filter(
            (item) =>
              item.categories.includes(currentCategory.value) &&
              (item.country.includes(userCountry.value) || item.country.includes('ALL'))
          ),
        };
      }) ?? []
  );
});

</script>

<template>
  <VPDocAsideSponsors v-if="data && sponsors !== null" :data="sponsors" />
</template>

<style>
.sponsor {
  margin-top: 1rem;
  margin-bottom: 1rem;
  border-radius: 14px;
  padding-top: 0.4rem;
  padding-bottom: 0.4rem;
  position: relative;
  font-size: 0.9rem;
  font-weight: 700;
  line-height: 1.1rem;
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  gap: 1rem;
  background-color: var(--vp-c-bg-alt);
  border: 2px solid var(--vp-c-bg-alt);
  transition: border-color 0.5s;
}
.sponsor:hover {
  border: 2px solid var(--vp-c-brand-light);
}
.sponsor img {
  transition: transform 0.5s;
  transform: scale(1.25);
}
.sponsor:hover img {
  transform: scale(1.75);
}
.sponsor .heading {
  background-image: linear-gradient(
    120deg,
    #b047ff 16%,
    var(--vp-c-brand-lighter),
    var(--vp-c-brand-lighter)
  );
  background-clip: text;
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.sponsor .extra-info {
  color: var(--vp-c-text-1);
  opacity: 0;
  font-size: 0.7rem;
  padding-left: 0.1rem;
  transition: opacity 0.5s;
}
.sponsor:hover .extra-info {
  opacity: 0.9;
}
</style>
