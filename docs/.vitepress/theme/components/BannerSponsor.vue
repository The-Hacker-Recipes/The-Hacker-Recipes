<!-- TODO: ADD PER COUNTRY FEATURE --> 

<template>
    <a v-if="currentSponsor" class="banner-sponsor" :href="currentSponsor.url" target="_blank" rel="noopener noreferrer">
      <img :src="logoSrc" :alt="currentSponsor.name" class="banner-logo" />
      <span class="banner-text">
        <div class="main-info">
          <p class="sponsor-name">{{ currentSponsor.name }}</p>
          <p class="sponsor-tagline">{{ currentSponsor.tagline }}</p>
        </div>
        <p class="sponsor-description">{{ currentSponsor.description }}</p>
      </span>
      <span class="official-sponsor">official sponsor</span>
    </a>
  </template>
  
  <script setup lang="ts">
  import { computed } from 'vue'
  import { useData } from 'vitepress'
  import { useSponsor } from '../composables/sponsors'
  
  const { isDark, page } = useData()
  const { data } = useSponsor()
  
  const currentCategory = computed(() => page.value.frontmatter.category || '')
  
  const currentSponsor = computed(() => {
    return data.value?.find(sponsor => 
      sponsor.tier === 'Banner Sponsors'
    )?.items.find(banner => 
      banner.categories.includes(currentCategory.value)
    )
  })
  
  const theme = computed(() => {
    if (!currentSponsor.value) return { primaryColor: '#000', secondaryColor: '#000', logo: '' }
    return isDark.value ? currentSponsor.value.darkTheme : currentSponsor.value.lightTheme
  })
  
  const logoSrc = computed(() => theme.value.logo || '')
  
  const gradientBorder = computed(() => `linear-gradient(120deg, ${theme.value.secondaryColor || '#000'}99, ${theme.value.primaryColor || '#000'}99)`)
  const gradientHover = computed(() => `linear-gradient(120deg, ${theme.value.secondaryColor || '#000'}, ${theme.value.primaryColor || '#000'})`)
  const gradientText = computed(() => `linear-gradient(120deg, ${theme.value.primaryColor || '#000'}, ${theme.value.secondaryColor || '#000'})`)
  </script>
  
  <style scoped>
  .banner-sponsor {
    display: flex;
    align-items: center;
    padding: 1.5rem 2rem;
    background-color: var(--vp-c-bg-alt);
    border: 3px solid transparent;
    border-radius: 14px;
    margin: 0 0 40px 0; /* Adjusted margin */
    width: 100%;
    box-sizing: border-box;
    text-decoration: none;
    transition: box-shadow 0.3s, transform 0.3s, border-color 0.3s;
    overflow: hidden;
    max-width: 100%;
    position: relative;
    background-image: linear-gradient(var(--vp-c-bg-alt), var(--vp-c-bg-alt)), v-bind(gradientBorder);
    background-origin: border-box;
    background-clip: padding-box, border-box;
  }
  
  .banner-sponsor:hover {
    box-shadow: 0 0 10px v-bind('theme.primaryColor + "80"'), 0 0 20px v-bind('theme.secondaryColor + "80"');
    background-image: linear-gradient(var(--vp-c-bg-alt), var(--vp-c-bg-alt)), v-bind(gradientHover);
  }
  
  .banner-logo {
    max-width: 80px;
    margin-right: 20px;
    border-radius: 50%;
    transition: transform 0.5s;
    flex-shrink: 0;
  }
  
  .banner-text {
    display: flex;
    justify-content: space-between;
    width: 100%;
    align-items: center;
    gap: 20px;
  }
  
  .main-info {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-width: 0;
    justify-content: center;
  }
  
  .sponsor-description {
    flex-shrink: 0;
    text-align: right;
    color: var(--vp-c-text-2); 
    font-size: 0.9rem;
    transition: color 0.3s;
    max-width: 60%;
    width: fit-content;
    min-width: 30%;
    overflow-wrap: break-word;
  }
  
  .sponsor-name {
    background-image: v-bind(gradientText);
    background-clip: text;
    -webkit-background-clip: text;
    font-size: 1.8rem;
    font-weight: 900;
    margin: 0;
    padding-bottom: 2px;
    line-height: 1.2;
    color: transparent;
    transition: background-image 0.3s, color 0.3s;
  }
  
  .sponsor-tagline {
    color: var(--vp-c-text-2);
    font-size: 1rem;
    transition: color 0.3s;
    padding-bottom: 2px;
    line-height: 1.2;
  }
  
  .official-sponsor {
    position: absolute;
    top: 5px;
    left: 10px;
    font-size: 0.7rem;
    color: var(--vp-c-text-3);
    opacity: 0.8;
    transition: opacity 0.3s;
  }
  
  .banner-sponsor:hover .official-sponsor {
    opacity: 1;
  }
  
  @media (max-width: 768px) {
    .banner-text {
      flex-direction: column;
      align-items: flex-start;
      gap: 10px;
    }
    
    .sponsor-description {
      text-align: left;
      max-width: 100%;
      min-width: unset;
    }
    
    .official-sponsor {
      top: 2px;
      left: 5px;
      font-size: 0.6rem;
    }
  }
  </style>
  