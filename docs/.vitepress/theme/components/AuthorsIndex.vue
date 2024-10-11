<template>
    <div class="authors-container">
      <p class="authors-title">Authors</p>
      <div v-if="authors.length" class="authors-grid">
        <a
          v-for="author in authors"
          :key="author.id"
          :href="author.html_url"
          target="_blank"
          rel="noopener noreferrer"
          class="author"
          :title="author.login"
        >
          <img :src="author.avatar_url + '?s=64'" />
        </a>
      </div>
      <p v-else class="no-authors">No authors found.</p>
    </div>
  </template>
  
  <script setup>
  import { ref, onMounted } from 'vue'
  
  // Importation du loader des auteurs
  import loadAuthors from '../composables/authorsLoader'
  
  const authors = ref([])
  
  onMounted(async () => {
    // Charger tous les auteurs à partir du loader
    const result = await loadAuthors()
  
    // Extraction des auteurs uniques et triés
    const allAuthors = result.map(item => item.authors).flat()
    const uniqueAuthors = Array.from(new Set(allAuthors))
  
    // Convertir chaque auteur en objet avec ses infos GitHub
    authors.value = uniqueAuthors.map(author => ({
      id: author,
      login: author,
      html_url: `https://github.com/${author}`,
      avatar_url: `https://avatars.githubusercontent.com/${author}`
    })).sort((a, b) => a.login.localeCompare(b.login))
  })
  </script>
  
  <style scoped>
  /* Styles identiques à Authors.vue */
  .authors-container {
    justify-content: center;
    align-items: center;
    margin-top: 24px;
    margin-bottom: 24px;
    padding: 16px 24px 24px 24px;
    border-radius: 12px;
    line-height: 18px;
    background-color: var(--vp-carbon-ads-bg-color);
  }
  
  .authors-title {
    line-height: 32px;
    padding-bottom: 6px;
    font-size: 14px;
    font-weight: 600;
  }
  
  .authors-grid {
    display: flex;
    padding-top: 4px;
    flex-wrap: wrap;
    gap: 4px;
  }
  
  .author img {
    width: 30px;
    height: 30px;
    padding: 1px;
    border-radius: 50%;
    border: none;
    transition: transform 0.2s ease;
  }
  
  .author:hover img {
    transform: scale(1.2);
  }
  
  .no-authors {
    font-size: 14px;
    color: var(--vp-c-text-2);
  }
  </style>
  