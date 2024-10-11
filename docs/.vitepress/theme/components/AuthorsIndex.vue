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
      <p v-else class="no-authors">Error occurred or no authors found.</p>
    </div>
  </template>
  
  <script setup>
  import { ref, onMounted } from 'vue'
  import { createContentLoader } from 'vitepress'
  
  const authors = ref([])
  
  const fetchAllAuthors = async () => {
    const contentLoader = createContentLoader('**/*.md', {
      includeMeta: true,
      transform(page) {
        const frontmatterAuthors = page.frontmatter.authors
          ? page.frontmatter.authors.split(',').map(author => author.trim())
          : []
        
        return frontmatterAuthors.map(author => ({
          id: author,
          login: author,
          html_url: `https://github.com/${author}`,
          avatar_url: `https://avatars.githubusercontent.com/${author}`
        }))
      }
    })
  
    const allPages = await contentLoader.load()
    const allAuthors = allPages.flatMap(page => page).filter(Boolean)
  
    // Remove duplicates and sort alphabetically by login
    const uniqueAuthors = Array.from(new Set(allAuthors.map(a => a.login)))
      .map(login => allAuthors.find(a => a.login === login))
      .sort((a, b) => a.login.localeCompare(b.login))
  
    authors.value = uniqueAuthors
  }
  
  onMounted(fetchAllAuthors)
  </script>
  
  <style scoped>
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
  
  @media (max-width: 768px) {
    .authors-container {
      border-left: none;
      padding-top: 24px;
      padding-bottom: 24px;
      border-top: 1px solid var(--vp-c-divider);
      border-bottom: 1px solid var(--vp-c-divider);
      margin-bottom: 18px;
    }
  
    .authors-title {
      border-top: none;
      padding-top: 0;
    }
  }
  </style>
  