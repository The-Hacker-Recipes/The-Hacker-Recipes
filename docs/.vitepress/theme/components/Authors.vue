<template>
  <div class="authors-container">
    <div class="authors-inner">
      <p class="authors-title">{{ title }}</p>
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
          <img :src="author.avatar_url + avatarSize" />
        </a>
      </div>
      <p v-else class="no-authors">{{ noAuthorsMessage }}</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch } from 'vue'
import { useRoute, useData } from 'vitepress'
import { data as authorsData } from '../../authors.data.ts' 

const authors = ref([])
const route = useRoute()
const { page } = useData()

const title = ref('')
const noAuthorsMessage = ref('')
const avatarSize = ref('')

//Load authors
const listAuthors = () => {
  if (route.path === '/') {
    //Load from authors.data.ts for index
    authors.value = authorsData
  } else {
    //Load authors from current page frontmatter
    const frontmatterAuthors = page.value.frontmatter?.authors
      ? page.value.frontmatter.authors.split(',').map((author) => author.trim())
      : []

    authors.value = frontmatterAuthors.map((author) => ({
      id: author,
      login: author,
      html_url: `https://github.com/${author}`,
      avatar_url: `https://avatars.githubusercontent.com/${author}`
    }))
  }
}

const setupContentBasedOnRoute = () => {
  if (route.path === '/') {
    title.value = 'Authors'
    noAuthorsMessage.value = 'No contributors found...'
    avatarSize.value = ''
  } else {
    title.value = 'Authors'
    noAuthorsMessage.value = 'Error occurred...'
    avatarSize.value = '?s=64'
  }
}

onMounted(() => {
  setupContentBasedOnRoute()
  listAuthors()
})

watch(() => route.path, () => {
  setupContentBasedOnRoute()
  listAuthors()
})
</script>

<style scoped>
.authors-container {
  display: flex;
  justify-content: center;
  margin-top: 1rem;
  margin-bottom: 0;
  padding: 16px;
  border-radius: 12px;
  line-height: 18px;
  background-color: var(--vp-carbon-ads-bg-color);
}

.authors-inner {
  width: fit-content;
  max-width: 100%;
}

.authors-title {
  line-height: 32px;
  padding-bottom: 6px;
  font-size: 14px;
  font-weight: 600;
}

.authors-grid {
  display: grid;
  grid-template-columns: repeat(5, 30px);
  gap: 4px;
  padding-top: 4px;
}

.author img {
  display: block;
  width: 30px;
  height: 30px;
  box-sizing: border-box;
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
