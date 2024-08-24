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
        <img :src="author.avatar_url + '&s=64'" :alt="author.login" />
      </a>
    </div>
    <p v-else class="no-authors">Error occured...</p>
  </div>
</template>

<script setup>
import { ref, watch, onMounted, computed } from 'vue'
import { useRoute } from 'vitepress'

const route = useRoute()
const authors = ref([])
const path = computed(() => route.path)

const REPO_OWNER = 'The-Hacker-Recipes'
const REPO_NAME = 'The-Hacker-Recipes'
const BASE_API_URL = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}`

const fetchContributors = async () => {
  try {
    if (path.value === '/') {
      let data = await fetchRepoContributors()
      authors.value = data
    } else {
      let data = await fetchFileContributors(getFilePath())
      authors.value = processFileContributors(data)
    }
  } catch (error) {
    console.error('Error fetching authors:', error)
    authors.value = []
  }
}

const fetchRepoContributors = async () => {
  return await fetchData(`${BASE_API_URL}/contributors`)
}

const fetchFileContributors = async (filePath) => {
  let baseFileContribsApiUrl = `${BASE_API_URL}/commits?path=docs/src`
  let data = await fetchData(`${baseFileContribsApiUrl}${filePath}`)
  if (data.length === 0 && path.value.endsWith('/')) {
    // Fallback to README.md if index.md returns no results
    data = await fetchData(`${baseFileContribsApiUrl}${getReadmePath()}`)
  }
  return data || []
}

const fetchData = async (url) => {
  let allData = []
  let page = 1
  let hasMorePages = true

  while (hasMorePages) {
    const fullUrl = `${url}${url.includes('?') ? '&' : '?'}per_page=100&page=${page}`
    const response = await fetch(fullUrl)
    console.log('Contributors request url:', fullUrl)
    const data = await response.json()
    
    if (!Array.isArray(data)) {
      console.error('Received non-array data:', data)
      break
    }

    allData = allData.concat(data)
    hasMorePages = data.length === 100
    page++
  }

  return allData
}

const getFilePath = () => {
  if (path.value.endsWith('/')) {
    return `${path.value}index.md`
  }
  return `${path.value}.md`
}

const getReadmePath = () => {
  return `${path.value}README.md`
}

const processFileContributors = (data) => {
  return Array.from(new Set(data.filter(commit => commit.author).map(commit => commit.author.id)))
    .map(id => data.find(commit => commit.author && commit.author.id === id).author)
    .filter(Boolean)
}

onMounted(fetchContributors)
watch(path, fetchContributors)
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