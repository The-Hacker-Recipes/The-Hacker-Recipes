<template>
  <div class="authors-container">
    <p class="authors-title">Contributors</p>
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
        <img :src="author.avatar_url" />
      </a>
    </div>
    <p v-else class="no-authors">No contributors found...</p>
  </div>
</template>

<script setup>
import { data as authors } from '../../authors.data.ts' // charger les données des auteurs
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
</style>
