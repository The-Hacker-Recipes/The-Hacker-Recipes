<template>
  <div class="page-not-found">
    <p class="code">404</p>
    <h1 class="title">Page not found</h1>
    <div class="divider"></div>
    <blockquote class="quote">
        You found a dead link: <a class="deadlink">{{ $route.path }}</a>
    </blockquote>
    <blockquote class="quote">
        Please <a href="https://github.com/ShutdownRepo/The-Hacker-Recipes/issues" target="_blank" rel="noopener noreferrer">let us know</a> so we can fix it.</blockquote>
    <div class="action">
        <a class="home_button" href="/" aria-label="go to home">Home</a>
    </div>
  </div>

</template>

<style scoped>
.page-not-found {
  padding: 64px 24px 96px;
  text-align: center;
}

.code {
  font-size: 64px;
  font-weight: 600;
}

.title {
  padding-top: 12px;
  letter-spacing: 2px;
  line-height: 20px;
  font-size: 20px;
  font-weight: 700;
}

.divider {
  margin: 24px auto 18px;
  width: 64px;
  height: 1px;
  background-color: var(--vp-c-divider);
}

.quote {
  margin: 0 auto;
  font-size: 14px;
  font-weight: 500;
  color: var(--vp-c-text-2);
}

.action {
  padding-top: 20px;
}

.home_button {
  display: inline-block;
  border: 1px solid var(--vp-c-brand);
  border-radius: 16px;
  padding: 3px 16px;
  font-size: 14px;
  font-weight: 500;
  color: var(--vp-c-brand);
  transition: border-color 0.25s, color 0.25s;
}

.home_button:hover {
  border-color: var(--vp-c-brand-dark);
  color: var(--vp-c-brand-dark);
}

.quote a {
  color: var(--vp-c-brand);
  text-decoration: none;
  transition: color 0.25s;
}

.quote a:hover {
  text-decoration: underline;
}

.quote a.deadlink {
  font-weight: bold;
  font-family: var(--vp-font-family-mono);
  color: var(--vp-c-brand);
  text-decoration: none;
  transition: none;
}

.quote a.deadlink:hover {
  text-decoration: none;
  color: var(--vp-c-brand);
}

</style>

<script setup>
import { useRoute } from 'vitepress'

const $route = useRoute()
</script>
