<template>
  <div class="action">
    <a class="news-button" href="/new_version">
      <span class="material-symbols-outlined">
        new_releases
      </span>
      &nbsp;&nbsp;Welcome to THR v2!
    </a>
  </div>
</template>

<style scoped>
.action {
  display: flex;
  justify-content: center;
  gap: 1rem;
  padding-top: 30px;
  padding-bottom: 16px;
}

.news-button {
  display: flex;
  align-items: center;
  border: 1px solid transparent;
  text-align: center;
  font-weight: 600;
  white-space: nowrap;
  transition:
    color 0.25s,
    border-color 0.25s,
    background-color 0.25s;
  border-radius: 20px;
  padding: 0 15px;
  line-height: 38px;
  font-size: 14px;
  border-color: var(--vp-c-border-2);
  color: var(--vp-c-text-1);
  background-color: transparent;
}

.news-button:hover {
  border-color: var(--vp-c-yellow-1);
  color: var(--vp-c-yellow-1);
  background-color: var(--vp-c-yellow-soft);
}
</style>
