// authorsLoader.ts
import { createContentLoader } from 'vitepress'

export default createContentLoader({
  pattern: '**/*.md',
  extract({ frontmatter }) {
    if (frontmatter.authors) {
      return {
        authors: frontmatter.authors.split(',').map((author: string) => author.trim()),
      }
    }
    return null
  }
})
