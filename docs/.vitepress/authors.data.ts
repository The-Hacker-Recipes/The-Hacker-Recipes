import { createContentLoader } from 'vitepress'

export default createContentLoader('../src/**/*.md', {
  transform(rawPages) {
    const authorSet = new Set()

    rawPages.forEach(page => {
      const authors = page.frontmatter.authors
      if (authors) {
        if (typeof authors === 'string') {
          authors.split(',').forEach(author => {
            authorSet.add(author.trim())  
          })
        }
        else if (Array.isArray(authors)) {
          authors.forEach(author => {
            author.split(',').forEach(individualAuthor => {
              authorSet.add(individualAuthor.trim()) 
            })
          })
        }
      }
    })

    //Sort
    const uniqueAuthors = Array.from(authorSet).sort((a, b) => a.localeCompare(b))

    //DEBUG
    //console.log('Auteurs trouvés :', uniqueAuthors)

    return uniqueAuthors.map(author => ({
      id: author,
      login: author,
      html_url: `https://github.com/${author}`,
      avatar_url: `https://avatars.githubusercontent.com/${author}?s=64`
    }))
  }
})
