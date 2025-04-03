---
authors: AzeTIIx, ShutdownRepo, WodenSec
category: contributing
---

# Guide for authors 📝

The Hacker Recipes is a community-driven project, and we welcome contributions from anyone who wants to share their knowledge and help others learn.
In order to keep the quality of the content high, in terms of readability and structure, we ask contributors to follow a consistent structure and best practices when writing articles.

This guide outlines the typical structure, file organization, and best practices for writing articles that align with the project's standards.

## Files and folders

All articles are stored in the `/docs/src` folder. 

::: tabs

=== Article without images

If the article doesn't include images (or other assets), it should be a markdown file with the `.md` extension, and named after the topic it covers.

=== Article with images

If the article includes images (or other media), the article should be named `index.md` and placed in a directory named after the topic it covers.
The assets should be stored in a subdirectory named `assets`, and referenced in the article using the `![](assets/image.png)` syntax.
```
topic
├── assets
│   ├── image1.png
│   ├── image2.png
└── index.md
```
:::

## Navigation panel

For the article to be included in the navigation panel, it should be added to the `config.mts` file, in the `sidebar` array, with the following structure:

```typescript
{
  "text": 'Category',
  "items": [
    {
      "text": 'Article without images',
      "link": '/.../category/topic.md',
    },
    {
      "text": 'Article with images',
      "link": '/.../category/topic/index.md',
    }
  ]
}
```

A category can be a container for articles, and/or be a container for other categories, and include (or not) an `index.md` file to provide a brief introduction to the category. For the latter, the structure goes like this:

```typescript
{
  "text": 'Category',
  "link": '/.../index.md'    
  "items": [
// ...
```

## Content structure

A typical article in this project follows a three-part structure:

1. **Theory**: provides an introduction to the topic, adds context, explains the concepts and ideas behind it.
2. **Practice**: delves into the practical aspects: step-by-step explanations and examples, with commands and code snippets. This part should include, whenever possible, a [tabs block](#tabs) with one tab for Unix-like commands, and another for Windows commands.
3. **Resources**: lists the sources that helped build the article, and additional resources that one can use to further their learning (e.g. articles, blogposts, whitepapers, videos)


## Writing style

When writing your article, one should keep the following tone & voice.

* **Professional and Authoritative**: The content should maintain a professional tone, suitable for a technical audience familiar with cybersecurity concepts.
* **Instructional and Informative**: The writing aims to educate the reader, with clear instructions and explanations. It avoids being overly casual, focusing instead on delivering detailed, technical knowledge.
* **Impersonal and Objective**: The writing should avoid directly addressing the reader (e.g., “you") or using personal pronouns. Instead, use passive constructions or neutral phrasing (e.g., “The attack can be conducted using tool XYZ" rather than “You can conduct the attack with tool XYZ").

> [!WARNING] Examples to avoid
> * "This attack is super easy to pull off!" → "This attack is straightforward to execute."
> * "Here’s a cool trick you can use to bypass the firewall" → "A technique to bypass the firewall involves…"
> * "Just try running this command and see what happens" → "Run this command to observe its effect."
> * "Don’t forget to check the logs!" → "Ensure that the logs are reviewed."
> * "You can conduct the attack with tool XYZ" → "The attack can be conducted with tool XYZ"
> * "We recommend using tool ABC for this process" → "Tool ABC is recommended for this process"
> * "First, you should verify the configuration settings" → "The configuration settings should first be verified"

> [!TIP]
> ChatGPT (or similar LLM agents) can be used to review content before creating a Pull Request :wink: Below is an example prompt.
> > "Please proofread the following text for tone, voice, and style consistency based on these guidelines: professional, instructional, and impersonal. Highlight any instances where casual language, direct address (e.g., 'you'), or personal pronouns are used, and suggest revisions. Here is the text: [insert your content]."

## Block Types

The project uses a variety of block types to organize and present content.
While this guide focuses on the main blocks used in this project, additionnal blocks are listed in the official [VitePress docs](https://vitepress.dev/guide/markdown).

### Code

Use triple backticks to delimit code blocks, specifying the language after the first set of backticks.
VitePress supports extended usage of code blocks such as [syntax highlighting](https://vitepress.dev/guide/markdown#syntax-highlighting-in-code-blocks), [line highlighting](https://vitepress.dev/guide/markdown#line-highlighting-in-code-blocks), [line focus](https://vitepress.dev/guide/markdown#focus-in-code-blocks), [colored diffs](https://vitepress.dev/guide/markdown#colored-diffs-in-code-blocks), [errors and warnings highlighting](https://vitepress.dev/guide/markdown#errors-and-warnings-in-code-blocks), [line numbers](https://vitepress.dev/guide/markdown#line-numbers), [code groups](https://vitepress.dev/guide/markdown#code-groups). 

But it can be as simple as that:

````
```python
print('hello world')
```
````

Giving the following output

```python
print('hello world')
```

--- 

### Tabs

Input

```markdown
:::tabs

== tab a

Some content

== tab b

b content

:::
```

Output

:::tabs

== tab a

Some content

== tab b

b content

:::

---

### Callouts

THR uses GitHub-flavored alerts to render most callouts. The most common callouts in The Hacker Recipes are:

> [!NOTE] NOTE
> Note from the author, not critical to the main content. To clarify, offer references, add content or background.

> [!TIP] TIP
> Offer helpful advice or best practices. Providing shortcuts or expert recommandations.

> [!WARNING] WARNING
> Alert the reader to potential dangers. Provide OPSEC advice.

> [!CAUTION] CAUTION
> When there's critical information the reader needs to be aware of.

> [!SUCCESS] SUCCESS
> When the author wants to highlight a successful outcome or scenario.

::: details
Details blocks can also be used
:::

The input for this goes like this:

```markdown
> [!NOTE] NOTE
> Note from the author, not critical to the main content. To clarify, offer references, add content or background.

> [!TIP] TIP
> Offer helpful advice or best practices. Providing shortcuts or expert recommandations.

> [!WARNING] WARNING
> Alert the reader to potential dangers. Provide OPSEC advice.

> [!CAUTION] CAUTION
> When there's critical information the reader needs to be aware of.

> [!SUCCESS] SUCCESS
> When the author wants to highlight a successful outcome or scenario.

::: details
Details blocks can also be used
:::
```

> [!NOTE]
> The title of a callout is optional.
> ```
> > [!NOTE]
> The title of a callout is optional.
> ```

---

### Images and links

As simple as `[title](link)` for links and `![](path/to/image)` for images.

> [!TIP]
> If there are spaces in the image path, either spaces need to be URL-encded (`%20`), or the following structure can be used (recommended):
> `![](<path/to/some image>)`

Images can also be given a caption

```markdown
![](path/to/image)
Some caption{.caption}
```
Which will output the following

![](https://developers.elementor.com/docs/assets/img/elementor-placeholder-image.png)
Some caption{.caption}

To embed a YouTube link, use the following tag format:

```
> [!YOUTUBE] https://www.youtube.com/watch?v=example
```

This will create a clickable link that directs users to the specified YouTube video. 

Which will output the following

> [!YOUTUBE] https://www.youtube.com/watch?v=dQw4w9WgXcQ

> [!WARNING] 
> Ensure you provide the full YouTube link, as using a shortened link will cause the tag to malfunction.

### Others

| Block                                                              | Description                                             |
|--------------------------------------------------------------------|---------------------------------------------------------|
| [Links](https://vitepress.dev/guide/markdown#links)                | Internal links (to other articles, or to anchor points) |
| [Tables](https://vitepress.dev/guide/markdown#github-style-tables) | Tables (like this one)                                  |
| [Emojis](https://vitepress.dev/guide/markdown#emoji)               | Emojis :tada:                                           |

```

### Quotes

> "Someone said something important and it should be highlighted in the article? Please quote it and attribute it to the initial author."
>  
> _(Author, date, [source](#))_

```markdown
> "Someone said something important and it should be highlighted in the article? Please quote it and attribute it to the initial author."
>  
> _(Author, date, [source](#))_
```

## Article template

An article template is available for a quick start: [Template](template).

## Frontmatter configuration

### Highlighting contributors

For contributors to be listed, they need to be listed in the `authors` property of the [frontmatter](https://vitepress.dev/guide/frontmatter) configuration of the corresponding page(s).

When contributing to a page, an author must add its GitHub username to it:

```markdown
---
authors: author1, author2, ...
---
```

### Category attribute

It is mandatory to specify the category of the article in the frontmatter configuration of the page (it can be `ad`, `infra`, `web`, etc.).

```markdown
---
category: ad
---
```

## Variable commands

When adding or editing content, please use the standardized variable names listed above to ensure a consistent experience across all documentation pages for [variable commands](variables)

### Variable Naming Standards

| Use This          | Instead Of                                      |
|-------------------|------------------------------------------------|
| `$NT_HASH`        | `$NThash`, `$nthash`, `$Nthash`                |
| `$LM_HASH`        | `$LMhash`, `$lmhash`, `$Lmhash`                |
| `$ATTACKER_IP`    | `$attackerIP`, `$attacker_ip`, `$LHOST`        |
| `$TARGET`         | `$TARGET_IP`, `$targetIP`, `$target_ip`        |
| `$DOMAIN`         | `$domain`, `$DOMAIN_NAME`                      |
| `$DC_IP`          | `$dc_ip`, `$dcIP`, `$domainController`         |
| `$USER`           | `$user`, `$username`, `$USER_NAME`             |
| `$INTERFACE`      | `$interface`, `$network_interface`             |

### Implementation Tips

1. When updating documentation, standardize any variable names you encounter
2. Use ALL_CAPS with underscore separators for all variables
3. For tool-specific variables, maintain consistency with our naming convention
4. Include brief comments when introducing new variables
5. Variables must be prefixed with `$` to be recognized by our substitution system 

## Get started :rocket:

1. Fork the repository (https://github.com/The-Hacker-Recipes/The-Hacker-Recipes/fork)
2. (optional) create a new branch in your fork, if you plan on working on different topics
3. Create your content using this guide, and the template if needed
4. Make sure the content builds fine with `npm install && npm run docs:dev`
5. Make a Pull Request (https://github.com/The-Hacker-Recipes/The-Hacker-Recipes/compare)
