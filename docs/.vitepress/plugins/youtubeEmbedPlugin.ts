import type MarkdownIt from 'markdown-it';

const markerRE = /^\[\!YOUTUBE\]\s*(https:\/\/www\.youtube\.com\/watch\?v=([a-zA-Z0-9_-]+))/i;

const youtubeEmbedPlugin = (md: MarkdownIt) => {
  md.core.ruler.after("block", "youtube-embed", (state) => {
    const tokens = state.tokens;
    for (let i = 0; i < tokens.length; i++) {
      if (tokens[i].type === "blockquote_open") {
        const startIndex = i;
        const open = tokens[startIndex];
        let endIndex = i + 1;
        while (endIndex < tokens.length && (tokens[endIndex].type !== "blockquote_close" || tokens[endIndex].level !== open.level))
          endIndex++;
        if (endIndex === tokens.length) continue;
        const close = tokens[endIndex];
        const firstContent = tokens.slice(startIndex, endIndex + 1).find((token) => token.type === "inline");
        if (!firstContent) continue;
        const match = firstContent.content.match(markerRE);
        if (!match) continue;
        const videoUrl = match[1];
        const videoId = match[2];
        firstContent.content = firstContent.content.slice(match[0].length).trimStart();
        open.type = "youtube_embed_open";
        open.tag = "div";
        open.meta = {
          videoUrl,
          videoId
        };
        close.type = "youtube_embed_close";
        close.tag = "div";
      }
    }
  });

  md.renderer.rules.youtube_embed_open = function(tokens, idx) {
    const { videoId } = tokens[idx].meta;
    return `<div class="youtube-embed">
  <iframe width="560" height="315" src="https://www.youtube.com/embed/${videoId}" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>\n`;
  };

  md.renderer.rules.youtube_embed_close = function() {
    return '</div>\n';
  };
};

export default youtubeEmbedPlugin;
