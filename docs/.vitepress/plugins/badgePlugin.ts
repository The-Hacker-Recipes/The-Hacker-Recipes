import type MarkdownIt from 'markdown-it';

const badgeMarkerRE = /^\[\!BADGE-(INFO|TIP|WARNING|DANGER)\](.*)?/i;

const badgePlugin = (md: MarkdownIt, options?: any) => {
  const badgeTypes = {
    info: 'info',
    tip: 'tip',
    warning: 'warning',
    danger: 'danger',
  };

  md.core.ruler.after('block', 'badge-plugin', (state) => {
    const tokens = state.tokens;

    for (let i = 0; i < tokens.length; i++) {
      if (tokens[i].type === 'inline' && tokens[i].content) {
        const content = tokens[i].content;
        const match = content.match(badgeMarkerRE);
        
        if (match) {
          const type = match[1].toLowerCase();
          const title = match[2].trim() || '';

          // Replace the content with the badge HTML
          tokens[i].type = 'html_inline';
          tokens[i].content = `<Badge type="${badgeTypes[type]}" text="${title}" />`;
        }
      }
    }
  });
};

export default badgePlugin;

/* [!BADGE-type] TITRE */