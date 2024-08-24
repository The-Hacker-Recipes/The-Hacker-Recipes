import type MarkdownIt from 'markdown-it';

const markerRE = /^\[\!(TIP|NOTE|INFO|IMPORTANT|WARNING|CAUTION|DANGER|SUCCESS)\]([^\n\r]*)/i;

const githubAlertsPlugin = (md: MarkdownIt, options?: any) => {
  const titleMark = {
    tip: options?.tipLabel || "TIP",
    note: options?.noteLabel || "NOTE",
    info: options?.infoLabel || "INFO",
    important: options?.importantLabel || "IMPORTANT",
    warning: options?.warningLabel || "WARNING",
    caution: options?.cautionLabel || "CAUTION",
    danger: options?.dangerLabel || "DANGER",
    success: options?.successLabel || "SUCCESS"
  };

  md.core.ruler.after("block", "github-alerts", (state) => {
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
        const type = match[1].toLowerCase();
        const title = match[2].trim();
        firstContent.content = firstContent.content.slice(match[0].length).trimStart();
        open.type = "github_alert_open";
        open.tag = "div";
        open.meta = {
          title,
          type
        };
        close.type = "github_alert_close";
        close.tag = "div";
      }
    }
  });

  md.renderer.rules.github_alert_open = function(tokens, idx) {
    const { title, type } = tokens[idx].meta;
    return `<div class="${type} custom-block">${title ? `<p class="custom-block-title">${title}</p>` : ''}\n`;
  };

  md.renderer.rules.github_alert_close = function() {
    return '</div>\n';
  };
};

export default githubAlertsPlugin;
