function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function sanitizeUrl(raw) {
  try {
    const baseUrl = globalThis.location?.href || "https://example.invalid/";
    const url = new URL(String(raw || "").trim(), baseUrl);
    if (!["http:", "https:", "mailto:"].includes(url.protocol)) return "";
    return url.href;
  } catch {
    return "";
  }
}

function isBlockStarter(line) {
  return (
    /^#{1,6}\s+/.test(line) ||
    /^>\s?/.test(line) ||
    /^```/.test(line) ||
    /^(\-|\*|\+)\s+/.test(line) ||
    /^\d+[.)]\s+/.test(line) ||
    /^(-{3,}|\*{3,}|_{3,})$/.test(line)
  );
}

function renderInline(source) {
  const codeTokens = [];
  let text = String(source || "").replace(/`([^`\n]+)`/g, (_match, code) => {
    const index = codeTokens.push(code) - 1;
    return `\u0000${index}\u0000`;
  });

  text = escapeHtml(text);
  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_match, label, url) => {
    const safeUrl = sanitizeUrl(url);
    if (!safeUrl) return escapeHtml(label);
    return `<a href="${escapeHtml(safeUrl)}" target="_blank" rel="noreferrer noopener">${escapeHtml(label)}</a>`;
  });
  text = text.replace(/(^|[^\w>])\*([^*\n]+)\*(?!\*)/g, (_match, prefix, body) => {
    return `${prefix}<em>${body}</em>`;
  });
  text = text.replace(/(^|[^\w>])_([^_\n]+)_(?!_)/g, (_match, prefix, body) => {
    return `${prefix}<em>${body}</em>`;
  });
  text = text.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  text = text.replace(/__(.+?)__/g, "<strong>$1</strong>");
  text = text.replace(/~~(.+?)~~/g, "<del>$1</del>");
  text = text.replace(/\u0000(\d+)\u0000/g, (_match, index) => {
    const value = codeTokens[Number(index)] || "";
    return `<code>${escapeHtml(value)}</code>`;
  });
  return text;
}

function renderParagraph(lines) {
  return `<p>${renderInline(lines.join(" ").trim())}</p>`;
}

function renderBlockquote(lines) {
  return `<blockquote>${lines.map((line) => renderParagraph([line])).join("")}</blockquote>`;
}

export function renderMarkdown(source) {
  const text = String(source || "").replace(/\r\n/g, "\n").trim();
  if (!text) return "";

  const lines = text.split("\n");
  const blocks = [];
  let i = 0;

  while (i < lines.length) {
    const rawLine = lines[i];
    const line = rawLine.trim();

    if (!line) {
      i += 1;
      continue;
    }

    const fenceMatch = line.match(/^```([\w-]+)?\s*$/);
    if (fenceMatch) {
      const lang = fenceMatch[1] || "";
      i += 1;
      const codeLines = [];
      while (i < lines.length && !/^```/.test(lines[i].trim())) {
        codeLines.push(lines[i]);
        i += 1;
      }
      if (i < lines.length && /^```/.test(lines[i].trim())) {
        i += 1;
      }
      blocks.push(
        `<pre${lang ? ` data-lang="${escapeHtml(lang)}"` : ""}><code>${escapeHtml(codeLines.join("\n"))}</code></pre>`
      );
      continue;
    }

    const headingMatch = line.match(/^(#{1,6})\s+(.*)$/);
    if (headingMatch) {
      const level = headingMatch[1].length;
      blocks.push(`<h${level}>${renderInline(headingMatch[2])}</h${level}>`);
      i += 1;
      continue;
    }

    if (/^(-{3,}|\*{3,}|_{3,})$/.test(line)) {
      blocks.push("<hr />");
      i += 1;
      continue;
    }

    if (/^>\s?/.test(line)) {
      const quoteLines = [];
      while (i < lines.length && /^>\s?/.test(lines[i].trim())) {
        quoteLines.push(lines[i].trim().replace(/^>\s?/, ""));
        i += 1;
      }
      blocks.push(renderBlockquote(quoteLines));
      continue;
    }

    const ulMatch = line.match(/^(\-|\*|\+)\s+(.*)$/);
    if (ulMatch) {
      const items = [];
      while (i < lines.length) {
        const match = lines[i].trim().match(/^(\-|\*|\+)\s+(.*)$/);
        if (!match) break;
        items.push(match[2]);
        i += 1;
      }
      blocks.push(`<ul>${items.map((item) => `<li>${renderInline(item)}</li>`).join("")}</ul>`);
      continue;
    }

    const olMatch = line.match(/^(\d+)[.)]\s+(.*)$/);
    if (olMatch) {
      const items = [];
      while (i < lines.length) {
        const match = lines[i].trim().match(/^(\d+)[.)]\s+(.*)$/);
        if (!match) break;
        items.push(match[2]);
        i += 1;
      }
      blocks.push(`<ol>${items.map((item) => `<li>${renderInline(item)}</li>`).join("")}</ol>`);
      continue;
    }

    const paragraphLines = [rawLine];
    i += 1;
    while (i < lines.length) {
      const nextLine = lines[i];
      const nextTrim = nextLine.trim();
      if (!nextTrim) break;
      if (isBlockStarter(nextTrim)) break;
      paragraphLines.push(nextLine);
      i += 1;
    }
    blocks.push(renderParagraph(paragraphLines));
  }

  return blocks.join("");
}
