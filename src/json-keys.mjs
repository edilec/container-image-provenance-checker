export function inspectJsonKeys(text, maxDepth) {
  let i = 0;
  const ws = () => { while (/[\u0020\t\r\n]/u.test(text[i] ?? '')) i++; };
  const string = () => { const start = i++; while (i < text.length) { if (text[i] === '\\') { i += 2; continue; } if (text[i++] === '"') return JSON.parse(text.slice(start, i)); } return ''; };
  const value = level => {
    if (level > maxDepth) return 'depth';
    ws();
    if (text[i] === '{') {
      i++; ws(); const keys = new Set();
      if (text[i] === '}') { i++; return null; }
      while (i < text.length) {
        const key = string(); if (keys.has(key)) return 'duplicate'; keys.add(key);
        ws(); i++; const problem = value(level + 1); if (problem) return problem;
        ws(); if (text[i++] === '}') return null; ws();
      }
    }
    if (text[i] === '[') {
      i++; ws(); if (text[i] === ']') { i++; return null; }
      while (i < text.length) { const problem = value(level + 1); if (problem) return problem; ws(); if (text[i++] === ']') return null; ws(); }
    }
    if (text[i] === '"') { string(); return null; }
    while (i < text.length && !/[\u0020\t\r\n,}\]]/u.test(text[i])) i++;
    return null;
  };
  return value(0);
}
