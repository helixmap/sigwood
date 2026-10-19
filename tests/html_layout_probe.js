// Read-only DOM oracle. Evaluate this function in the browser pane against a
// rendered report; the caller supplies independent fixture address identities.
({ knownAddresses = [] } = {}) => {
  const rect = r => ({ x: r.x, y: r.y, width: r.width, height: r.height });
  const nodes = element => {
    const found = [];
    const visit = node => {
      if (node.nodeType === 3) found.push(node);
      else for (const child of node.childNodes) visit(child);
    };
    visit(element);
    return found;
  };
  const fragments = (node, start = 0, end = node.textContent.length) => {
    const range = document.createRange();
    range.setStart(node, start);
    range.setEnd(node, end);
    return Array.from(range.getClientRects(), rect).filter(r => r.width > 0);
  };
  const group = el => el.closest('.group').querySelector('.group-name').textContent;
  const addresses = selector => Array.from(document.querySelectorAll(selector)).flatMap(el =>
    nodes(el).flatMap(node => knownAddresses.flatMap(address => {
      const hits = [];
      let start = 0;
      while ((start = node.textContent.indexOf(address, start)) >= 0) {
        hits.push({ address, detector: group(el), text: el.textContent,
          rects: fragments(node, start, start + address.length) });
        start += address.length;
      }
      return hits;
    })));
  return {
    viewport: { width: window.innerWidth, height: window.innerHeight },
    bodyWidth: document.documentElement.scrollWidth,
    tokens: Array.from(document.querySelectorAll('span.tok'), el => ({
      text: el.textContent, detector: group(el),
      rects: Array.from(el.getClientRects(), rect),
      cellClientWidth: el.closest('td').clientWidth,
      cellScrollWidth: el.closest('td').scrollWidth,
    })),
    wrappers: Array.from(document.querySelectorAll('.table-scroll'), el => ({
      detector: group(el), clientWidth: el.clientWidth, scrollWidth: el.scrollWidth,
    })),
    separators: Array.from(document.querySelectorAll('.finding-row td')).filter(el =>
      el.querySelector('wbr')).map(el => ({ detector: group(el), text: el.textContent,
      pieces: nodes(el).map(node => ({text: node.textContent, rects: fragments(node)})),
    })),
    headlineAddresses: addresses('.finding-row td'),
    verboseAddresses: addresses('.kv .v'),
    unbrokenPrincipals: Array.from(document.querySelectorAll('.finding-row td')).filter(el =>
      group(el) === 'aws' && !el.classList.contains('data') &&
      !el.classList.contains('sev-cell') && !el.querySelector('wbr')).map(el => ({
      text: el.textContent, rects: nodes(el).flatMap(node => fragments(node)),
    })),
    reasons: Array.from(document.querySelectorAll('td.col-reason'), el => ({
      text: el.textContent, rects: nodes(el).flatMap(node => fragments(node)),
    })),
    syslog: Array.from(document.querySelectorAll('.syslog-table'), el => ({
      wrapped: Boolean(el.closest('.table-scroll')), width: el.getBoundingClientRect().width,
      clips: Array.from(el.querySelectorAll('.clip'), clip => ({
        clientWidth: clip.clientWidth, scrollWidth: clip.scrollWidth,
      })),
    })),
  };
}
