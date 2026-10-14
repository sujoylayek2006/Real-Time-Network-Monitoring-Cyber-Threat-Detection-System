// The only React part of the demo: the live alert centre.
// Plain React.createElement is used so the page runs by double-clicking index.html, with no build step.
(() => {
  const { useState, useEffect } = React;
  const h = React.createElement;
  const SEV_LABEL = { high: 'High', medium: 'Medium', low: 'Low' };
  const STATUS_LABEL = { blocked: 'Blocked', dismissed: 'False positive' };
  const time = d => d.toLocaleTimeString([], { hour12: false });

  function Bars({ feats }) {
    return h('ul', { className: 'bars' }, feats.map(([name, v]) =>
      h('li', { key: name },
        h('span', { className: 'bar-name' }, name),
        h('span', { className: 'bar-track' },
          h('span', { className: 'bar-fill ' + (v < 0 ? 'neg' : 'pos'), style: { width: Math.round(Math.abs(v) * 100) + '%' } })),
        h('span', { className: 'bar-val' }, (v > 0 ? '+' : '') + v.toFixed(2)))));
  }

  function Detail({ a, onBlock, onDismiss }) {
    const done = a.status !== 'open';
    return h('div', { className: 'detail' },
      h('div', { className: 'detail-title' },
        h('h3', null, a.title),
        h('span', { className: 'badge ' + a.sev }, SEV_LABEL[a.sev])),
      h('p', { className: 'why' }, a.why),
      h('h4', null, 'Alert details'),
      h('dl', { className: 'meta' },
        h('dt', null, 'Source'), h('dd', null, a.src),
        h('dt', null, 'Target'), h('dd', null, `${a.dst}, port ${a.port}`),
        h('dt', null, 'Detected by'), h('dd', null, a.engine),
        h('dt', null, 'Confidence'), h('dd', null, a.conf + '%'),
        h('dt', null, 'MITRE ATT&CK'), h('dd', null, a.mitre),
        h('dt', null, 'Detection time'), h('dd', null, a.latency + ' ms')),
      h('h4', null, 'Why the model flagged this'),
      h(Bars, { feats: a.feats }),
      h('p', { className: 'note' }, 'Red bars pushed the score toward attack, green bars pushed it toward normal (SHAP style contribution).'),
      h('div', { className: 'actions' },
        h('button', { className: 'btn primary', disabled: done, onClick: () => onBlock(a) },
          a.status === 'blocked' ? 'Source blocked' : 'Block source IP'),
        h('button', { className: 'btn', disabled: done, onClick: () => onDismiss(a) },
          a.status === 'dismissed' ? 'Marked as false positive' : 'Mark as false positive')));
  }

  function AlertCenter() {
    const [alerts, setAlerts] = useState([]);
    const [filter, setFilter] = useState('all');
    const [selId, setSelId] = useState(null);

    useEffect(() => {
      const onAlert = e => {
        setAlerts(prev => [e.detail, ...prev].slice(0, 40));
        setSelId(id => id || e.detail.id);
      };
      window.addEventListener('ids:alert', onAlert);
      return () => window.removeEventListener('ids:alert', onAlert);
    }, []);

    const patch = (id, change) => setAlerts(prev => prev.map(x => x.id === id ? { ...x, ...change } : x));
    const block = a => { patch(a.id, { status: 'blocked' }); window.dispatchEvent(new CustomEvent('ids:block', { detail: { ip: a.src } })); };
    const dismiss = a => patch(a.id, { status: 'dismissed' });

    const shown = alerts.filter(a => filter === 'all' || a.sev === filter);
    const selected = alerts.find(a => a.id === selId);

    return h(React.Fragment, null,
      h('div', { className: 'alerts-head' },
        h('h2', null, `Live alerts (${alerts.length})`),
        h('div', { className: 'chips', role: 'group', 'aria-label': 'Filter by severity' },
          ['all', 'high', 'medium', 'low'].map(f =>
            h('button', { key: f, className: 'chip', 'aria-pressed': filter === f, onClick: () => setFilter(f) },
              f === 'all' ? 'All' : SEV_LABEL[f])))),
      shown.length === 0
        ? h('p', { className: 'empty' }, 'No alerts in this view yet. Use "Trigger a test attack" to create one.')
        : h('ul', { className: 'list' }, shown.map(a =>
            h('li', { key: a.id },
              h('button', { className: 'item', 'aria-current': a.id === selId, onClick: () => setSelId(a.id) },
                h('span', { className: 'badge ' + a.sev }, SEV_LABEL[a.sev]),
                h('span', { className: 't' }, a.title),
                h('span', { className: 'tm' }, time(a.time)),
                h('span', { className: 'ip' }, a.src),
                h('span', { className: 'st' }, STATUS_LABEL[a.status] || ''))))),
      selected && h(Detail, { a: selected, onBlock: block, onDismiss: dismiss }));
  }

  ReactDOM.createRoot(document.getElementById('alert-root')).render(h(AlertCenter));
})();
