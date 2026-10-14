(() => {
  const rand = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
  const pick = arr => arr[rand(0, arr.length - 1)];
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const ext = () => `${pick([45, 103, 185, 91, 203])}.${rand(1, 254)}.${rand(1, 254)}.${rand(1, 254)}`;
  const lan = () => `10.10.${rand(1, 20)}.${rand(2, 250)}`;
  const $ = id => document.getElementById(id);

  // Each entry mirrors one detector from the project design.
  // feats = how strongly each feature pushed the score toward "attack" (SHAP style).
  const CATALOG = {
    scan: {
      title: 'Port scan', sev: 'high', engine: 'Rule engine', mitre: 'T1046 Network service discovery',
      spike: 25, port: () => 'many ports',
      why: () => `${rand(300, 520)} connection attempts to ${rand(40, 90)} different ports in 5 seconds.`,
      feats: [['Distinct destination ports', .91], ['SYN rate', .74], ['Flow duration', -.22], ['Bytes per flow', -.12]]
    },
    syn: {
      title: 'SYN flood', sev: 'high', engine: 'Rule engine and XGBoost', mitre: 'T1498 Network denial of service',
      spike: 45, port: () => pick([80, 443]),
      why: () => `${rand(4000, 9000)} SYN packets per second with almost no replies completing the handshake.`,
      feats: [['SYN packet count', .95], ['ACK to SYN ratio', .68], ['Packet length variance', -.2], ['Flow duration', .15]]
    },
    brute: {
      title: 'SSH brute force', sev: 'medium', engine: 'Rule engine', mitre: 'T1110 Brute force',
      spike: 15, port: () => 22,
      why: () => `${rand(40, 120)} failed login attempts from one address in 60 seconds.`,
      feats: [['Repeated connections to port 22', .88], ['Short flow duration', .59], ['Bytes per flow', -.18], ['Packet rate', .27]]
    },
    arp: {
      title: 'ARP spoofing', sev: 'high', engine: 'Rule engine', mitre: 'T1557.002 ARP cache poisoning',
      spike: 0, port: () => 'n/a',
      why: () => 'The gateway address is now answered by an unknown MAC address.',
      feats: [['MAC and IP mapping changed', .97], ['Unsolicited ARP replies', .81], ['Packet rate', -.1]]
    },
    zero: {
      title: 'Unusual traffic pattern', sev: 'medium', engine: 'Autoencoder (unknown threats)', mitre: 'Not mapped, flagged as anomaly',
      spike: 12, port: () => rand(1025, 65000),
      why: () => `Reconstruction error is ${(Math.random() * 3 + 2.5).toFixed(1)} times above the normal range for this device.`,
      feats: [['Outbound bytes per second', .72], ['Inter-arrival time', .55], ['Destination country is new', .43], ['Protocol mix', -.16]]
    },
    rogue: {
      title: 'Unknown device joined', sev: 'low', engine: 'Device inventory', mitre: 'T1200 Hardware additions',
      spike: 0, port: () => 'n/a',
      why: () => 'This MAC address is not in the approved device list.',
      feats: [['MAC not in inventory', .99], ['First time seen', .64]]
    }
  };

  const state = { alerts: 0, blocked: 0, latencies: [], spike: 0, spikeLevel: 0, id: 0 };

  // ---- Alert generation -> sent to the React component as a browser event
  function fireAlert(type) {
    const c = CATALOG[type];
    const jitter = v => Math.round(clamp(v + (Math.random() - .5) * .1, -.99, .99) * 100) / 100;
    const latency = rand(80, 240);
    state.alerts++;
    state.latencies.push(latency);
    if (c.spike) { state.spike = 6; state.spikeLevel = c.spike; }
    window.dispatchEvent(new CustomEvent('ids:alert', {
      detail: {
        id: ++state.id, time: new Date(), title: c.title, sev: c.sev, engine: c.engine, mitre: c.mitre,
        conf: rand(88, 99), src: type === 'rogue' ? lan() : ext(), dst: lan(), port: c.port(),
        why: c.why(), feats: c.feats.map(([n, v]) => [n, jitter(v)]), status: 'open', latency
      }
    }));
  }

  document.querySelectorAll('[data-sim]').forEach(b =>
    b.addEventListener('click', () => fireAlert(b.dataset.sim)));

  // ---- Toast + block events coming from React
  let toastTimer;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
  }
  window.addEventListener('ids:block', e => {
    state.blocked++;
    toast(`Blocked ${e.detail.ip} (simulated firewall rule)`);
  });

  // ---- Live traffic chart
  const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
  const N = 45;
  const inbound = Array(N).fill(30), outbound = Array(N).fill(14);
  const chart = new Chart($('trafficChart'), {
    type: 'line',
    data: {
      labels: Array(N).fill(''),
      datasets: [
        { label: 'Inbound', data: inbound, borderColor: css('--accent'), backgroundColor: css('--accent-soft'), fill: true, tension: .35, pointRadius: 0, borderWidth: 2 },
        { label: 'Outbound', data: outbound, borderColor: css('--muted'), tension: .35, pointRadius: 0, borderWidth: 1.5 }
      ]
    },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      scales: {
        x: { display: false },
        y: { beginAtZero: true, grid: { color: css('--line') }, ticks: { color: css('--muted'), callback: v => v + ' Mbps' } }
      },
      plugins: { legend: { position: 'bottom', labels: { usePointStyle: true, color: css('--muted') } } }
    }
  });

  // ---- One tick per second: move traffic, update numbers, sometimes raise a random alert
  let quiet = rand(6, 10);
  setInterval(() => {
    let i = clamp(inbound[N - 1] + rand(-4, 4), 18, 50);
    const o = clamp(outbound[N - 1] + rand(-2, 2), 8, 24);
    if (state.spike > 0) { i += state.spikeLevel; state.spike--; }
    inbound.push(i); inbound.shift();
    outbound.push(o); outbound.shift();
    chart.update('none');

    $('k-pps').textContent = Math.round(i * 115 + rand(-200, 200)).toLocaleString();
    $('k-flows').textContent = (rand(180, 260) + (state.spike > 0 ? 400 : 0)).toLocaleString();
    $('k-alerts').textContent = state.alerts;
    $('k-blocked').textContent = state.blocked;
    const L = state.latencies;
    $('k-latency').textContent = L.length ? Math.round(L.reduce((a, b) => a + b, 0) / L.length) + ' ms' : '0 ms';

    if (--quiet <= 0) {
      fireAlert(pick(Object.keys(CATALOG)));
      quiet = rand(9, 16);
    }
  }, 1000);

  // first alerts so the screen is never empty at the start of the demo
  setTimeout(() => fireAlert('rogue'), 600);
  setTimeout(() => fireAlert('scan'), 1800);
})();
