let allFindings = [];
let sevChart, typeChart;

async function startScan() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) { alert('Please enter a target URL'); return; }

  const checks = [...document.querySelectorAll('.checks-row input:checked')]
    .map(input => input.value);
  if (!checks.length) { alert('Select at least one check type'); return; }

  // UI: disable button and show progress
  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.textContent = '⏳ SCANNING...';

  const progressWrap = document.getElementById('progressWrap');
  const fill = document.getElementById('progressFill');
  const status = document.getElementById('progressStatus');
  progressWrap.classList.add('show');
  document.getElementById('dashboard').classList.remove('show');

  // Animate progress bar
  const steps = [
    [10, 'Resolving target...'],
    [25, 'Crawling page and extracting forms...'],
    [45, 'Running SQL injection tests...'],
    [65, 'Running XSS payload tests...'],
    [80, 'Checking authentication issues...'],
    [92, 'Aggregating results...'],
  ];

  let stepIndex = 0;
  const ticker = setInterval(() => {
    if (stepIndex < steps.length) {
      fill.style.width = steps[stepIndex][0] + '%';
      status.textContent = steps[stepIndex][1];
      stepIndex++;
    }
  }, 700);

  try {
    const response = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, checks })
    });

    const data = await response.json();
    clearInterval(ticker);
    fill.style.width = '100%';
    status.textContent = '✅ Scan complete!';

    setTimeout(() => {
      progressWrap.classList.remove('show');
      renderDashboard(data);
    }, 600);

  } catch (error) {
    clearInterval(ticker);
    status.textContent = `❌ Error: ${error.message}`;
    console.error('Scan failed:', error);
  }

  btn.disabled = false;
  btn.textContent = '▶ SCAN';
}

function renderDashboard(data) {
  const { meta, findings, summary } = data;
  allFindings = findings;

  document.getElementById('dashboard').classList.add('show');

  // Meta bar
  const safe = (str) => {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  };
  document.getElementById('metaBar').innerHTML = `
    <div>TARGET <span>${safe(meta.url)}</span></div>
    <div>SCANNED <span>${safe(meta.timestamp)}</span></div>
    <div>DURATION <span>${safe(meta.duration)}s</span></div>
    <div>ISSUES <span>${summary.total}</span></div>
  `;

  // Animate stat counters
  animateCount('statTotal', summary.total);
  animateCount('statCritical', summary.severity_counts.critical || 0);
  animateCount('statHigh', summary.severity_counts.high || 0);
  animateCount('statRisk', summary.risk_score);

  renderCharts(summary);
  renderFindings(allFindings);

  document.getElementById('dashboard').scrollIntoView({ behavior: 'smooth' });
}

function animateCount(elementId, target) {
  const el = document.getElementById(elementId);
  let current = 0;
  const step = Math.max(1, Math.ceil(target / 30));
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    el.textContent = current;
    if (current >= target) clearInterval(timer);
  }, 40);
}

function renderFindings(list) {
  const container = document.getElementById('findingsList');
  if (!list.length) {
    container.innerHTML = `
      <div class="no-findings">
        <div style="font-size:2.5rem;margin-bottom:.5rem">✅</div>
        No vulnerabilities found for this filter.
      </div>`;
    return;
  }
  container.innerHTML = list.map(f => `
    <div class="finding-row">
      <div class="sev-badge sev-${f.severity}">${f.severity}</div>
      <div>
        <div class="finding-type">${f.type}</div>
        <div class="finding-detail">${f.detail}</div>
        <div class="finding-location">${f.location}</div>
      </div>
      <div class="finding-payload" title="${f.payload}">${f.payload}</div>
    </div>
  `).join('');
}

function filterFindings(severity, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const filtered = severity === 'all'
    ? allFindings
    : allFindings.filter(f => f.severity === severity);
  renderFindings(filtered);
}

function renderCharts(summary) {
  if (sevChart) sevChart.destroy();
  if (typeChart) typeChart.destroy();

  const sc = summary.severity_counts;
  const tc = summary.type_counts;

  Chart.defaults.color = '#4a6070';
  Chart.defaults.font.family = 'Rajdhani';

  // Doughnut chart
  sevChart = new Chart(document.getElementById('sevChart'), {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [sc.critical || 0, sc.high || 0, sc.medium || 0, sc.low || 0],
        backgroundColor: ['#ff4d6d', '#ff8c42', '#f9c74f', '#00f5d4'],
        borderWidth: 0,
        hoverOffset: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: '#c9d1d9', font: { size: 12 } } }
      }
    }
  });

  // Bar chart
  typeChart = new Chart(document.getElementById('typeChart'), {
    type: 'bar',
    data: {
      labels: Object.keys(tc),
      datasets: [{
        data: Object.values(tc),
        backgroundColor: ['#00f5d4', '#ff4d6d', '#f9c74f'],
        borderRadius: 6,
        borderWidth: 0,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#4a6070' }, grid: { display: false } },
        y: { ticks: { color: '#4a6070', stepSize: 1 }, grid: { color: '#1e3a4a' } }
      }
    }
  });
}

// Enter key to scan
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('urlInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') startScan();
  });
});