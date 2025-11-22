class TestDashboard {
  constructor() {
    this.tests = [];
    this.resultsBody = document.querySelector('#resultsTable tbody');
    this.testsBody = document.querySelector('#testsTable tbody');
    this.rawOutput = document.getElementById('rawOutput');
    this.bind();
    this.loadTests();
  }
  bind() {
    document.getElementById('btnRefresh').addEventListener('click', () => this.loadTests());
    document.getElementById('btnRunAll').addEventListener('click', () => this.runAll());
    document.getElementById('btnClear').addEventListener('click', () => this.clearResults());
  }
  setLoading(btn, loading) {
    if (!btn) return;
    if (loading) {
      btn.disabled = true;
      btn.dataset.original = btn.innerHTML;
      btn.innerHTML = '<span class="spinner"></span>';
    } else {
      btn.disabled = false;
      if (btn.dataset.original) btn.innerHTML = btn.dataset.original;
    }
  }
  async loadTests() {
    const btn = document.getElementById('btnRefresh');
    this.setLoading(btn, true);
    try {
      const res = await fetch('/api/tests/list');
      if (!res.ok) throw new Error('Failed to load tests');
      this.tests = await res.json();
      this.renderTests();
    } catch (e) {
      console.error(e);
      alert('Failed loading tests: ' + e.message);
    } finally {
      this.setLoading(btn, false);
    }
  }
  renderTests() {
    this.testsBody.innerHTML = '';
    this.tests.forEach(test => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${test.name}</code></td>
        <td><span class="badge ${test.category}">${test.category}</span></td>
        <td>${test.description}</td>
        <td><button data-test="${test.name}">Run</button></td>
      `;
      tr.querySelector('button').addEventListener('click', (e) => this.runSingle(test.name, e.target));
      this.testsBody.appendChild(tr);
    });
  }
  appendResult(result) {
    const tr = document.createElement('tr');
    tr.className = 'result-row ' + (result.passed ? 'pass' : 'fail');
    tr.innerHTML = `
      <td><code>${result.name}</code></td>
      <td class="${result.passed ? 'status-pass' : 'status-fail'}">${result.passed ? 'PASS' : 'FAIL'}</td>
      <td>${result.duration_ms}</td>
      <td>${result.error ? this.escape(result.error) : ''}</td>
    `;
    this.resultsBody.appendChild(tr);
    this.rawOutput.textContent += `${result.passed ? 'PASS' : 'FAIL'} ${result.name} (${result.duration_ms}ms)${result.error ? ' :: ' + result.error : ''}\n`;
    this.rawOutput.scrollTop = this.rawOutput.scrollHeight;
  }
  clearResults() {
    this.resultsBody.innerHTML = '';
    this.rawOutput.textContent = '';
  }
  async runSingle(name, btn) {
    this.setLoading(btn, true);
    try {
      const res = await fetch(`/api/tests/run?name=${encodeURIComponent(name)}`);
      if (res.status === 404) { alert('Unknown test'); return; }
      if (!res.ok) throw new Error('Run failed');
      const data = await res.json();
      this.appendResult(data.result);
    } catch (e) {
      alert('Error running test: ' + e.message);
    } finally {
      this.setLoading(btn, false);
    }
  }
  async runAll() {
    const btn = document.getElementById('btnRunAll');
    this.setLoading(btn, true);
    try {
      const res = await fetch('/api/tests/run');
      if (!res.ok) throw new Error('Run all failed');
      const data = await res.json();
      data.forEach(r => this.appendResult(r));
    } catch (e) {
      alert('Error running all tests: ' + e.message);
    } finally {
      this.setLoading(btn, false);
    }
  }
  escape(str) { const div = document.createElement('div'); div.textContent = str; return div.innerHTML; }
}

window.addEventListener('DOMContentLoaded', () => new TestDashboard());
