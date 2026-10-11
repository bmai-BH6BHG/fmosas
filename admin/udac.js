/* UDAC 管理页前端（零依赖）——数据来自 /api/udac/*（管理口）
 *
 * 页面结构 = 需求的 udac-admin-ui：信任分布仪表盘、桥接健康/音质、
 * 台站信任排行、决策审计、策略编辑器（版本/灰度/回滚/仿真）、事件日志。
 * 所有写操作（发布/转正/回滚/重算）都有二次确认。
 */
(function () {
  'use strict';

  var STATUS_MS = 10000;   // 状态/排行每 10 秒刷新
  var DEC_MS = 15000;      // 决策/事件每 15 秒刷新
  var timer = null;

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function ago(ts) {
    if (!ts) return '—';
    var d = Math.max(0, Date.now() / 1000 - Number(ts));
    if (d < 60) return Math.round(d) + ' 秒前';
    if (d < 3600) return Math.round(d / 60) + ' 分钟前';
    if (d < 86400) return Math.round(d / 3600) + ' 小时前';
    return Math.round(d / 86400) + ' 天前';
  }

  function hhmm(ts) {
    if (!ts) return '—';
    var d = new Date(Number(ts) * 1000);
    function p(n) { return (n < 10 ? '0' : '') + n; }
    return p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
           p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
  }

  function req(path, opts) {
    return fetch(path, opts).then(function (r) {
      return r.text().then(function (t) {
        var j;
        try { j = JSON.parse(t); } catch (e) { throw new Error('服务端返回的不是 JSON'); }
        if (!j.ok) throw new Error(j.error || ('HTTP ' + r.status));
        return j;
      });
    });
  }
  function get(path) { return req(path); }
  function post(path, body) {
    return req(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    });
  }

  function toast(msg, ok) {
    var t = $('ud-toast');
    if (!t) {
      t = document.createElement('div');
      t.id = 'ud-toast';
      t.style.cssText = 'position:fixed;right:18px;bottom:18px;z-index:99;' +
        'padding:10px 16px;border-radius:8px;font-size:13px;max-width:420px;' +
        'box-shadow:0 8px 30px #0008;line-height:1.6;';
      document.body.appendChild(t);
    }
    t.style.background = ok === false ? '#7f1d1d' : '#134e2f';
    t.style.color = '#fff';
    t.textContent = msg;
    t.style.display = 'block';
    clearTimeout(t._h);
    t._h = setTimeout(function () { t.style.display = 'none'; }, 3500);
  }

  var LEVEL_CN = { normal: '正常', watch: '观察', alert: '警戒', danger: '危险' };
  function levelPill(lv) {
    var cn = LEVEL_CN[lv] || lv || '—';
    return '<span class="pill ' + esc(lv || '') + '">' + esc(cn) + '</span>';
  }
  function actionPill(a) {
    var CN = { allow: '允许', rate_limit: '限流', degrade: '降权', step_up: '二次认证',
               deny: '拒绝', disconnect: '断连', quarantine: '隔离', by_trust_score: '按信任分' };
    return '<span class="pill ' + esc(a || '') + '">' + esc(CN[a] || a || '—') + '</span>';
  }

  /* ---------------- 状态 + 桥接健康 ---------------- */
  function loadStatus() {
    get('/api/udac/status').then(function (j) {
      var d = j.trust_dist || {};
      $('ud-n-normal').textContent = d.normal || 0;
      $('ud-n-watch').textContent = d.watch || 0;
      $('ud-n-alert').textContent = d.alert || 0;
      $('ud-n-danger').textContent = d.danger || 0;
      var total = (d.normal || 0) + (d.watch || 0) + (d.alert || 0) + (d.danger || 0);
      ['normal', 'watch', 'alert', 'danger'].forEach(function (k) {
        var pct = total ? Math.round((d[k] || 0) / total * 100) : 0;
        $('ud-bar-' + k).style.width = pct + '%';
      });
      $('ud-dist-leg').innerHTML =
        '<span><i class="dot normal"></i>正常 <b>' + (d.normal || 0) + '</b></span>' +
        '<span><i class="dot watch"></i>观察 <b>' + (d.watch || 0) + '</b></span>' +
        '<span><i class="dot alert"></i>警戒 <b>' + (d.alert || 0) + '</b></span>' +
        '<span><i class="dot danger"></i>危险 <b>' + (d.danger || 0) + '</b></span>' +
        '<span>决策总数 <b>' + (j.decisions_count || 0) + '</b></span>' +
        '<span>P99 <b>' + (j.p99_ms || 0) + 'ms</b>' +
        (j.p99_ms > 50 ? '（超目标 50ms）' : '（目标 <50ms ✓）') + '</span>';

      $('ud-p99').textContent = 'P99 ' + (j.p99_ms || 0) + 'ms';
      $('ud-ver').textContent = '策略 v' + (j.policy_version || '—') +
        (j.policy_status === 'grayscale' ? '(灰度)' : '');

      var cur = j.policy_definition || {};
      $('ud-cur-desc').textContent = 'v' + (j.policy_version || '—') + ' ' +
        (cur.name || '-') + ' · effect=' + (cur.effect || '-') +
        ' · scope=' + (cur.scope || 'local');
      $('ud-cur-def').textContent = JSON.stringify(cur, null, 2);

      // 桥接健康与音质
      var b = j.bridge || {};
      var h = b.health || {}, a = b.audio || {};
      var kv;
      if (!b.enabled) {
        kv = '<span>桥接未启用 —— 健康度/音质维度不参与信任评分</span>';
      } else {
        kv =
          '<span>RTT <b>' + (h.local_rtt_ms != null ? h.local_rtt_ms : '—') + 'ms</b></span>' +
          '<span>丢包 <b>' + ((h.packet_loss_rate || 0) * 100).toFixed(2) + '%</b></span>' +
          '<span>抖动 <b>' + (h.jitter_ms != null ? h.jitter_ms : '—') + 'ms</b>' +
          (Number(h.jitter_ms) > 30 ? '（超标）' : '（目标 <30ms ✓）') + '</span>' +
          '<span>重连 <b>' + (h.reconnects_total || 0) + '</b> 次</span>' +
          '<span>MOS <b>' + (a.mos_estimate != null ? a.mos_estimate : '—') + '</b>' +
          (a.mos_estimate != null && Number(a.mos_estimate) < 3.5 ? '（低于 3.5）' : '（目标 ≥3.5 ✓）') + '</span>' +
          '<span>抖动缓冲 <b>' + (a.jitter_buffer_ms || 0) + 'ms</b></span>' +
          '<span>编解码 <b class="mono">' + esc(a.codec || 'unknown') + '</b></span>' +
          '<span>队列 <b>' + (h.queue_depth || 0) + '</b></span>';
      }
      $('ud-bridge').innerHTML = kv;

      if (j.last_fullscan) {
        var lp = j.last_fullscan.payload || {};
        $('ud-bridge').innerHTML +=
          '<span>最近全量扫描联动 <b>' + esc(lp.scan_id || '-') + '</b>（' +
          esc(lp.station_count || 0) + ' 台站 / ' + ago(j.last_fullscan.ts) + '）</span>';
      }
    }).catch(function (e) {
      $('ud-bridge').innerHTML = '<span style="color:var(--danger)">UDAC 状态读取失败: ' +
        esc(e.message) + '</span>';
    });
  }

  /* ---------------- 信任排行 ---------------- */
  function loadRanking() {
    get('/api/udac/ranking?limit=50').then(function (j) {
      var rows = j.ranking || [];
      if (!rows.length) {
        $('ud-rank').innerHTML = '<tr><td colspan="5" class="empty">' +
          '暂无台站信任数据 —— 认证事件积累后自动生成，也可点「重算全量」</td></tr>';
        return;
      }
      $('ud-rank').innerHTML = rows.map(function (r, i) {
        return '<tr><td>' + (i + 1) + '</td>' +
          '<td class="mono">' + esc(r.callsign) + '</td>' +
          '<td><b>' + Number(r.score).toFixed(1) + '</b></td>' +
          '<td>' + levelPill(r.level) + '</td>' +
          '<td>' + ago(r.updated_at) + '</td></tr>';
      }).join('');
    }).catch(function (e) {
      $('ud-rank').innerHTML = '<tr><td colspan="5" class="empty">排行读取失败: ' +
        esc(e.message) + '</td></tr>';
    });
  }

  /* ---------------- 决策审计 ---------------- */
  function loadDecisions() {
    get('/api/udac/decisions?limit=50').then(function (j) {
      var rows = j.decisions || [];
      if (!rows.length) {
        $('ud-dec').innerHTML = '<tr><td colspan="7" class="empty">暂无决策记录 —— /auth 认证通过后即产生</td></tr>';
        return;
      }
      $('ud-dec').innerHTML = rows.map(function (r) {
        var reasons = (r.reasons || []);
        // 桥接直通：不评分、不受策略门控（用户要求：MQTT 桥接是直接通过的）
        var ex = !!r.exempt;
        var passBadge = ex
          ? ' <span title="MQTT 桥接：不评分、不受策略门控与 fail-closed 影响，直接通过"'
            + ' style="font-size:11px;padding:1px 6px;border-radius:6px;'
            + 'background:rgba(16,185,129,.15);color:#10b981;">直通</span>'
          : '';
        var scoreCell = ex
          ? '<span style="color:var(--muted)">不评分</span>'
          : '<b>' + Number(r.score || 0).toFixed(1) + '</b> ' + levelPill(r.level);
        return '<tr>' +
          '<td>' + hhmm(r.ts) + '</td>' +
          '<td class="mono">' + esc(r.callsign || '-') + '</td>' +
          '<td>' + actionPill(r.effect) + passBadge + '</td>' +
          '<td>' + scoreCell + '</td>' +
          '<td>' + Number(r.latency_ms || 0).toFixed(1) + 'ms</td>' +
          '<td>' + (r.policy_version != null ? 'v' + esc(r.policy_version) : '—') + '</td>' +
          '<td style="white-space:normal;min-width:220px;color:var(--muted)">' +
            esc(reasons.slice(0, 3).join('；')) + '</td></tr>';
      }).join('');
    }).catch(function (e) {
      $('ud-dec').innerHTML = '<tr><td colspan="7" class="empty">决策读取失败: ' +
        esc(e.message) + '</td></tr>';
    });
  }

  /* ---------------- 策略版本 ---------------- */
  function loadPolicy() {
    get('/api/udac/policy').then(function (j) {
      var vs = j.versions || [];
      if (!vs.length) {
        $('ud-p-vers').innerHTML = '<tr><td colspan="7" class="empty">—</td></tr>';
        return;
      }
      $('ud-p-vers').innerHTML = vs.map(function (v) {
        var ops = '';
        if (v.status !== 'active') {
          ops += '<button class="btn ghost" onclick="UDAC.promote(' + v.version + ')">转正</button> ';
        }
        ops += '<button class="btn ghost" onclick="UDAC.rollback(' + v.version + ')">回滚到此版</button>';
        return '<tr>' +
          '<td><b>v' + v.version + '</b></td>' +
          '<td><span class="pill ' + esc(v.status) + '">' + esc(v.status) + '</span></td>' +
          '<td>' + (v.gray_percent || 0) + '%</td>' +
          '<td>' + esc(v.created_by || '-') + '</td>' +
          '<td>' + hhmm(v.created_at) + '</td>' +
          '<td style="white-space:normal;min-width:140px;color:var(--muted)">' +
            esc(v.note || (v.definition && v.definition.name) || '-') + '</td>' +
          '<td>' + ops + '</td></tr>';
      }).join('');
    }).catch(function (e) {
      $('ud-p-vers').innerHTML = '<tr><td colspan="7" class="empty">策略读取失败: ' +
        esc(e.message) + '</td></tr>';
    });
  }

  function publish() {
    var def;
    try {
      def = JSON.parse($('ud-p-def').value);
    } catch (e) {
      toast('策略定义不是合法 JSON: ' + e.message, false);
      return;
    }
    var gray = Number($('ud-p-gray').value || 0);
    var note = $('ud-p-note').value.trim();
    if (!confirm('发布新策略版本？（灰度 ' + gray + '%）\n\n灰度命中呼号立即按新策略决策；\n转正前随时可回滚。')) return;
    post('/api/udac/policy', { definition: def, gray_percent: gray, note: note })
      .then(function (j) {
        toast('已发布策略 v' + j.version + (gray > 0 ? '（灰度 ' + gray + '%）' : ''), true);
        loadPolicy(); loadStatus();
      })
      .catch(function (e) { toast('发布失败: ' + e.message, false); });
  }

  function simulate() {
    var cs = $('ud-s-cs').value.trim();
    var score = Number($('ud-s-score').value || 0);
    var ver = $('ud-s-ver').value ? Number($('ud-s-ver').value) : null;
    post('/api/udac/policy/simulate', {
      callsign: cs, trust_score: score, version: ver,
      action: 'mqtt.connect'
    }).then(function (j) {
      var out = {
        命中策略: j.simulate.matched_policy || '（内置信任门控）',
        策略版本: j.simulate.matched_version != null ? ('v' + j.simulate.matched_version) : '—',
        灰度命中: j.simulate.gray_hit ? '是' : '否',
        决策效果: j.simulate.effect,
        匹配原因: j.simulate.reason,
        该呼号实时信任分: j.demo_trust ? j.demo_trust.score : '（未填呼号）'
      };
      var el = $('ud-s-out');
      el.style.display = 'block';
      el.textContent = JSON.stringify(out, null, 2);
    }).catch(function (e) { toast('仿真失败: ' + e.message, false); });
  }

  /* ---------------- 事件日志 ---------------- */
  function loadEvents() {
    get('/api/udac/events?limit=60').then(function (j) {
      var rows = j.events || [];
      if (!rows.length) {
        $('ud-ev').innerHTML = '<tr><td colspan="3" class="empty">暂无事件</td></tr>';
        return;
      }
      $('ud-ev').innerHTML = rows.map(function (r) {
        var isScan = r.type === 'udac.cert.fullscan.triggered';
        return '<tr><td>' + hhmm(r.ts) + '</td>' +
          '<td class="ev-type ' + (isScan ? 'ev-scan' : '') + '">' + esc(r.type) + '</td>' +
          '<td style="white-space:normal;min-width:260px;color:var(--muted)">' +
            esc(JSON.stringify(r.payload)) + '</td></tr>';
      }).join('');
    }).catch(function (e) {
      $('ud-ev').innerHTML = '<tr><td colspan="3" class="empty">事件读取失败: ' +
        esc(e.message) + '</td></tr>';
    });
  }

  /* ---------------- 写操作（都有二次确认） ---------------- */
  function rescan() {
    if (!confirm('重算全部台站信任分快照？（数据量大时可能需要几秒）')) return;
    toast('正在重算…', true);
    post('/api/udac/rescan', {}).then(function (j) {
      toast('已重算 ' + j.count + ' 条信任分', true);
      loadRanking(); loadStatus();
    }).catch(function (e) { toast('重算失败: ' + e.message, false); });
  }
  function promote(v) {
    if (!confirm('把策略 v' + v + ' 转正为生效版本？\n\n当前生效版本将转为 deprecated。')) return;
    post('/api/udac/policy/promote', { version: v }).then(function () {
      toast('策略 v' + v + ' 已转正', true);
      loadPolicy(); loadStatus();
    }).catch(function (e) { toast('转正失败: ' + e.message, false); });
  }
  function rollback(v) {
    if (!confirm('回滚到策略 v' + v + '？\n\n之后发布的所有版本将全部失效（deprecated）。')) return;
    post('/api/udac/policy/rollback', { version: v }).then(function () {
      toast('已回滚到 v' + v, true);
      loadPolicy(); loadStatus();
    }).catch(function (e) { toast('回滚失败: ' + e.message, false); });
  }

  /* ---------------- 启动 ---------------- */
  function loadAll() { loadStatus(); loadRanking(); loadDecisions(); loadPolicy(); loadEvents(); }

  $('ud-reload').addEventListener('click', loadAll);
  $('ud-rescan').addEventListener('click', rescan);
  $('ud-p-publish').addEventListener('click', publish);
  $('ud-p-simulate').addEventListener('click', simulate);
  $('ud-s-run').addEventListener('click', simulate);
  window.UDAC = { promote: promote, rollback: rollback };   // 内联按钮

  loadAll();
  timer = setInterval(loadAll, STATUS_MS);
  window.addEventListener('beforeunload', function () { if (timer) clearInterval(timer); });
})();
