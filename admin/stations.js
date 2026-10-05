/* FMO 站点页前端（零依赖） */
(function () {
  'use strict';

  var timer = null;
  var scanned = false;      // 是否已扫描过（决定是否显示可达状态）

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function ago(ts) {
    if (!ts) return '';
    var d = Math.max(0, Date.now() / 1000 - Number(ts));
    if (d < 60) return Math.round(d) + ' 秒前';
    if (d < 3600) return Math.round(d / 60) + ' 分钟前';
    if (d < 86400) return Math.round(d / 3600) + ' 小时前';
    return Math.round(d / 86400) + ' 天前';
  }

  function card(st) {
    // 扫描过之后，可达性优先决定卡片样式：通过=青/绿，不通=红且灰
    var cls;
    if (scanned) {
      if (st.reachable === false) cls = 'unreachable';
      else if (st.is_self) cls = 'self';
      else cls = 'online';
    } else {
      cls = st.is_self ? 'self' : (st.online ? 'online' : 'offline');
    }

    var pills = '';
    if (st.is_self) pills += '<span class="pill self">本机</span>';
    if (scanned && st.scan) {
      pills += st.reachable
        ? '<span class="pill on">✓ 可以通过</span>'
        : '<span class="pill off" style="color:var(--danger);border-color:var(--danger)">✗ 不通</span>';
    } else {
      pills += st.online
        ? '<span class="pill on">在线</span>'
        : '<span class="pill off">离线</span>';
    }
    if (st.mqtt_live) pills += '<span class="pill">实时抄收</span>';

    var no = (st.station_no === null || st.station_no === undefined)
      ? '' : '<span class="st-no">站号 ' + esc(st.station_no) + '</span>';

    var meta = '';
    if (st.total_users !== null && st.total_users !== undefined) {
      meta += '<span>用户 <b>' + esc(st.total_users) + '</b></span>';
    }
    if (st.online_users) {
      meta += '<span>在线 <b>' + esc(st.online_users) + '</b></span>';
    }
    if (scanned && st.scan && st.scan.ms) {
      meta += '<span>延迟 <b>' + esc(st.scan.ms) + 'ms</b></span>';
    }
    if (st.last_report) {
      meta += '<span>最后上报 <b>' + esc(ago(st.last_report)) + '</b></span>';
    }
    if (st.scan && st.scan.error) {
      meta += '<span class="st-lat bad">' + esc(st.scan.error) + '</span>';
    }

    var url = st.entry_url || '';
    var enter;
    if (scanned && st.reachable === false) {
      enter = '<span class="st-enter disabled" title="探测不通">不通</span>';
    } else if (url) {
      enter = '<a class="st-enter" href="' + esc(url) + '" target="_blank" rel="noopener">进入</a>';
    } else {
      enter = '<span class="st-enter disabled" title="没有可用地址">不可进入</span>';
    }

    return '<div class="st-card ' + cls + '">' +
      '<div class="st-head">' +
        '<span class="st-name">' + esc(st.name || '(未命名站点)') + '</span>' +
        (st.callsign ? '<span class="st-cs">' + esc(st.callsign) + '</span>' : '') +
        no +
      '</div>' +
      '<div class="st-desc">' + (st.desc ? esc(st.desc) : '<span class="muted">（无简介）</span>') + '</div>' +
      '<div>' + pills + '</div>' +
      '<div class="st-meta">' + meta + '</div>' +
      '<div class="st-foot">' +
        '<span class="st-url">' + esc(url || '—') + '</span>' + enter +
      '</div>' +
    '</div>';
  }

  function render(j) {
    var list = j.stations || [];
    var grid = $('st-grid');

    $('st-count').textContent = j.scan
      ? (j.scan.passed + '/' + j.scan.total + ' 通过')
      : (list.length + ' 个站点');

    var src = j.sources || {};
    var bits = [];
    if (src.master_rows) bits.push('总系统登记 ' + src.master_rows + ' 条');
    if (src.mqtt_live) bits.push('MQTT 实时抄收 ' + src.mqtt_live + ' 个');
    if (src.master_db) bits.push('站点库 ' + src.master_db);
    if (src.note) bits.push(src.note);
    $('st-src').textContent = bits.join(' · ') + (scanned ? '　（已扫描）' : '');

    if (!list.length) {
      grid.innerHTML = '';
      $('st-empty').classList.remove('hidden');
      $('st-empty').textContent = scanned
        ? '扫描完成：没有任何台站探测通过。'
        : '还没有抄收到任何站点名片。';
      return;
    }
    $('st-empty').classList.add('hidden');
    grid.innerHTML = list.map(card).join('');
  }

  function load() {
    return fetch('/api/fus/stations').then(function (r) { return r.json(); })
      .then(function (j) {
        if (!j.ok) {
          $('st-src').textContent = '加载失败：' + (j.error || '未知错误');
          return;
        }
        render(j);
      })
      .catch(function (e) {
        $('st-src').textContent = '加载失败：' + e;
      });
  }

  function scan() {
    var bar = $('st-scanbar');
    var btn = $('st-scan');
    btn.disabled = true;
    bar.classList.remove('hidden');
    bar.innerHTML = '<span class="st-scanning"></span> 正在扫描全部台站（逐个探测健康接口）…'
      + '　结果只保留探测通过的站';

    fetch('/api/fus/stations/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ only_reachable: $('st-passed').checked })
    }).then(function (r) { return r.json(); })
      .then(function (j) {
        btn.disabled = false;
        if (!j.ok) {
          bar.textContent = '扫描失败：' + (j.error || '未知错误');
          return;
        }
        scanned = true;
        var s = j.scan || {};
        bar.textContent = '扫描完成：共 ' + s.total + ' 个台站，通过 ' + s.passed
          + ' 个，不通 ' + s.failed + ' 个，用时 ' + s.elapsed_ms + ' ms'
          + (j.only_reachable ? '（只显示通过的）' : '（显示全部）');
        render(j);
      })
      .catch(function (e) {
        btn.disabled = false;
        bar.textContent = '扫描失败：' + e;
      });
  }

  $('st-reload').addEventListener('click', function () {
    scanned = false;
    $('st-scanbar').classList.add('hidden');
    load();
  });
  $('st-scan').addEventListener('click', scan);
  $('st-passed').addEventListener('change', function () {
    if (scanned) scan();     // 切筛选时按新条件重扫（结果一致，只是是否保留不通的）
  });

  load();
})();
