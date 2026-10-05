/* FMO 台站页前端（零依赖）——数据来自 APRS 扫描 */
(function () {
  'use strict';

  var scanned = false;

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
    var cls = st.reachable ? 'self' : (st.alive ? 'online' : 'offline');
    var pills = '';
    if (st.reachable) {
      pills += '<span class="pill on">✓ 能进入</span>';
    } else if (st.reachable === false) {
      pills += '<span class="pill off" style="color:var(--danger);border-color:var(--danger)">✗ 进不去</span>';
    } else {
      pills += '<span class="pill off">未探测</span>';
    }
    if (st.has_cert) pills += '<span class="pill">带证书</span>';
    if (st.country) pills += '<span class="pill">' + esc(st.country) + '</span>';

    var meta = '';
    if (st.online !== null && st.online !== undefined) {
      meta += '<span>在线 <b>' + esc(st.online) + '</b>';
      if (st.total) meta += ' / ' + esc(st.total);
      meta += '</span>';
    }
    if (st.probe_ms) meta += '<span>连接 <b>' + esc(st.probe_ms) + 'ms</b></span>';
    if (st.freq) meta += '<span>频率 <b>' + esc(st.freq) + '</b></span>';
    if (st.cover_km) meta += '<span>覆盖 <b>' + esc(st.cover_km) + ' km</b></span>';
    if (st.last_seen) meta += '<span>听到于 <b>' + esc(ago(st.last_seen)) + '</b></span>';
    if (st.reachable === false && st.probe_error) {
      meta += '<span class="st-lat bad">' + esc(st.probe_error) + '</span>';
    }

    var detail = '';
    if (st.rig) detail += '<span>设备 ' + esc(st.rig) + '</span>';
    if (st.ant) detail += '<span>天线 ' + esc(st.ant) + '</span>';
    if (st.height) detail += '<span>高度 ' + esc(st.height) + '</span>';

    var addr = st.mqtt_addr || st.host || '';
    var enter = st.reachable
      ? '<span class="st-enter copy" data-addr="' + esc(addr) + '" '
        + 'title="点击复制该台站 MQTT 地址">复制地址</span>'
      : '<span class="st-enter disabled">进不去</span>';

    return '<div class="st-card ' + cls + '">' +
      '<div class="st-head">' +
        '<span class="st-name">' + esc(st.name || '(未命名台站)') + '</span>' +
        '<span class="st-cs">' + esc(st.callsign) + '</span>' +
      '</div>' +
      '<div>' + pills + '</div>' +
      '<div class="st-meta">' + meta + '</div>' +
      (detail ? '<div class="st-desc">' + detail + '</div>' : '') +
      '<div class="st-foot">' +
        '<span class="st-url">' + esc(addr || '—') + '</span>' + enter +
      '</div>' +
    '</div>';
  }

  function render(j) {
    var list = j.stations || [];
    var stat = j.stats || {};
    var grid = $('st-grid');

    var enterable = list.filter(function (s) { return s.reachable; }).length;
    $('st-count').textContent = enterable + ' 个可进入';

    var bits = [];
    if (stat.total !== undefined) bits.push('台账累积 ' + stat.total + ' 个台站');
    if (stat.recent_30min !== undefined) {
      bits.push('30 分钟内还在播 ' + stat.recent_30min + ' 个');
    }
    if (stat.online_users) bits.push('合计在线 ' + stat.online_users + ' 人');
    var c = j.collector || {};
    if (c.state) {
      var st_txt = { connected: '持续扫描中', connecting: '连接 APRS 中',
                     error: '重连中', idle: '未启动' }[c.state] || c.state;
      bits.push(st_txt + '（' + (c.host || '') + ':' + (c.port || '')
                + '，已发现 ' + (c.discovered || 0)
                + '，已探测 ' + (c.probed || 0) + '）');
    }
    if (j.only_enterable) bits.push('只显示能进入的（进不去的已隐藏）');
    $('st-src').textContent = bits.join(' · ');

    if (!list.length) {
      grid.innerHTML = '';
      $('st-empty').classList.remove('hidden');
      var total = (stat.total || 0);
      var rootUrl = j.root_url || (location.origin + '/api/ca/root.json?raw=1');
      $('st-empty').innerHTML =
        '<div style="font-size:16px;font-weight:700;color:#e0e6f0;margin-bottom:10px;">'
        + '当前没有「能进入」的台站</div>'
        + '<div style="max-width:820px;margin:0 auto;text-align:left;line-height:2;">'
        + '台账已累积 <b>' + total + '</b> 个台站，但拿本机证书去登录，'
        + '对方 broker 全部回 <code>CONNACK 5（未授权）</code> —— '
        + '<b>说明对方不信任本机根 CA</b>，所以你的 APP 也进不去。<br>'
        + '要让对方放行，把这台服务器的<b>根证书</b>发给对方，'
        + '放进对方的信任目录即可（官方 SAS 是 <code>Trust.RootsDir</code>）：<br>'
        + '<code style="display:block;margin:8px 0;padding:10px;background:#0e1217;'
        + 'border:1px solid var(--line);border-radius:6px;word-break:break-all;">'
        + 'sudo curl -fsS -o /root/.sas/roots/BH6BHG-CA.json "'
        + esc(rootUrl) + '" &amp;&amp; sudo systemctl restart fmo-sas</code>'
        + '对方接种后，回本页点「扫描全部台站」，能进的台站就会出现在这里。'
        + '</div>';
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
      .catch(function (e) { $('st-src').textContent = '加载失败：' + e; });
  }

  function scan() {
    var bar = $('st-scanbar');
    var btn = $('st-scan');
    btn.disabled = true;
    bar.classList.remove('hidden');
    bar.innerHTML = '<span class="st-scanning"></span> 已启动**持续扫描**'
      + '（不限时）：采集器一直听 APRS，发现新台站立刻用本机证书真实登录探测…';

    fetch('/api/fus/stations/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ continuous: true })
    }).then(function (r) { return r.json(); })
      .then(function (j) {
        btn.disabled = false;
        if (!j.ok) { bar.textContent = '启动失败：' + (j.error || '未知错误'); return; }
        var s = j.scan || {};
        bar.textContent = '持续扫描中（不限时）：台账 ' + (s.total || 0)
          + ' 个台站' + (s.swept ? '，已提交 ' + s.swept + ' 个重探' : '')
          + (s.restarted ? '，采集线程已重启' : '')
          + '。本页每 10 秒自动刷新，能进的台站会自动出现。';
        render(j);
      })
      .catch(function (e) {
        btn.disabled = false;
        bar.textContent = '启动失败：' + e;
      });
  }

  $('st-reload').addEventListener('click', function () {
    scanned = false;
    $('st-scanbar').classList.add('hidden');
    load();
  });
  $('st-scan').addEventListener('click', scan);

  // 「复制地址」：点一下把该台站的 MQTT 地址拷走
  document.addEventListener('click', function (ev) {
    var el = ev.target;
    if (!el || !el.classList || !el.classList.contains('copy')) return;
    var addr = el.getAttribute('data-addr') || '';
    if (!addr) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(addr).then(function () {
        var old = el.textContent;
        el.textContent = '已复制';
        setTimeout(function () { el.textContent = old; }, 1200);
      });
    }
  });

  load();
  setInterval(load, 10000);     // 持续扫描：每 10 秒自动刷新台账与能进入的台站
})();
