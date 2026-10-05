/* FMO 站点页前端（零依赖） */
(function () {
  'use strict';

  var timer = null;

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
    var cls = st.is_self ? 'self' : (st.online ? 'online' : 'offline');
    var pills = '';
    if (st.is_self) pills += '<span class="pill self">本机</span>';
    pills += st.online
      ? '<span class="pill on">在线</span>'
      : '<span class="pill off">离线</span>';
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
    if (st.last_report) {
      meta += '<span>最后上报 <b>' + esc(ago(st.last_report)) + '</b></span>';
    }
    if (!meta && st.last_seen) {
      meta += '<span>抄收于 <b>' + esc(ago(st.last_seen)) + '</b></span>';
    }

    var url = st.entry_url || '';
    var enter = url
      ? '<a class="st-enter" href="' + esc(url) + '" target="_blank" rel="noopener">进入</a>'
      : '<span class="st-enter disabled" title="没有可用地址">不可进入</span>';

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
    $('st-count').textContent = list.length + ' 个站点';
    var src = j.sources || {};
    var bits = [];
    if (src.master_rows) bits.push('总系统登记 ' + src.master_rows + ' 条');
    if (src.mqtt_live) bits.push('MQTT 实时抄收 ' + src.mqtt_live + ' 个');
    if (src.master_db) bits.push('站点库 ' + src.master_db);
    if (src.note) bits.push(src.note);
    $('st-src').textContent = bits.join(' · ');

    if (!list.length) {
      grid.innerHTML = '';
      $('st-empty').classList.remove('hidden');
      return;
    }
    $('st-empty').classList.add('hidden');
    grid.innerHTML = list.map(card).join('');
  }

  function load() {
    fetch('/api/fus/stations').then(function (r) { return r.json(); })
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

  function setAuto(on) {
    if (timer) { clearInterval(timer); timer = null; }
    if (on) timer = setInterval(load, 15000);
  }

  $('st-reload').addEventListener('click', load);
  $('st-auto').addEventListener('change', function () {
    setAuto(this.checked);
  });

  load();
  setAuto(true);
})();
