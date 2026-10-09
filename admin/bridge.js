/* MQTT 互联桥接管理页前端（零依赖）——数据来自 /api/bridge/*（管理口） */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function num(v) {
    var n = Number(v);
    if (!isFinite(n)) n = 0;
    return n.toLocaleString('zh-CN');   // 收发计数动辄上万，加千分位更好读
  }

  /* 「xx 秒前」：last_rx 是 Unix 秒；0 表示从没收到过，直接说清楚 */
  function ago(ts) {
    if (!ts) return '从未收到';
    var d = Math.max(0, Date.now() / 1000 - Number(ts));
    if (d < 60) return Math.round(d) + ' 秒前';
    if (d < 3600) return Math.round(d / 60) + ' 分钟前';
    if (d < 86400) return Math.round(d / 3600) + ' 小时前';
    return Math.round(d / 86400) + ' 天前';
  }

  /* uptime 用「已持续」而不是时间点，因为后端给的就是持续秒数 */
  function dur(sec) {
    sec = Math.max(0, Math.round(Number(sec) || 0));
    if (sec < 60) return sec + ' 秒';
    if (sec < 3600) return Math.floor(sec / 60) + ' 分 ' + (sec % 60) + ' 秒';
    if (sec < 86400) return Math.floor(sec / 3600) + ' 小时 ' + Math.floor((sec % 3600) / 60) + ' 分';
    return Math.floor(sec / 86400) + ' 天 ' + Math.floor((sec % 86400) / 3600) + ' 小时';
  }

  /* 后端 state 是英文枚举，这里只做展示映射，不改变语义 */
  var STATE = {
    connected:  ['已连接', 'ok'],
    connecting: ['连接中', 'mid'],
    error:      ['错误', 'bad'],
    disabled:   ['未加入', '']
  };
  function stateOf(p) {
    return STATE[p && p.state] || [p && p.state ? String(p.state) : '未知', ''];
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
  function post(path, body) {
    return req(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    });
  }
  function fail(where, e) {
    $('br-err').textContent = where + '失败：' + (e && e.message ? e.message : e);
  }
  function clear(where) {
    // 只在提示的就是自己那一类错误时才清，免得把别的操作刚报的错抹掉
    var el = $('br-err');
    if (el.textContent.indexOf(where + '失败') === 0) el.textContent = '';
  }
  function ok(msgEl, msg) {
    clear('添加对端');
    msgEl.textContent = msg;
    setTimeout(function () { if (msgEl.textContent === msg) msgEl.textContent = ''; }, 3000);
  }

  /* ---------------- 总状态 ---------------- */
  function renderTop(j) {
    var on = !!j.enabled;
    var top = $('br-top');
    top.className = 'br-top ' + (on ? 'on' : 'off');
    $('br-state').textContent = on ? '桥接已启用' : '桥接已停用';

    var kv = [];
    kv.push('节点 <b class="mono">' + esc(j.node_name || '未命名') + '</b>'
            + (j.node_id ? '（' + esc(j.node_id) + '）' : ''));
    kv.push('broker <b class="mono">' + esc(j.broker || '—') + '</b>');
    kv.push('主题 ' + (j.topics && j.topics.length
      ? j.topics.map(function (t) { return '<b>' + esc(t) + '</b>'; }).join(' + ') : '—'));
    $('br-node').innerHTML = kv.join('');

    // 只在没有用户交互时同步勾选态，避免和正在点的开关抢焦点
    var en = $('br-enabled');
    if (document.activeElement !== en) en.checked = on;
  }

  /* ---------------- 本机流量 ---------------- */
  function card(k, v) {
    return '<div class="card"><div class="k">' + esc(k) + '</div><div class="v">' + esc(v) + '</div></div>';
  }
  function renderStats(local, peerCount) {
    var l = local || {};
    $('br-stats').innerHTML =
      card('本机已发出', num(l.published)) +
      card('已接收', num(l.rx_frames)) +
      card('去重丢弃', num(l.deduped)) +
      card('对端数量', num(peerCount));
    $('br-stats-src').textContent = '已发出 = 本机向对端发布的帧数；已接收 = 从对端收到的帧数；'
      + '去重丢弃 = 回路里重复到达、已丢弃的帧数。';
  }

  /* ---------------- 对端卡片 ---------------- */
  function peerCard(p) {
    var st = stateOf(p);

    var bits = [];
    bits.push('收到 <b>' + num(p.rx_frames) + '</b> 帧');
    bits.push('发出 <b>' + num(p.tx_frames) + '</b> 帧');
    var rx = ago(p.last_rx);
    var at = p.last_rx
      ? ' title="' + esc(new Date(Number(p.last_rx) * 1000).toLocaleString('zh-CN')) + '"'
      : '';
    bits.push('最近收到 <b' + at + '>' + esc(rx) + '</b>');
    bits.push('重连 <b>' + num(p.reconnects) + '</b> 次');
    if (p.connected && p.uptime) bits.push('已持续 <b>' + esc(dur(p.uptime)) + '</b>');

    return '<div class="br-card ' + esc(p.state || '') + (p.send ? ' sending' : '') +
        '" data-id="' + esc(p.id || '') + '">' +
      '<div class="br-head">' +
        '<span class="br-name">' + esc(p.name || p.id || '(未命名对端)') + '</span>' +
        '<span class="br-host">' + esc((p.host || '—') + ':' + (p.port || 1883)) + '</span>' +
      '</div>' +
      '<div><span class="br-dot ' + st[1] + '"></span> ' +
        '<span class="br-st' + (st[1] ? ' ' + st[1] : '') + '">' + esc(st[0]) + '</span>' +
        (p.enabled ? '' : ' <span class="muted small">（不加入）</span>') +
      '</div>' +
      '<div class="br-meta">' + bits.join('') + '</div>' +
      (p.note ? '<div class="br-note">备注：' + esc(p.note) + '</div>' : '') +
      (p.last_error ? '<div class="br-err">' + esc(p.last_error) + '</div>' : '') +
      '<div class="br-ctl">' +
        '<div class="br-toggles">' +
          '<label class="br-tg' + (p.enabled ? ' on' : '') + '" title="加入＝本机连接对方，接收并播放对方语音">' +
            '<input type="checkbox" data-toggle="enabled" data-id="' + esc(p.id) + '"' +
            (p.enabled ? ' checked' : '') + '> 加入' +
          '</label>' +
          '<label class="br-tg send' + (p.send ? ' on' : '') + '" title="发送本机语音给对方">' +
            '<input type="checkbox" data-toggle="send" data-id="' + esc(p.id) + '"' +
            (p.send ? ' checked' : '') + '> 发送本机语音' +
          '</label>' +
        '</div>' +
        '<button class="btn danger" data-del="' + esc(p.id) + '" style="margin-left:auto">删除</button>' +
      '</div>' +
    '</div>';
  }

  function renderPeers(peers) {
    peers = peers || [];
    $('br-peer-n').textContent = peers.length;
    $('br-count').textContent = peers.length + ' 个对端';
    var grid = $('br-peers');
    if (!peers.length) {
      grid.innerHTML = '';
      $('br-empty').classList.remove('hidden');
      return;
    }
    $('br-empty').classList.add('hidden');
    grid.innerHTML = peers.map(peerCard).join('');
  }

  /* ---------------- 推荐对端 ---------------- */
  function renderCands(list) {
    var box = $('br-cands');
    list = list || [];
    if (!list.length) {
      box.innerHTML = '';
      $('br-cand-msg').textContent = 'APRS 里暂时没有扫到可互联的节点。';
      return;
    }
    $('br-cand-msg').textContent = '共 ' + list.length + ' 个候选，已在列表里的会标注出来。';
    box.innerHTML = list.map(function (c) {
      return '<div class="br-cand' + (c.already ? ' already' : '') + '">' +
        '<span class="br-cn">' + esc(c.name || c.callsign || '未命名节点') + '</span>' +
        '<span class="br-ca">' + esc(c.callsign || '') + '</span>' +
        '<span class="br-host">' + esc(c.mqtt_addr || ((c.host || '') + ':' + (c.port || 1883))) + '</span>' +
        (c.already
          ? '<span class="pill">已在对端列表</span>'
          : '<button class="btn" style="margin-left:auto" data-cand="' + esc(c.callsign || '') + '">添加</button>') +
      '</div>';
    }).join('');
  }

  function loadCands() {
    return req('/api/bridge/candidates')
      .then(function (j) { renderCands(j.candidates); })
      .catch(function (e) {
        // 推荐列表是增值信息，取不到不算页面失败，只在那一行提示
        $('br-cand-msg').textContent = '读取推荐失败：' + (e && e.message ? e.message : e);
      });
  }

  /* ---------------- 轮询 ---------------- */
  var busy = {};          // 正在切换的对端，避免 10 秒轮询把乐观更新刷回去
  var delPending = {};    // 「删除」二次确认的中间态

  function load() {
    return req('/api/bridge/status').then(function (j) {
      renderTop(j);
      renderStats(j.local, (j.peers || []).length);
      var pending = Object.keys(busy).length > 0;
      if (!pending) renderPeers(j.peers);
      clear('读取状态');
    }).catch(function (e) {
      $('br-state').textContent = '读取桥接状态失败';
      fail('读取状态', e);
    });
  }

  /* 切换后立刻重新拉一次，以服务端实际状态为准（本地先乐观更新，点着不卡） */
  function toggle(id, field, value, box) {
    busy[id] = true;
    var card = document.querySelector('.br-card[data-id="' + id.replace(/"/g, '') + '"]');
    var tg = box.closest ? box.closest('.br-tg') : null;
    if (tg) tg.classList.add('busy');
    post('/api/bridge/peers/toggle', { id: id, field: field, value: !!value })
      .catch(function (e) {
        box.checked = !value;                    // 失败就把勾选还原，别让界面说谎
        fail('切换开关', e);
      })
      .then(function () {
        delete busy[id];                         // 先解除保护，后面的拉取才能重建列表
        if (tg) tg.classList.remove('busy');
        if (card) {                              // 拉取回来之前先给个即时反馈
          var on = box.checked;
          if (tg) tg.classList.toggle('on', on);
          if (field === 'send') card.classList.toggle('sending', on);
          if (field === 'enabled') card.classList.toggle('disabled', !on);
        }
        return load();
      });
  }

  function setEnabled(value, box) {
    box.disabled = true;
    post('/api/bridge/config', { enabled: !!value })
      .then(function () { return load(); })
      .catch(function (e) { box.checked = !value; fail('切换桥接总开关', e); })
      .then(function () { box.disabled = false; });
  }

  function addPeer(data, msgEl) {
    return post('/api/bridge/peers', data).then(function () {
      ok(msgEl, '已添加并生效');
      return load();
    }).catch(function (e) {
      msgEl.textContent = '';
      fail('添加对端', e);
    });
  }
  function deletePeer(id, btn) {
    if (!delPending[id]) {
      // 二次确认：不弹窗打断，按钮自己变成确认态 3 秒
      delPending[id] = true;
      btn.dataset.old = btn.textContent;
      btn.textContent = '确认删除？';
      setTimeout(function () {
        if (delPending[id]) { delPending[id] = false; btn.textContent = btn.dataset.old || '删除'; }
      }, 3000);
      return;
    }
    delete delPending[id];
    btn.disabled = true;
    post('/api/bridge/peers/delete', { id: id })
      .then(function () { return load(); })
      .catch(function (e) { btn.disabled = false; fail('删除对端', e); });
  }

  /* ---------------- 事件绑定 ---------------- */
  document.addEventListener('change', function (ev) {
    var el = ev.target;
    if (!el || !el.getAttribute) return;
    var field = el.getAttribute('data-toggle');
    if (!field) return;
    toggle(el.getAttribute('data-id'), field, el.checked, el);
  });

  document.addEventListener('click', function (ev) {
    var el = ev.target;
    if (!el || !el.getAttribute) return;

    var del = el.getAttribute('data-del');
    if (del) { deletePeer(del, el); return; }

    var cand = el.getAttribute('data-cand');
    if (cand) {
      var box = el.closest ? el.closest('.br-cand') : null;
      var hostEl = box ? box.querySelector('.br-host') : null;
      var addr = hostEl ? hostEl.textContent.trim() : '';
      var i = addr.lastIndexOf(':');
      var host = i > 0 ? addr.slice(0, i) : addr;
      var port = i > 0 ? parseInt(addr.slice(i + 1), 10) || 1883 : 1883;
      var nameEl = box ? box.querySelector('.br-cn') : null;
      el.disabled = true;
      el.textContent = '添加中…';
      addPeer({
        id: '', name: nameEl ? nameEl.textContent.trim() : cand,
        host: host, port: port, enabled: true, send: true,
        note: '来自 APRS 推荐（' + cand + '）'
      }, $('br-cand-msg')).then(function () {
        el.disabled = false;
        el.textContent = '添加';
        loadCands();
      });
    }
  });

  $('br-enabled').addEventListener('change', function () { setEnabled(this.checked, this); });

  $('br-reload').addEventListener('click', function () {
    $('br-err').textContent = '';
    load();
    loadCands();
  });
  $('br-cand-reload').addEventListener('click', loadCands);

  $('br-add').addEventListener('click', function () {
    var host = $('br-f-host').value.trim();
    var msg = $('br-add-msg');
    if (!host) { msg.textContent = '主机不能为空'; return; }
    var port = parseInt($('br-f-port').value, 10);
    if (!port || port < 1 || port > 65535) { msg.textContent = '端口要在 1-65535 之间'; return; }
    msg.textContent = '';
    addPeer({
      id: '',
      name: $('br-f-name').value.trim(),
      host: host,
      port: port,
      enabled: $('br-f-enabled').checked,
      send: $('br-f-send').checked,
      note: $('br-f-note').value.trim()
    }, msg).then(function () {
      $('br-f-name').value = '';
      $('br-f-host').value = '';
      $('br-f-note').value = '';
    });
  });

  load();
  loadCands();
  setInterval(load, 10000);        // 桥接状态每 10 秒刷新一次
  setInterval(function () {
    // 表单里正在输入时不要动推荐区，免得把光标下的内容换掉
    var a = document.activeElement;
    if (a && a.closest && a.closest('[data-add-peer]')) return;
    loadCands();
  }, 30000);
})();
