/* MQTT 互联集群管理页前端（零依赖）——数据来自 /api/bridge/*（管理口）
 *
 * 模型（用户明确要求的那一个）：
 *   服务器级只有一个开关 —— 加入集群 / 退出集群。加入后，所有已加入集群的
 *   服务器之间**自动全互通**，用户不需要也不应该去逐个挑服务器。
 *
 * 所以这个页面刻意**不提供**任何「逐对端」的开关：
 *   * 没有「加入这个对端」勾选框；
 *   * 没有「发送本机语音给这个对端」勾选框（拉取模型下后端也不再逐对端发送，
 *     tx_frames 恒为 0，所以界面上不出现「发出」这种会误导的指标）；
 *   * 成员列表只读，只有「手动补充」进来的地址才有删除按钮（名册里的删不掉，
 *     后端会重新发现，给按钮反而是骗人）。
 */
(function () {
  'use strict';

  var STATUS_MS = 10000;   // 集群状态每 10 秒刷新
  var CAND_MS = 30000;     // 集群名册预览每 30 秒刷新（名册来自总服务器）

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

  /* 后端 state 是英文枚举，这里只做展示映射，不改变语义。
     ★ connected 只表示「已连上、还在等对方的名片」，不等于已互通 ——
       真正互通看 member，所以卡片上 member 会盖掉这里的文案。 */
  var STATE = {
    connected:  ['已连接，等待集群名片', 'mid'],
    connecting: ['连接中…', 'mid'],
    error:      ['连不上', 'bad'],
    not_member: ['对方未加入集群', 'off'],
    disabled:   ['本机未加入集群', 'off'],
    stopped:    ['连接已断开', 'off']
  };
  function stateOf(p) {
    var st = STATE[p && p.state];
    if (st) return st;
    return [p && p.state ? String(p.state) : '未知', 'off'];
  }

  /* 本机 broker 连接状态：它坏了的话「已加入集群」只是名义上的 */
  var LOCAL = {
    connected: '已连接', connecting: '连接中',
    disabled: '未加入集群', error: '连接失败', stopped: '已断开'
  };

  function req(path, opts) {
    return fetch(path, opts).then(function (r) {
      return r.text().then(function (t) {
        var j;
        try { j = JSON.parse(t); } catch (e) { throw new Error('服务端返回的不是 JSON'); }
        if (!j.ok) {
          // ★ 把整个失败响应挂在错误上：否则调用方只拿到一句 error 文本，
          //   像 tried（每个地址各自的失败原因）这种排查信息就丢了。
          var err = new Error(j.error || ('HTTP ' + r.status));
          err.payload = j;
          throw err;
        }
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
    msgEl.textContent = msg;
    setTimeout(function () { if (msgEl.textContent === msg) msgEl.textContent = ''; }, 3000);
  }

  /* ---------------- 集群主控区（那一个开关） ---------------- */
  var busyJoin = false;    // 开关请求在飞：别让 10 秒轮询把按钮文案刷回旧状态
  var busyPub = false;     // 对外发送开关同理
  var curEnabled = false;  // 最近一次服务端确认的「加没加入」，点按钮时按它取反

  function renderTop(j) {
    var on = !!j.enabled;
    curEnabled = on;
    $('br-top').className = 'br-top ' + (on ? 'on' : 'off');
    $('br-state').textContent = on
      ? '已加入集群 · 与所有成员自动互通'
      : '未加入集群 · 暂不与其他服务器互联';

    var kv = [];
    kv.push('本机节点 <b class="mono">' + esc(j.node_name || '未命名') + '</b>'
            + (j.node_id ? '（' + esc(j.node_id) + '）' : ''));
    kv.push('broker <b class="mono">' + esc(j.broker || '—') + '</b>');
    kv.push('集群频道 ' + (j.topics && j.topics.length
      ? j.topics.map(function (t) { return '<b>' + esc(t) + '</b>'; }).join(' + ') : '—'));
    $('br-node').innerHTML = kv.join('');

    var ls = LOCAL[j.local_state] || (j.local_state ? String(j.local_state) : '未知');
    $('br-local').innerHTML = '本机 broker 连接：<b>' + esc(ls) + '</b>'
      + (j.local_connected ? '（本机语音可收发）' : '');

    // 所属集群（互联分组）：只有同集群的服务器之间才会互通
    var cur = j.cluster || j.default_cluster || '主集群';
    if ($('br-cluster-cur')) $('br-cluster-cur').textContent = cur;

    var le = $('br-local-err');
    if (j.local_error) {
      le.textContent = '本机 broker：' + j.local_error;
      le.classList.remove('hidden');
    } else {
      le.textContent = '';
      le.classList.add('hidden');
    }

    var btn = $('br-join');
    if (!busyJoin) {
      btn.textContent = on ? '退出集群' : '加入集群';
      btn.className = 'btn br-join ' + (on ? 'danger' : 'primary');
      btn.title = on
        ? '退出后本机不再与其他服务器互通语音（不影响别人的互联）'
        : '加入后自动与其他已加入的服务器互通语音';
    }
    if (!busyPub) {
      $('br-pub').checked = !!j.publish_local;
      $('br-pub-wrap').className = 'br-tg' + (j.publish_local ? ' on' : '');
    }
  }

  /* ---------------- 运行统计 ---------------- */
  function card(k, v, cls) {
    return '<div class="card"><div class="k">' + esc(k) + '</div>'
      + '<div class="v' + (cls ? ' ' + cls : '') + '">' + esc(v) + '</div></div>';
  }
  function renderStats(j) {
    var l = j.local || {};
    $('br-stats').innerHTML =
      card('已加入状态', j.enabled ? '已加入' : '未加入', j.enabled ? 'ok' : '') +
      card('集群成员数', num(j.member_count)) +
      card('本机已发出', num(l.published)) +
      card('已接收（互联）', num(l.rx_frames)) +
      card('去重丢弃', num(l.deduped));
    $('br-stats-src').textContent = '已加入状态 = 本机有没有加入集群；集群成员数 = 已确认加入集群的服务器数；'
      + '本机已发出 = 本机放到桥接主题上供成员拉取的帧数；已接收（互联）= 从集群成员收到的帧数；'
      + '去重丢弃 = 重复到达、已丢弃的帧数。';
  }

  /* ---------------- 成员列表（只读为主） ---------------- */
  var openMore = {};       // 记住哪些卡片的「详情」是展开的，刷新后不塌回去
  var delPending = {};     // 「删除」二次确认的中间态
  var holdRender = false;  // 有删除确认/请求在飞时不重建卡片，否则按钮状态会被轮询刷掉

  function counts(j) {
    var list = j.peers || [];
    var m = (typeof j.member_count === 'number')
      ? j.member_count
      : list.filter(function (p) { return p.member; }).length;
    $('br-count').textContent = '集群成员 ' + num(m) + ' 个';
    $('br-member-n').textContent = num(m);
    $('br-sum').textContent = '本机已发现 ' + num(list.length) + ' 个候选，其中 '
      + num(m) + ' 个已加入集群。';
    return m;
  }

  function memberCard(p) {
    var id = p.id || '';
    var st = stateOf(p);

    var badges = [];
    if (p.member) {
      badges.push('<span class="br-pill ok">✓ 已在集群</span>');
    } else {
      badges.push('<span class="br-pill ' + st[1] + '">' + esc(st[0]) + '</span>');
    }
    // 来源用徽章说明：提醒用户「这张卡片是自动来的，不能删」
    badges.push(p.manual
      ? '<span class="br-pill info">手动补充</span>'
      : '<span class="br-pill">' + esc(p.note || '总服务器名册') + '</span>');

    var meta = [];
    meta.push('<span>收到 <b>' + num(p.rx_frames) + '</b> 帧</span>');
    var at = p.last_rx
      ? ' title="' + esc(new Date(Number(p.last_rx) * 1000).toLocaleString('zh-CN')) + '"'
      : '';
    meta.push('<span>最近收到 <b' + at + '>' + esc(ago(p.last_rx)) + '</b></span>');

    var more = [];
    more.push('<span>重连 <b>' + num(p.reconnects) + '</b> 次</span>');
    if (p.connected && p.uptime) {
      more.push('<span>本次连接已持续 <b>' + esc(dur(p.uptime)) + '</b></span>');
    }
    if (!p.member && p.state === 'not_member') {
      more.push('<span class="muted">对方没加入集群，稍后会自动重试</span>');
    }

    return '<div class="br-card ' + esc(p.state || '') + (p.member ? ' member' : '')
        + '" data-id="' + esc(id) + '">' +
      '<div class="br-head">' +
        '<span class="br-name">' + esc(p.name || id || '(未命名候选)') + '</span>' +
        '<span class="br-host">' + esc((p.host || '—') + ':' + (p.port || 1883)) + '</span>' +
      '</div>' +
      '<div class="br-badges">' + badges.join('') + '</div>' +
      '<div class="br-meta">' + meta.join('') + '</div>' +
      (p.remote_id
        ? '<div class="br-note">对端节点标识 <b class="mono">' + esc(p.remote_id) + '</b>'
          + (p.member
              ? (p.verified
                  ? ' <span class="br-ok">✓ 已与总服务器名册核对一致</span>'
                  : ' <span class="br-warn">未核对'
                    + (p.expect_id ? '（名册登记为 ' + esc(p.expect_id) + '）' : '（名册里没有此站点）')
                    + '</span>')
              : '')
          + '</div>'
        : '') +
      (p.last_error ? '<div class="br-err">' + esc(p.last_error) + '</div>' : '') +
      '<details class="br-more"' + (openMore[id] ? ' open' : '') + '>' +
        '<summary>详情</summary>' +
        '<div class="br-meta">' + more.join('') + '</div>' +
        (p.manual && p.note ? '<div class="br-note">备注：' + esc(p.note) + '</div>' : '') +
      '</details>' +
      (p.manual
        ? '<div class="br-ctl">'
          + '<button class="btn danger" data-del="' + esc(id) + '">删除</button>'
          + '<span class="muted small">只删这条手工补充的地址</span>'
          + '</div>'
        : '') +
    '</div>';
  }

  /* 未加入集群时，文案由上面的 #br-offline 提示条负责，空状态框不再重复说一遍 */
  function emptyHtml() {
    return '<div class="br-eh">还没发现其他 FUS 系统</div><div>'
      + '确保对方也加入了集群；总服务器名册需要对方上报后才会出现。</div>';
  }

  function renderMembers(j) {
    counts(j);
    var list = j.peers || [];
    var on = !!j.enabled;
    $('br-offline').classList.toggle('hidden', on);
    var grid = $('br-peers');
    grid.classList.toggle('off', !on);       // 未加入集群：列表置灰，别看着像在互通
    if (!on) {
      // 后端在未加入时不会去连任何人（peers 为空），这里只负责把残留卡片置灰
      grid.innerHTML = list.map(memberCard).join('');
      $('br-empty').classList.add('hidden');
      return;
    }
    if (!list.length) {
      grid.innerHTML = '';
      $('br-empty').innerHTML = emptyHtml();
      $('br-empty').classList.remove('hidden');
      return;
    }
    $('br-empty').classList.add('hidden');
    grid.innerHTML = list.map(memberCard).join('');
  }

  /* ---------------- 集群名册预览（只读，来自总服务器） ---------------- */
  function renderCands(list) {
    var box = $('br-cands');
    list = list || [];
    if (!list.length) {
      box.innerHTML = '';
      $('br-cand-msg').textContent =
        '总服务器名册里还没有其他 FUS 分系统（或暂时拉不到名册，稍后自动再看）。';
      return;
    }
    var joined = list.filter(function (c) { return c.already; }).length;
    var offline = list.filter(function (c) { return c.online === false; }).length;
    $('br-cand-msg').textContent = '总服务器名册共 ' + num(list.length) + ' 台 FUS 分系统'
      + (joined ? '，其中 ' + num(joined) + ' 台已在互联' : '')
      + (offline ? '，' + num(offline) + ' 台离线' : '')
      + '。加入集群后自动互联，无需手工操作。';
    box.innerHTML = list.map(function (c) {
      return '<div class="br-cand' + (c.already ? ' already' : '') + '">' +
        '<span class="br-cn">' + esc(c.name || c.subsystem_id || '未命名分系统') + '</span>' +
        (c.subsystem_id ? '<span class="br-ca">' + esc(c.subsystem_id) + '</span>' : '') +
        '<span class="br-host">'
          + esc(c.mqtt_addr || ((c.host || '') + ':' + (c.port || 1883))) + '</span>' +
        (c.online === false ? '<span class="br-pill off">离线</span>' : '') +
        (c.already ? '<span class="br-pill ok">已在互联</span>' : '') +
      '</div>';
    }).join('');
  }

  function loadCands() {
    return req('/api/bridge/candidates')
      .then(function (j) { renderCands(j.candidates); })
      .catch(function (e) {
        // 预览是增值信息，取不到不算页面失败，只在那一行提示
        $('br-cand-msg').textContent = '读取集群名册失败：' + (e && e.message ? e.message : e);
      });
  }

  /* ---------------- 轮询 ---------------- */
  function load() {
    return req('/api/bridge/status').then(function (j) {
      renderTop(j);
      renderStats(j);
      // 删除二次确认期间只更新计数，不重建卡片（否则「确认删除？」会被刷掉）
      if (holdRender) counts(j); else renderMembers(j);
      clear('读取状态');
    }).catch(function (e) {
      $('br-state').textContent = '读取集群状态失败';
      fail('读取状态', e);
    });
  }

  /* ---------------- 操作 ---------------- */
  /* 加入 / 退出集群：全页唯一的开关，成功后立刻重新拉状态（以服务端为准） */
  function setEnabled(value, btn) {
    busyJoin = true;
    btn.disabled = true;
    var old = btn.textContent;
    btn.textContent = value ? '正在加入集群…' : '正在退出集群…';
    post('/api/bridge/config', { enabled: !!value })
      .catch(function (e) {
        fail(value ? '加入集群' : '退出集群', e);
        btn.textContent = old;               // 失败就还原，别让界面说谎
        return null;
      })
      .then(function () {
        busyJoin = false;
        btn.disabled = false;
        return load();
      });
  }

  /* 次级开关：本机语音要不要放出去给成员听 */
  function setPublish(value, box) {
    busyPub = true;
    box.disabled = true;
    post('/api/bridge/config', { publish_local: !!value })
      .catch(function (e) {
        fail('切换对外发送', e);
        return null;
      })
      .then(function () {
        busyPub = false;
        box.disabled = false;
        return load();
      });
  }

  function addPeer(data, msgEl) {
    return post('/api/bridge/peers', data).then(function () {
      ok(msgEl, '已补充，加入集群时会去互联');
      return load();
    }).catch(function (e) {
      msgEl.textContent = '';
      fail('手动补充', e);
    });
  }

  /* 删除：只针对手动补充的条目。二次确认不弹窗打断，按钮自己变成确认态 3 秒 */
  function deletePeer(id, btn) {
    if (!delPending[id]) {
      delPending[id] = true;
      holdRender = true;
      btn.dataset.old = btn.textContent;
      btn.textContent = '确认删除？';
      setTimeout(function () {
        if (delPending[id]) {
          delPending[id] = false;
          holdRender = Object.keys(delPending).length > 0;
          if (document.body.contains(btn)) btn.textContent = btn.dataset.old || '删除';
        }
      }, 3000);
      return;
    }
    delete delPending[id];
    holdRender = Object.keys(delPending).length > 0;
    btn.disabled = true;
    btn.textContent = '删除中…';
    post('/api/bridge/peers/delete', { id: id })
      .then(function () { return load(); })
      .catch(function (e) {
        btn.disabled = false;
        btn.textContent = '删除';
        fail('删除候选', e);
      });
  }

  /* ---------------- 所属集群（互联分组） ----------------
   * 集群在**总系统**上创建（总系统 → 集群管理）；这里只能从已有集群里选一个。
   * 选择会写入本机配置，并立刻上报总系统 —— 总系统的名册按集群过滤，
   * 于是互联自动被限定在同集群内。原本那套全局互联保留为「主集群」。
   */
  var clusterBusy = false;

  function loadClusters() {
    var sel = $('br-cluster-sel');
    var msg = $('br-cluster-msg');
    if (!sel) return;
    return req('/api/bridge/clusters').then(function (d) {
      var list = d.clusters || [];
      var cur = d.current || d.default || '主集群';
      if (msg) {
        var why = d.error || '未知';
        if (d.tried && d.tried.length) {
          // 把每个候选地址各自失败的原因列出来 —— 否则现场只能看到一句
          // "获取失败"，根本没法判断是网络不通、路径被挡、还是总系统没起来。
          why += '（依次尝试：' + d.tried.map(function (t) {
            return t.url + ' → ' + t.error;
          }).join('；') + '）';
        }
        msg.textContent = d.ok
          ? '总系统上有 ' + list.length + ' 个集群可选。'
          : ('读不到总系统的集群列表：' + why +
             '（不影响互联，仅无法在此切换）');
      }
      var html = '';
      var hasCur = false;
      for (var i = 0; i < list.length; i++) {
        var c = list[i];
        if (String(c.name) === String(cur)) hasCur = true;
        html += '<option value="' + esc(c.name) + '"'
          + (String(c.name) === String(cur) ? ' selected' : '') + '>'
          + esc(c.name)
          + (c.is_default ? '（默认）' : '')
          + ' · ' + num(c.member_count) + ' 台'
          + '</option>';
      }
      if (!hasCur) {
        // 当前集群不在列表里（总系统还没记下本机的选择，或集群被删了）
        html = '<option value="' + esc(cur) + '" selected>' + esc(cur)
          + '（当前，总系统暂未收录）</option>' + html;
      }
      sel.innerHTML = html || '<option value="">（总系统上还没有集群）</option>';
      if ($('br-cluster-cur')) $('br-cluster-cur').textContent = cur;
    }).catch(function (e) {
      var p = e && e.payload;
      if (msg && p && p.tried && p.tried.length) {
        msg.textContent = '读取集群列表失败：' + (e.message || e) + '（依次尝试：'
          + p.tried.map(function (t) { return t.url + ' → ' + t.error; }).join('；') + '）';
      } else if (msg) {
        msg.textContent = '读取集群列表失败：' + (e && e.message ? e.message : e);
      }
    });
  }

  function applyCluster(btn) {
    var sel = $('br-cluster-sel');
    var msg = $('br-cluster-msg');
    if (!sel || clusterBusy) return;
    var name = sel.value;
    if (!name) return;
    clusterBusy = true;
    if (btn) { btn.disabled = true; btn.textContent = '切换中…'; }
    post('/api/bridge/cluster', { cluster: name }).then(function (d) {
      if (msg) {
        msg.textContent = '已切换到「' + (d.cluster || name) + '」'
          + (d.reported ? '，已上报总系统' : '（总系统会在下个上报周期记下）');
      }
      return load();
    }).then(loadClusters).catch(function (e) {
      if (msg) msg.textContent = '切换失败：' + (e && e.message ? e.message : e);
    }).then(function () {
      clusterBusy = false;
      if (btn) { btn.disabled = false; btn.textContent = '切换到该集群'; }
    });
  }

  /* ---------------- 事件绑定 ---------------- */
  if ($('br-cluster-apply')) {
    $('br-cluster-apply').addEventListener('click', function () { applyCluster(this); });
  }
  if ($('br-cluster-refresh')) {
    $('br-cluster-refresh').addEventListener('click', function () { loadClusters(); });
  }

  $('br-join').addEventListener('click', function () {
    // 按最近一次服务端确认的状态取反，不做界面文案推断
    setEnabled(!curEnabled, this);
  });

  $('br-pub').addEventListener('change', function () { setPublish(this.checked, this); });

  document.addEventListener('click', function (ev) {
    var el = ev.target;
    if (!el || !el.getAttribute) return;
    var del = el.getAttribute('data-del');
    if (del) deletePeer(del, el);
  });

  // details 的 toggle 事件不冒泡，用捕获阶段监听，记住「详情」展开状态
  document.addEventListener('toggle', function (ev) {
    var el = ev.target;
    if (!el || !el.classList || !el.classList.contains('br-more')) return;
    var box = el.closest ? el.closest('.br-card') : null;
    var id = box ? box.getAttribute('data-id') : '';
    if (id) openMore[id] = !!el.open;
  }, true);

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
      note: $('br-f-note').value.trim()
    }, msg).then(function () {
      $('br-f-name').value = '';
      $('br-f-host').value = '';
      $('br-f-note').value = '';
    });
  });

  load();
  loadCands();
  loadClusters();               // 所属集群（可选列表来自总系统）
  setInterval(load, STATUS_MS);
  setInterval(loadClusters, CAND_MS);
  setInterval(function () {
    // 正在填「手动补充」表单时不要动预览区，免得把光标下的内容换掉
    var a = document.activeElement;
    if (a && a.closest && a.closest('[data-add-peer]')) return;
    loadCands();
  }, CAND_MS);
})();
