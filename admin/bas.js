/* FAS 审计控制台前端（零依赖） */
(function () {
  'use strict';

  var TABS = [
    ['status', '总览'], ['online', '在线'], ['leaderboard', '排行榜'],
    ['topics', '主题统计'], ['audit', '身份审计'], ['blacklist', '黑名单'],
    ['quarantine', '待审救援'], ['health', '健康'], ['settings', '设置']
  ];
  var token = localStorage.getItem('bas_token') || '';
  var current = 'status';

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function api(path, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    if (token) opts.headers['X-BAS-Token'] = token;
    if (opts.body && typeof opts.body !== 'string') {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    return fetch('/api/bas/' + path, opts).then(function (r) {
      return r.json().then(function (j) {
        if (r.status === 401 && j.need_login) { showLogin(); throw new Error('未登录'); }
        return j;
      });
    });
  }

  /* ---------------- 登录 ---------------- */
  function showLogin() {
    $('login').classList.remove('hidden');
    api('bootstrap').then(function (j) {
      var need = j.need_setup;
      $('setup-fields').classList.toggle('hidden', !need);
      $('login-fields').classList.toggle('hidden', need);
      $('login-hint').textContent = need ? '首次使用：创建管理员账号' : '请输入管理员账号';
    }).catch(function () {
      $('login-hint').textContent = '请输入管理员账号';
    });
  }
  function hideLogin() { $('login').classList.add('hidden'); }

  $('btn-login').addEventListener('click', function () {
    $('login-err').textContent = '';
    fetch('/api/bas/session', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: $('li-user').value, password: $('li-pass').value })
    }).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.ok) { $('login-err').textContent = j.error || '登录失败'; return; }
      token = j.token; localStorage.setItem('bas_token', token);
      hideLogin(); boot();
    }).catch(function (e) { $('login-err').textContent = String(e); });
  });
  $('btn-setup').addEventListener('click', function () {
    $('login-err').textContent = '';
    fetch('/api/bas/setup-admin', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: $('su-user').value, password: $('su-pass').value })
    }).then(function (r) { return r.json(); }).then(function (j) {
      if (!j.ok) { $('login-err').textContent = j.error || '创建失败'; return; }
      showLogin();
      $('login-hint').textContent = '管理员已创建，请登录';
    }).catch(function (e) { $('login-err').textContent = String(e); });
  });
  $('btn-logout').addEventListener('click', function () {
    api('session', { method: 'DELETE' }).catch(function () { });
    token = ''; localStorage.removeItem('bas_token'); showLogin();
  });

  /* ---------------- 导航 ---------------- */
  function buildNav() {
    $('nav').innerHTML = TABS.map(function (t) {
      return '<a href="#' + t[0] + '" data-tab="' + t[0] + '">' + t[1] + '</a>';
    }).join('');
    Array.prototype.forEach.call($('nav').querySelectorAll('a'), function (a) {
      a.addEventListener('click', function (e) {
        e.preventDefault();
        switchTab(a.getAttribute('data-tab'));
      });
    });
  }
  function switchTab(name) {
    current = name;
    TABS.forEach(function (t) {
      $('tab-' + t[0]).classList.toggle('hidden', t[0] !== name);
    });
    Array.prototype.forEach.call($('nav').querySelectorAll('a'), function (a) {
      a.classList.toggle('active', a.getAttribute('data-tab') === name);
    });
    location.hash = name;
    load(name);
    setOnlineTimer(name === 'online');   // 在线页 5 秒实时刷新，离开即停
  }

  /* 在线页实时刷新（原实现只在切页/点按钮时取一次，界面看着是"死的"） */
  var onlineTimer = null;
  function setOnlineTimer(on) {
    if (onlineTimer) { clearInterval(onlineTimer); onlineTimer = null; }
    if (!on) return;
    onlineTimer = setInterval(function () {
      if (current !== 'online') { setOnlineTimer(false); return; }
      if ($('online-auto') && !$('online-auto').checked) return;
      loadOnline();
    }, 5000);
  }

  /* ---------------- 渲染工具 ---------------- */
  function table(el, cols, rows) {
    var html = '<thead><tr>' + cols.map(function (c) { return '<th>' + esc(c[0]) + '</th>'; }).join('') + '</tr></thead><tbody>';
    if (!rows || !rows.length) {
      html += '<tr><td colspan="' + cols.length + '" class="muted">暂无数据</td></tr>';
    } else {
      rows.forEach(function (r) {
        html += '<tr>' + cols.map(function (c) {
          var v = typeof c[1] === 'function' ? c[1](r) : r[c[1]];
          return '<td>' + (v === null || v === undefined ? '' : v) + '</td>';
        }).join('') + '</tr>';
      });
    }
    el.innerHTML = html + '</tbody>';
  }
  function fmtBytes(n) {
    n = Number(n || 0);
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1073741824).toFixed(2) + ' GB';
  }
  function card(k, v, cls) {
    return '<div class="card"><div class="k">' + esc(k) + '</div><div class="v ' + (cls || '') + '">' + v + '</div></div>';
  }
  function dtLocal(offsetMin) {
    var d = new Date(Date.now() + (offsetMin || 0) * 60000);
    var p = function (x) { return (x < 10 ? '0' : '') + x; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' +
      p(d.getHours()) + ':' + p(d.getMinutes());
  }
  function csv(name, cols, rows) {
    var lines = [cols.map(function (c) { return c[0]; }).join(',')];
    rows.forEach(function (r) {
      lines.push(cols.map(function (c) {
        var v = typeof c[1] === 'function' ? c[1](r) : r[c[1]];
        v = String(v === null || v === undefined ? '' : v);
        if (/^[=+\-@]/.test(v)) v = "'" + v;     /* 公式注入防护 */
        return '"' + v.replace(/"/g, '""') + '"';
      }).join(','));
    });
    var blob = new Blob(['\ufeff' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
  }

  /* ---------------- 各页加载 ---------------- */
  function load(name) {
    ({
      status: loadStatus, online: loadOnline, leaderboard: loadLb, topics: loadTopics,
      audit: loadAudit, blacklist: loadBl, quarantine: loadQuar, health: loadHealth,
      settings: loadSettings
    }[name] || function () { })();
  }

  function loadStatus() {
    api('status').then(function (j) {
      if (!j.ok) return;
      var s = j.status || {}, pol = s.policy || {}, sum = j.summary || {};
      var mode = pol.mode || 'warn';
      var badge = $('policy-badge');
      badge.textContent = '策略: ' + mode;
      badge.className = 'badge ' + (mode === 'ban' ? 'ban' : (mode === 'off' ? 'off' : 'warn'));
      $('cards').innerHTML =
        card('EMQX 在线客户端', s.online || 0) +
        card('身份审计 KICK', s.audit_kick || 0, s.audit_kick ? 'bad' : 'ok') +
        card('告警 WARN', s.audit_warn || 0, s.audit_warn ? 'warn' : '') +
        card('自动封禁', s.bans || 0, s.bans ? 'bad' : 'ok') +
        card('待审（疑似误封）', s.quarantined || 0, s.quarantined ? 'warn' : 'ok') +
        card('收数次数', s.ingest_total || 0) +
        card('消息速率 in/out', (s.ingest_ok || 0) + ' / ' + ((s.policy || {}).mode || '')) +
        card('统计行数（分钟/主题/事件）', (sum.minute_stats || 0) + ' / ' + (sum.topic_stats || 0) + ' / ' + (sum.audit_packets || 0));
      var lines = [];
      lines.push('身份控制: ' + (s.identity_control ? '启用' : '关闭') +
        '（模式 ' + mode + '，自动拉黑 ' + (pol.auto_ban ? '开' : '关') + '）');
      lines.push('UID 不一致判定: ' + (pol.uid_mismatch_verdict || '-') +
        '　单侧身份缺失: ' + (pol.partial_attr_verdict || '-'));
      lines.push('白名单: ' + ((pol.ban_whitelist && pol.ban_whitelist.length) ? pol.ban_whitelist.join(', ') : '（空）'));
      lines.push('每次采集: ' + (s.collect_last_ok ? new Date(s.collect_last_ok * 1000).toLocaleString() : '尚未成功') +
        (s.collect_last_error ? '　最近错误: ' + esc(s.collect_last_error) : ''));
      var svc = j.services || {};
      Object.keys(svc).forEach(function (k) { lines.push(k + ': ' + esc(svc[k])); });
      $('status-detail').innerHTML = lines.map(function (l) { return '<div>' + l + '</div>'; }).join('');
    });
  }

  function loadOnline() {
    api('online').then(function (j) {
      var rows = j.clients || [];
      var users = j.users || [];
      // ① 用户视图：页面要的是"人"，不是"连接"（同呼号多设备要合并）
      table($('t-online-users'), [
        ['呼号', function (r) { return '<b>' + esc(r.callsign) + '</b>'; }],
        ['类型', function (r) { return esc(r.kinds); }],
        ['连接数', function (r) { return r.conns; }],
        ['UID', function (r) { return esc(r.uids); }],
        ['IP', function (r) { return esc(r.ips); }],
        ['在线时长', function (r) { return esc(r.online_text); }],
        ['操作', function (r) {
          return '<button class="btn ghost" onclick="FUS.ban(\'' + esc(r.callsign) + '\')">拉黑</button>';
        }]
      ], users);
      // ② 连接明细
      table($('t-online'), [
        ['呼号', function (r) { return esc(r.callsign || r.username || '-'); }],
        ['类型', function (r) { return esc(r.kind || ''); }],
        ['UID', function (r) { return esc(r.uid || '-'); }],
        ['clientid', function (r) { return '<span class="mono">' + esc(r.clientid) + '</span>'; }],
        ['IP', function (r) { return esc(r.ip_address); }],
        ['在线时长', function (r) { return esc(r.online_text || ''); }],
        ['连接时间', function (r) { return esc(String(r.connected_at || '').replace('T', ' ').slice(0, 19)); }],
        ['订阅', function (r) { return (r.subscriptions_cnt === undefined ? '-' : r.subscriptions_cnt); }],
        ['收/发消息', function (r) { return (r.recv_msg || 0) + ' / ' + (r.send_msg || 0); }],
        ['收/发字节', function (r) { return fmtBytes(r.recv_oct) + ' / ' + fmtBytes(r.send_oct); }],
        ['操作', function (r) {
          var who = esc(r.callsign || r.username || '');
          var cid = esc(r.clientid || '');
          var b = '<button class="btn ghost" onclick="FUS.kick(\'' + cid + '\')">踢下线</button>';
          if (who) b += ' <button class="btn danger" onclick="FUS.ban(\'' + who + '\')">拉黑</button>';
          return b;
        }]
      ], rows);
      $('online-count').textContent = '用户 ' + users.length + ' 人 · 连接 ' + rows.length + ' 个';
      // ③ 最近在线：含"刚断开/短线重连"的用户（否则像 BA4LKK 那样来回掉线就看不见了）
      var recent = j.recent || [];
      var onlineSet = {};
      users.forEach(function (u) { onlineSet[u.callsign] = true; });
      table($('t-online-recent'), [
        ['呼号', function (r) { return '<b>' + esc(r.callsign || '(未知)') + '</b>'; }],
        ['状态', function (r) {
          return onlineSet[r.callsign]
            ? '<span class="tag PASS">在线</span>'
            : '<span class="tag WARN">已断开</span>';
        }],
        ['最后在线', function (r) { return esc(String(r.last_seen || '').slice(11, 19)); }],
        ['连接次数', function (r) { return r.conns; }],
        ['UID', function (r) { return esc(r.uid); }],
        ['最后 IP', function (r) { return esc(r.last_ip); }],
        ['最近 clientid', function (r) { return '<span class="mono">' + esc(r.last_clientid) + '</span>'; }]
      ], recent);
      if ($('recent-minutes')) $('recent-minutes').textContent = (j.recent_minutes || 30);
      if ($('online-at')) {
        $('online-at').textContent = '（' + (j.fetched_at || '').slice(11, 19)
          + ' 取自已 ' + (j.source || 'EMQX') + '）';
      }
    });
  }

  function loadLb() {
    var since = $('lb-since').value ? $('lb-since').value.replace('T', ' ') + ':00' : '';
    var until = $('lb-until').value ? $('lb-until').value.replace('T', ' ') + ':59' : '';
    var group = $('lb-group').value;
    var q = [];
    if (since) q.push('since=' + encodeURIComponent(since));
    if (until) q.push('until=' + encodeURIComponent(until));
    q.push('group=' + group, 'limit=200');
    api('leaderboard?' + q.join('&')).then(function (j) {
      var rows = j.rows || [];
      var cols = [
        ['#', function (r) { return rows.indexOf(r) + 1; }],
        ['呼号/clientid', function (r) { return esc(r.name); }],
        ['消息', function (r) { return r.msgs || 0; }],
        ['包数', function (r) { return r.pkts || 0; }],
        ['字节', function (r) { return fmtBytes(r.bytes); }],
        ['设备数', function (r) { return r.clients || 0; }],
        ['最近出现', function (r) { return esc(r.last_seen); }],
        ['操作', function (r) {
          return '<button class="btn ghost" onclick="FUS.detail(\'' + esc(r.name) + '\')">明细</button> ' +
            '<button class="btn ghost" onclick="FUS.ban(\'' + esc(r.name) + '\')">拉黑</button>';
        }]
      ];
      table($('t-lb'), cols, rows);
      $('lb-csv').onclick = function () {
        csv('fus-leaderboard.csv', cols.slice(0, 7), rows);
      };
    });
  }

  function loadTopics() {
    var q = 'bucket=' + $('tp-bucket').value;
    var topic = $('tp-topic').value.trim();
    if (topic) q += '&topic=' + encodeURIComponent(topic);
    api('topics/top?top=5&' + q).then(function (j) {
      var buckets = j.buckets || [];
      var max = 1;
      buckets.forEach(function (b) { max = Math.max(max, b.total_bytes || 0); });
      $('timeline').innerHTML = buckets.map(function (b) {
        var h = Math.max(2, Math.round((b.total_bytes || 0) * 100 / max));
        var tip = b.bucket + '\n' + (b.top || []).map(function (t) {
          return '  ' + t.name + '  ' + fmtBytes(t.bytes);
        }).join('\n');
        return '<div class="bar" style="height:' + h + 'px"><span class="tip">' + esc(tip) + '</span></div>';
      }).join('') || '<span class="muted">暂无数据</span>';
    });
    api('topics?' + q).then(function (j) {
      var rows = j.rows || [];
      var cols = [
        ['时间桶', function (r) { return esc(r.bucket); }],
        ['呼号', function (r) { return esc(r.name); }],
        ['消息', function (r) { return r.msgs || 0; }],
        ['字节', function (r) { return fmtBytes(r.bytes); }]
      ];
      table($('t-topics'), cols, rows);
      $('tp-csv').onclick = function () { csv('fus-topics.csv', cols, rows); };
    });
  }

  /* 事件类型友好名：一眼看出这条是什么事 */
  var SCENE_LABEL = {
    auth_ok: '认证通过',
    pass: '报文身份一致',
    forged: '盗用呼号（包内≠连接）',
    fake_cert: '假证书/验签失败',
    non_app_client: '非本 APP 客户端',
    uid_mismatch: 'UID 不符',
    dup_identity: '重复身份',
    bad_packet: '非法包',
    sas_unknown: '本机库查不到（仅参考）',
    sas_unavailable: '本机库不可用',
    attr_missing: '缺少身份属性',
    both_missing: '连接与包内都缺身份'
  };

  function loadAudit() {
    var q = [];
    if ($('au-verdict').value) q.push('verdict=' + $('au-verdict').value);
    if ($('au-callsign').value.trim()) q.push('callsign=' + encodeURIComponent($('au-callsign').value.trim()));
    q.push('limit=300');
    api('audit?' + q.join('&')).then(function (j) {
      var cols = [
        ['时间', function (r) { return esc(String(r.ts || '').replace('T', ' ').slice(0, 19)); }],
        ['判决', function (r) { return '<span class="tag ' + esc(r.verdict) + '">' + esc(r.verdict) + '</span>'; }],
        ['事件', function (r) {
          return esc(SCENE_LABEL[r.scene] || r.scene) +
            '<br><span class="muted small">' + esc(r.scene) + '</span>';
        }],
        // ★ 主列：这个事件里的「人」是谁（认证事件来自证书，报文事件来自 EMQX 下发的连接身份）
        ['身份（谁）', function (r) {
          var who = r.conn_callsign || '';
          if (!who) { return '<span class="muted small">（未知）</span>'; }
          var src = r.source === 'auth' ? '证书认证' : (r.source === 'packet' ? '连接身份' : (r.source || ''));
          return '<b>' + esc(who) + '</b>' + (r.conn_uid ? '(' + esc(r.conn_uid) + ')' : '') +
            '<br><span class="muted small">' + esc(src) + '</span>';
        }],
        // 包头身份：包内自称的呼号/UID，以及它与连接身份是否一致（盗用呼号就是在这里露馅）
        ['包头身份', function (r) {
          if (r.pkt_callsign) {
            var same = String(r.pkt_callsign).toUpperCase() ===
                       String(r.conn_callsign || '').toUpperCase();
            return esc(r.pkt_callsign) + (r.pkt_uid ? '(' + esc(r.pkt_uid) + ')' : '') +
              '<br><span class="tag ' + (same ? 'PASS' : 'KICK') + '">' +
              (same ? '与连接一致' : '与连接不一致') + '</span>';
          }
          if (r.pkt_callsign_recent) {
            return esc(r.pkt_callsign_recent) +
              (r.pkt_uid_recent ? '(' + esc(r.pkt_uid_recent) + ')' : '') +
              '<br><span class="muted small">该连接最近报文 ' +
              esc(String(r.pkt_recent_at || '').slice(11, 19)) + '</span>';
          }
          return '<span class="muted small">本次事件无报文<br>（认证在 CONNECT 时完成）</span>';
        }],
        ['IP', function (r) {
          if (r.ip) { return '<span class="mono">' + esc(r.ip) + '</span>'; }
          // 老事件没存 IP：fake_cert 的原因串里有 ip=...
          var m = /ip=([0-9a-fA-F:.]+)/.exec(String(r.reason || ''));
          return m ? '<span class="mono">' + esc(m[1]) + '</span>'
                   : '<span class="muted small">—</span>';
        }],
        ['clientid', function (r) { return '<span class="mono">' + esc(r.clientid) + '</span>'; }],
        ['置信度', function (r) { return r.confidence === null ? '' : Number(r.confidence).toFixed(2); }],
        ['已封', function (r) { return r.ban ? '<span class="tag KICK">是</span>' : '否'; }],
        ['原因', function (r) { return esc(r.reason); }]
      ];
      table($('t-audit'), cols, j.rows || []);
      if ($('au-csv')) {
        $('au-csv').onclick = function () { csv('fus-audit.csv', cols, j.rows || []); };
      }
    });
    api('audit/stats').then(function (j) {
      if ($('au-count')) {
        $('au-count').textContent = '共 ' + (j.total || 0) + ' 条（其中假证书 '
          + (j.fake_cert || 0) + ' 条）';
      }
    });
  }

  function loadBl() {
    // ---- EMQX 实际封禁名单（权威）：按 as 维度解封 ----
    api('banned').then(function (j) {
      var rows = j.rows || [];
      table($('t-bn'), [
        ['维度', function (r) { return '<span class="tag WARN">' + esc(r.as) + '</span>'; }],
        ['对象', function (r) { return esc(r.who); }],
        ['到期', function (r) {
          return esc(r.is_forever ? '永久' : r.until);
        }],
        ['原因', function (r) { return esc(r.reason); }],
        ['操作', function (r) {
          return '<button class="btn ghost" onclick="FUS.unbanEx(\'' + esc(r.as) + '\',\'' +
            esc(r.who) + '\')">解封</button>';
        }]
      ], rows);
      if (j.error) { $('bn-sum') && ($('bn-sum').textContent = '读取失败: ' + j.error); }
    });

    api('blacklist').then(function (j) {
      // ★ active = 与 EMQX 实时名单核对后**确实还在生效**的；
      //   stale  = 审计流水里还记着、但 EMQX 里已经没有了（手动解封或已到期）
      var stale = j.stale || [];
      var rows = (j.active || []).concat(stale.map(function (r) {
        var c = {}; for (var k in r) c[k] = r[k];
        c._stale = true; return c;
      }));
      table($('t-bl'), [
        ['呼号', function (r) { return esc(r.who); }],
        ['维度', function (r) { return esc(r.as_type || 'username'); }],
        ['状态', function (r) {
          return r._stale
            ? '<span class="tag PASS">已失效</span>'
            : '<span class="tag KICK">生效中</span>';
        }],
        ['原因', function (r) { return esc(r.reason); }],
        ['到期', function (r) { return esc(r.until === 'infinity' ? '永久' : r.until); }],
        ['操作者', function (r) { return esc(r.operator); }],
        ['时间', function (r) { return esc(r.created_at); }],
        ['操作', function (r) {
          if (r._stale) return '<span class="muted small">EMQX 中已无此封禁</span>';
          return '<button class="btn ghost" onclick="FUS.unban(\'' + esc(r.who) + '\')">解封</button>';
        }]
      ], rows);
      if ($('bl-sum')) {
        $('bl-sum').textContent = '生效中 ' + (j.active || []).length + ' 条'
          + (stale.length ? ('，已失效 ' + stale.length + ' 条（可一键清理）') : '')
          + (j.note ? ('　' + j.note) : '');
      }
      if ($('bl-sync')) { $('bl-sync').disabled = !stale.length; }
    });
    // 白名单（名单内呼号永不被自动封禁）
    api('whitelist').then(function (j) {
      var rows = (j.rows || []).map(function (x) { return { callsign: x }; });
      table($('t-wl'), [
        ['呼号', function (r) { return '<b>' + esc(r.callsign) + '</b>'; }],
        ['操作', function (r) {
          return '<button class="btn ghost" onclick="FUS.wlRemove(\'' + esc(r.callsign) +
            '\')">移出白名单</button>';
        }]
      ], rows);
    });
    api('blacklist/history?limit=300').then(function (j) {
      table($('t-blh'), [
        ['时间', function (r) { return esc(r.created_at); }],
        ['动作', function (r) { return '<span class="tag ' + (r.action === 'ban' ? 'KICK' : 'PASS') + '">' + esc(r.action) + '</span>'; }],
        ['呼号', function (r) { return esc(r.who); }],
        ['原因', function (r) { return esc(r.reason); }],
        ['到期', function (r) { return esc(r.until); }],
        ['操作者', function (r) { return esc(r.operator); }]
      ], j.rows || []);
    });
  }

  function loadQuar() {
    api('quarantine?status=' + encodeURIComponent($('q-status').value)).then(function (j) {
      table($('t-quarantine'), [
        ['时间', function (r) { return esc(r.created_at); }],
        ['场景', function (r) { return esc(r.scene); }],
        ['连接身份', function (r) { return esc(r.conn_callsign) + (r.conn_uid ? '(' + esc(r.conn_uid) + ')' : ''); }],
        ['包头身份', function (r) { return esc(r.pkt_callsign) + (r.pkt_uid ? '(' + esc(r.pkt_uid) + ')' : ''); }],
        ['clientid', function (r) { return '<span class="mono">' + esc(r.clientid) + '</span>'; }],
        ['置信度', function (r) { return r.confidence === null ? '' : Number(r.confidence).toFixed(2); }],
        ['原因', function (r) { return esc(r.reason); }],
        ['状态', function (r) { return esc(r.status); }],
        ['操作', function (r) {
          return r.status === 'pending'
            ? '<button class="btn primary" onclick="FUS.release(' + r.id + ')">放行</button>'
            : '';
        }]
      ], j.rows || []);
    });
  }

  function loadHealth() {
    api('health').then(function (j) {
      var e = j.emqx || {}, series = j.series || [];
      $('health-cards').innerHTML =
        card('EMQX 可达', e.reachable ? '是' : '否', e.reachable ? 'ok' : 'bad') +
        card('EMQX 版本', esc(e.version || '-') + (e.supported ? '' : ' ⚠'), e.supported ? 'ok' : 'warn') +
        card('在线客户端', e.online || 0) +
        card('消息速率 in/out', (e.msg_rate ? e.msg_rate.in.toFixed(1) : 0) + ' / ' + (e.msg_rate ? e.msg_rate.out.toFixed(1) : 0));
      table($('t-health'), [
        ['时间', function (r) { return esc(r.ts); }],
        ['CPU%', function (r) { return r.host_cpu_pct === null ? '' : r.host_cpu_pct; }],
        ['内存%', function (r) { return r.host_mem_pct === null ? '' : r.host_mem_pct; }],
        ['磁盘%', function (r) { return r.host_disk_pct === null ? '' : r.host_disk_pct; }],
        ['EMQX 连接', function (r) { return r.emqx_conns; }],
        ['load1', function (r) { return r.emqx_cpu_pct; }],
        ['告警', function (r) { return esc(r.emqx_alarms); }],
        ['速率 in/out', function (r) { return (r.msg_rate_in || 0) + ' / ' + (r.msg_rate_out || 0); }]
      ], series.slice(-60).reverse());

      renderUntrustedRoots(j.untrusted_roots || []);
    });
  }

  /* 未信任根台账：把完整公钥摆出来，方便复制与判断 */
  function renderUntrustedRoots(rows) {
    var el = $('t-uroot');
    if (!el) return;
    var cnt = $('uroot-count');
    if (cnt) cnt.textContent = rows.length ? ('共 ' + rows.length + ' 个') : '暂无记录';
    if (!rows.length) {
      el.innerHTML = '<thead><tr><th>状态</th></tr></thead><tbody>' +
        '<tr><td class="muted">没有记录：当前没有客户端用陌生根 CA 的证书来登录。</td></tr></tbody>';
      return;
    }
    el.innerHTML = '<thead><tr>' +
      ['根 CA 公钥（完整，可复制加白）', '首次出现', '最近出现', '次数',
       '自称呼号数', '最近自称呼号', '最近 clientid', '最近 IP'].map(function (h) {
        return '<th>' + h + '</th>';
      }).join('') + '</tr></thead><tbody>' +
      rows.map(function (r) {
        var suspicious = (r.distinct_cs || 0) > 3 || (r.hits || 0) > 20;
        return '<tr>' +
          '<td class="mono" style="white-space:normal;word-break:break-all;">' +
            esc(r.root_pubkey) + '</td>' +
          '<td class="mono">' + esc(r.first_ts || '') + '</td>' +
          '<td class="mono">' + esc(r.ts || '') + '</td>' +
          '<td>' + (r.hits || 0) + '</td>' +
          '<td>' + (r.distinct_cs || 0) +
            (suspicious ? ' <span class="tag FAIL">可疑</span>' : '') + '</td>' +
          '<td>' + esc(r.last_callsign || '-') + '</td>' +
          '<td class="mono">' + esc(r.last_clientid || '-') + '</td>' +
          '<td class="mono">' + esc(r.last_ip || '-') + '</td>' +
          '</tr>';
      }).join('') + '</tbody>';
  }

  function loadSettings() {
    api('settings').then(function (j) {
      var s = j.settings || {}, p = j.policy || {};
      $('st-url').value = s.emqx_url || '';
      $('st-key').value = s.emqx_api_key || '';
      $('st-topic').value = s.topic_name || 'FMO/RAW';
      $('st-webhook').value = j.webhook_url || '';
      $('st-ingest').textContent = '/api/ingest（token 前 4 位: ' + (j.ingest_token_hint || '未生成') + '）';
      $('po-mode').value = p.mode || 'warn';
      $('po-auto').checked = !!p.auto_ban;
      $('po-uid').value = p.uid_mismatch_verdict || 'warn';
      $('po-partial').value = p.partial_attr_verdict || 'warn';
      $('po-wl').value = (p.ban_whitelist || []).join(',');
      $('po-rate').value = p.ban_rate_limit_per_hour === undefined ? 3 : p.ban_rate_limit_per_hour;
      $('po-hours').value = p.ban_hours === null || p.ban_hours === undefined ? '' : p.ban_hours;
      $('po-sas').checked = !!p.ban_when_sas_unavailable;
      $('po-hint').textContent = p.mode === 'ban'
        ? '当前会按策略自动封人；建议先观察一段时间再开启'
        : '当前不会自动封人，可疑事件进入「待审救援」';
    });
  }

  /* ---------------- 事件 ---------------- */
  Array.prototype.forEach.call(document.querySelectorAll('[data-reload]'), function (b) {
    b.addEventListener('click', function () { load(b.getAttribute('data-reload')); });
  });
  $('bl-ban').addEventListener('click', function () {
    var who = $('bl-who').value.trim().toUpperCase();
    if (!who) return alert('请填写呼号');
    api('blacklist/ban', {
      method: 'POST',
      body: { who: who, reason: $('bl-reason').value || '手动拉黑', hours: $('bl-hours').value || null }
    }).then(function (j) {
      alert(j.ok ? ('已拉黑 ' + who + '（踢下线 ' + (j.kicked || 0) + ' 个连接）') : ('失败: ' + j.error));
      loadBl();
    });
  });
  $('st-save').addEventListener('click', function () {
    api('settings', {
      method: 'POST',
      body: {
        emqx_url: $('st-url').value.trim(), emqx_api_key: $('st-key').value.trim(),
        emqx_api_secret: $('st-secret').value, topic_name: $('st-topic').value.trim() || 'FMO/RAW'
      }
    }).then(function (j) { alert(j.ok ? '已保存' : ('失败: ' + j.error)); });
  });
  $('st-apply').addEventListener('click', function () {
    api('settings', {
      method: 'POST',
      body: {
        emqx_url: $('st-url').value.trim(), emqx_api_key: $('st-key').value.trim(),
        emqx_api_secret: $('st-secret').value, topic_name: $('st-topic').value.trim() || 'FMO/RAW',
        webhook_url: $('st-webhook').value.trim() || null, apply: true
      }
    }).then(function (j) {
      var r = j.result || {};
      var msg = (r.reachable ? 'EMQX 连接正常\n' : 'EMQX 不可达: ' + (r.detail || '') + '\n');
      (r.steps || []).forEach(function (s) { msg += '  ' + s.step + ': ' + (s.detail || '') + '\n'; });
      alert(msg);
      loadSettings();
    });
  });
  $('st-teardown').addEventListener('click', function () {
    if (!confirm('从 EMQX 删除本服务的规则与桥接？')) return;
    api('teardown-rule', { method: 'POST' }).then(function (j) { alert(j.ok ? '已移除' : '失败'); });
  });

  /* ---------------- 身份链路诊断 ---------------- */
  $('dg-run').addEventListener('click', function () {
    $('dg-log').textContent = '诊断中（会读取 EMQX 认证配置并探测 SAS /auth）...';
    api('diagnose').then(function (j) {
      var r = j.report || {};
      var lines = [];
      if (r.error) lines.push('诊断异常: ' + r.error);
      (r.findings || []).forEach(function (f) {
        var tag = f.level === 'fatal' ? '✗ 必须修' : (f.level === 'warn' ? '! 建议修' : '✓');
        lines.push(tag + '  [' + f.code + '] ' + f.title);
        if (f.detail) lines.push('      现象: ' + f.detail);
        if (f.fix) lines.push('      修法: ' + f.fix);
      });
      var ft = r.facts || {};
      lines.push('');
      lines.push('EMQX: ' + (ft.emqx_url || '-') + '  版本=' + (ft.emqx_version || '-') +
        '  可达=' + ft.emqx_reachable);
      lines.push('HTTP 认证器数量: ' + (ft.http_authn_count === undefined ? '-' : ft.http_authn_count));
      (ft.authn_detail || []).forEach(function (a) {
        lines.push('  · ' + a.id + '  method=' + a.method + '  body键=' + (a.body_keys || []).join(','));
      });
      if (ft.other_authn && ft.other_authn.length) {
        lines.push('其它认证器: ' + ft.other_authn.map(function (x) { return x.backend; }).join(','));
      }
      if (ft.audit_scenes_24h) lines.push('近 24h 审计场景: ' + JSON.stringify(ft.audit_scenes_24h));
      $('dg-log').textContent = lines.join('\n');
      $('dg-sum').textContent = r.ok ? '链路正常' : '发现问题，见下方【修法】';
    }).catch(function (e) { $('dg-log').textContent = '请求失败: ' + e; });
  });

  /* ---------------- MQTT 认证接管 ---------------- */
  function authSwitch(dry) {
    api('emqx-auth' + (dry ? '' : ''), {
      method: dry ? 'GET' : 'POST',
      body: dry ? undefined : {
        dry_run: false,
        force_all: $('aa-force').checked,
        target_url: $('aa-target').value.trim() || null
      }
    }).then(function (j) {
      var r = j.result || {};
      var lines = [];
      if (r.error) { lines.push('错误: ' + r.error); }
      lines.push('MQTT 探测: ' + ((r.detect && (r.detect.note || '发现 EMQX')) || '-'));
      if (r.emqx_url) lines.push('EMQX: ' + r.emqx_url + ' 可达=' + r.reachable + ' ' + (r.detail || ''));
      if (r.target_url) lines.push('目标认证 URL: ' + r.target_url);
      var cur = r.current || {};
      if (cur.items) {
        lines.push('当前认证链 ' + cur.items.length + ' 项（像 SAS 的 ' + cur.sas_like_count +
          ' 项，已指向目标=' + cur.target_active + '）');
        cur.items.forEach(function (it) {
          lines.push('  · [' + it.scope + '] ' + (it.backend || '?') + ' ' + (it.url || '') +
            (it.already_target ? ' ✓已是目标' : ''));
        });
      }
      var sw = r.switch || {};
      (sw.changed || []).forEach(function (x) { lines.push('改: ' + x); });
      (sw.skipped || []).forEach(function (x) { lines.push('跳过: ' + x); });
      (sw.errors || []).forEach(function (x) { lines.push('错误: ' + x); });
      if (dry) lines.push('—— 以上为预览，未修改任何配置 ——');
      else lines.push('结果: ' + (sw.ok ? '认证已指向本服务' : '未完成，请检查 EMQX'));
      $('aa-log').textContent = lines.join('\n');
      $('aa-status').textContent = dry ? '预览完成（未改配置）'
        : (sw.ok ? '已接管：EMQX 认证指向本服务' : '接管未完成');
    }).catch(function (e) { $('aa-log').textContent = '请求失败: ' + e; });
  }
  $('aa-preview').addEventListener('click', function () { authSwitch(true); });
  $('aa-apply').addEventListener('click', function () {
    if (!confirm('将修改 EMQX 的客户端认证配置（会先备份，可回滚）。继续？')) return;
    authSwitch(false);
  });
  $('po-save').addEventListener('click', function () {
    api('policy', {
      method: 'POST',
      body: {
        mode: $('po-mode').value, auto_ban: $('po-auto').checked,
        uid_mismatch_verdict: $('po-uid').value, partial_attr_verdict: $('po-partial').value,
        ban_whitelist: $('po-wl').value.split(',').map(function (s) { return s.trim(); }).filter(Boolean),
        ban_rate_limit_per_hour: Number($('po-rate').value || 0),
        ban_hours: $('po-hours').value ? Number($('po-hours').value) : null,
        ban_when_sas_unavailable: $('po-sas').checked
      }
    }).then(function (j) { alert(j.ok ? '策略已保存' : '失败'); loadSettings(); loadStatus(); });
  });

  /* 暴露给内联按钮（页面内 onclick 用的是 FUS.xxx） */
  window.FUS = {
    ban: function (who) {
      var reason = prompt('拉黑 ' + who + ' 的原因（留痕）：', '管理员手动拉黑');
      if (reason === null) return;
      api('blacklist/ban', { method: 'POST', body: { who: who, reason: reason } })
        .then(function () { load(current); });
    },
    unban: function (who) {
      api('blacklist/unban', { method: 'POST', body: { who: who } }).then(function (j) {
        alert(j.ok ? ('解封结果: ' + (j.detail || '成功')) : ('失败: ' + j.error));
        loadBl();
      });
    },
    // 按 EMQX 的实际维度解封（username / clientid / peerhost）
    unbanEx: function (asType, who) {
      api('banned/unban', { method: 'POST', body: { who: who, as_type: asType } })
        .then(function (j) {
          alert(j.ok ? ('解封结果: ' + (j.detail || '成功')) : ('失败: ' + j.error));
          loadBl();
        });
    },
    release: function (id) {
      api('quarantine/release', { method: 'POST', body: { id: id } })
        .then(function (j) { alert(j.ok ? '已放行并解封' : ('失败: ' + j.error)); loadQuar(); });
    },
    kick: function (clientid) {
      if (!confirm('把该连接踢下线？（只踢不封，它会自己重连）')) return;
      api('kick', { method: 'POST', body: { clientid: clientid } }).then(function (j) {
        alert(j.ok ? (j.detail || '已踢下线') : ('失败: ' + j.error));
        loadOnline();
      });
    },
    banIp: function (ip) {
      var h = prompt('封禁 IP ' + ip + ' 多少小时？（留空=24）', '24');
      if (h === null) return;
      api('ban-ip', { method: 'POST', body: { ip: ip, hours: h || 24 } })
        .then(function (j) { alert(j.ok ? (j.detail || '已封禁') : ('失败: ' + j.error)); loadBl(); });
    },
    wlRemove: function (cs) {
      if (!confirm('把 ' + cs + ' 移出白名单？')) return;
      api('whitelist/remove', { method: 'POST', body: { callsign: cs } })
        .then(function (j) { loadBl(); });
    },
    detail: function (name) {
      api('leaderboard/' + encodeURIComponent(name)).then(function (j) {
        var rows = j.rows || [];
        var html = '<h3>' + esc(name) + ' 明细</h3><div class="panel table-wrap"><table><thead><tr>' +
          ['clientid', 'IP', '消息', '字节', '重连', '首见', '末见'].map(function (h) { return '<th>' + h + '</th>'; }).join('') +
          '</tr></thead><tbody>' + rows.map(function (r) {
            return '<tr><td class="mono">' + esc(r.clientid) + '</td><td>' + esc(r.ip_address) + '</td><td>' +
              (r.msgs || 0) + '</td><td>' + fmtBytes(r.bytes) + '</td><td>' + (r.reconnects || 0) + '</td><td>' +
              esc(r.first_seen) + '</td><td>' + esc(r.last_seen) + '</td></tr>';
          }).join('') + '</tbody></table></div>';
        $('lb-detail').innerHTML = html;
      });
    }
  };
  window.BAS = window.FUS;   // 兼容旧引用（历史名 BAS）

  /* ---------------- 启动 ---------------- */
  function boot() {
    buildNav();
    $('lb-since').value = dtLocal(-24 * 60);
    $('lb-until').value = dtLocal(0);
    // 一键全部解封（清空 EMQX 封禁名单）
    if ($('bn-unban-all')) {
      $('bn-unban-all').addEventListener('click', function () {
        if (!confirm('确定清空 EMQX 全部封禁？')) return;
        api('banned/unban-all', { method: 'POST', body: {} }).then(function (j) {
          alert(j.ok ? (j.detail || '已清空') : ('部分失败: ' + j.error + ' / ' + (j.detail || '')));
          loadBl();
        });
      });
    }
    // 审计：清理旧事件
    if ($('au-prune')) {
      $('au-prune').addEventListener('click', function () {
        var days = parseInt($('au-days').value || '30', 10);
        if (!confirm('清理 ' + days + ' 天前的审计事件？（不可撤销）')) return;
        api('audit/prune', { method: 'POST', body: { days: days } }).then(function (j) {
          alert(j.ok ? (j.detail || '已清理') : ('失败: ' + j.error));
          loadAudit();
        });
      });
    }
    // 黑名单：按 IP 封禁
    if ($('bn-ban-ip')) {
      $('bn-ban-ip').addEventListener('click', function () {
        var ip = ($('bn-ip').value || '').trim();
        if (!ip) { alert('请填写 IP'); return; }
        var h = parseInt($('bn-ip-hours').value || '24', 10);
        if (!confirm('把 IP ' + ip + ' 封禁 ' + h + ' 小时？')) return;
        api('ban-ip', { method: 'POST', body: { ip: ip, hours: h } }).then(function (j) {
          alert(j.ok ? (j.detail || '已封禁') : ('失败: ' + j.error));
          loadBl();
        });
      });
    }
    // 白名单：加入
    if ($('wl-add')) {
      $('wl-add').addEventListener('click', function () {
        var cs = ($('wl-who').value || '').trim();
        if (!cs) { alert('请填写呼号'); return; }
        api('whitelist/add', { method: 'POST', body: { callsign: cs } }).then(function (j) {
          if (!j.ok) { alert('失败: ' + j.error); return; }
          $('wl-who').value = '';
          loadBl();
        });
      });
    }
    if ($('bl-sync')) {
      $('bl-sync').addEventListener('click', function () {
        api('blacklist/sync', { method: 'POST', body: {} }).then(function (j) {
          alert(j.ok ? (j.detail || '已清理') : ('失败: ' + j.error));
          loadBl();
        });
      });
    }
    if ($('bn-refresh')) {
      $('bn-refresh').addEventListener('click', function () {
        api('banned').then(function (j) {
          var rows = j.rows || [];
          alert('EMQX 当前封禁 ' + rows.length + ' 条'
                + (j.error ? ('（读取有误: ' + j.error + '）') : ''));
          loadBl();
        });
      });
    }
    if ($('online-auto')) {
      $('online-auto').addEventListener('change', function () {
        setOnlineTimer(current === 'online');
      });
    }
    var hash = (location.hash || '#status').slice(1);
    switchTab(TABS.some(function (t) { return t[0] === hash; }) ? hash : 'status');
  }
  window.addEventListener('hashchange', function () {
    var h = (location.hash || '').slice(1);
    if (h && h !== current) switchTab(h);
  });

  /* ---------------- 启动（已取消后台账号登录） ----------------
     管理口默认直连：不再要求登录，也不再弹出登录遮罩。
     如需恢复登录：把 bas_http.py 里的 BAS_ADMIN_LOGIN_REQUIRED 改回 True 即可，
     这里的登录界面与逻辑都保留未删。 */
  boot();
})();
