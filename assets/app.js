/* 学籍信息核对系统 —— 前端核心逻辑（通用版，字段与分组均由 data.js 驱动）
 * ---------------------------------------------------------------
 * 口令 = 学生本人身份证号后 6 位
 *   master = PBKDF2-HMAC-SHA256(PEPPER + 口令, salt_i, iter)
 *   idx    = HMAC-SHA256(master, "idx")[0:4]   -> 定位记录（不含口令信息）
 *   encKey = HMAC-SHA256(master, "enc")        -> HMAC-CTR 流加密密钥
 *   macKey = HMAC-SHA256(master, "mac")        -> 完整性校验
 * 全部计算在浏览器本地完成，不发送任何网络请求。
 */
(function () {
  'use strict';

  var DATA = window.SIC_DATA;
  var PEPPER_B64 = window.SIC_PEPPER_B64 || '';
  var enc = new TextEncoder();
  var dec = new TextDecoder();

  var MAX_TRIES = 5;
  var LOCK_MS = 3 * 60 * 1000;
  var AUTO_LOCK_MS = 5 * 60 * 1000;
  var BATCH = 8;

  var LS_FAIL = 'sic_fail_v1';
  var LS_LOCK = 'sic_lock_v1';
  var LS_OK = 'sic_confirmed_v1';

  var state = { rec: null, priv: null, revealed: false, timer: null };

  var $ = function (id) { return document.getElementById(id); };
  var gateView = $('gateView'), resultView = $('resultView');
  var tailInput = $('tailInput'), verifyBtn = $('verifyBtn'), clearBtn = $('clearBtn');
  var errBox = $('errBox'), triesBox = $('triesBox'), groups = $('groups');
  var spinner = document.querySelector('#verifyBtn .spinner');
  var btnText = document.querySelector('#verifyBtn .btn-text');

  // ---------------------------------------------------------------- 初始化
  function init() {
    if (!window.crypto || !window.crypto.subtle) {
      $('insecureTip').hidden = false;
      verifyBtn.disabled = true;
      tailInput.disabled = true;
      return;
    }
    if (!DATA || !DATA.records || !DATA.records.length) {
      showError('数据未加载，请检查 assets/data.js 是否存在。');
      verifyBtn.disabled = true;
      return;
    }
    var m = DATA.meta || {};
    $('sysTitle').textContent = m.title || '学籍信息核对确认';
    $('sysSub').textContent = [m.school, m.className].filter(Boolean).join(' · ');
    $('sysMeta').innerHTML = [
      '登记人数 ' + m.count + ' 人',
      '数据更新 ' + (m.updated || '-'),
      '加密强度 PBKDF2 × ' + (m.iter || 0)
    ].map(function (t) { return '<span>' + esc(t) + '</span>'; }).join('');
    $('footMeta').textContent = '加密算法：' + (m.algo || '-');

    bindEvents();
    refreshLockState();
    tailInput.focus();
  }

  function bindEvents() {
    tailInput.addEventListener('input', function () {
      var v = tailInput.value.toUpperCase().replace(/[^0-9X]/g, '').slice(0, 6);
      if (v !== tailInput.value) tailInput.value = v;
      clearBtn.hidden = !v;
      hideError();
    });
    tailInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); doVerify(); }
    });
    clearBtn.addEventListener('click', function () {
      tailInput.value = ''; clearBtn.hidden = true; hideError(); tailInput.focus();
    });
    verifyBtn.addEventListener('click', doVerify);

    $('toggleMaskBtn').addEventListener('click', function () {
      state.revealed = !state.revealed;
      renderGroups();
      $('toggleMaskBtn').textContent = state.revealed ? '隐藏完整号码' : '显示完整号码';
      resetAutoLock();
    });
    $('lockBtn').addEventListener('click', lockNow);

    $('okBtn').addEventListener('click', function () {
      var key = LS_OK + '_' + (state.rec ? state.rec.idx : '');
      var t = new Date().toLocaleString('zh-CN', { hour12: false });
      try { localStorage.setItem(key, t); } catch (e) {}
      var n = $('confirmNote');
      n.hidden = false;
      n.textContent = '✓ 已记录：你于 ' + t + ' 确认学籍信息核对无误。如需再次核对请重新核验。';
      toast('已标记为核对无误');
    });

    $('fixBtn').addEventListener('click', openFixModal);
    $('copyBtn').addEventListener('click', copyFixText);
    Array.prototype.forEach.call(document.querySelectorAll('[data-close]'), function (el) {
      el.addEventListener('click', function () { $('modal').hidden = true; });
    });
    $('modal').addEventListener('click', function (e) {
      if (e.target.hasAttribute('data-close')) $('modal').hidden = true;
    });
    document.addEventListener('visibilitychange', function () {
      if (document.hidden && state.rec) lockNow();
    });
  }

  // ---------------------------------------------------------------- 尝试次数 / 锁定
  function lsGet(k, d) { try { var v = localStorage.getItem(k); return v === null ? d : v; } catch (e) { return d; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  function getFail() { return parseInt(lsGet(LS_FAIL, '0'), 10) || 0; }
  function getLockUntil() { return parseInt(lsGet(LS_LOCK, '0'), 10) || 0; }

  function refreshLockState() {
    var left = getLockUntil() - Date.now();
    if (left > 0) { lockUI(left); return; }
    lsSet(LS_LOCK, '0');
    if (getFail() > 0) {
      triesBox.hidden = false;
      triesBox.textContent = '已连续输错 ' + getFail() + ' 次，剩余 ' + (MAX_TRIES - getFail()) + ' 次机会';
    } else {
      triesBox.hidden = true;
    }
  }

  function lockUI(ms) {
    verifyBtn.disabled = true;
    tailInput.disabled = true;
    triesBox.hidden = false;
    triesBox.textContent = '尝试次数过多，请 ' + Math.ceil(ms / 1000) + ' 秒后重试';
    setTimeout(function () {
      var left = getLockUntil() - Date.now();
      if (left > 0) { lockUI(left); }
      else {
        verifyBtn.disabled = false; tailInput.disabled = false;
        lsSet(LS_FAIL, '0'); triesBox.hidden = true; tailInput.focus();
      }
    }, 1000);
  }

  // ---------------------------------------------------------------- 核验
  function doVerify() {
    var tail = tailInput.value.trim().toUpperCase();
    hideError();
    if (getLockUntil() > Date.now()) { refreshLockState(); return; }
    if (!/^[0-9]{5}[0-9X]$/.test(tail)) {
      showError('请输入 6 位号码：前 5 位为数字，末位为数字或字母 X。');
      flashError();
      return;
    }
    setLoading(true);
    var t0 = performance.now();
    lookup(tail).then(function (res) {
      var wait = Math.max(0, 260 - (performance.now() - t0));
      return new Promise(function (r) { setTimeout(function () { r(res); }, wait); });
    }).then(function (res) {
      setLoading(false);
      if (!res) {
        var n = getFail() + 1;
        lsSet(LS_FAIL, String(n));
        if (n >= MAX_TRIES) {
          lsSet(LS_LOCK, String(Date.now() + LOCK_MS));
          lsSet(LS_FAIL, '0');
          showError('连续 ' + MAX_TRIES + ' 次核验失败，已临时锁定 3 分钟。');
        } else {
          showError('未找到匹配记录。请核对身份证号码后 6 位，或联系班主任确认登记信息。');
        }
        flashError();
        refreshLockState();
        return;
      }
      lsSet(LS_FAIL, '0');
      triesBox.hidden = true;
      state.rec = res.rec;
      state.priv = res.priv;
      state.revealed = false;
      $('toggleMaskBtn').textContent = '显示完整号码';
      showResult();
    }).catch(function (err) {
      setLoading(false);
      console.error(err);
      showError('核验过程出错：' + (err && err.message ? err.message : err) + '（请刷新页面重试）');
    });
  }

  function setLoading(on) {
    verifyBtn.disabled = on;
    tailInput.disabled = on;
    spinner.hidden = !on;
    btnText.textContent = on ? '正在核验…' : '核 验 并 查 看';
  }

  function lookup(tail) {
    var recs = DATA.records, iter = DATA.meta.iter;
    var pwBytes = concat(b64ToBytes(PEPPER_B64), enc.encode(tail));
    return crypto.subtle.importKey('raw', pwBytes, 'PBKDF2', false, ['deriveBits'])
      .then(function (baseKey) {
        var chain = Promise.resolve(null);
        for (var i = 0; i < recs.length; i += BATCH) {
          (function (slice) {
            chain = chain.then(function (hit) {
              if (hit) return hit;
              return Promise.all(slice.map(function (r) {
                return crypto.subtle.deriveBits(
                  { name: 'PBKDF2', salt: b64ToBytes(r.salt), iterations: iter, hash: 'SHA-256' },
                  baseKey, 256).then(function (b) { return new Uint8Array(b); });
              })).then(function (masters) {
                var inner = Promise.resolve(null);
                slice.forEach(function (r, j) {
                  inner = inner.then(function (hit) {
                    if (hit) return hit;
                    return hmac(masters[j], enc.encode('idx')).then(function (h) {
                      return toHex(h.slice(0, 4)) === r.idx ? decrypt(masters[j], r) : null;
                    });
                  });
                });
                return inner;
              });
            });
          })(recs.slice(i, i + BATCH));
        }
        return chain;
      });
  }

  function decrypt(master, rec) {
    var nonce = b64ToBytes(rec.nonce), ct = b64ToBytes(rec.ct);
    return Promise.all([hmac(master, enc.encode('enc')), hmac(master, enc.encode('mac'))])
      .then(function (k) {
        return hmac(k[1], concat(nonce, ct)).then(function (tag) {
          if (toHex(tag) !== toHex(b64ToBytes(rec.tag))) throw new Error('数据完整性校验失败');
          return hmacCtr(k[0], nonce, ct);
        });
      })
      .then(function (pt) { return { rec: rec, priv: JSON.parse(dec.decode(pt)) }; });
  }

  // ---------------------------------------------------------------- 加密原语
  function hmac(keyBytes, msg) {
    return crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
      .then(function (k) { return crypto.subtle.sign('HMAC', k, msg); })
      .then(function (s) { return new Uint8Array(s); });
  }

  function hmacCtr(keyBytes, nonce, data) {
    var out = new Uint8Array(data.length), pos = 0, counter = 0;
    function step() {
      if (pos >= data.length) return Promise.resolve(out);
      return hmac(keyBytes, concat(nonce, u32(counter))).then(function (block) {
        var n = Math.min(block.length, data.length - pos);
        for (var k = 0; k < n; k++) out[pos + k] = data[pos + k] ^ block[k];
        pos += n; counter++;
        return step();
      });
    }
    return step();
  }

  function u32(n) { return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]); }
  function concat(a, b) { var r = new Uint8Array(a.length + b.length); r.set(a, 0); r.set(b, a.length); return r; }
  function b64ToBytes(s) { var bin = atob(s), r = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) r[i] = bin.charCodeAt(i); return r; }
  function toHex(u8) { var s = ''; for (var i = 0; i < u8.length; i++) s += ('0' + u8[i].toString(16)).slice(-2); return s; }

  // ---------------------------------------------------------------- 渲染
  function fieldDef(key) {
    var all = (DATA.privFields || []).concat(DATA.pubFields || []);
    for (var i = 0; i < all.length; i++) if (all[i].key === key) return all[i];
    return { key: key, label: key };
  }

  function valueOf(key) {
    var p = state.priv, pub = state.rec ? state.rec.pub : {};
    if (p && Object.prototype.hasOwnProperty.call(p, key)) return p[key];
    return pub[key] || '';
  }

  function isPhoneLike(s) {
    var d = String(s).replace(/\D/g, '');
    return d.length >= 7 && d.length <= 20 && d.length / Math.max(String(s).length, 1) > 0.6;
  }

  function maskValue(key, val) {
    if (state.revealed) return val;
    var def = fieldDef(key);
    if (!def.sensitive) return val;
    var s = String(val);

    // 打码规则优先取字段配置；未配置时按内容推断（长数字串=身份证，其余=电话）
    var mode = def.mask;
    if (!mode) {
      mode = (/^\d{15,}$/.test(s.trim())) ? 'id' : (isPhoneLike(s) ? 'phone' : 'id');
    }

    if (mode === 'id') {
      return s.length >= 10 ? s.slice(0, 6) + '********' + s.slice(-4) : s.replace(/./g, '*');
    }
    return s.split('/').map(function (p) {
      p = p.trim();
      var d = p.replace(/\D/g, '');
      return d.length >= 7 ? d.slice(0, 3) + '****' + d.slice(-4) : p.replace(/./g, '*');
    }).join(' / ');
  }

  function renderGroups() {
    var gs = (DATA.groups && DATA.groups.length) ? DATA.groups : [];
    if (!gs.length) {
      gs = [{ title: '全部信息', keys: (DATA.privFields || []).concat(DATA.pubFields || [])
        .map(function (f) { return f.key; }) }];
    }
    var html = '';
    gs.forEach(function (g) {
      var rows = '';
      g.keys.forEach(function (key) {
        var raw = valueOf(key), def = fieldDef(key);
        var content;
        if (!raw) {
          content = '<span class="row-value empty">未登记</span>';
        } else {
          var masked = def.sensitive && !state.revealed;
          content = '<span class="row-value"><span class="mono">' + esc(maskValue(key, raw)) + '</span>' +
            (masked ? '<button class="eye" data-eye="' + key + '">显示</button>' : '') + '</span>';
        }
        rows += '<div class="row"><div class="row-label">' + esc(def.label) + '</div>' +
          '<div class="row-value-wrap">' + content + '</div></div>';
      });
      html += '<div class="group"><div class="group-title">' + esc(g.title) + '</div>' + rows + '</div>';
    });
    groups.innerHTML = html;

    Array.prototype.forEach.call(groups.querySelectorAll('[data-eye]'), function (btn) {
      btn.addEventListener('click', function () {
        state.revealed = true;
        renderGroups();
        $('toggleMaskBtn').textContent = '隐藏完整号码';
        resetAutoLock();
      });
    });
  }

  function showResult() {
    var m = DATA.meta || {}, p = state.priv, pub = state.rec.pub;
    var name = p.name || '同学';
    $('resAvatar').textContent = name.charAt(0);
    $('resName').textContent = name;
    $('resClass').textContent = [m.school, m.className].filter(Boolean).join(' · ');

    var badge = $('resStatus');
    if (m.badgeField && valueOf(m.badgeField)) {
      badge.textContent = valueOf(m.badgeField);
      // 未签字 / 填写异常 用警示色，正常状态用绿色
      badge.className = 'badge ' + (/^(未|已填写)/.test(badge.textContent) ? 'badge-warn' : 'badge-ok');
    } else {
      badge.textContent = '在籍在读';
      badge.className = 'badge badge-ok';
    }

    renderGroups();

    var confirmed = lsGet(LS_OK + '_' + state.rec.idx, '');
    var n = $('confirmNote');
    if (confirmed) {
      n.hidden = false;
      n.textContent = '✓ 你曾于 ' + confirmed + ' 确认信息核对无误。';
    } else { n.hidden = true; }

    gateView.hidden = true;
    resultView.hidden = false;
    window.scrollTo(0, 0);
    resetAutoLock();
  }

  function resetAutoLock() {
    if (state.timer) clearTimeout(state.timer);
    state.timer = setTimeout(function () {
      if (state.rec) { lockNow(); toast('长时间未操作，已自动锁定'); }
    }, AUTO_LOCK_MS);
  }

  function lockNow() {
    if (state.timer) clearTimeout(state.timer);
    state.rec = null; state.priv = null; state.revealed = false;
    groups.innerHTML = '';
    resultView.hidden = true;
    gateView.hidden = false;
    tailInput.value = '';
    clearBtn.hidden = true;
    hideError();
    tailInput.focus();
  }

  // ---------------------------------------------------------------- 更正申请
  function openFixModal() {
    var m = DATA.meta || {}, p = state.priv, pub = state.rec.pub;
    var lines = ['【学籍信息更正申请】',
      '班级：' + (m.className || ''),
      '姓名：' + (p.name || ''),
      '核对时间：' + new Date().toLocaleString('zh-CN', { hour12: false }),
      '',
      '以下项目中，需要更正的请保留并在后面写出正确内容，其余请删除：', ''];
    var n = 1;
    ((DATA.groups && DATA.groups.length) ? DATA.groups : []).forEach(function (g) {
      g.keys.forEach(function (key) {
        var v = valueOf(key);
        if (!v) return;
        lines.push(n + '. ' + fieldDef(key).label + '：' + v + '　→ 正确内容为：');
        n++;
      });
    });
    lines.push('', '（更正依据：户口本 / 身份证 / 其他）');
    $('fixText').value = lines.join('\n');
    $('modal').hidden = false;
    resetAutoLock();
  }

  function copyFixText() {
    var ta = $('fixText');
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) {}
    if (!ok && navigator.clipboard) {
      navigator.clipboard.writeText(ta.value).then(function () { toast('已复制到剪贴板'); });
      return;
    }
    toast(ok ? '已复制到剪贴板' : '复制失败，请长按选中后手动复制');
  }

  // ---------------------------------------------------------------- 小工具
  function showError(msg) { errBox.hidden = false; errBox.textContent = msg; }
  function hideError() { errBox.hidden = true; }
  function flashError() { tailInput.classList.add('is-error'); setTimeout(function () { tailInput.classList.remove('is-error'); }, 900); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  var toastTimer = null;
  function toast(msg) {
    var t = $('toast');
    t.textContent = msg;
    t.hidden = false;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.hidden = true; }, 2200);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else { init(); }
})();
