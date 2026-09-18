/* Node 端冒烟测试：用与 app.js 完全相同的 WebCrypto 流程验证 data.js
 * 运行： node tools/nodecheck.js
 */
const fs = require('fs');
const path = require('path');
const { webcrypto } = require('crypto');
const crypto = webcrypto;

const ROOT = path.join(__dirname, '..');
const dataSrc = fs.readFileSync(path.join(ROOT, 'assets/data.js'), 'utf8');
const pepperSrc = fs.readFileSync(path.join(ROOT, 'assets/pepper.js'), 'utf8');
const DATA = JSON.parse(dataSrc.match(/window\.SIC_DATA\s*=\s*([\s\S]+?);\s*$/)[1]);
const PEPPER_B64 = pepperSrc.match(/PEPPER_B64\s*=\s*"([^"]+)"/)[1];

const enc = new TextEncoder();
const dec = new TextDecoder();
const b64ToBytes = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const concat = (a, b) => { const r = new Uint8Array(a.length + b.length); r.set(a, 0); r.set(b, a.length); return r; };
const toHex = (u8) => Array.from(u8).map((x) => ('0' + x.toString(16)).slice(-2)).join('');
const u32 = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);

function hmac(keyBytes, msg) {
  return crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    .then((k) => crypto.subtle.sign('HMAC', k, msg))
    .then((s) => new Uint8Array(s));
}

function hmacCtr(keyBytes, nonce, data) {
  const out = new Uint8Array(data.length);
  let pos = 0, counter = 0;
  return (function step() {
    if (pos >= data.length) return Promise.resolve(out);
    return hmac(keyBytes, concat(nonce, u32(counter))).then((block) => {
      const n = Math.min(block.length, data.length - pos);
      for (let k = 0; k < n; k++) out[pos + k] = data[pos + k] ^ block[k];
      pos += n; counter++;
      return step();
    });
  })();
}

function lookup(tail) {
  const recs = DATA.records, iter = DATA.meta.iter;
  const pwBytes = concat(b64ToBytes(PEPPER_B64), enc.encode(tail));
  return crypto.subtle.importKey('raw', pwBytes, 'PBKDF2', false, ['deriveBits']).then((baseKey) => {
    let chain = Promise.resolve(null);
    for (let i = 0; i < recs.length; i += 8) {
      const slice = recs.slice(i, i + 8);
      chain = chain.then((hit) => hit || Promise.all(slice.map((r) =>
        crypto.subtle.deriveBits(
          { name: 'PBKDF2', salt: b64ToBytes(r.salt), iterations: iter, hash: 'SHA-256' },
          baseKey, 256).then((b) => new Uint8Array(b))
      )).then((masters) => {
        let inner = Promise.resolve(null);
        slice.forEach((r, j) => {
          inner = inner.then((hit) => hit || hmac(masters[j], enc.encode('idx')).then((h) =>
            toHex(h.slice(0, 4)) === r.idx ? decrypt(masters[j], r) : null));
        });
        return inner;
      }));
    }
    return chain;
  });
}

function decrypt(master, rec) {
  const nonce = b64ToBytes(rec.nonce), ct = b64ToBytes(rec.ct);
  return Promise.all([hmac(master, enc.encode('enc')), hmac(master, enc.encode('mac'))])
    .then((k) => hmac(k[1], concat(nonce, ct)).then((tag) => {
      if (toHex(tag) !== toHex(b64ToBytes(rec.tag))) throw new Error('完整性校验失败');
      return hmacCtr(k[0], nonce, ct);
    }))
    .then((pt) => ({ rec, priv: JSON.parse(dec.decode(pt)) }));
}

(async () => {
  const tails = JSON.parse(fs.readFileSync(path.join(__dirname, '.test_tails.json'), 'utf8'));
  const entries = Object.entries(tails);
  console.log('记录数：%d  迭代：%d', DATA.records.length, DATA.meta.iter);
  let okCount = 0;
  for (const [idx, tail] of entries) {
    const t0 = Date.now();
    const res = await lookup(tail);
    const ms = Date.now() - t0;
    if (!res) { console.log('  ✗ %s 未命中', tail); continue; }
    if (res.rec.idx !== idx) { console.log('  ✗ %s 命中错误记录', tail); continue; }
    okCount++;
    if (okCount <= 3 || tail === entries[0][1]) {
      console.log('  ✓ %s -> %s | %s | 班%s 序%s | %s | %s | %s | %dms',
        tail, res.priv.name, res.priv.idCard, res.rec.pub.ban, res.priv.seq,
        res.priv.sex, res.priv.nation, res.priv.srcSchool, ms);
    }
    if (okCount === 4) console.log('  …（其余记录逐条验证中）');
  }
  let wrong = 0;
  for (const bad of ['000000', '123456', '99999X']) {
    if (await lookup(bad)) wrong++;
  }
  console.log('-'.repeat(52));
  console.log('正确口令命中：%d / %d', okCount, entries.length);
  console.log('错误口令误命中：%d（应为 0）', wrong);
  console.log('结果：%s', wrong === 0 && okCount === entries.length ? '全部通过 ✅' : '存在问题 ❌');
})();
