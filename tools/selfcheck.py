# -*- coding: utf-8 -*-
"""
自检脚本：验证 data.js 能被正确解密，且错误口令无法命中。
模拟前端 app.js 的同样流程（PBKDF2 -> HMAC idx -> HMAC-CTR -> 校验 tag）。

用法： python selfcheck.py
"""
import os
import re
import json
import hmac
import base64
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ASSETS = os.path.join(ROOT, "assets")

sys.path.insert(0, HERE)
from build_data import (pbkdf2, hmac_sha256, hmac_ctr_crypt, load_or_create_pepper,  # noqa: E402
                        read_rows, clean_id, XLSX_PATH, SHEET_NAME, C_NAME, C_ID, C_SEQ)


def load_data():
    src = open(os.path.join(ASSETS, "data.js"), encoding="utf-8").read()
    m = re.search(r"window\.SIC_DATA\s*=\s*(.+?);\s*$", src, re.S)
    return json.loads(m.group(1))


def load_pepper():
    src = open(os.path.join(ASSETS, "pepper.js"), encoding="utf-8").read()
    m = re.search(r'PEPPER_B64\s*=\s*"([^"]+)"', src)
    return base64.b64decode(m.group(1))


def build_test_tails(data, pepper, it):
    """从原始 xlsx 现算 每条记录 idx -> 正确后六位"""
    rows = read_rows(XLSX_PATH, SHEET_NAME)
    out = {}
    for vals in rows:
        idc = clean_id(vals[C_ID])
        if len(idc) < 6:
            continue
        tail = idc[-6:].upper()
        for r in data["records"]:
            m = pbkdf2(pepper + tail.encode(), base64.b64decode(r["salt"]), it)
            if hmac_sha256(m, b"idx")[:4].hex() == r["idx"]:
                out[r["idx"]] = tail
                break
    return out


def main():
    data = load_data()
    pepper = load_pepper()
    recs = data["records"]
    it = data["meta"]["iter"]
    print("记录数：%d    迭代次数：%d" % (len(recs), it))

    cache = os.path.join(HERE, ".test_tails.json")
    try:
        if os.path.exists(cache):
            tails = json.load(open(cache, encoding="utf-8"))
        else:
            print("首次运行，正在从 xlsx 生成测试口令表…")
            tails = build_test_tails(data, pepper, it)
            json.dump(tails, open(cache, "w", encoding="utf-8"), ensure_ascii=False)
            print("（已缓存到 tools/.test_tails.json，含明文口令，请勿上传仓库）")
    except Exception as e:
        print("无法生成测试口令表：%s" % e)
        sys.exit(1)

    ok = 0
    for r in recs:
        pw = tails.get(r["idx"])
        if pw is None:
            continue
        master = pbkdf2(pepper + pw.encode(), base64.b64decode(r["salt"]), it)
        if hmac_sha256(master, b"idx")[:4].hex() != r["idx"]:
            print("  ✗ 口令 %s 索引不匹配" % pw)
            continue
        enc_key = hmac_sha256(master, b"enc")
        mac_key = hmac_sha256(master, b"mac")
        nonce = base64.b64decode(r["nonce"])
        ct = base64.b64decode(r["ct"])
        if hmac_sha256(mac_key, nonce + ct) != base64.b64decode(r["tag"]):
            print("  ✗ 口令 %s 完整性校验失败" % pw)
            continue
        pt = json.loads(hmac_ctr_crypt(enc_key, nonce, ct).decode("utf-8"))
        ok += 1
        print("  ✓ %-6s -> %-5s  %s" % (pw, pt["name"], pt["idCard"]))

    wrong_hit = 0
    for wrong in ["000000", "123456", "99999X", "12345X"]:
        for r in recs:
            m = pbkdf2(pepper + wrong.encode(), base64.b64decode(r["salt"]), it)
            if hmac_sha256(m, b"idx")[:4].hex() == r["idx"]:
                wrong_hit += 1
    print("-" * 50)
    print("正确口令解密成功：%d / %d" % (ok, len(tails)))
    print("错误口令误命中次数：%d （应为 0）" % wrong_hit)
    print("结果：%s" % ("全部通过 ✅" if wrong_hit == 0 and ok == len(tails) else "存在问题 ❌"))


if __name__ == "__main__":
    main()
