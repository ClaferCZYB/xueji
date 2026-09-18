# -*- coding: utf-8 -*-
"""
学籍信息核对系统 —— 数据构建脚本（配置化通用版）
=================================================
用途：从学生信息 xlsx 生成前端可用的加密数据文件 assets/data.js

★ 换一张新表时，只需要修改下面的 ===== CONFIG 配置区 ===== ，其余代码不用动。

安全设计（重要）
----------------
1. data.js 中不存在任何明文的姓名 / 身份证号 / 电话，只有密文与盐值。
2. 密钥派生：master = PBKDF2-HMAC-SHA256(PEPPER + 身份证后六位, salt_i, ITER)
   - PEPPER 是构建时随机生成的常量，保存在 assets/pepper.js（与 data.js 分离）
   - salt_i 每条记录独立随机
3. 记录定位：idx = HMAC-SHA256(master, "idx")[:4]，避免直接存口令索引被反查。
4. 数据加密：HMAC-SHA256-CTR 流加密 + HMAC-SHA256 认证标签（Encrypt-then-MAC）。
5. 因此：拿到 data.js 的人，必须对每个后六位组合跑数万次 PBKDF2 才能试出一条记录。

用法
----
    python build_data.py                      # 使用 CONFIG 里配置的 xlsx
    python build_data.py "D:/path/表.xlsx"     # 临时指定其他文件
    python build_data.py --iter 200000        # 提高迭代次数（更安全，但核验更慢）
"""

import os
import re
import sys
import json
import hmac
import base64
import hashlib
import datetime
import argparse

try:
    import openpyxl
except ImportError:
    sys.exit("缺少依赖 openpyxl，请先安装：pip install openpyxl")

# ============================================================================
#                          ★★★ CONFIG 配置区 ★★★
#                          换表时只改这里即可
# ============================================================================

XLSX_PATH = r"C:/Users/86187/Downloads/潼南中学2026年高2029届上报学籍学生信息确认表.xlsx"
SHEET_NAME = "高2029届学生信息确认表"
HEADER_ROWS = 1            # 表头占几行（数据从第 HEADER_ROWS+1 行开始）
DEFAULT_ITER = 50000       # PBKDF2 迭代次数

# 页面显示用的标题信息
SCHOOL_NAME = "重庆市潼南中学"
CLASS_NAME = "高2029届13班"
PAGE_TITLE = "学籍信息核对确认"
BADGE_FIELD = "sign"       # 结果页右上角徽章取哪个字段

# 列索引（0-based，从左到右 A=0, B=1, ...）
C_BAN, C_SEQ, C_NAME, C_SEX, C_ID, C_NATION, C_SRC, C_SIGN = range(8)

# 公开字段（全班一致、无个人隐私风险，明文存放）
PUB_FIELDS = [
    {"key": "ban", "label": "班级"},
]

# 私密字段（加密存放）
#   sensitive=True 默认打码；mask 指定打码规则："id"=身份证（保留前6后4），"phone"=电话（保留前3后4）
PRIV_FIELDS = [
    {"key": "seq", "label": "班内序号"},
    {"key": "name", "label": "姓名"},
    {"key": "sex", "label": "性别"},
    {"key": "idCard", "label": "身份证号", "sensitive": True, "mask": "id"},
    {"key": "nation", "label": "民族"},
    {"key": "srcSchool", "label": "生源学校"},
    {"key": "sign", "label": "签字确认"},
]

# 页面分组展示顺序（key 必须来自上面的 pub/priv 字段）
GROUPS = [
    {"title": "基本信息", "keys": ["name", "sex", "nation", "idCard"]},
    {"title": "学籍登记信息", "keys": ["ban", "seq", "srcSchool"]},
    {"title": "确认状态", "keys": ["sign"]},
]

# ============================================================================
#                          以下为通用代码，一般无需修改
# ============================================================================

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ASSETS = os.path.join(ROOT, "assets")
DATA_JS = os.path.join(ASSETS, "data.js")
PEPPER_JS = os.path.join(ASSETS, "pepper.js")
IDX_HTML = os.path.join(ROOT, "index.html")
DATA_START_ROW = HEADER_ROWS + 1

PRIV_KEYS = [f["key"] for f in PRIV_FIELDS]
PUB_KEYS = [f["key"] for f in PUB_FIELDS]


# ----------------------------------------------------------------------------
# 清洗工具
# ----------------------------------------------------------------------------
def clean(v):
    if v is None:
        return ""
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    s = str(v).replace("\u00a0", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return "" if s in ("None", "nan", "/", "-", "无") else s


def clean_id(v):
    s = clean(v).replace(" ", "").upper()
    return s[:-2] if s.endswith(".0") else s


def b64(b):
    return base64.b64encode(b).decode("ascii")


def pbkdf2(password: bytes, salt: bytes, iterations: int, dklen: int = 32):
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen)


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def hmac_ctr_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 生成 keystream 的 CTR 流加密（加解密同函数）。"""
    out = bytearray()
    counter = pos = 0
    while pos < len(data):
        block = hmac_sha256(key, nonce + counter.to_bytes(4, "big"))
        chunk = data[pos:pos + len(block)]
        out.extend(a ^ b for a, b in zip(chunk, block))
        pos += len(block)
        counter += 1
    return bytes(out)


def encrypt_record(pepper: bytes, tail6: str, salt: bytes, nonce: bytes,
                   iterations: int, plaintext: bytes):
    master = pbkdf2(pepper + tail6.encode("utf-8"), salt, iterations)
    idx = hmac_sha256(master, b"idx")[:4].hex()
    enc_key = hmac_sha256(master, b"enc")
    mac_key = hmac_sha256(master, b"mac")
    ct = hmac_ctr_crypt(enc_key, nonce, plaintext)
    tag = hmac_sha256(mac_key, nonce + ct)
    return idx, ct, tag


# ----------------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------------
def load_or_create_pepper():
    if os.path.exists(PEPPER_JS):
        m = re.search(r'PEPPER_B64\s*=\s*"([^"]+)"',
                      open(PEPPER_JS, encoding="utf-8").read())
        if m:
            return base64.b64decode(m.group(1))
    pepper = os.urandom(32)
    os.makedirs(ASSETS, exist_ok=True)
    with open(PEPPER_JS, "w", encoding="utf-8") as f:
        f.write("// 自动生成，请勿手工修改。\n"
                "// 与 data.js 分离存放；重建数据时若此文件存在会自动复用。\n"
                "// 若怀疑密钥泄露，删除本文件后重新运行 build_data.py 即可全部重新加密。\n"
                'window.SIC_PEPPER_B64 = "%s";\n' % b64(pepper))
    return pepper


def read_rows(xlsx_path, sheet_name):
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)
    ws = wb[sheet_name] if sheet_name in wb.sheetnames else wb.worksheets[0]
    out = []
    for r in ws.iter_rows(min_row=DATA_START_ROW, max_row=ws.max_row, values_only=True):
        vals = [clean(x) for x in r]
        if not any(vals):
            continue
        out.append(vals)
    return out


def build(xlsx_path, sheet_name, iterations):
    pepper = load_or_create_pepper()
    raw_rows = read_rows(xlsx_path, sheet_name)
    if not raw_rows:
        sys.exit("未读取到任何数据，请检查 xlsx 路径与工作表名。")

    records, warnings, tail_map = [], [], {}
    stat = {"signed": 0, "unsigned": 0, "odd": 0}

    for vals in raw_rows:
        def col(i):
            return vals[i] if i < len(vals) else ""

        name = col(C_NAME)
        idcard = clean_id(col(C_ID))
        if not name and not idcard:
            continue
        if len(idcard) < 6:
            warnings.append("序号 %s（%s）身份证号缺失或过短，已跳过" % (col(C_SEQ), name))
            continue

        tail6 = idcard[-6:].upper()
        if tail6 in tail_map:
            warnings.append("身份证后六位 %s 重复（%s 与 %s），只能有一人被检索到"
                            % (tail6, tail_map[tail6], name))
        tail_map[tail6] = name

        if len(idcard) != 18:
            warnings.append("⚠ %s（序号 %s）身份证号为 %d 位，疑似录入有误：%s"
                            % (name, col(C_SEQ), len(idcard), idcard))

        # 签字列：与姓名一致才算已签字；填了别的内容原样展示，便于发现填写异常
        sign_raw = col(C_SIGN)
        if not sign_raw:
            sign = "未签字"
            stat["unsigned"] += 1
        elif sign_raw == name:
            sign = "已签字确认"
            stat["signed"] += 1
        else:
            sign = "已填写：" + sign_raw
            stat["odd"] += 1
            warnings.append("⚠ %s（序号 %s）签字列非本人签名，原样展示：%s"
                            % (name, col(C_SEQ), sign_raw))

        priv = {
            "seq": col(C_SEQ),
            "name": name,
            "sex": col(C_SEX),
            "idCard": idcard,
            "nation": col(C_NATION),
            "srcSchool": col(C_SRC),
            "sign": sign,
        }
        pub = {"ban": col(C_BAN)}

        plaintext = json.dumps({k: priv[k] for k in PRIV_KEYS},
                               ensure_ascii=False).encode("utf-8")
        salt, nonce = os.urandom(16), os.urandom(12)
        idx, ct, tag = encrypt_record(pepper, tail6, salt, nonce, iterations, plaintext)

        records.append({
            "idx": idx, "salt": b64(salt), "nonce": b64(nonce),
            "tag": b64(tag), "ct": b64(ct), "pub": pub,
        })

    data = {
        "meta": {
            "title": PAGE_TITLE,
            "school": SCHOOL_NAME,
            "className": CLASS_NAME,
            "badgeField": BADGE_FIELD,
            "count": len(records),
            "updated": datetime.date.today().isoformat(),
            "iter": iterations,
            "algo": "PBKDF2-HMAC-SHA256 + HMAC-SHA256-CTR + HMAC-SHA256 tag",
        },
        "pubFields": PUB_FIELDS,
        "privFields": PRIV_FIELDS,
        "groups": GROUPS,
        "records": records,
    }

    os.makedirs(ASSETS, exist_ok=True)
    with open(DATA_JS, "w", encoding="utf-8") as f:
        f.write("// 自动生成，请勿手工修改。重新生成请运行 tools/build_data.py\n")
        f.write("// 本文件不含任何明文个人信息，全部字段均已加密。\n")
        f.write("window.SIC_DATA = ")
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
        f.write(";\n")

    # 更新 index.html 里 data.js 的版本号，避免浏览器缓存旧数据
    stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    if os.path.exists(IDX_HTML):
        html = open(IDX_HTML, encoding="utf-8").read()
        new_html = re.sub(r'(assets/data\.js\?v=)[^"\']+', r"\g<1>" + stamp, html)
        if new_html != html:
            open(IDX_HTML, "w", encoding="utf-8").write(new_html)
            print("已更新 index.html 中 data.js 版本号 -> %s" % stamp)

    print("=" * 62)
    print("生成完成：%s" % DATA_JS)
    print("  学生记录数：%d" % len(records))
    print("  学校 / 班级：%s  %s" % (SCHOOL_NAME, CLASS_NAME))
    print("  PBKDF2 迭代：%d 次" % iterations)
    print("  文件大小：%.1f KB" % (os.path.getsize(DATA_JS) / 1024.0))
    if stat["signed"] or stat["unsigned"] or stat["odd"]:
        print("  签字情况：已签 %d 人 / 未签 %d 人 / 填写异常 %d 人"
              % (stat["signed"], stat["unsigned"], stat["odd"]))
    if warnings:
        print("-" * 62)
        for w in warnings:
            print("  ! " + w)
    print("=" * 62)


def main():
    ap = argparse.ArgumentParser(description="生成学籍信息核对系统的加密数据文件")
    ap.add_argument("xlsx", nargs="?", default=XLSX_PATH, help="xlsx 源文件路径")
    ap.add_argument("--sheet", default=SHEET_NAME, help="工作表名")
    ap.add_argument("--iter", type=int, default=DEFAULT_ITER, help="PBKDF2 迭代次数")
    a = ap.parse_args()
    build(a.xlsx, a.sheet, a.iter)


if __name__ == "__main__":
    main()
