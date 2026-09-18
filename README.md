# 学籍信息核对确认系统

学生输入**本人身份证号后 6 位**，即可在线查验自己在《上报学籍学生信息确认表》中所在行的完整信息。
纯静态页面，可直接部署到 **GitHub Pages**（也可用 Vercel / EdgeOne 等任意静态托管）。

本版本为**配置化通用版**：换一张新表只需修改 `tools/build_data.py` 顶部的配置区，其余代码无需改动。

## 安全设计（务必先读）

GitHub Pages 是**公开网站**，任何人都能下载页面文件。因此本系统**不是**"明文数据 + 口令比对"，
而是真正的加密查询：

| 措施 | 说明 |
|------|------|
| 全量加密 | `data.js` 中只有密文，**不存在任何明文**姓名 / 身份证号 / 民族 / 生源学校 |
| 密钥派生 | `PBKDF2-HMAC-SHA256`（默认 5 万次迭代），口令 = 本人身份证后 6 位 + 构建 PEPPER |
| 逐条独立 | 每条记录独立盐值与密钥，破解一条不影响其他记录 |
| 完整性校验 | HMAC-SHA256 认证标签，密文被篡改时拒绝展示 |
| 防在线枚举 | 连错 5 次锁定 3 分钟；离开页面 5 分钟自动锁定 |
| 默认打码 | 身份证号默认打码（保留前 6 后 4），需点击才展开 |

**风险边界（必须知晓）**：纯静态站点无法做到绝对安全。理论上攻击者可离线暴力枚举
10⁶ 种后六位组合——5 万次 PBKDF2 迭代下，单条记录枚举约需数小时至数天。
若需更强保护，把 `DEFAULT_ITER` 提高到 200000（代价：学生核验等待时间变长），
或改用带服务端（如 Cloudflare Workers）的方案。

## 目录结构

```
xueji-info-check/
├── index.html              # 页面入口
├── assets/
│   ├── style.css           # 样式
│   ├── app.js              # 核验逻辑（WebCrypto，全部本地计算）
│   ├── data.js             # ★ 加密数据（构建脚本生成）
│   └── pepper.js           # ★ 构建密钥（构建脚本生成，勿外传完整项目）
├── tools/
│   ├── build_data.py       # ★ 数据构建脚本（xlsx → data.js，顶部为配置区）
│   ├── selfcheck.py        # Python 自检（全量解密验证）
│   └── nodecheck.js        # Node 自检（模拟浏览器 WebCrypto 流程）
└── README.md
```

## 部署到 GitHub Pages

```bash
cd xueji-info-check
git init
git add index.html assets/ README.md
git commit -m "init: 学籍信息核对系统"
git branch -M main
git remote add origin https://github.com/<你的用户名>/<仓库名>.git
git push -u origin main
```

仓库 **Settings → Pages → Source** 选 `Deploy from a branch`，分支 `main`，目录 `/ (root)`，保存。
约 1 分钟后访问 `https://<用户名>.github.io/<仓库名>/`，手机扫码即可使用。

> ⚠️ `tools/.test_tails.json`（自检口令缓存）**绝不能上传**，`.gitignore` 已排除。

## 更新数据 / 换新表

**只需两步**：改配置 → 重跑脚本。

1. 打开 `tools/build_data.py`，修改顶部配置区：

   ```python
   XLSX_PATH = r"..."          # 新表路径
   SHEET_NAME = "..."          # 工作表名
   HEADER_ROWS = 1             # 表头占几行
   SCHOOL_NAME = "重庆市潼南中学"
   CLASS_NAME = "高2029届13班"
   BADGE_FIELD = "sign"        # 右上角徽章字段
   C_BAN, C_SEQ, ... = range(8)  # 各字段所在列（A=0, B=1, ...）
   PUB_FIELDS / PRIV_FIELDS / GROUPS   # 字段定义与分组
   ```

2. 运行并推送：

   ```bash
   python tools/build_data.py
   python tools/selfcheck.py      # 建议跑一次
   git add assets/data.js index.html && git commit -m "update: 更新学生数据" && git push
   ```

脚本会自动：更新 `index.html` 中 `data.js` 的版本号（防浏览器缓存）、
检出**身份证号位数异常**、**后六位重复**、**签字列填写异常**并打印警告。

## 本地预览

```bash
python -m http.server 8900
# 浏览器打开 http://127.0.0.1:8900/
```

WebCrypto 需要安全上下文，`file://` 直接打开**不可用**，必须走 http/https。

## 常见问题

| 现象 | 原因与处理 |
|------|-----------|
| 提示"不支持安全加密模块" | WebCrypto 需要 HTTPS 或 localhost；确认通过 `https://` 访问 |
| 核验要等 1~3 秒 | 正常：56 条记录 × 5 万次 PBKDF2，是刻意保留的安全成本 |
| 学生说"未找到匹配记录" | 核对是否输错（末位 X 需大写）；或该生信息未录入本次表格 |
| 想更换全体口令体系 | 删除 `assets/pepper.js` 后重新构建，所有记录将用新 PEPPER 重新加密 |
| 修改了 app.js 但页面没变 | 把 `index.html` 里 `app.js?v=` 的版本号 +1 |
