import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'

type Bindings = {
  DB: D1Database
  ADMIN_SECRET: string
}

const app = new Hono<{ Bindings: Bindings }>()

app.use('/api/*', cors())
app.use('/static/*', serveStatic({ root: './' }))

// ==================== 公開API ====================

// イベント一覧（検索・フィルター対応）
app.get('/api/events', async (c) => {
  const { date, venue_id, area, genre, month, keyword } = c.req.query()
  const db = c.env.DB

  let query = `
    SELECT e.*, v.name as venue_name, v.area as venue_area, v.address as venue_address
    FROM events e
    JOIN venues v ON e.venue_id = v.id
    WHERE e.status = 'published'
  `
  const params: string[] = []

  if (date) {
    query += ` AND e.event_date = ?`
    params.push(date)
  }
  if (month) {
    query += ` AND e.event_date LIKE ?`
    params.push(`${month}%`)
  }
  if (venue_id) {
    query += ` AND e.venue_id = ?`
    params.push(venue_id)
  }
  if (area) {
    query += ` AND v.area = ?`
    params.push(area)
  }
  if (genre) {
    query += ` AND e.genre LIKE ?`
    params.push(`%${genre}%`)
  }
  if (keyword) {
    query += ` AND (e.title LIKE ? OR e.artists LIKE ? OR e.description LIKE ?)`
    params.push(`%${keyword}%`, `%${keyword}%`, `%${keyword}%`)
  }

  query += ` ORDER BY e.event_date ASC, e.start_time ASC`

  try {
    const stmt = db.prepare(query)
    const result = await stmt.bind(...params).all()
    return c.json({ events: result.results })
  } catch (e) {
    return c.json({ error: 'DB error', detail: String(e) }, 500)
  }
})

// 会場一覧
app.get('/api/venues', async (c) => {
  const db = c.env.DB
  try {
    const result = await db.prepare('SELECT * FROM venues ORDER BY area, name').all()
    return c.json({ venues: result.results })
  } catch (e) {
    return c.json({ error: 'DB error' }, 500)
  }
})

// イベント詳細
app.get('/api/events/:id', async (c) => {
  const id = c.req.param('id')
  const db = c.env.DB
  try {
    const result = await db.prepare(`
      SELECT e.*, v.name as venue_name, v.area as venue_area, v.address as venue_address, v.website as venue_website
      FROM events e JOIN venues v ON e.venue_id = v.id
      WHERE e.id = ? AND e.status = 'published'
    `).bind(id).first()
    if (!result) return c.json({ error: 'Not found' }, 404)
    return c.json({ event: result })
  } catch (e) {
    return c.json({ error: 'DB error' }, 500)
  }
})

// ==================== 管理者API ====================

// シンプルな認証ミドルウェア
const authMiddleware = async (c: any, next: any) => {
  const auth = c.req.header('Authorization') || ''
  const token = auth.replace('Bearer ', '')
  
  // セッショントークンをKVやDBで管理する本格実装の代わりに
  // シンプルなセッション確認（本番はJWT推奨）
  if (!token || token === 'null') {
    return c.json({ error: 'Unauthorized' }, 401)
  }
  // DBからセッション確認（今回はAdminトークンをDBに保存する簡易方式）
  const db = c.env.DB
  try {
    const admin = await db.prepare('SELECT id FROM admins WHERE session_token = ?').bind(token).first()
    if (!admin) {
      return c.json({ error: 'Unauthorized' }, 401)
    }
    c.set('adminId', admin.id)
  } catch {
    return c.json({ error: 'Unauthorized' }, 401)
  }
  await next()
}

// 管理者ログイン
app.post('/api/admin/login', async (c) => {
  const { username, password } = await c.req.json()
  const db = c.env.DB

  // パスワードをSHA-256でハッシュ化
  const encoder = new TextEncoder()
  const data = encoder.encode(password)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

  try {
    const admin = await db.prepare(
      'SELECT id, username FROM admins WHERE username = ? AND password_hash = ?'
    ).bind(username, hashHex).first()

    if (!admin) {
      return c.json({ error: 'ユーザー名またはパスワードが違います' }, 401)
    }

    // セッショントークン生成
    const tokenBytes = new Uint8Array(32)
    crypto.getRandomValues(tokenBytes)
    const sessionToken = Array.from(tokenBytes).map(b => b.toString(16).padStart(2, '0')).join('')

    // DBにセッション保存
    await db.prepare('UPDATE admins SET session_token = ? WHERE id = ?').bind(sessionToken, admin.id).run()

    return c.json({ token: sessionToken, username: admin.username })
  } catch (e) {
    return c.json({ error: 'Login error', detail: String(e) }, 500)
  }
})

// 管理者ログアウト
app.post('/api/admin/logout', authMiddleware, async (c) => {
  const adminId = c.get('adminId')
  const db = c.env.DB
  await db.prepare('UPDATE admins SET session_token = NULL WHERE id = ?').bind(adminId).run()
  return c.json({ success: true })
})

// 管理者: 全イベント取得（下書き含む）
app.get('/api/admin/events', authMiddleware, async (c) => {
  const db = c.env.DB
  const { month } = c.req.query()
  let query = `
    SELECT e.*, v.name as venue_name, v.area as venue_area
    FROM events e JOIN venues v ON e.venue_id = v.id
  `
  const params: string[] = []
  if (month) {
    query += ` WHERE e.event_date LIKE ?`
    params.push(`${month}%`)
  }
  query += ` ORDER BY e.event_date DESC, e.start_time ASC`

  try {
    const result = await db.prepare(query).bind(...params).all()
    return c.json({ events: result.results })
  } catch (e) {
    return c.json({ error: 'DB error' }, 500)
  }
})

// 管理者: イベント作成
app.post('/api/admin/events', authMiddleware, async (c) => {
  const body = await c.req.json()
  const db = c.env.DB
  const { venue_id, title, description, event_date, start_time, open_time, end_time,
          artists, genre, charge_info, ticket_url, image_url, status } = body

  try {
    const result = await db.prepare(`
      INSERT INTO events (venue_id, title, description, event_date, start_time, open_time, end_time,
        artists, genre, charge_info, ticket_url, image_url, status, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).bind(venue_id, title, description || '', event_date, start_time || '', open_time || '',
            end_time || '', artists || '', genre || '', charge_info || '', ticket_url || '',
            image_url || '', status || 'published').run()
    return c.json({ id: result.meta.last_row_id, success: true })
  } catch (e) {
    return c.json({ error: 'Insert error', detail: String(e) }, 500)
  }
})

// 管理者: イベント更新
app.put('/api/admin/events/:id', authMiddleware, async (c) => {
  const id = c.req.param('id')
  const body = await c.req.json()
  const db = c.env.DB
  const { venue_id, title, description, event_date, start_time, open_time, end_time,
          artists, genre, charge_info, ticket_url, image_url, status } = body

  try {
    await db.prepare(`
      UPDATE events SET venue_id=?, title=?, description=?, event_date=?, start_time=?,
        open_time=?, end_time=?, artists=?, genre=?, charge_info=?, ticket_url=?, image_url=?,
        status=?, updated_at=CURRENT_TIMESTAMP
      WHERE id=?
    `).bind(venue_id, title, description || '', event_date, start_time || '', open_time || '',
            end_time || '', artists || '', genre || '', charge_info || '', ticket_url || '',
            image_url || '', status || 'published', id).run()
    return c.json({ success: true })
  } catch (e) {
    return c.json({ error: 'Update error', detail: String(e) }, 500)
  }
})

// 管理者: イベント削除
app.delete('/api/admin/events/:id', authMiddleware, async (c) => {
  const id = c.req.param('id')
  const db = c.env.DB
  try {
    await db.prepare('DELETE FROM events WHERE id = ?').bind(id).run()
    return c.json({ success: true })
  } catch (e) {
    return c.json({ error: 'Delete error' }, 500)
  }
})

// 管理者: 会場一覧取得
app.get('/api/admin/venues', authMiddleware, async (c) => {
  const db = c.env.DB
  try {
    const result = await db.prepare('SELECT * FROM venues ORDER BY area, name').all()
    return c.json({ venues: result.results })
  } catch (e) {
    return c.json({ error: 'DB error' }, 500)
  }
})

// 管理者: 会場作成
app.post('/api/admin/venues', authMiddleware, async (c) => {
  const body = await c.req.json()
  const db = c.env.DB
  const { name, area, address, phone, website, description } = body
  try {
    const result = await db.prepare(`
      INSERT INTO venues (name, area, address, phone, website, description)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(name, area, address || '', phone || '', website || '', description || '').run()
    return c.json({ id: result.meta.last_row_id, success: true })
  } catch (e) {
    return c.json({ error: 'Insert error', detail: String(e) }, 500)
  }
})

// 管理者: 会場更新
app.put('/api/admin/venues/:id', authMiddleware, async (c) => {
  const id = c.req.param('id')
  const body = await c.req.json()
  const db = c.env.DB
  const { name, area, address, phone, website, description } = body
  try {
    await db.prepare(`
      UPDATE venues SET name=?, area=?, address=?, phone=?, website=?, description=?, updated_at=CURRENT_TIMESTAMP
      WHERE id=?
    `).bind(name, area, address || '', phone || '', website || '', description || '', id).run()
    return c.json({ success: true })
  } catch (e) {
    return c.json({ error: 'Update error' }, 500)
  }
})

// 管理者: 会場削除
app.delete('/api/admin/venues/:id', authMiddleware, async (c) => {
  const id = c.req.param('id')
  const db = c.env.DB
  try {
    await db.prepare('DELETE FROM venues WHERE id = ?').bind(id).run()
    return c.json({ success: true })
  } catch (e) {
    return c.json({ error: 'Delete error' }, 500)
  }
})

// 管理者: パスワード変更
app.put('/api/admin/password', authMiddleware, async (c) => {
  const adminId = c.get('adminId')
  const { current_password, new_password } = await c.req.json()
  const db = c.env.DB

  const hash = async (pw: string) => {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw))
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
  }

  const currentHash = await hash(current_password)
  const admin = await db.prepare('SELECT id FROM admins WHERE id = ? AND password_hash = ?')
    .bind(adminId, currentHash).first()
  if (!admin) return c.json({ error: '現在のパスワードが違います' }, 400)

  const newHash = await hash(new_password)
  await db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').bind(newHash, adminId).run()
  return c.json({ success: true })
})

// ==================== フロントエンド ====================

// 管理者ページ
app.get('/admin', (c) => {
  return c.html(adminHTML())
})
app.get('/admin/*', (c) => {
  return c.html(adminHTML())
})

// メインページ（全ルートをSPAに）
app.get('*', (c) => {
  return c.html(mainHTML())
})

// ==================== HTML テンプレート ====================

function mainHTML() {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>熊本ライブスケジュール | KUMAMOTO LIVE GUIDE</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700;900&family=Bebas+Neue&family=Oswald:wght@600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.0/css/all.min.css">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --red:    #ff2d55;
      --red-dim: rgba(255,45,85,0.18);
      --cyan:   #00e5ff;
      --cyan-dim: rgba(0,229,255,0.12);
      --gold:   #ffd60a;
      --bg:     #080808;
      --bg1:    #111114;
      --bg2:    #18181c;
      --bg3:    #202026;
      --border: rgba(255,255,255,0.07);
      --text:   #f0f0f0;
      --muted:  #666;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Noto Sans JP', sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* ─── ノイズ質感オーバーレイ ─── */
    body::before {
      content: '';
      position: fixed; inset: 0; z-index: 0; pointer-events: none;
      background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.04'/%3E%3C/svg%3E");
      opacity: 0.5;
    }

    /* ─── スクロールバー ─── */
    ::-webkit-scrollbar { width: 4px; }
    ::-webkit-scrollbar-track { background: #0a0a0a; }
    ::-webkit-scrollbar-thumb { background: var(--red); border-radius: 2px; }

    /* ─── ナビ ─── */
    #topnav {
      position: sticky; top: 0; z-index: 100;
      display: flex; align-items: center; justify-content: space-between;
      padding: 0 24px; height: 58px;
      background: rgba(8,8,8,0.92);
      border-bottom: 1px solid var(--border);
      backdrop-filter: blur(14px);
    }
    .logo {
      font-family: 'Bebas Neue', sans-serif;
      font-size: 26px; letter-spacing: 0.08em;
      background: linear-gradient(90deg, #fff 30%, var(--red) 100%);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .logo-sub {
      font-size: 10px; letter-spacing: 0.25em; color: var(--muted);
      text-transform: uppercase; margin-left: 2px;
      font-family: 'Noto Sans JP', sans-serif;
      -webkit-text-fill-color: var(--muted);
    }

    /* ─── ヒーロー ─── */
    #hero {
      position: relative; overflow: hidden;
      padding: 64px 24px 56px;
      display: flex; flex-direction: column; align-items: center; text-align: center;
    }
    #hero::before {
      content: '';
      position: absolute; inset: 0; z-index: 0;
      background:
        radial-gradient(ellipse 80% 60% at 20% 50%, rgba(255,45,85,0.13) 0%, transparent 70%),
        radial-gradient(ellipse 60% 50% at 80% 40%, rgba(0,229,255,0.07) 0%, transparent 70%);
    }
    .hero-eyebrow {
      position: relative; z-index: 1;
      display: inline-flex; align-items: center; gap: 8px;
      font-size: 11px; letter-spacing: 0.3em; text-transform: uppercase;
      color: var(--red); border: 1px solid var(--red-dim);
      background: var(--red-dim); border-radius: 100px;
      padding: 4px 16px; margin-bottom: 20px;
    }
    .hero-title {
      position: relative; z-index: 1;
      font-family: 'Oswald', sans-serif;
      font-size: clamp(36px, 6vw, 72px);
      font-weight: 700; line-height: 1.05;
      letter-spacing: -0.01em;
      margin-bottom: 16px;
    }
    .hero-title .hl { color: var(--red); }
    .hero-sub {
      position: relative; z-index: 1;
      font-size: 14px; color: var(--muted); margin-bottom: 40px;
      letter-spacing: 0.05em;
    }

    /* 走るスペクトルライン */
    .spectrum-line {
      position: absolute; bottom: 0; left: 0; right: 0; height: 2px; z-index: 1;
      background: linear-gradient(90deg,
        transparent 0%, var(--red) 30%, var(--cyan) 60%, transparent 100%);
      animation: scanLine 3s linear infinite;
      background-size: 200% 100%;
    }
    @keyframes scanLine {
      0%   { background-position: -100% 0; }
      100% { background-position: 200% 0; }
    }

    /* ─── 検索パネル ─── */
    #searchPanel {
      position: relative; z-index: 2;
      background: rgba(255,255,255,0.03);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 20px 24px;
      width: 100%; max-width: 860px;
      backdrop-filter: blur(8px);
    }
    .s-label {
      font-size: 10px; letter-spacing: 0.2em; text-transform: uppercase;
      color: var(--muted); margin-bottom: 6px; display: block;
    }
    .s-input {
      width: 100%; background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.1);
      color: var(--text); border-radius: 8px;
      padding: 9px 12px; font-size: 13px;
      font-family: 'Noto Sans JP', sans-serif;
      transition: border-color 0.2s, box-shadow 0.2s;
      -webkit-appearance: none;
    }
    .s-input:focus {
      outline: none;
      border-color: var(--red);
      box-shadow: 0 0 0 3px rgba(255,45,85,0.12);
    }
    .s-input option { background: #1a1a1a; }
    .s-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 12px; margin-bottom: 12px; }
    @media(max-width:640px){ .s-grid { grid-template-columns: repeat(2,1fr); } }
    .btn-search {
      background: var(--red); color: #fff; border: none;
      border-radius: 8px; padding: 9px 28px;
      font-weight: 700; font-size: 14px; cursor: pointer;
      font-family: 'Noto Sans JP', sans-serif;
      transition: all 0.2s; white-space: nowrap;
    }
    .btn-search:hover { background: #e0193f; transform: translateY(-1px); box-shadow: 0 4px 20px rgba(255,45,85,0.4); }
    .btn-clear {
      background: transparent; border: 1px solid rgba(255,255,255,0.12);
      color: var(--muted); border-radius: 8px; padding: 9px 16px;
      cursor: pointer; font-family: 'Noto Sans JP', sans-serif;
      transition: all 0.2s;
    }
    .btn-clear:hover { border-color: var(--red); color: var(--red); }

    /* ─── メインレイアウト ─── */
    #main { max-width: 1200px; margin: 0 auto; padding: 40px 20px 80px; position: relative; z-index: 1; }

    /* ─── タブ ─── */
    .tab-bar {
      display: flex; gap: 0; margin-bottom: 28px;
      border-bottom: 1px solid var(--border);
    }
    .tab-btn {
      padding: 10px 24px; font-size: 13px; font-weight: 700;
      letter-spacing: 0.05em; cursor: pointer;
      border: none; background: transparent; color: var(--muted);
      border-bottom: 2px solid transparent; margin-bottom: -1px;
      font-family: 'Noto Sans JP', sans-serif;
      transition: all 0.2s;
    }
    .tab-btn:hover { color: var(--text); }
    .tab-btn.active { color: var(--red); border-bottom-color: var(--red); }

    /* ─── カレンダー ─── */
    .cal-nav {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 20px;
    }
    .cal-month-title {
      font-family: 'Oswald', sans-serif;
      font-size: 28px; letter-spacing: 0.04em; color: #fff;
    }
    .cal-nav-btn {
      width: 36px; height: 36px; border-radius: 8px;
      border: 1px solid var(--border); background: var(--bg2);
      color: var(--muted); cursor: pointer; font-size: 14px;
      display: flex; align-items: center; justify-content: center;
      transition: all 0.2s;
    }
    .cal-nav-btn:hover { border-color: var(--red); color: var(--red); }

    .cal-grid { display: grid; grid-template-columns: repeat(7,1fr); gap: 3px; }
    .cal-head {
      text-align: center; font-size: 11px; font-weight: 700;
      letter-spacing: 0.1em; padding: 8px 0; color: var(--muted);
    }
    .cal-head.sun { color: #ff6b6b; }
    .cal-head.sat { color: #5b9cf6; }

    .cal-cell {
      min-height: 82px; border-radius: 8px;
      background: var(--bg2); border: 1px solid var(--border);
      padding: 7px 6px; cursor: pointer; position: relative;
      transition: all 0.18s;
    }
    .cal-cell:hover { background: var(--bg3); border-color: rgba(255,255,255,0.15); }
    .cal-cell.has-ev { border-color: rgba(255,45,85,0.35); }
    .cal-cell.selected {
      background: rgba(255,45,85,0.1);
      border-color: var(--red);
      box-shadow: 0 0 16px rgba(255,45,85,0.15);
    }
    .cal-cell.other { opacity: 0.28; }
    .cal-cell.sun-c .day-n { color: #ff6b6b; }
    .cal-cell.sat-c .day-n { color: #5b9cf6; }

    .day-n {
      font-size: 13px; font-weight: 700;
      width: 26px; height: 26px;
      display: flex; align-items: center; justify-content: center;
      margin-bottom: 4px;
    }
    .cal-cell.today .day-n {
      background: var(--red); color: #fff; border-radius: 50%;
    }

    .ev-pill {
      display: block; font-size: 9px; font-weight: 700;
      border-radius: 3px; padding: 2px 5px; margin-bottom: 2px;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
      max-width: 100%; color: #fff;
      background: var(--red);
      letter-spacing: 0.02em;
    }
    .ev-pill.jazz    { background: #7c3aed; }
    .ev-pill.blues   { background: #1d52c4; }
    .ev-pill.acoustic{ background: #047857; }
    .ev-pill.soul    { background: #b45309; }
    .ev-pill.idol    { background: #be185d; }
    .ev-more { font-size: 9px; color: var(--muted); }

    @media(max-width:600px){
      .cal-cell { min-height: 48px; padding: 4px 3px; }
      .ev-pill  { display: none; }
      .cal-cell.has-ev::after {
        content: ''; display: block; width: 5px; height: 5px;
        border-radius: 50%; background: var(--red); margin: 2px auto 0;
      }
    }

    /* 選択日パネル */
    #selDatePanel {
      margin-top: 28px;
      border-top: 1px solid var(--border);
      padding-top: 24px;
    }
    .sel-date-title {
      font-family: 'Oswald', sans-serif;
      font-size: 20px; letter-spacing: 0.05em;
      color: var(--red); margin-bottom: 16px;
    }

    /* ─── イベントカード ─── */
    .ev-cards { display: grid; grid-template-columns: repeat(3,1fr); gap: 16px; }
    @media(max-width:900px){ .ev-cards { grid-template-columns: repeat(2,1fr); } }
    @media(max-width:560px){ .ev-cards { grid-template-columns: 1fr; } }

    .ev-card {
      background: var(--bg1);
      border: 1px solid var(--border);
      border-radius: 12px; padding: 18px;
      cursor: pointer; position: relative; overflow: hidden;
      transition: all 0.22s;
    }
    .ev-card::before {
      content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
      background: linear-gradient(90deg, var(--red), transparent);
      opacity: 0; transition: opacity 0.2s;
    }
    .ev-card:hover {
      border-color: rgba(255,45,85,0.4);
      transform: translateY(-3px);
      box-shadow: 0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,45,85,0.15);
    }
    .ev-card:hover::before { opacity: 1; }

    .ev-card-date {
      font-family: 'Oswald', sans-serif;
      font-size: 13px; letter-spacing: 0.08em; color: var(--gold);
      margin-bottom: 6px;
    }
    .ev-card-title {
      font-size: 15px; font-weight: 900; line-height: 1.3;
      margin-bottom: 8px; color: #fff;
    }
    .ev-card-venue {
      font-size: 12px; color: var(--muted); margin-bottom: 6px;
      display: flex; align-items: center; gap: 5px;
    }
    .ev-card-artists {
      font-size: 11px; color: #888; margin-bottom: 10px;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .ev-card-footer {
      display: flex; align-items: center; justify-content: space-between;
      border-top: 1px solid var(--border); padding-top: 10px; margin-top: 4px;
    }
    .ev-card-time { font-size: 11px; color: var(--muted); }
    .ev-card-price { font-size: 11px; font-weight: 700; color: var(--gold); }

    .badge-genre {
      display: inline-block; font-size: 10px; font-weight: 700;
      letter-spacing: 0.06em; border-radius: 3px;
      padding: 2px 8px; margin-bottom: 8px;
      background: var(--red-dim); color: var(--red);
      border: 1px solid rgba(255,45,85,0.3);
    }
    .badge-area {
      display: inline-block; font-size: 10px; font-weight: 700;
      letter-spacing: 0.06em; border-radius: 3px;
      padding: 2px 8px;
      background: var(--cyan-dim); color: var(--cyan);
      border: 1px solid rgba(0,229,255,0.25);
    }

    /* ─── 検索結果バー ─── */
    .result-bar {
      font-size: 12px; color: var(--muted); margin-bottom: 16px;
      letter-spacing: 0.05em;
    }
    .result-bar span { color: var(--red); font-weight: 700; font-size: 16px; }

    /* ─── ローディング ─── */
    .spinner {
      width: 32px; height: 32px; border: 2px solid var(--bg3);
      border-top-color: var(--red); border-radius: 50%;
      animation: spin 0.7s linear infinite; margin: 48px auto;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* ─── Empty ─── */
    .empty-state {
      text-align: center; padding: 80px 20px; color: var(--muted);
    }
    .empty-state i { font-size: 48px; opacity: 0.2; margin-bottom: 16px; display: block; }
    .empty-state p { font-size: 14px; }

    /* ─── モーダル ─── */
    .modal-overlay {
      position: fixed; inset: 0; z-index: 1000;
      background: rgba(0,0,0,0.88);
      display: flex; align-items: center; justify-content: center;
      backdrop-filter: blur(6px);
    }
    .modal-box {
      background: var(--bg1);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 16px; padding: 32px;
      max-width: 560px; width: 92%; max-height: 90vh; overflow-y: auto;
      position: relative;
      box-shadow: 0 24px 80px rgba(0,0,0,0.7);
    }
    .modal-box::before {
      content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
      background: linear-gradient(90deg, var(--red), var(--cyan));
      border-radius: 16px 16px 0 0;
    }
    .modal-close {
      position: absolute; top: 16px; right: 16px;
      width: 32px; height: 32px; border-radius: 50%;
      border: 1px solid var(--border); background: var(--bg2);
      color: var(--muted); cursor: pointer; font-size: 14px;
      display: flex; align-items: center; justify-content: center;
      transition: all 0.2s;
    }
    .modal-close:hover { border-color: var(--red); color: var(--red); }
    .modal-title {
      font-family: 'Oswald', sans-serif;
      font-size: 26px; letter-spacing: 0.03em;
      color: #fff; margin: 12px 0 20px; line-height: 1.2;
    }
    .modal-info-row {
      display: flex; align-items: center; gap: 10px;
      font-size: 13px; color: #ccc; padding: 7px 0;
      border-bottom: 1px solid var(--border);
    }
    .modal-info-row i { width: 16px; text-align: center; color: var(--muted); }
    .modal-info-row .val { color: #fff; font-weight: 600; }
    .artist-chip {
      display: inline-block; font-size: 12px;
      background: var(--bg3); border: 1px solid var(--border);
      border-radius: 100px; padding: 4px 14px; margin: 3px;
    }
    .modal-desc {
      background: var(--bg2); border-radius: 8px; padding: 14px 16px;
      font-size: 13px; line-height: 1.7; color: #aaa; margin: 16px 0;
    }
    .btn-ticket {
      display: block; text-align: center; width: 100%;
      background: var(--red); color: #fff; border: none;
      border-radius: 8px; padding: 12px; font-size: 14px; font-weight: 700;
      cursor: pointer; text-decoration: none; margin-top: 12px;
      font-family: 'Noto Sans JP', sans-serif;
      transition: all 0.2s;
    }
    .btn-ticket:hover { background: #e0193f; box-shadow: 0 4px 20px rgba(255,45,85,0.4); }
    .btn-venue-link {
      display: block; text-align: center; width: 100%;
      background: transparent; color: var(--muted);
      border: 1px solid var(--border); border-radius: 8px;
      padding: 10px; font-size: 13px; font-weight: 600;
      cursor: pointer; text-decoration: none; margin-top: 8px;
      font-family: 'Noto Sans JP', sans-serif;
      transition: all 0.2s;
    }
    .btn-venue-link:hover { border-color: var(--cyan); color: var(--cyan); }

    /* ─── フッター ─── */
    footer {
      border-top: 1px solid var(--border);
      padding: 32px 24px; text-align: center;
      font-size: 12px; color: var(--muted); letter-spacing: 0.1em;
      position: relative; z-index: 1;
    }
    footer .footer-logo {
      font-family: 'Bebas Neue', sans-serif;
      font-size: 18px; letter-spacing: 0.1em;
      color: rgba(255,255,255,0.2); margin-bottom: 6px;
    }
  </style>
</head>
<body>

<!-- ナビ -->
<nav id="topnav">
  <div style="display:flex;align-items:baseline;gap:10px">
    <div class="logo">KUMAMOTO LIVE GUIDE</div>
    <div class="logo-sub">熊本ライブ情報</div>
  </div>
  <div id="currentMonthLabel" style="font-size:12px;color:var(--muted);letter-spacing:0.1em"></div>
</nav>

<!-- ヒーロー -->
<section id="hero">
  <div class="hero-eyebrow">
    <i class="fas fa-bolt" style="font-size:9px"></i>
    KUMAMOTO LIVE SCHEDULE
  </div>
  <p class="hero-sub" style="margin-bottom:32px">ライブハウス・ライブバーのスケジュールを一括検索</p>

  <!-- 検索パネル -->
  <div id="searchPanel">
    <div class="s-grid">
      <div>
        <span class="s-label"><i class="fas fa-calendar-alt" style="margin-right:4px"></i>日付</span>
        <input type="date" id="searchDate" class="s-input">
      </div>
      <div>
        <span class="s-label"><i class="fas fa-map-marker-alt" style="margin-right:4px"></i>地区</span>
        <select id="searchArea" class="s-input">
          <option value="">すべての地区</option>
          <option value="下通">下通</option>
          <option value="上通">上通</option>
          <option value="新市街">新市街</option>
          <option value="水道町">水道町</option>
          <option value="帯山">帯山</option>
          <option value="その他">その他</option>
        </select>
      </div>
      <div>
        <span class="s-label"><i class="fas fa-store" style="margin-right:4px"></i>会場</span>
        <select id="searchVenue" class="s-input">
          <option value="">すべての会場</option>
        </select>
      </div>
      <div>
        <span class="s-label"><i class="fas fa-guitar" style="margin-right:4px"></i>ジャンル</span>
        <select id="searchGenre" class="s-input">
          <option value="">すべてのジャンル</option>
          <option value="ロック">ロック</option>
          <option value="ジャズ">ジャズ</option>
          <option value="ブルース">ブルース</option>
          <option value="アコースティック">アコースティック</option>
          <option value="ポップス">ポップス</option>
          <option value="ソウル">ソウル・ファンク</option>
          <option value="メタル">メタル</option>
          <option value="パンク">パンク</option>
          <option value="アイドル">アイドル</option>
        </select>
      </div>
    </div>
    <div style="display:flex;gap:8px">
      <input type="text" id="searchKeyword" class="s-input" style="flex:1"
        placeholder="アーティスト名・イベント名で検索...">
      <button onclick="doSearch()" class="btn-search"><i class="fas fa-search" style="margin-right:6px"></i>検索</button>
      <button onclick="clearSearch()" class="btn-clear" title="クリア"><i class="fas fa-times"></i></button>
    </div>
  </div>
  <div class="spectrum-line"></div>
</section>

<!-- メイン -->
<main id="main">
  <!-- タブ -->
  <div class="tab-bar">
    <button class="tab-btn active" onclick="showTab('calendar')" id="tab-calendar">
      <i class="fas fa-calendar-alt" style="margin-right:6px"></i>カレンダー
    </button>
    <button class="tab-btn" onclick="showTab('list')" id="tab-list">
      <i class="fas fa-list" style="margin-right:6px"></i>一覧
    </button>
  </div>

  <!-- カレンダービュー -->
  <div id="view-calendar">
    <div class="cal-nav">
      <button class="cal-nav-btn" onclick="changeMonth(-1)"><i class="fas fa-chevron-left"></i></button>
      <div id="calMonthTitle" class="cal-month-title"></div>
      <button class="cal-nav-btn" onclick="changeMonth(1)"><i class="fas fa-chevron-right"></i></button>
    </div>
    <div class="cal-grid" style="margin-bottom:4px">
      <div class="cal-head sun">SUN</div>
      <div class="cal-head">MON</div>
      <div class="cal-head">TUE</div>
      <div class="cal-head">WED</div>
      <div class="cal-head">THU</div>
      <div class="cal-head">FRI</div>
      <div class="cal-head sat">SAT</div>
    </div>
    <div class="cal-grid" id="calendarBody"></div>

    <div id="selectedDateEvents" class="hidden" style="margin-top:28px;border-top:1px solid var(--border);padding-top:24px">
      <div id="selectedDateTitle" class="sel-date-title"></div>
      <div id="selectedDateEventList" class="ev-cards"></div>
    </div>
  </div>

  <!-- 一覧ビュー -->
  <div id="view-list" class="hidden">
    <div id="searchResultInfo" class="result-bar"></div>
    <div id="loadingSpinner" class="hidden"><div class="spinner"></div></div>
    <div id="eventList" class="ev-cards"></div>
    <div id="noResults" class="hidden empty-state">
      <i class="fas fa-music"></i>
      <p style="font-size:16px;color:#555;margin-bottom:6px">イベントが見つかりませんでした</p>
      <p>検索条件を変えてお試しください</p>
    </div>
  </div>
</main>

<!-- 詳細モーダル -->
<div id="eventModal" class="modal-overlay hidden" onclick="closeModal(event)">
  <div class="modal-box" onclick="event.stopPropagation()">
    <button class="modal-close" onclick="closeModal()"><i class="fas fa-times"></i></button>
    <div id="modalContent"></div>
  </div>
</div>

<!-- フッター -->
<footer>
  <div class="footer-logo">KUMAMOTO LIVE GUIDE</div>
  <div>熊本市内のライブハウス・ライブバーのスケジュール情報サイト</div>
</footer>

<script>
let currentMonth = new Date();
let allVenues = [];
let calendarEvents = {};
let selectedDate = null;
let currentTab = 'calendar';
let allEvents = [];

async function init() {
  const now = new Date();
  currentMonth = new Date(now.getFullYear(), now.getMonth(), 1);
  await loadVenues();
  await loadMonthEvents();
  renderCalendar();
  document.getElementById('searchKeyword').addEventListener('keydown', e => {
    if (e.key === 'Enter') doSearch();
  });
}

async function loadVenues() {
  try {
    const res = await fetch('/api/venues');
    const data = await res.json();
    allVenues = data.venues || [];
    const sel = document.getElementById('searchVenue');
    allVenues.forEach(v => {
      const opt = document.createElement('option');
      opt.value = v.id; opt.textContent = v.name;
      sel.appendChild(opt);
    });
  } catch(e) {}
}

async function loadMonthEvents() {
  const y = currentMonth.getFullYear();
  const m = String(currentMonth.getMonth() + 1).padStart(2,'0');
  try {
    const res = await fetch('/api/events?month=' + y + '-' + m);
    const data = await res.json();
    calendarEvents = {};
    (data.events || []).forEach(ev => {
      if (!calendarEvents[ev.event_date]) calendarEvents[ev.event_date] = [];
      calendarEvents[ev.event_date].push(ev);
    });
    document.getElementById('currentMonthLabel').textContent = y + '.' + m;
  } catch(e) {}
}

function renderCalendar() {
  const y = currentMonth.getFullYear();
  const m = currentMonth.getMonth();
  document.getElementById('calMonthTitle').textContent =
    y + ' / ' + String(m+1).padStart(2,'0');

  const firstDay  = new Date(y, m, 1).getDay();
  const lastDate  = new Date(y, m+1, 0).getDate();
  const prevLast  = new Date(y, m, 0).getDate();
  const todayStr  = new Date().toISOString().split('T')[0];
  const total     = Math.ceil((firstDay + lastDate) / 7) * 7;

  let html = ''; let day = 1; let nxt = 1;
  for (let i = 0; i < total; i++) {
    const col = i % 7;
    let ds, dn, cls = ['cal-cell'];
    if (i < firstDay) {
      dn = prevLast - firstDay + i + 1;
      const pm = m === 0 ? 12 : m, py = m === 0 ? y-1 : y;
      ds = py+'-'+String(pm).padStart(2,'0')+'-'+String(dn).padStart(2,'0');
      cls.push('other');
    } else if (day <= lastDate) {
      dn = day; ds = y+'-'+String(m+1).padStart(2,'0')+'-'+String(dn).padStart(2,'0'); day++;
    } else {
      dn = nxt++;
      const nm = m+2>12?1:m+2, ny = m+2>12?y+1:y;
      ds = ny+'-'+String(nm).padStart(2,'0')+'-'+String(dn).padStart(2,'0');
      cls.push('other');
    }
    if (col===0) cls.push('sun-c');
    if (col===6) cls.push('sat-c');
    if (ds===todayStr) cls.push('today');
    if (ds===selectedDate) cls.push('selected');
    const evs = calendarEvents[ds] || [];
    if (evs.length) cls.push('has-ev');

    const pills = evs.slice(0,3).map(ev => {
      const gc = getGenreCls(ev.genre);
      return \`<span class="ev-pill \${gc}">\${ev.venue_name||ev.title}</span>\`;
    }).join('');
    const more = evs.length > 3 ? \`<span class="ev-more">+\${evs.length-3}</span>\` : '';

    html += \`<div class="\${cls.join(' ')}" onclick="selectDate('\${ds}')">
      <div class="day-n">\${dn}</div>\${pills}\${more}
    </div>\`;
  }
  document.getElementById('calendarBody').innerHTML = html;
}

function getGenreCls(g) {
  if (!g) return '';
  if (g.includes('ジャズ')) return 'jazz';
  if (g.includes('ブルース')) return 'blues';
  if (g.includes('アコースティック')) return 'acoustic';
  if (g.includes('ソウル')||g.includes('ファンク')) return 'soul';
  if (g.includes('アイドル')) return 'idol';
  return '';
}

function selectDate(ds) {
  selectedDate = selectedDate === ds ? null : ds;
  renderCalendar();
  const panel = document.getElementById('selectedDateEvents');
  if (!selectedDate) { panel.classList.add('hidden'); return; }

  const evs = calendarEvents[ds] || [];
  const d = new Date(ds + 'T00:00:00');
  const wd = ['SUN','MON','TUE','WED','THU','FRI','SAT'][d.getDay()];
  document.getElementById('selectedDateTitle').textContent =
    \`\${d.getMonth()+1}.\${String(d.getDate()).padStart(2,'0')} (\${wd}) — \${evs.length} EVENT\${evs.length!==1?'S':''}\`;

  const cont = document.getElementById('selectedDateEventList');
  cont.innerHTML = evs.length
    ? evs.map(ev => renderCard(ev)).join('')
    : '<p style="color:var(--muted);font-size:13px">この日はイベントがありません</p>';

  panel.classList.remove('hidden');
  panel.scrollIntoView({ behavior:'smooth', block:'nearest' });
}

async function changeMonth(d) {
  currentMonth = new Date(currentMonth.getFullYear(), currentMonth.getMonth()+d, 1);
  selectedDate = null;
  document.getElementById('selectedDateEvents').classList.add('hidden');
  await loadMonthEvents();
  renderCalendar();
}

function showTab(tab) {
  currentTab = tab;
  document.getElementById('view-calendar').classList.toggle('hidden', tab!=='calendar');
  document.getElementById('view-list').classList.toggle('hidden', tab!=='list');
  document.getElementById('tab-calendar').classList.toggle('active', tab==='calendar');
  document.getElementById('tab-list').classList.toggle('active', tab==='list');
  if (tab==='list' && allEvents.length===0) loadListEvents();
}

async function loadListEvents(params) {
  document.getElementById('loadingSpinner').classList.remove('hidden');
  document.getElementById('eventList').innerHTML = '';
  document.getElementById('noResults').classList.add('hidden');
  try {
    const url = params ? '/api/events?'+new URLSearchParams(params) : '/api/events';
    const data = await (await fetch(url)).json();
    allEvents = data.events || [];
    renderList(allEvents);
  } catch(e) {
    document.getElementById('eventList').innerHTML = '<p style="color:#f87171">読み込みエラー</p>';
  } finally {
    document.getElementById('loadingSpinner').classList.add('hidden');
  }
}

function renderList(evs) {
  const info = document.getElementById('searchResultInfo');
  const list = document.getElementById('eventList');
  const none = document.getElementById('noResults');
  if (evs.length===0) {
    info.innerHTML=''; list.innerHTML=''; none.classList.remove('hidden'); return;
  }
  info.innerHTML = \`<span>\${evs.length}</span> 件のイベントが見つかりました\`;
  none.classList.add('hidden');
  list.innerHTML = evs.map(ev => renderCard(ev)).join('');
}

function renderCard(ev) {
  const d = new Date(ev.event_date+'T00:00:00');
  const wd = ['SUN','MON','TUE','WED','THU','FRI','SAT'][d.getDay()];
  const dl = \`\${d.getMonth()+1}/\${String(d.getDate()).padStart(2,'0')} \${wd}\`;
  const tl = ev.open_time ? \`開場 \${ev.open_time}　\` : '';
  const sl = ev.start_time ? \`開演 \${ev.start_time}\` : '';
  return \`
    <div class="ev-card" onclick="showDetail(\${ev.id})">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:6px">
        \${ev.genre ? \`<span class="badge-genre">\${ev.genre}</span>\` : '<span></span>'}
        <span class="badge-area">\${ev.venue_area}</span>
      </div>
      <div class="ev-card-date">\${dl}</div>
      <div class="ev-card-title">\${ev.title}</div>
      <div class="ev-card-venue"><i class="fas fa-store"></i>\${ev.venue_name}</div>
      \${ev.artists ? \`<div class="ev-card-artists"><i class="fas fa-microphone" style="margin-right:4px;opacity:.5"></i>\${ev.artists}</div>\` : ''}
      <div class="ev-card-footer">
        <span class="ev-card-time">\${tl}\${sl}</span>
        <span class="ev-card-price">\${ev.charge_info||''}</span>
      </div>
    </div>
  \`;
}

async function doSearch() {
  const p = {};
  const date = document.getElementById('searchDate').value;
  const area = document.getElementById('searchArea').value;
  const vid  = document.getElementById('searchVenue').value;
  const genre= document.getElementById('searchGenre').value;
  const kw   = document.getElementById('searchKeyword').value;
  if (date)  p.date = date;
  if (area)  p.area = area;
  if (vid)   p.venue_id = vid;
  if (genre) p.genre = genre;
  if (kw)    p.keyword = kw;
  showTab('list');
  await loadListEvents(p);
}

function clearSearch() {
  ['searchDate','searchArea','searchVenue','searchGenre','searchKeyword']
    .forEach(id => { const el=document.getElementById(id); if(el.tagName==='SELECT') el.selectedIndex=0; else el.value=''; });
  allEvents=[];
  document.getElementById('eventList').innerHTML='';
  document.getElementById('searchResultInfo').innerHTML='';
  showTab('calendar');
}

async function showDetail(id) {
  document.getElementById('eventModal').classList.remove('hidden');
  document.getElementById('modalContent').innerHTML='<div class="spinner"></div>';
  try {
    const ev = (await (await fetch('/api/events/'+id)).json()).event;
    const d = new Date(ev.event_date+'T00:00:00');
    const wd = ['日','月','火','水','木','金','土'][d.getDay()];
    const artists = ev.artists ? ev.artists.split(',').map(a=>a.trim()).filter(a=>a) : [];
    document.getElementById('modalContent').innerHTML = \`
      \${ev.genre ? \`<span class="badge-genre">\${ev.genre}</span>\` : ''}
      <h2 class="modal-title">\${ev.title}</h2>
      <div style="border-top:1px solid var(--border)">
        <div class="modal-info-row">
          <i class="fas fa-calendar-alt" style="color:var(--gold)"></i>
          <span class="val">\${d.getFullYear()}年\${d.getMonth()+1}月\${d.getDate()}日（\${wd}）</span>
        </div>
        \${ev.open_time ? \`<div class="modal-info-row"><i class="fas fa-door-open"></i><span>開場</span><span class="val">\${ev.open_time}</span></div>\` : ''}
        \${ev.start_time ? \`<div class="modal-info-row"><i class="fas fa-play-circle" style="color:var(--red)"></i><span>開演</span><span class="val">\${ev.start_time}</span></div>\` : ''}
        <div class="modal-info-row">
          <i class="fas fa-map-marker-alt"></i>
          <span class="val">\${ev.venue_name}</span><span style="color:var(--muted);font-size:12px">（\${ev.venue_area}）</span>
        </div>
        \${ev.venue_address ? \`<div class="modal-info-row"><i class="fas fa-location-dot"></i><span style="color:#888;font-size:12px">\${ev.venue_address}</span></div>\` : ''}
        \${ev.charge_info ? \`<div class="modal-info-row"><i class="fas fa-ticket" style="color:var(--gold)"></i><span class="val" style="color:var(--gold)">\${ev.charge_info}</span></div>\` : ''}
      </div>
      \${artists.length ? \`
        <div style="margin-top:16px">
          <div style="font-size:10px;letter-spacing:0.2em;color:var(--muted);margin-bottom:8px">ARTIST</div>
          \${artists.map(a=>\`<span class="artist-chip">\${a}</span>\`).join('')}
        </div>
      \` : ''}
      \${ev.description ? \`<div class="modal-desc">\${ev.description}</div>\` : ''}
      \${ev.ticket_url ? \`<a href="\${ev.ticket_url}" target="_blank" class="btn-ticket"><i class="fas fa-ticket" style="margin-right:8px"></i>チケット購入</a>\` : ''}
      \${ev.venue_website ? \`<a href="\${ev.venue_website}" target="_blank" class="btn-venue-link"><i class="fas fa-globe" style="margin-right:8px"></i>会場公式サイト</a>\` : ''}
    \`;
  } catch(e) {
    document.getElementById('modalContent').innerHTML='<p style="color:#f87171">読み込みエラー</p>';
  }
}

function closeModal(e) {
  if (!e || e.target===document.getElementById('eventModal'))
    document.getElementById('eventModal').classList.add('hidden');
}
document.addEventListener('keydown', e => { if(e.key==='Escape') closeModal(); });

init();
</script>
</body>
</html>`
}

function adminHTML() {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>管理者ページ | KUMAMOTO LIVE GUIDE</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.0/css/all.min.css">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700;900&display=swap');
    * { font-family: 'Noto Sans JP', sans-serif; }
    body { background: #0f0f0f; color: #f0f0f0; }
    .input-field {
      background: #111; border: 1px solid #444; color: #f0f0f0;
      border-radius: 8px; padding: 8px 12px; width: 100%;
      transition: border-color 0.2s;
    }
    .input-field:focus { outline: none; border-color: #e11d48; box-shadow: 0 0 0 2px rgba(225,29,72,0.15); }
    .input-field option { background: #1a1a1a; }
    .btn-primary { background: #e11d48; color: white; border: none; border-radius: 8px; padding: 8px 20px; font-weight: 700; cursor: pointer; transition: all 0.2s; }
    .btn-primary:hover { background: #be123c; }
    .btn-secondary { background: #374151; color: white; border: none; border-radius: 8px; padding: 8px 20px; font-weight: 700; cursor: pointer; transition: all 0.2s; }
    .btn-secondary:hover { background: #4b5563; }
    .btn-danger { background: #7f1d1d; color: #fca5a5; border: 1px solid #991b1b; border-radius: 6px; padding: 5px 12px; font-size: 13px; cursor: pointer; }
    .btn-danger:hover { background: #991b1b; }
    .btn-edit { background: #1e3a5f; color: #93c5fd; border: 1px solid #1e40af; border-radius: 6px; padding: 5px 12px; font-size: 13px; cursor: pointer; }
    .btn-edit:hover { background: #1e40af; }
    .card { background: #1a1a1a; border: 1px solid #333; border-radius: 12px; }
    .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.85); z-index: 1000; display: flex; align-items: center; justify-content: center; backdrop-filter: blur(4px); }
    .modal-box { background: #1c1c1c; border: 1px solid #444; border-radius: 16px; padding: 24px; max-width: 620px; width: 94%; max-height: 92vh; overflow-y: auto; }
    .sidebar-btn { display: flex; align-items: center; gap: 10px; width: 100%; padding: 10px 16px; border-radius: 8px; cursor: pointer; transition: all 0.2s; color: #9ca3af; font-weight: 500; border: none; background: transparent; text-align: left; }
    .sidebar-btn:hover { background: #222; color: #f0f0f0; }
    .sidebar-btn.active { background: rgba(225,29,72,0.15); color: #fb7185; }
    /* モバイル用サイドバー */
    #adminSidebar { transition: transform 0.3s ease; }
    #sidebarOverlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6); z-index: 40; }
    @media (max-width: 767px) {
      #adminSidebar { position: fixed; top: 56px; left: 0; height: calc(100% - 56px); z-index: 50; transform: translateX(-100%); }
      #adminSidebar.open { transform: translateX(0); }
      #sidebarOverlay.open { display: block; }
      #mobileHeader { display: flex !important; }
      #adminMain { flex-direction: column; }
      #adminContent { margin-top: 56px; height: calc(100vh - 56px); }
    }
    #mobileHeader { display: none; position: fixed; top: 0; left: 0; right: 0; height: 56px; background: #111; border-bottom: 1px solid #333; z-index: 60; align-items: center; padding: 0 16px; gap: 12px; }
    .status-badge { font-size: 11px; border-radius: 100px; padding: 2px 10px; display: inline-block; }
    .status-published { background: rgba(16,185,129,0.15); color: #34d399; border: 1px solid rgba(16,185,129,0.3); }
    .status-draft { background: rgba(245,158,11,0.1); color: #fbbf24; border: 1px solid rgba(245,158,11,0.3); }
    .status-cancelled { background: rgba(239,68,68,0.1); color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: #111; }
    ::-webkit-scrollbar-thumb { background: #444; border-radius: 3px; }
    label { font-size: 13px; color: #9ca3af; margin-bottom: 4px; display: block; }
    .form-group { margin-bottom: 14px; }
  </style>
</head>
<body class="flex h-screen overflow-hidden">

<!-- モバイルヘッダー -->
<div id="mobileHeader">
  <button onclick="toggleSidebar()" style="background:none;border:none;color:#f0f0f0;font-size:22px;cursor:pointer;padding:4px;">
    <i class="fas fa-bars"></i>
  </button>
  <span style="font-size:14px;font-weight:900;color:#fb7185;"><i class="fas fa-music mr-1"></i>KUMAMOTO LIVE</span>
</div>

<!-- サイドバーオーバーレイ -->
<div id="sidebarOverlay" onclick="closeSidebar()"></div>

<!-- ログイン画面 -->
<div id="loginScreen" class="fixed inset-0 bg-gray-950 flex items-center justify-center z-50">
  <div class="w-full max-w-sm mx-4">
    <div class="text-center mb-8">
      <i class="fas fa-music text-red-500 text-4xl mb-3 block"></i>
      <h1 class="text-2xl font-black">KUMAMOTO LIVE GUIDE</h1>
      <p class="text-gray-500 text-sm mt-1">管理者ログイン</p>
    </div>
    <div class="card p-6">
      <div class="form-group">
        <label>ユーザー名</label>
        <input type="text" id="loginUser" class="input-field" placeholder="admin">
      </div>
      <div class="form-group">
        <label>パスワード</label>
        <input type="password" id="loginPass" class="input-field" placeholder="••••••••"
          onkeydown="if(event.key==='Enter')doLogin()">
      </div>
      <p id="loginError" class="text-red-400 text-sm mb-3 hidden"></p>
      <button onclick="doLogin()" class="btn-primary w-full py-3 rounded-lg">
        <i class="fas fa-sign-in-alt mr-2"></i>ログイン
      </button>
    </div>
  </div>
</div>

<!-- メイン管理画面 -->
<div id="adminMain" class="hidden flex w-full h-full">
  <!-- サイドバー -->
  <aside id="adminSidebar" class="w-56 flex-shrink-0 border-r border-gray-800 flex flex-col" style="background:#111">
    <div class="p-4 border-b border-gray-800">
      <div class="text-sm font-black text-red-400"><i class="fas fa-music mr-1"></i>KUMAMOTO LIVE</div>
      <div class="text-xs text-gray-600 mt-0.5">管理画面</div>
    </div>
    <nav class="flex-1 p-3 space-y-1">
      <button class="sidebar-btn active" onclick="showSection('events')" id="nav-events">
        <i class="fas fa-calendar-alt" style="width:18px;text-align:center;"></i>イベント管理
      </button>
      <button class="sidebar-btn" onclick="showSection('venues')" id="nav-venues">
        <i class="fas fa-store" style="width:18px;text-align:center;"></i>会場管理
      </button>
      <button class="sidebar-btn" onclick="showSection('settings')" id="nav-settings">
        <i class="fas fa-cog" style="width:18px;text-align:center;"></i>設定
      </button>
    </nav>
    <div class="p-3 border-t border-gray-800">
      <p id="adminUsername" class="text-xs text-gray-500 mb-2"></p>
      <button onclick="doLogout()" class="sidebar-btn text-gray-500 text-sm">
        <i class="fas fa-sign-out-alt" style="width:18px;text-align:center;"></i>ログアウト
      </button>
      <a href="/" target="_blank" class="sidebar-btn text-gray-500 text-sm mt-1 block no-underline">
        <i class="fas fa-external-link-alt" style="width:18px;text-align:center;"></i>公開サイト
      </a>
    </div>
  </aside>

  <!-- コンテンツエリア -->
  <main id="adminContent" class="flex-1 overflow-y-auto">
    <!-- ==================== イベント管理 ==================== -->
    <div id="section-events" class="p-6">
      <div class="flex items-center justify-between mb-6">
        <div>
          <h2 class="text-xl font-bold">イベント管理</h2>
          <p class="text-gray-500 text-sm">ライブスケジュールの追加・編集・削除</p>
        </div>
        <div class="flex gap-2 items-center">
          <input type="month" id="filterMonth" class="input-field w-40 text-sm" onchange="loadAdminEvents()">
          <button onclick="openEventForm()" class="btn-primary">
            <i class="fas fa-plus mr-1"></i>新規追加
          </button>
        </div>
      </div>
      
      <div id="eventsTable" class="space-y-3">
        <div class="text-center py-8 text-gray-500"><i class="fas fa-spinner fa-spin mr-2"></i>読み込み中...</div>
      </div>
    </div>

    <!-- ==================== 会場管理 ==================== -->
    <div id="section-venues" class="p-6 hidden">
      <div class="flex items-center justify-between mb-6">
        <div>
          <h2 class="text-xl font-bold">会場管理</h2>
          <p class="text-gray-500 text-sm">ライブハウス・ライブバーの情報管理</p>
        </div>
        <button onclick="openVenueForm()" class="btn-primary">
          <i class="fas fa-plus mr-1"></i>会場追加
        </button>
      </div>
      <div id="venuesTable" class="space-y-3">
        <div class="text-center py-8 text-gray-500"><i class="fas fa-spinner fa-spin mr-2"></i>読み込み中...</div>
      </div>
    </div>

    <!-- ==================== 設定 ==================== -->
    <div id="section-settings" class="p-6 hidden">
      <h2 class="text-xl font-bold mb-6">設定</h2>
      <div class="card p-6 max-w-md">
        <h3 class="font-bold mb-4 text-gray-200">パスワード変更</h3>
        <div class="form-group">
          <label>現在のパスワード</label>
          <input type="password" id="curPw" class="input-field">
        </div>
        <div class="form-group">
          <label>新しいパスワード</label>
          <input type="password" id="newPw" class="input-field">
        </div>
        <div class="form-group">
          <label>新しいパスワード（確認）</label>
          <input type="password" id="newPw2" class="input-field">
        </div>
        <p id="pwMsg" class="text-sm mb-3 hidden"></p>
        <button onclick="changePassword()" class="btn-primary">変更する</button>
      </div>
    </div>
  </main>
</div>

<!-- イベントフォームモーダル -->
<div id="eventFormModal" class="modal-overlay hidden">
  <div class="modal-box">
    <div class="flex items-center justify-between mb-5">
      <h3 id="eventFormTitle" class="text-lg font-bold">イベント追加</h3>
      <button onclick="closeEventForm()" class="text-gray-500 hover:text-white text-xl"><i class="fas fa-times"></i></button>
    </div>
    <form id="eventForm" onsubmit="saveEvent(event)">
      <input type="hidden" id="eventId">
      <div class="grid grid-cols-2 gap-3">
        <div class="form-group col-span-2">
          <label>イベントタイトル <span class="text-red-400">*</span></label>
          <input type="text" id="evTitle" class="input-field" required placeholder="例: Rock Night Vol.12">
        </div>
        <div class="form-group">
          <label>会場 <span class="text-red-400">*</span></label>
          <select id="evVenue" class="input-field" required></select>
        </div>
        <div class="form-group">
          <label>開催日 <span class="text-red-400">*</span></label>
          <input type="date" id="evDate" class="input-field" required>
        </div>
        <div class="form-group">
          <label>開場時間</label>
          <input type="time" id="evOpenTime" class="input-field">
        </div>
        <div class="form-group">
          <label>開演時間</label>
          <input type="time" id="evStartTime" class="input-field">
        </div>
        <div class="form-group col-span-2">
          <label>出演アーティスト（カンマ区切り）</label>
          <input type="text" id="evArtists" class="input-field" placeholder="バンド名A, バンド名B, バンド名C">
        </div>
        <div class="form-group">
          <label>ジャンル</label>
          <select id="evGenre" class="input-field">
            <option value="">選択してください</option>
            <option>ロック</option><option>ジャズ</option><option>ブルース</option>
            <option>アコースティック</option><option>ポップス・ロック</option><option>ソウル・ファンク</option>
            <option>メタル</option><option>パンク</option><option>アイドル</option>
            <option>ヒップホップ</option><option>レゲエ</option><option>オールジャンル</option>
          </select>
        </div>
        <div class="form-group">
          <label>料金情報</label>
          <input type="text" id="evCharge" class="input-field" placeholder="例: 前売¥2,000 / 当日¥2,500">
        </div>
        <div class="form-group col-span-2">
          <label>チケットURL</label>
          <input type="url" id="evTicket" class="input-field" placeholder="https://...">
        </div>
        <div class="form-group col-span-2">
          <label>イベント説明</label>
          <textarea id="evDesc" class="input-field" rows="3" placeholder="イベントの詳細説明..."></textarea>
        </div>
        <div class="form-group">
          <label>公開ステータス</label>
          <select id="evStatus" class="input-field">
            <option value="published">公開</option>
            <option value="draft">下書き</option>
            <option value="cancelled">中止</option>
          </select>
        </div>
      </div>
      <div class="flex gap-3 justify-end mt-4 pt-4 border-t border-gray-800">
        <button type="button" onclick="closeEventForm()" class="btn-secondary">キャンセル</button>
        <button type="submit" class="btn-primary"><i class="fas fa-save mr-1"></i>保存する</button>
      </div>
    </form>
  </div>
</div>

<!-- 会場フォームモーダル -->
<div id="venueFormModal" class="modal-overlay hidden">
  <div class="modal-box">
    <div class="flex items-center justify-between mb-5">
      <h3 id="venueFormTitle" class="text-lg font-bold">会場追加</h3>
      <button onclick="closeVenueForm()" class="text-gray-500 hover:text-white text-xl"><i class="fas fa-times"></i></button>
    </div>
    <form id="venueForm" onsubmit="saveVenue(event)">
      <input type="hidden" id="venueId">
      <div class="form-group">
        <label>会場名 <span class="text-red-400">*</span></label>
        <input type="text" id="vnName" class="input-field" required placeholder="例: B.9 V1">
      </div>
      <div class="form-group">
        <label>地区 <span class="text-red-400">*</span></label>
        <select id="vnArea" class="input-field" required>
          <option value="下通">下通</option><option value="上通">上通</option>
          <option value="新市街">新市街</option><option value="水道町">水道町</option>
          <option value="帯山">帯山</option><option value="その他">その他</option>
        </select>
      </div>
      <div class="form-group">
        <label>住所</label>
        <input type="text" id="vnAddress" class="input-field" placeholder="熊本市中央区...">
      </div>
      <div class="form-group">
        <label>電話番号</label>
        <input type="tel" id="vnPhone" class="input-field" placeholder="096-xxx-xxxx">
      </div>
      <div class="form-group">
        <label>公式サイトURL</label>
        <input type="url" id="vnWebsite" class="input-field" placeholder="https://...">
      </div>
      <div class="form-group">
        <label>説明</label>
        <textarea id="vnDesc" class="input-field" rows="2" placeholder="会場の説明..."></textarea>
      </div>
      <div class="flex gap-3 justify-end mt-4 pt-4 border-t border-gray-800">
        <button type="button" onclick="closeVenueForm()" class="btn-secondary">キャンセル</button>
        <button type="submit" class="btn-primary"><i class="fas fa-save mr-1"></i>保存する</button>
      </div>
    </form>
  </div>
</div>

<script>
let adminToken = localStorage.getItem('adminToken');
let adminUser = localStorage.getItem('adminUser');
let adminVenues = [];

// ==================== 認証 ====================
async function doLogin() {
  const username = document.getElementById('loginUser').value;
  const password = document.getElementById('loginPass').value;
  const errEl = document.getElementById('loginError');
  errEl.classList.add('hidden');

  try {
    const res = await fetch('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (!res.ok) {
      errEl.textContent = data.error || 'ログインエラー';
      errEl.classList.remove('hidden');
      return;
    }
    adminToken = data.token;
    adminUser = data.username;
    localStorage.setItem('adminToken', adminToken);
    localStorage.setItem('adminUser', adminUser);
    showAdmin();
  } catch(e) {
    errEl.textContent = 'サーバーエラーが発生しました';
    errEl.classList.remove('hidden');
  }
}

async function doLogout() {
  try {
    await apiFetch('/api/admin/logout', { method: 'POST' });
  } catch {}
  localStorage.removeItem('adminToken');
  localStorage.removeItem('adminUser');
  adminToken = null;
  location.reload();
}

function showAdmin() {
  document.getElementById('loginScreen').classList.add('hidden');
  document.getElementById('adminMain').classList.remove('hidden');
  document.getElementById('adminMain').style.display = 'flex';
  document.getElementById('adminUsername').textContent = adminUser + 'さん';
  
  // 今月をデフォルト
  const now = new Date();
  document.getElementById('filterMonth').value = now.getFullYear() + '-' + String(now.getMonth()+1).padStart(2,'0');
  
  loadAdminVenues();
  loadAdminEvents();
}

// ==================== API ヘルパー ====================
async function apiFetch(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: {
      'Authorization': 'Bearer ' + adminToken,
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });
  if (res.status === 401) {
    localStorage.removeItem('adminToken');
    location.reload();
    throw new Error('Unauthorized');
  }
  return res;
}

// ==================== モバイルサイドバー開閉 ====================
function toggleSidebar() {
  const sidebar = document.getElementById('adminSidebar');
  const overlay = document.getElementById('sidebarOverlay');
  sidebar.classList.toggle('open');
  overlay.classList.toggle('open');
}
function closeSidebar() {
  document.getElementById('adminSidebar').classList.remove('open');
  document.getElementById('sidebarOverlay').classList.remove('open');
}

// ==================== セクション切替 ====================
function showSection(name) {
  ['events','venues','settings'].forEach(s => {
    document.getElementById('section-' + s).classList.toggle('hidden', s !== name);
    document.getElementById('nav-' + s).classList.toggle('active', s === name);
  });
  if (name === 'venues') loadAdminVenuesTable();
  // モバイルではメニュー選択後に自動クローズ
  closeSidebar();
}

// ==================== イベント管理 ====================
async function loadAdminEvents() {
  const month = document.getElementById('filterMonth').value;
  const params = month ? '?month=' + month : '';
  try {
    const res = await apiFetch('/api/admin/events' + params);
    const data = await res.json();
    renderAdminEvents(data.events || []);
  } catch(e) {
    document.getElementById('eventsTable').innerHTML = '<p class="text-red-400">読み込みエラー</p>';
  }
}

function renderAdminEvents(events) {
  const el = document.getElementById('eventsTable');
  // イベントデータをグローバルマップに保存（onclick属性内でJSONを扱わないため）
  window._adminEventsMap = {};
  events.forEach(ev => { window._adminEventsMap[ev.id] = ev; });

  if (events.length === 0) {
    el.innerHTML = '<div class="text-center py-12 text-gray-500"><i class="fas fa-calendar-times text-3xl mb-3 block opacity-30"></i>イベントがありません</div>';
    return;
  }
  el.innerHTML = events.map(ev => {
    const statusClass = ev.status === 'published' ? 'status-published' : ev.status === 'draft' ? 'status-draft' : 'status-cancelled';
    const statusLabel = ev.status === 'published' ? '公開' : ev.status === 'draft' ? '下書き' : '中止';
    return \`
      <div class="card p-4 flex items-start justify-between gap-3">
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 mb-1 flex-wrap">
            <span class="text-xs font-bold text-amber-400">\${ev.event_date}</span>
            <span class="status-badge \${statusClass}">\${statusLabel}</span>
            \${ev.genre ? \`<span class="text-xs text-gray-500">\${ev.genre}</span>\` : ''}
          </div>
          <p class="font-bold truncate">\${ev.title}</p>
          <p class="text-sm text-gray-400"><i class="fas fa-store mr-1"></i>\${ev.venue_name}（\${ev.venue_area}）</p>
          \${ev.artists ? \`<p class="text-xs text-gray-500 mt-1">\${ev.artists}</p>\` : ''}
        </div>
        <div class="flex gap-2 flex-shrink-0">
          <button class="btn-edit" onclick="openEventFormById(\${ev.id})">編集</button>
          <button class="btn-danger" onclick="deleteEvent(\${ev.id})">削除</button>
        </div>
      </div>
    \`;
  }).join('');
}

function openEventFormById(id) {
  const ev = window._adminEventsMap && window._adminEventsMap[id];
  openEventForm(ev || null);
}

function openEventForm(ev) {
  document.getElementById('eventFormModal').classList.remove('hidden');
  document.getElementById('eventFormTitle').textContent = ev ? 'イベント編集' : 'イベント追加';
  
  // 会場セレクト更新
  const sel = document.getElementById('evVenue');
  sel.innerHTML = adminVenues.map(v => \`<option value="\${v.id}">\${v.name}（\${v.area}）</option>\`).join('');
  
  if (ev) {
    document.getElementById('eventId').value = ev.id;
    document.getElementById('evTitle').value = ev.title || '';
    document.getElementById('evVenue').value = ev.venue_id || '';
    document.getElementById('evDate').value = ev.event_date || '';
    document.getElementById('evOpenTime').value = ev.open_time || '';
    document.getElementById('evStartTime').value = ev.start_time || '';
    document.getElementById('evArtists').value = ev.artists || '';
    document.getElementById('evGenre').value = ev.genre || '';
    document.getElementById('evCharge').value = ev.charge_info || '';
    document.getElementById('evTicket').value = ev.ticket_url || '';
    document.getElementById('evDesc').value = ev.description || '';
    document.getElementById('evStatus').value = ev.status || 'published';
  } else {
    document.getElementById('eventId').value = '';
    document.getElementById('eventForm').reset();
    // デフォルト値
    const today = new Date();
    document.getElementById('evDate').value = today.toISOString().split('T')[0];
  }
}

function closeEventForm() {
  document.getElementById('eventFormModal').classList.add('hidden');
}

async function saveEvent(e) {
  e.preventDefault();
  const id = document.getElementById('eventId').value;
  const body = {
    venue_id: document.getElementById('evVenue').value,
    title: document.getElementById('evTitle').value,
    description: document.getElementById('evDesc').value,
    event_date: document.getElementById('evDate').value,
    open_time: document.getElementById('evOpenTime').value,
    start_time: document.getElementById('evStartTime').value,
    artists: document.getElementById('evArtists').value,
    genre: document.getElementById('evGenre').value,
    charge_info: document.getElementById('evCharge').value,
    ticket_url: document.getElementById('evTicket').value,
    status: document.getElementById('evStatus').value,
  };

  try {
    const res = await apiFetch(
      id ? \`/api/admin/events/\${id}\` : '/api/admin/events',
      { method: id ? 'PUT' : 'POST', body: JSON.stringify(body) }
    );
    if (res.ok) {
      closeEventForm();
      loadAdminEvents();
    } else {
      const d = await res.json();
      alert('保存エラー: ' + (d.error || ''));
    }
  } catch(e) {
    alert('エラーが発生しました');
  }
}

async function deleteEvent(id) {
  const ev = window._adminEventsMap && window._adminEventsMap[id];
  const title = ev ? ev.title : 'このイベント';
  if (!confirm(\`「\${title}」を削除しますか？\`)) return;
  try {
    const res = await apiFetch(\`/api/admin/events/\${id}\`, { method: 'DELETE' });
    if (res.ok) loadAdminEvents();
    else alert('削除エラー');
  } catch(e) { alert('エラー'); }
}

// ==================== 会場管理 ====================
async function loadAdminVenues() {
  try {
    const res = await apiFetch('/api/admin/venues');
    const data = await res.json();
    adminVenues = data.venues || [];
  } catch(e) {}
}

async function loadAdminVenuesTable() {
  await loadAdminVenues();
  // 会場データをグローバルマップに保存
  window._adminVenuesMap = {};
  adminVenues.forEach(v => { window._adminVenuesMap[v.id] = v; });

  const el = document.getElementById('venuesTable');
  if (adminVenues.length === 0) {
    el.innerHTML = '<p class="text-gray-500 text-center py-8">会場がありません</p>';
    return;
  }
  el.innerHTML = adminVenues.map(v => \`
    <div class="card p-4 flex items-start justify-between gap-3">
      <div class="flex-1">
        <div class="flex items-center gap-2 mb-1">
          <span class="font-bold">\${v.name}</span>
          <span class="text-xs px-2 py-0.5 rounded-full bg-amber-900 text-amber-300">\${v.area}</span>
        </div>
        \${v.address ? \`<p class="text-sm text-gray-400">\${v.address}</p>\` : ''}
        \${v.website ? \`<a href="\${v.website}" target="_blank" class="text-xs text-blue-400 hover:underline">\${v.website}</a>\` : ''}
      </div>
      <div class="flex gap-2">
        <button class="btn-edit" onclick="openVenueFormById(\${v.id})">編集</button>
        <button class="btn-danger" onclick="deleteVenue(\${v.id})">削除</button>
      </div>
    </div>
  \`).join('');
}

function openVenueFormById(id) {
  const v = window._adminVenuesMap && window._adminVenuesMap[id];
  openVenueForm(v || null);
}

function openVenueForm(v) {
  document.getElementById('venueFormModal').classList.remove('hidden');
  document.getElementById('venueFormTitle').textContent = v ? '会場編集' : '会場追加';
  if (v) {
    document.getElementById('venueId').value = v.id;
    document.getElementById('vnName').value = v.name || '';
    document.getElementById('vnArea').value = v.area || '';
    document.getElementById('vnAddress').value = v.address || '';
    document.getElementById('vnPhone').value = v.phone || '';
    document.getElementById('vnWebsite').value = v.website || '';
    document.getElementById('vnDesc').value = v.description || '';
  } else {
    document.getElementById('venueId').value = '';
    document.getElementById('venueForm').reset();
  }
}

function closeVenueForm() {
  document.getElementById('venueFormModal').classList.add('hidden');
}

async function saveVenue(e) {
  e.preventDefault();
  const id = document.getElementById('venueId').value;
  const body = {
    name: document.getElementById('vnName').value,
    area: document.getElementById('vnArea').value,
    address: document.getElementById('vnAddress').value,
    phone: document.getElementById('vnPhone').value,
    website: document.getElementById('vnWebsite').value,
    description: document.getElementById('vnDesc').value,
  };
  try {
    const res = await apiFetch(
      id ? \`/api/admin/venues/\${id}\` : '/api/admin/venues',
      { method: id ? 'PUT' : 'POST', body: JSON.stringify(body) }
    );
    if (res.ok) {
      closeVenueForm();
      loadAdminVenuesTable();
      loadAdminVenues();
    } else {
      alert('保存エラー');
    }
  } catch(e) { alert('エラー'); }
}

async function deleteVenue(id) {
  const v = window._adminVenuesMap && window._adminVenuesMap[id];
  const name = v ? v.name : 'この会場';
  if (!confirm(\`「\${name}」を削除しますか？\`)) return;
  try {
    const res = await apiFetch(\`/api/admin/venues/\${id}\`, { method: 'DELETE' });
    if (res.ok) { loadAdminVenuesTable(); loadAdminVenues(); }
    else alert('削除エラー');
  } catch(e) { alert('エラー'); }
}

// ==================== 設定 ====================
async function changePassword() {
  const cur = document.getElementById('curPw').value;
  const nw = document.getElementById('newPw').value;
  const nw2 = document.getElementById('newPw2').value;
  const msg = document.getElementById('pwMsg');
  msg.classList.remove('hidden','text-green-400','text-red-400');
  if (nw !== nw2) {
    msg.textContent = '新しいパスワードが一致しません';
    msg.classList.add('text-red-400');
    msg.classList.remove('hidden');
    return;
  }
  try {
    const res = await apiFetch('/api/admin/password', {
      method: 'PUT',
      body: JSON.stringify({ current_password: cur, new_password: nw })
    });
    const data = await res.json();
    if (res.ok) {
      msg.textContent = 'パスワードを変更しました';
      msg.classList.add('text-green-400');
      document.getElementById('curPw').value = '';
      document.getElementById('newPw').value = '';
      document.getElementById('newPw2').value = '';
    } else {
      msg.textContent = data.error || '変更エラー';
      msg.classList.add('text-red-400');
    }
    msg.classList.remove('hidden');
  } catch(e) {
    msg.textContent = 'サーバーエラー';
    msg.classList.add('text-red-400');
    msg.classList.remove('hidden');
  }
}

// ==================== 初期化 ====================
if (adminToken) {
  showAdmin();
}
</script>
</body>
</html>`
}

export default app
