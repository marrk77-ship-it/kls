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
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.0/css/all.min.css">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;700;900&display=swap');
    * { font-family: 'Noto Sans JP', sans-serif; }
    
    :root {
      --primary: #e11d48;
      --primary-dark: #9f1239;
      --bg-dark: #0f0f0f;
      --bg-card: #1a1a1a;
      --bg-card2: #242424;
      --text: #f0f0f0;
      --text-muted: #9ca3af;
      --border: #333;
      --accent: #f59e0b;
    }
    
    body { background: var(--bg-dark); color: var(--text); }
    
    .hero-gradient {
      background: linear-gradient(135deg, #0f0f0f 0%, #1a0a12 50%, #0f0f0f 100%);
      border-bottom: 1px solid #330a1a;
      position: relative;
      overflow: hidden;
    }
    .hero-gradient::before {
      content: '';
      position: absolute;
      top: -50%;
      left: -50%;
      width: 200%;
      height: 200%;
      background: radial-gradient(circle at 30% 50%, rgba(225,29,72,0.08) 0%, transparent 50%),
                  radial-gradient(circle at 70% 50%, rgba(245,158,11,0.05) 0%, transparent 50%);
      animation: bgPulse 8s ease-in-out infinite alternate;
    }
    @keyframes bgPulse {
      0% { transform: scale(1) rotate(0deg); }
      100% { transform: scale(1.1) rotate(3deg); }
    }
    
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      transition: all 0.25s ease;
    }
    .card:hover {
      border-color: var(--primary);
      box-shadow: 0 4px 24px rgba(225,29,72,0.15);
      transform: translateY(-2px);
    }
    
    .search-panel {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
    }
    
    .input-field {
      background: #111;
      border: 1px solid #444;
      color: var(--text);
      border-radius: 8px;
      padding: 8px 12px;
      width: 100%;
      transition: border-color 0.2s;
    }
    .input-field:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(225,29,72,0.15);
    }
    .input-field option { background: #1a1a1a; }
    
    .btn-primary {
      background: var(--primary);
      color: white;
      border: none;
      border-radius: 8px;
      padding: 8px 20px;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-primary:hover { background: #be123c; transform: translateY(-1px); }
    
    .btn-outline {
      background: transparent;
      color: var(--text-muted);
      border: 1px solid #444;
      border-radius: 8px;
      padding: 6px 16px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-outline:hover { border-color: var(--primary); color: var(--primary); }
    .btn-outline.active { border-color: var(--primary); color: var(--primary); background: rgba(225,29,72,0.1); }
    
    /* カレンダー */
    .calendar-grid {
      display: grid;
      grid-template-columns: repeat(7, 1fr);
      gap: 4px;
    }
    .cal-header {
      text-align: center;
      font-size: 12px;
      font-weight: 700;
      padding: 8px 4px;
      color: var(--text-muted);
    }
    .cal-header.sun { color: #f87171; }
    .cal-header.sat { color: #60a5fa; }
    .cal-day {
      min-height: 80px;
      background: var(--bg-card2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 6px;
      cursor: pointer;
      transition: all 0.2s;
      position: relative;
    }
    .cal-day:hover { border-color: #555; background: #2a2a2a; }
    .cal-day.has-event { border-color: rgba(225,29,72,0.4); }
    .cal-day.selected { border-color: var(--primary); background: rgba(225,29,72,0.1); }
    .cal-day.today .day-num { 
      background: var(--primary); color: white; border-radius: 50%;
      width: 26px; height: 26px; display: flex; align-items: center; justify-content: center;
    }
    .cal-day.other-month { opacity: 0.35; }
    .cal-day.sun-col .day-num { color: #f87171; }
    .cal-day.sat-col .day-num { color: #60a5fa; }
    .day-num { font-size: 13px; font-weight: 700; margin-bottom: 4px; width: 26px; height: 26px; display: flex; align-items: center; justify-content: center; }
    .event-dot {
      font-size: 10px;
      background: var(--primary);
      color: white;
      border-radius: 4px;
      padding: 1px 4px;
      margin-bottom: 2px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 100%;
      display: block;
    }
    .event-dot.jazz { background: #7c3aed; }
    .event-dot.blues { background: #1d4ed8; }
    .event-dot.acoustic { background: #059669; }
    .event-dot.soul { background: #d97706; }
    .event-dot.idol { background: #db2777; }
    
    /* イベントカード */
    .genre-badge {
      font-size: 11px;
      border-radius: 100px;
      padding: 2px 10px;
      background: rgba(225,29,72,0.15);
      color: #fb7185;
      border: 1px solid rgba(225,29,72,0.3);
      display: inline-block;
    }
    .area-badge {
      font-size: 11px;
      border-radius: 100px;
      padding: 2px 10px;
      background: rgba(245,158,11,0.1);
      color: #fbbf24;
      border: 1px solid rgba(245,158,11,0.3);
      display: inline-block;
    }
    
    /* モーダル */
    .modal-overlay {
      position: fixed; inset: 0; background: rgba(0,0,0,0.85);
      z-index: 1000; display: flex; align-items: center; justify-content: center;
      backdrop-filter: blur(4px);
    }
    .modal-box {
      background: #1c1c1c; border: 1px solid #444; border-radius: 16px;
      padding: 28px; max-width: 560px; width: 92%; max-height: 90vh; overflow-y: auto;
    }
    
    .logo-text {
      font-size: 22px;
      font-weight: 900;
      letter-spacing: 0.05em;
    }
    .logo-text span { color: var(--primary); }
    
    .nav-tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border); margin-bottom: 20px; }
    .nav-tab {
      padding: 8px 20px;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      font-weight: 500;
      color: var(--text-muted);
      transition: all 0.2s;
    }
    .nav-tab.active { border-bottom-color: var(--primary); color: var(--primary); }
    
    @media (max-width: 640px) {
      .cal-day { min-height: 52px; padding: 3px; }
      .day-num { font-size: 11px; }
      .event-dot { display: none; }
      .cal-day.has-event::after {
        content: '●';
        color: var(--primary);
        font-size: 8px;
        display: block;
      }
    }
    
    .loading-spinner {
      width: 36px; height: 36px; border: 3px solid #333;
      border-top-color: var(--primary); border-radius: 50%;
      animation: spin 0.8s linear infinite; margin: 20px auto;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: #111; }
    ::-webkit-scrollbar-thumb { background: #444; border-radius: 3px; }
  </style>
</head>
<body>

<!-- ナビゲーション -->
<nav class="sticky top-0 z-50 border-b border-gray-800" style="background: rgba(15,15,15,0.95); backdrop-filter: blur(10px);">
  <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
    <div class="logo-text">
      <i class="fas fa-music text-red-500 mr-2"></i>
      KUMAMOTO <span>LIVE</span> GUIDE
    </div>
    <div class="flex items-center gap-3">
      <span id="currentMonthLabel" class="text-gray-400 text-sm hidden sm:block"></span>
    </div>
  </div>
</nav>

<!-- ヒーロー & 検索 -->
<div class="hero-gradient py-10 px-4">
  <div class="max-w-7xl mx-auto relative z-10">
    <div class="text-center mb-8">
      <h1 class="text-3xl sm:text-4xl font-black mb-2">
        熊本のライブ情報を<span style="color: var(--primary)">まとめて</span>チェック
      </h1>
      <p class="text-gray-400">ライブハウス・ライブバーのスケジュールを一括検索</p>
    </div>
    
    <!-- 検索パネル -->
    <div class="search-panel p-5 max-w-4xl mx-auto">
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
        <div>
          <label class="text-xs text-gray-400 mb-1 block"><i class="fas fa-calendar-alt mr-1"></i>日付</label>
          <input type="date" id="searchDate" class="input-field text-sm">
        </div>
        <div>
          <label class="text-xs text-gray-400 mb-1 block"><i class="fas fa-map-marker-alt mr-1"></i>地区</label>
          <select id="searchArea" class="input-field text-sm">
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
          <label class="text-xs text-gray-400 mb-1 block"><i class="fas fa-store mr-1"></i>会場</label>
          <select id="searchVenue" class="input-field text-sm">
            <option value="">すべての会場</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-gray-400 mb-1 block"><i class="fas fa-guitar mr-1"></i>ジャンル</label>
          <select id="searchGenre" class="input-field text-sm">
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
      <div class="flex gap-2">
        <div class="flex-1">
          <input type="text" id="searchKeyword" placeholder="🔍  アーティスト名・イベント名で検索..." class="input-field text-sm">
        </div>
        <button onclick="doSearch()" class="btn-primary px-6"><i class="fas fa-search mr-1"></i>検索</button>
        <button onclick="clearSearch()" class="btn-outline px-3" title="クリア"><i class="fas fa-times"></i></button>
      </div>
    </div>
  </div>
</div>

<!-- メインコンテンツ -->
<div class="max-w-7xl mx-auto px-4 py-8">
  
  <!-- タブ -->
  <div class="nav-tabs">
    <div class="nav-tab active" onclick="showTab('calendar')" id="tab-calendar">
      <i class="fas fa-calendar-alt mr-1"></i>カレンダー
    </div>
    <div class="nav-tab" onclick="showTab('list')" id="tab-list">
      <i class="fas fa-list mr-1"></i>一覧
    </div>
  </div>

  <!-- カレンダービュー -->
  <div id="view-calendar">
    <div class="flex items-center justify-between mb-5">
      <button onclick="changeMonth(-1)" class="btn-outline px-4">
        <i class="fas fa-chevron-left"></i>
      </button>
      <h2 id="calMonthTitle" class="text-xl font-bold"></h2>
      <button onclick="changeMonth(1)" class="btn-outline px-4">
        <i class="fas fa-chevron-right"></i>
      </button>
    </div>
    
    <div class="calendar-grid mb-2">
      <div class="cal-header sun">日</div>
      <div class="cal-header">月</div>
      <div class="cal-header">火</div>
      <div class="cal-header">水</div>
      <div class="cal-header">木</div>
      <div class="cal-header">金</div>
      <div class="cal-header sat">土</div>
    </div>
    <div class="calendar-grid" id="calendarBody"></div>
    
    <!-- 選択日のイベント -->
    <div id="selectedDateEvents" class="mt-6 hidden">
      <h3 id="selectedDateTitle" class="text-lg font-bold mb-4 text-gray-200"></h3>
      <div id="selectedDateEventList" class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3"></div>
    </div>
  </div>

  <!-- 一覧ビュー -->
  <div id="view-list" class="hidden">
    <div id="searchResultInfo" class="text-sm text-gray-400 mb-4"></div>
    <div id="loadingSpinner" class="hidden"><div class="loading-spinner"></div></div>
    <div id="eventList" class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3"></div>
    <div id="noResults" class="hidden text-center py-16 text-gray-500">
      <i class="fas fa-music text-5xl mb-4 block opacity-30"></i>
      <p class="text-lg">イベントが見つかりませんでした</p>
      <p class="text-sm mt-2">検索条件を変えてお試しください</p>
    </div>
  </div>
</div>

<!-- イベント詳細モーダル -->
<div id="eventModal" class="modal-overlay hidden" onclick="closeModal(event)">
  <div class="modal-box" onclick="event.stopPropagation()">
    <button onclick="closeModal()" class="float-right text-gray-500 hover:text-white text-xl"><i class="fas fa-times"></i></button>
    <div id="modalContent"></div>
  </div>
</div>

<!-- フッター -->
<footer class="border-t border-gray-800 mt-16 py-8 px-4 text-center text-gray-600 text-sm">
  <p class="font-bold text-gray-400 mb-1"><i class="fas fa-music mr-1"></i>KUMAMOTO LIVE GUIDE</p>
  <p>熊本市内のライブハウス・ライブバーのスケジュール情報サイト</p>
</footer>

<script>
// ==================== グローバル状態 ====================
let currentMonth = new Date();
let allVenues = [];
let calendarEvents = {};
let selectedDate = null;
let currentTab = 'calendar';
let allEvents = [];

// ==================== 初期化 ====================
async function init() {
  const now = new Date();
  currentMonth = new Date(now.getFullYear(), now.getMonth(), 1);
  document.getElementById('currentMonthLabel').textContent =
    now.getFullYear() + '年' + (now.getMonth() + 1) + '月';
  
  await loadVenues();
  await loadMonthEvents();
  renderCalendar();
  
  // エンターキーで検索
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
      opt.value = v.id;
      opt.textContent = v.name;
      sel.appendChild(opt);
    });
  } catch(e) {}
}

async function loadMonthEvents() {
  const y = currentMonth.getFullYear();
  const m = String(currentMonth.getMonth() + 1).padStart(2, '0');
  const monthStr = y + '-' + m;
  try {
    const res = await fetch('/api/events?month=' + monthStr);
    const data = await res.json();
    calendarEvents = {};
    (data.events || []).forEach(ev => {
      if (!calendarEvents[ev.event_date]) calendarEvents[ev.event_date] = [];
      calendarEvents[ev.event_date].push(ev);
    });
    document.getElementById('currentMonthLabel').textContent = y + '年' + parseInt(m) + '月';
  } catch(e) {}
}

// ==================== カレンダー ====================
function renderCalendar() {
  const y = currentMonth.getFullYear();
  const m = currentMonth.getMonth();
  document.getElementById('calMonthTitle').textContent = y + '年' + (m + 1) + '月';
  
  const firstDay = new Date(y, m, 1).getDay();
  const lastDate = new Date(y, m + 1, 0).getDate();
  const prevLastDate = new Date(y, m, 0).getDate();
  const today = new Date();
  const todayStr = today.getFullYear() + '-' + String(today.getMonth()+1).padStart(2,'0') + '-' + String(today.getDate()).padStart(2,'0');

  let html = '';
  let day = 1;
  let nextDay = 1;
  const totalCells = Math.ceil((firstDay + lastDate) / 7) * 7;

  for (let i = 0; i < totalCells; i++) {
    const col = i % 7;
    let dateStr, dayNum, classes = ['cal-day'];

    if (i < firstDay) {
      dayNum = prevLastDate - firstDay + i + 1;
      const pm = m === 0 ? 12 : m;
      const py = m === 0 ? y - 1 : y;
      dateStr = py + '-' + String(pm).padStart(2,'0') + '-' + String(dayNum).padStart(2,'0');
      classes.push('other-month');
    } else if (day <= lastDate) {
      dayNum = day;
      dateStr = y + '-' + String(m+1).padStart(2,'0') + '-' + String(dayNum).padStart(2,'0');
      day++;
    } else {
      dayNum = nextDay++;
      const nm = m + 2 > 12 ? 1 : m + 2;
      const ny = m + 2 > 12 ? y + 1 : y;
      dateStr = ny + '-' + String(nm).padStart(2,'0') + '-' + String(dayNum).padStart(2,'0');
      classes.push('other-month');
    }

    if (col === 0) classes.push('sun-col');
    if (col === 6) classes.push('sat-col');
    if (dateStr === todayStr) classes.push('today');
    if (selectedDate === dateStr) classes.push('selected');

    const dayEvents = calendarEvents[dateStr] || [];
    if (dayEvents.length > 0) classes.push('has-event');

    const eventsHtml = dayEvents.slice(0, 3).map(ev => {
      const genreClass = getGenreClass(ev.genre);
      const label = ev.venue_name || ev.title;
      return \`<span class="event-dot \${genreClass}" title="\${ev.title}">\${label}</span>\`;
    }).join('');
    const moreHtml = dayEvents.length > 3 ? \`<span style="font-size:10px;color:#888">+\${dayEvents.length - 3}件</span>\` : '';

    html += \`<div class="\${classes.join(' ')}" onclick="selectDate('\${dateStr}')">
      <div class="day-num">\${dayNum}</div>
      \${eventsHtml}\${moreHtml}
    </div>\`;
  }

  document.getElementById('calendarBody').innerHTML = html;
}

function getGenreClass(genre) {
  if (!genre) return '';
  if (genre.includes('ジャズ')) return 'jazz';
  if (genre.includes('ブルース')) return 'blues';
  if (genre.includes('アコースティック')) return 'acoustic';
  if (genre.includes('ソウル') || genre.includes('ファンク')) return 'soul';
  if (genre.includes('アイドル')) return 'idol';
  return '';
}

function selectDate(dateStr) {
  selectedDate = selectedDate === dateStr ? null : dateStr;
  renderCalendar();
  
  if (!selectedDate) {
    document.getElementById('selectedDateEvents').classList.add('hidden');
    return;
  }
  
  const events = calendarEvents[dateStr] || [];
  const d = new Date(dateStr + 'T00:00:00');
  const weekday = ['日','月','火','水','木','金','土'][d.getDay()];
  document.getElementById('selectedDateTitle').textContent =
    \`\${d.getFullYear()}年\${d.getMonth()+1}月\${d.getDate()}日（\${weekday}）のライブ\`;
  
  const container = document.getElementById('selectedDateEventList');
  if (events.length === 0) {
    container.innerHTML = '<p class="text-gray-500 col-span-3">この日はイベントがありません</p>';
  } else {
    container.innerHTML = events.map(ev => renderEventCard(ev)).join('');
  }
  document.getElementById('selectedDateEvents').classList.remove('hidden');
  document.getElementById('selectedDateEvents').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function changeMonth(delta) {
  currentMonth = new Date(currentMonth.getFullYear(), currentMonth.getMonth() + delta, 1);
  selectedDate = null;
  document.getElementById('selectedDateEvents').classList.add('hidden');
  await loadMonthEvents();
  renderCalendar();
}

// ==================== 一覧・検索 ====================
function showTab(tab) {
  currentTab = tab;
  document.getElementById('view-calendar').classList.toggle('hidden', tab !== 'calendar');
  document.getElementById('view-list').classList.toggle('hidden', tab !== 'list');
  document.getElementById('tab-calendar').classList.toggle('active', tab === 'calendar');
  document.getElementById('tab-list').classList.toggle('active', tab === 'list');
  if (tab === 'list' && allEvents.length === 0) loadListEvents();
}

async function loadListEvents(params) {
  const spinner = document.getElementById('loadingSpinner');
  spinner.classList.remove('hidden');
  document.getElementById('eventList').innerHTML = '';
  document.getElementById('noResults').classList.add('hidden');

  try {
    const url = params ? '/api/events?' + new URLSearchParams(params) : '/api/events';
    const res = await fetch(url);
    const data = await res.json();
    allEvents = data.events || [];
    renderEventList(allEvents);
  } catch(e) {
    document.getElementById('eventList').innerHTML = '<p class="text-red-400">読み込みエラー</p>';
  } finally {
    spinner.classList.add('hidden');
  }
}

function renderEventList(events) {
  const info = document.getElementById('searchResultInfo');
  const list = document.getElementById('eventList');
  const noRes = document.getElementById('noResults');

  if (events.length === 0) {
    info.textContent = '';
    list.innerHTML = '';
    noRes.classList.remove('hidden');
    return;
  }

  info.textContent = \`\${events.length}件のイベントが見つかりました\`;
  noRes.classList.add('hidden');
  list.innerHTML = events.map(ev => renderEventCard(ev)).join('');
}

function renderEventCard(ev) {
  const d = new Date(ev.event_date + 'T00:00:00');
  const weekday = ['日','月','火','水','木','金','土'][d.getDay()];
  const dateLabel = \`\${d.getMonth()+1}/\${d.getDate()}(\${weekday})\`;
  const timeLabel = ev.open_time ? \`開場\${ev.open_time} / \` : '';
  const startLabel = ev.start_time ? \`開演\${ev.start_time}\` : '';

  return \`
    <div class="card p-4 cursor-pointer" onclick="showEventDetail(\${ev.id})">
      <div class="flex items-start justify-between mb-2">
        <div>
          <span class="text-xs font-bold" style="color: var(--accent)">\${dateLabel}</span>
          \${ev.genre ? \`<span class="genre-badge ml-2">\${ev.genre}</span>\` : ''}
        </div>
        <span class="area-badge">\${ev.venue_area}</span>
      </div>
      <h3 class="font-bold text-base mb-1 leading-tight">\${ev.title}</h3>
      <p class="text-sm text-gray-400 mb-2">
        <i class="fas fa-store mr-1 text-gray-500"></i>\${ev.venue_name}
      </p>
      \${ev.artists ? \`<p class="text-xs text-gray-400 mb-2"><i class="fas fa-microphone mr-1 text-gray-500"></i>\${ev.artists}</p>\` : ''}
      <div class="flex items-center justify-between mt-3 pt-3 border-t border-gray-800">
        <span class="text-xs text-gray-500">\${timeLabel}\${startLabel}</span>
        <span class="text-xs font-bold" style="color: var(--accent)">\${ev.charge_info || ''}</span>
      </div>
    </div>
  \`;
}

async function doSearch() {
  const date = document.getElementById('searchDate').value;
  const area = document.getElementById('searchArea').value;
  const venue_id = document.getElementById('searchVenue').value;
  const genre = document.getElementById('searchGenre').value;
  const keyword = document.getElementById('searchKeyword').value;

  const params = {};
  if (date) params.date = date;
  if (area) params.area = area;
  if (venue_id) params.venue_id = venue_id;
  if (genre) params.genre = genre;
  if (keyword) params.keyword = keyword;

  showTab('list');
  await loadListEvents(params);
}

function clearSearch() {
  document.getElementById('searchDate').value = '';
  document.getElementById('searchArea').value = '';
  document.getElementById('searchVenue').value = '';
  document.getElementById('searchGenre').value = '';
  document.getElementById('searchKeyword').value = '';
  allEvents = [];
  document.getElementById('eventList').innerHTML = '';
  document.getElementById('searchResultInfo').textContent = '';
  showTab('calendar');
}

// ==================== 詳細モーダル ====================
async function showEventDetail(id) {
  document.getElementById('eventModal').classList.remove('hidden');
  document.getElementById('modalContent').innerHTML = '<div class="loading-spinner"></div>';
  try {
    const res = await fetch('/api/events/' + id);
    const data = await res.json();
    const ev = data.event;
    const d = new Date(ev.event_date + 'T00:00:00');
    const weekday = ['日','月','火','水','木','金','土'][d.getDay()];
    const artists = ev.artists ? ev.artists.split(',').map(a => a.trim()).filter(a => a) : [];

    document.getElementById('modalContent').innerHTML = \`
      <div>
        \${ev.genre ? \`<span class="genre-badge mb-3 inline-block">\${ev.genre}</span>\` : ''}
        <h2 class="text-xl font-black mb-3 leading-tight">\${ev.title}</h2>
        
        <div class="space-y-2 mb-5">
          <div class="flex items-center gap-2 text-sm">
            <i class="fas fa-calendar w-5 text-center" style="color:var(--accent)"></i>
            <span class="font-bold">\${d.getFullYear()}年\${d.getMonth()+1}月\${d.getDate()}日（\${weekday}）</span>
          </div>
          \${ev.open_time ? \`<div class="flex items-center gap-2 text-sm"><i class="fas fa-door-open w-5 text-center text-gray-500"></i><span>開場: \${ev.open_time}</span></div>\` : ''}
          \${ev.start_time ? \`<div class="flex items-center gap-2 text-sm"><i class="fas fa-play-circle w-5 text-center text-gray-500"></i><span>開演: \${ev.start_time}</span></div>\` : ''}
          <div class="flex items-center gap-2 text-sm">
            <i class="fas fa-map-marker-alt w-5 text-center text-gray-500"></i>
            <span>\${ev.venue_name}（\${ev.venue_area}）</span>
          </div>
          \${ev.venue_address ? \`<div class="flex items-center gap-2 text-sm"><i class="fas fa-location-dot w-5 text-center text-gray-500"></i><span class="text-gray-400">\${ev.venue_address}</span></div>\` : ''}
          \${ev.charge_info ? \`<div class="flex items-center gap-2 text-sm"><i class="fas fa-ticket w-5 text-center text-gray-500"></i><span class="font-bold" style="color:var(--accent)">\${ev.charge_info}</span></div>\` : ''}
        </div>
        
        \${artists.length > 0 ? \`
          <div class="mb-4">
            <p class="text-xs text-gray-500 uppercase tracking-wider mb-2">出演</p>
            <div class="flex flex-wrap gap-2">
              \${artists.map(a => \`<span class="text-sm bg-gray-800 rounded-full px-3 py-1">\${a}</span>\`).join('')}
            </div>
          </div>
        \` : ''}
        
        \${ev.description ? \`
          <div class="mb-4 p-3 rounded-lg bg-gray-900 text-sm text-gray-300 leading-relaxed">
            \${ev.description}
          </div>
        \` : ''}
        
        \${ev.ticket_url ? \`
          <a href="\${ev.ticket_url}" target="_blank" class="btn-primary inline-block text-center w-full mt-2 py-2 rounded-lg no-underline">
            <i class="fas fa-ticket mr-2"></i>チケット購入
          </a>
        \` : ''}
        \${ev.venue_website ? \`
          <a href="\${ev.venue_website}" target="_blank" class="btn-outline block text-center w-full mt-2 py-2 rounded-lg no-underline">
            <i class="fas fa-globe mr-2"></i>会場公式サイト
          </a>
        \` : ''}
      </div>
    \`;
  } catch(e) {
    document.getElementById('modalContent').innerHTML = '<p class="text-red-400">読み込みエラー</p>';
  }
}

function closeModal(e) {
  if (!e || e.target === document.getElementById('eventModal')) {
    document.getElementById('eventModal').classList.add('hidden');
  }
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
});

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
    .sidebar-btn { display: flex; align-items: center; gap-3; width: 100%; padding: 10px 16px; border-radius: 8px; cursor: pointer; transition: all 0.2s; color: #9ca3af; font-weight: 500; border: none; background: transparent; }
    .sidebar-btn:hover { background: #222; color: #f0f0f0; }
    .sidebar-btn.active { background: rgba(225,29,72,0.15); color: #fb7185; }
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
  <aside class="w-56 flex-shrink-0 border-r border-gray-800 flex flex-col" style="background:#111">
    <div class="p-4 border-b border-gray-800">
      <div class="text-sm font-black text-red-400"><i class="fas fa-music mr-1"></i>KUMAMOTO LIVE</div>
      <div class="text-xs text-gray-600 mt-0.5">管理画面</div>
    </div>
    <nav class="flex-1 p-3 space-y-1">
      <button class="sidebar-btn active" onclick="showSection('events')" id="nav-events">
        <i class="fas fa-calendar-alt w-5"></i>イベント管理
      </button>
      <button class="sidebar-btn" onclick="showSection('venues')" id="nav-venues">
        <i class="fas fa-store w-5"></i>会場管理
      </button>
      <button class="sidebar-btn" onclick="showSection('settings')" id="nav-settings">
        <i class="fas fa-cog w-5"></i>設定
      </button>
    </nav>
    <div class="p-3 border-t border-gray-800">
      <p id="adminUsername" class="text-xs text-gray-500 mb-2"></p>
      <button onclick="doLogout()" class="sidebar-btn text-gray-500 text-sm">
        <i class="fas fa-sign-out-alt w-5"></i>ログアウト
      </button>
      <a href="/" target="_blank" class="sidebar-btn text-gray-500 text-sm mt-1 block no-underline">
        <i class="fas fa-external-link-alt w-5"></i>公開サイト
      </a>
    </div>
  </aside>

  <!-- コンテンツエリア -->
  <main class="flex-1 overflow-y-auto">
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

// ==================== セクション切替 ====================
function showSection(name) {
  ['events','venues','settings'].forEach(s => {
    document.getElementById('section-' + s).classList.toggle('hidden', s !== name);
    document.getElementById('nav-' + s).classList.toggle('active', s === name);
  });
  if (name === 'venues') loadAdminVenuesTable();
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
