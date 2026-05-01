-- 会場テーブル
CREATE TABLE IF NOT EXISTS venues (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  area TEXT NOT NULL,  -- 例: 下通, 上通, 新市街, 水道町, その他
  address TEXT,
  phone TEXT,
  website TEXT,
  description TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- イベント/スケジュールテーブル
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  venue_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  event_date TEXT NOT NULL,   -- YYYY-MM-DD
  start_time TEXT,            -- HH:MM
  open_time TEXT,             -- HH:MM (開場時間)
  end_time TEXT,              -- HH:MM
  artists TEXT,               -- 出演アーティスト (カンマ区切り or JSON)
  genre TEXT,                 -- 音楽ジャンル
  charge_info TEXT,           -- 料金情報
  ticket_url TEXT,            -- チケットURL
  image_url TEXT,             -- イベントフライヤー画像URL
  status TEXT DEFAULT 'published', -- published / draft / cancelled
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (venue_id) REFERENCES venues(id)
);

-- 管理者テーブル
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  session_token TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- インデックス
CREATE INDEX IF NOT EXISTS idx_events_date ON events(event_date);
CREATE INDEX IF NOT EXISTS idx_events_venue_id ON events(venue_id);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status);

-- 初期会場データ（熊本市内の代表的なライブスポット）
INSERT OR IGNORE INTO venues (name, area, address, description) VALUES
  ('B.9 V1', '下通', '熊本市中央区下通1丁目', '熊本を代表するライブハウス'),
  ('B.9 V2', '下通', '熊本市中央区下通1丁目', 'B.9の姉妹店'),
  ('Django', '上通', '熊本市中央区上通町', 'ジャズ・ブルース系ライブバー'),
  ('NAVARO', '新市街', '熊本市中央区新市街', 'ロック系ライブハウス'),
  ('shuffle', '水道町', '熊本市中央区水道町', 'ライブバー'),
  ('Gate''s 7', '上通', '熊本市中央区上通町', 'ライブバー・バー'),
  ('SPAZIO', '帯山', '熊本市中央区帯山', 'ライブスペース'),
  ('DRUM Be-9', '下通', '熊本市中央区下通', '老舗ライブハウス');

-- 初期管理者アカウント (username: admin, password: kumamoto2024)
-- パスワードハッシュは SHA-256: kumamoto2024
INSERT OR IGNORE INTO admins (username, password_hash) VALUES
  ('admin', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8');
