-- 地区テーブル
CREATE TABLE IF NOT EXISTS areas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  sort_order INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 既存の地区データを初期投入
INSERT OR IGNORE INTO areas (name, sort_order) VALUES
  ('下通', 1),
  ('上通', 2),
  ('新市街', 3),
  ('水道町', 4),
  ('帯山', 5),
  ('その他', 99);
