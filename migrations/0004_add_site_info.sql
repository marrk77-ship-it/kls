-- サイト情報テーブル（キーバリュー形式）
CREATE TABLE IF NOT EXISTS site_info (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT '',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 初期値
INSERT OR IGNORE INTO site_info (key, value) VALUES
  ('site_description', '熊本市内のライブハウス・ライブバーのスケジュール情報をまとめたサイトです。'),
  ('team',             '熊本ライブガイド 運営チーム'),
  ('contact_email',    ''),
  ('contact_note',     '');
