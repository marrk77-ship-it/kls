-- サンプルイベントデータ
INSERT OR IGNORE INTO events (venue_id, title, description, event_date, start_time, open_time, artists, genre, charge_info, status) VALUES
  (1, 'Rock Night Vol.12', '熊本ローカルバンドが集結するロックナイト！', '2026-05-03', '19:00', '18:30', '爆音トリオ, THE KUMAMOTO, FIRE BOYS', 'ロック', '前売¥2,000 / 当日¥2,500', 'published'),
  (1, 'Spring Live 2026', 'GWスペシャルライブ', '2026-05-04', '18:00', '17:30', 'サクラダファミリア, BLUE NOTE', 'ポップス・ロック', '前売¥1,500 / 当日¥2,000', 'published'),
  (2, 'JAZZ NIGHT', 'ジャズセッションナイト', '2026-05-03', '20:00', '19:30', 'Kumamoto Jazz Trio', 'ジャズ', '¥1,000 (1ドリンク付)', 'published'),
  (3, 'Django Blues Session', '毎月恒例ブルースセッション', '2026-05-10', '20:00', '19:30', 'Django House Band & Guest', 'ブルース', '¥800 (1ドリンク付)', 'published'),
  (4, 'NAVARO ROCK FEST', 'ナバロロックフェスティバル', '2026-05-17', '18:00', '17:00', '熊本ロッカーズ, STEEL THUNDER, Crimson Wave', 'ロック・メタル', '前売¥2,500 / 当日¥3,000', 'published'),
  (1, 'Acoustic Sunday', 'アコースティックライブの夕べ', '2026-05-11', '17:00', '16:30', '田中 誠, 山本 花, DUO HARMONY', 'アコースティック', '¥1,000 (1ドリンク付)', 'published'),
  (5, 'shuffle OPEN MIC', 'オープンマイクナイト', '2026-05-08', '20:00', '19:30', 'OPEN MIC (参加自由)', 'オールジャンル', '無料 (1ドリンクオーダー)', 'published'),
  (2, 'IDOL NIGHT', 'アイドルライブナイト', '2026-05-24', '18:00', '17:00', 'Honey Drop, くまもとガールズ', 'アイドル', '前売¥2,000 / 当日¥2,500', 'published'),
  (6, 'Soul & Funk Night', 'ソウル・ファンクナイト', '2026-05-16', '21:00', '20:30', 'Groove Station', 'ソウル・ファンク', '¥1,000 (1ドリンク付)', 'published'),
  (1, 'Punk Rock Party', 'パンクロックパーティー！', '2026-05-30', '18:30', '18:00', 'THE PUNKS, Chaos Theory, DEAD HEAT', 'パンク', '前売¥2,000 / 当日¥2,500', 'published'),
  (3, 'Django Jazz Live', 'ジャズライブディナー', '2026-05-17', '19:00', '18:30', 'Django Jazz Quartet', 'ジャズ', '¥1,500 (1ドリンク付)', 'published'),
  (7, 'SPAZIO Live', '多ジャンルライブイベント', '2026-05-22', '19:00', '18:30', '山田バンド, ECHO, あおぞら', 'ポップス・ロック', '前売¥1,800 / 当日¥2,200', 'published'),
  (8, 'Drum Be-9 Special', '老舗ライブハウス特別公演', '2026-05-25', '17:00', '16:00', 'LEGENDARY KUMAMOTO BAND, 新世代バンド', 'ロック', '前売¥3,000 / 当日¥3,500', 'published');
