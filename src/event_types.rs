// --- 必要なクレートの説明 ---
// このファイルはイベント情報を保持する構造体や型定義をまとめるモジュールです
// 標準クレートのみで動作（外部依存なし）

/// イベント情報を保持する構造体や型定義をまとめる
/// 今後必要に応じて拡張

#[derive(Debug, Clone)] // デバッグ表示・クローン可
pub struct EventRecord {
    pub datetime_utc: String,      // UTC日時文字列
    pub log_name: String,          // ログ名
    pub user: String,              // ユーザー名
    pub event_id: String,          // イベントID
    pub action: String,            // アクション種別
    pub description: String,       // イベント説明
    pub proc_info: String,         // プロセス名やコマンドライン等
    pub logon_type: String,        // ログオンタイプ（4624用）
    pub command_line: String,      // コマンドライン（4688用）
}
