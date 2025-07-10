// --- 必要なクレートの説明 ---
// このファイルは除外判定・svchostロジックをまとめるモジュールです
// crate::event_types::EventRecord: イベントレコード型（判定対象）

use crate::event_types::EventRecord; // イベントレコード型をインポート

// 除外プロセスリスト（1行1プロセス＋コメントで可読性向上）
const EXCLUDE_PROCS: &[&str] = &[
    "ctfmon.exe",                 // 入力関連
    "explorer.exe",               // エクスプローラ
    "OneDrive.exe",               // OneDrive
    "runtimebroker.exe",          // ランタイムブローカー
    "RuntimeBroker.exe",          // ランタイムブローカー（大文字）
    "sihost.exe",                 // Shell Infrastructure Host
    "startmenuexperiencehost.exe",// スタートメニュー
    "StartMenuExperienceHost.exe",// スタートメニュー（大文字）
    "taskhostw.exe",              // タスクホスト
    "ProcessListEnd",             // プロセスリスト終端
    "SearchIndexer.exe",          // 検索インデクサ
    "SearchHost.exe",             // 検索ホスト
    "ShellExperienceHost.exe",    // シェル体験ホスト
    "smartscreen.exe",            // SmartScreen
    "dwm.exe",                    // デスクトップウィンドウマネージャ
    "lsass.exe",                  // ローカルセキュリティ
    "lsm.exe",                    // ローカルセッションマネージャ
    "services.exe",               // サービスコントローラ
    "wininit.exe",                // Windows初期化
    "winlogon.exe",               // ログオンプロセス
    "csrss.exe",                  // クライアントサーバランタイム
    "spoolsv.exe",                // プリントスプーラ
    "audiodg.exe",                // オーディオデバイスグラフ
    "fontdrvhost.exe",            // フォントドライバホスト
    "SystemSettings.exe",         // システム設定
    "SecurityHealthSystray.exe",  // セキュリティ通知
    "conhost.exe",                // コンソールホスト
    "msedge.exe",                 // Microsoft Edge
    "chrome.exe",                 // Google Chrome
    "firefox.exe"                 // Firefox
];
// svchost.exeで起動される代表的なサービス名リスト（1行1サービス＋コメントで可読性向上）
const EXCLUDE_SVCHOST_SERVICES: &[&str] = &[
    "wuauserv",           // Windows Update
    "Dnscache",           // DNS Client
    "Dhcp",               // DHCP Client
    "EventLog",           // イベントログ
    "lmhosts",            // LMHOSTS
    "Themes",             // テーマ
    "ProfSvc",            // ユーザープロファイル
    "BITS",               // BITS
    "Winmgmt",            // WMI
    "Schedule",           // タスクスケジューラ
    "CryptSvc",           // 暗号化サービス
    "AudioSrv",           // オーディオ
    "LanmanWorkstation",  // ワークステーション
    "LanmanServer",       // サーバ
    "wscsvc",             // セキュリティセンター
    "w32time",            // 時刻同期
    "EventSystem",        // イベントシステム
    "PlugPlay",           // プラグアンドプレイ
    "Power",              // 電源
    "Spooler",            // プリントスプーラ
    "Netman",             // ネットワーク接続
    "WlanSvc",            // WLAN
    "Wecsvc",             // イベントコレクタ
    "RemoteRegistry",     // リモートレジストリ
    "SessionEnv",         // リモートデスクトップ
    "TermService",        // ターミナルサービス
    "WinDefend"           // Windows Defender
];

/// 除外プロセス・サービス判定、svchost出力レベル判定など
pub fn should_exclude(event: &EventRecord, svchost_level: u8, cmdline_audit_enabled: bool) -> bool {
    let app_name_lower = event.proc_info.to_ascii_lowercase(); // プロセス名を小文字化
    let is_svchost = app_name_lower.ends_with("svchost.exe"); // svchost.exeか判定
    let should_exclude_proc = EXCLUDE_PROCS.iter().any(|p| app_name_lower.ends_with(&p.to_ascii_lowercase())); // 除外プロセス判定
    // svchost.exeサービス名抽出（簡易）
    let mut svchost_service_name = String::new(); // サービス名初期化
    if is_svchost {
        if let Some(idx) = event.proc_info.find("-s ") { // コマンドラインに-sが含まれるか
            let rest = &event.proc_info[idx+3..]; // -s以降を取得
            if let Some(end) = rest.find(' ') { // 次の空白まで
                svchost_service_name = rest[..end].to_string(); // サービス名抽出
            } else {
                svchost_service_name = rest.to_string(); // 末尾まで
            }
        }
    }
    // svchost_levelによる分岐
    let svchost_output = match svchost_level {
        0 => true, // 全出力
        1 => {
            // 除外サービス名なら出力しない
            !(is_svchost && !svchost_service_name.is_empty() && EXCLUDE_SVCHOST_SERVICES.iter().any(|s| svchost_service_name.eq_ignore_ascii_case(s)))
        },
        2 => !is_svchost, // svchost.exeは全て出力しない
        _ => true, // デフォルトは全出力
    };
    // 除外判定
    should_exclude_proc || (is_svchost && (!cmdline_audit_enabled || !svchost_output)) // 除外条件
}
