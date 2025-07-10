// --- 必要なクレートの説明 ---
// std::process::Command: 外部コマンド実行用（wevtutil, powershell, AuditPol等の呼び出しに使用）
// std::fs::File: ファイル作成・書き込み用
// std::io::Write: ファイルへの書き込み用
// chrono: 日時操作用（JST変換や期間指定、稼働時間計算）
// regex: 正規表現でイベントログXMLから情報抽出
//
// ※Cargo.tomlで chrono, regex を明示的に追加してください

use std::process::Command; // 外部コマンド実行
use std::fs::File;         // ファイル作成
use std::io::Write;        // ファイル書き込み
use chrono;                // 日時操作

// Security監査状態をチェックし、標準出力に通知
pub fn check_audit_log() {
    let output = Command::new("AuditPol") // AuditPolコマンド実行
        .args(&["/get", "/category:*"])
        .output()
        .expect("Failed");
    let result = String::from_utf8_lossy(&output.stdout); // コマンド出力を文字列化
    if result.contains("No Auditing") {
        println!("⚠️ Security監査が無効です。ログ改ざん検知が機能しません！");
    } else {
        println!("✅ Security監査は有効です。ログを分析可能です！");
    }
}

// 指定ログが有効かどうかを判定
pub fn check_log_enabled(log_name: &str) -> bool {
    let output = Command::new("wevtutil") // wevtutil glコマンド実行
        .args(&["gl", log_name])
        .output()
        .expect("Failed to run wevtutil gl");
    let result = String::from_utf8_lossy(&output.stdout); // コマンド出力を文字列化
    // enabled: true または enabled: 1 を含むかで判定
    result.to_lowercase().contains("enabled: true") || result.to_lowercase().contains("enabled: 1")
}

/// 管理者権限チェック・ログ有効化チェック・現在日時・稼働時間・監査状態・監査範囲出力をまとめて実行し、
/// 監査対象の開始・終了時刻（UTC）を返す。
pub fn precheck_and_info() -> Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>, chrono::FixedOffset, bool)> {
    // --- 管理者権限チェック（net sessionで判定） ---
    let admin_check = Command::new("cmd") // cmdでnet session実行
        .args(&["/C", "net session >nul 2>&1"])
        .status()
        .expect("Failed to check admin");
    if !admin_check.success() {
        let msg = "🛑 このアプリは管理者権限で実行してください。\n"; // 権限警告
        println!("{}", msg.trim());
        let mut file = File::create("output.txt").expect("ファイル作成失敗"); // 警告をoutput.txtにも出力
        file.write_all(msg.as_bytes()).unwrap();
        return None;
    }

    // --- イベントログの有効化状態をチェック ---
    let mut file = File::create("output.txt").expect("ファイル作成失敗"); // 出力ファイル作成
    let mut all_enabled = true; // すべて有効か
    let mut log_enabled_map = std::collections::HashMap::new(); // ログ名→有効/無効
    for log in ["System", "Application", "Microsoft-Windows-TaskScheduler/Operational", "Security"] {
        let enabled = check_log_enabled(log); // ログ有効判定
        log_enabled_map.insert(log, enabled); // 結果をマップに格納
        if enabled {
            let msg = format!("✅ {} ログは記録有効です。\n", log); // 有効通知
            println!("{}", msg.trim());
            file.write_all(msg.as_bytes()).unwrap();
        } else {
            let msg = format!("⚠️ {} ログは記録が無効です。\n", log); // 無効通知
            println!("{}", msg.trim());
            file.write_all(msg.as_bytes()).unwrap();
            all_enabled = false;
        }
    }
    if !all_enabled {
        let msg = "⚠️ 記録が無効なログはイベントビューアーでプロパティから「ログの有効化」にチェックを入れてください。\n"; // 全体警告
        println!("{}", msg.trim());
        file.write_all(msg.as_bytes()).unwrap();
        // return; ← ここを削除して続行
    }

    // --- 現在日時（アプリ起動日時）をJSTで出力 ---
    let now = chrono::Utc::now(); // UTC現在時刻取得
    let jst = chrono::FixedOffset::east_opt(9*3600).unwrap(); // JSTタイムゾーン
    let mut file = File::create("output.txt").expect("ファイル作成失敗"); // 出力ファイル再作成
    let msg = format!("ℹ️ アプリ起動日時: {}\n", now.with_timezone(&jst).format("%Y/%m/%d %H:%M:%S")); // 起動日時
    println!("{}", msg.trim());
    file.write_all(msg.as_bytes()).unwrap();

    // --- システム稼働時間をPowerShellで取得 ---
    let uptime_cmd = ["-Command", "(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')"];
    let uptime_output = Command::new("powershell")
        .args(&uptime_cmd)
        .output()
        .expect("Failed to get uptime");
    let boot_time_str = String::from_utf8_lossy(&uptime_output.stdout).trim().to_string(); // ブート時刻文字列
    // システム稼働時間-180秒からアプリ起動日時までの間のイベントを抽出
    let mut start_time = now;
    let mut end_time = now;
    if !boot_time_str.is_empty() {
        // --- ブート時刻のパース（ISO8601） ---
        if let Ok(boot_time) = chrono::DateTime::parse_from_rfc3339(&boot_time_str) {
            let now_utc = now.with_timezone(&chrono::Utc);
            start_time = boot_time.with_timezone(&chrono::Utc) - chrono::Duration::seconds(30); // ブート時刻-30秒
            // 直近のブート後1.5時間（90分）までを監査対象の終端とする
            let boot_plus_90 = boot_time.with_timezone(&chrono::Utc) + chrono::Duration::minutes(90);
            end_time = if now_utc < boot_plus_90 { now_utc } else { boot_plus_90 };
            let uptime_msg = format!("ℹ️ システム稼働時間: {}日 {}時間 {}分 {}秒\n", (now_utc - boot_time.with_timezone(&chrono::Utc)).num_days(), (now_utc - boot_time.with_timezone(&chrono::Utc)).num_hours()%24, (now_utc - boot_time.with_timezone(&chrono::Utc)).num_minutes()%60, (now_utc - boot_time.with_timezone(&chrono::Utc)).num_seconds()%60); // 稼働時間
            println!("{}", uptime_msg.trim());
            file.write_all(uptime_msg.as_bytes()).unwrap();
            // 監査対象日時範囲をJSTで出力
            let audit_range_msg = format!(
                "ℹ️ イベント監査対象日時: {} ～ {}\n",
                start_time.with_timezone(&jst).format("%Y/%m/%d %H:%M:%S"),
                end_time.with_timezone(&jst).format("%Y/%m/%d %H:%M:%S")
            );
            println!("{}", audit_range_msg.trim());
            file.write_all(audit_range_msg.as_bytes()).unwrap();
        } else if let Ok(boot_time) = chrono::DateTime::parse_from_str(&boot_time_str, "%Y-%m-%dT%H:%M:%S%.3fZ") {
            // --- 予備パース（ミリ秒3桁Z付き） ---
            let now_utc = now.with_timezone(&chrono::Utc);
            start_time = boot_time.with_timezone(&chrono::Utc) - chrono::Duration::seconds(180); // ブート時刻-180秒
            let boot_plus_90 = boot_time.with_timezone(&chrono::Utc) + chrono::Duration::minutes(90);
            end_time = if now_utc < boot_plus_90 { now_utc } else { boot_plus_90 };
            let uptime_msg = format!("ℹ️ システム稼働時間: {}日 {}時間 {}分 {}秒\n", (now_utc - boot_time.with_timezone(&chrono::Utc)).num_days(), (now_utc - boot_time.with_timezone(&chrono::Utc)).num_hours()%24, (now_utc - boot_time.with_timezone(&chrono::Utc)).num_minutes()%60, (now_utc - boot_time.with_timezone(&chrono::Utc)).num_seconds()%60); // 稼働時間
            println!("{}", uptime_msg.trim());
            file.write_all(uptime_msg.as_bytes()).unwrap();
            // 監査対象日時範囲をJSTで出力
            let audit_range_msg = format!(
                "ℹ️ イベント監査対象日時: {} ～ {}\n",
                start_time.with_timezone(&jst).format("%Y/%m/%d %H:%M:%S"),
                end_time.with_timezone(&jst).format("%Y/%m/%d %H:%M:%S")
            );
            println!("{}", audit_range_msg.trim());
            file.write_all(audit_range_msg.as_bytes()).unwrap();
        } else {
            // --- パース失敗時 ---
            let msg = format!("⚠️ システム稼働時間: 取得失敗 (生データ: {})\n", boot_time_str); // 失敗通知
            println!("{}", msg.trim());
            file.write_all(msg.as_bytes()).unwrap();
        }
    } else {
        // --- 取得失敗時 ---
        let msg = "⚠️ システム稼働時間: 取得失敗\n"; // 失敗通知
        println!("{}", msg.trim());
        file.write_all(msg.as_bytes()).unwrap();
    }

    // --- Security監査状態を確認 ---
    check_audit_log(); // 監査状態チェック

    // --- コマンドライン監査ポリシーの有効/未構成チェック ---
    let mut cmdline_audit_enabled = true; // 監査ポリシーフラグ
    let auditpol_output = Command::new("powershell")
        .args(["-Command", "Get-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessCreationIncludeCmdLine_Enabled"])
        .output();
    if let Ok(out) = auditpol_output {
        let val = String::from_utf8_lossy(&out.stdout).trim().to_string(); // レジストリ値
        if val != "1" {
            cmdline_audit_enabled = false;
            let msg = "⚠️ プロセス作成イベントにコマンドラインを含める監査ポリシーが未構成または無効です。svchost.exeの挙動詳細は出力できません。\n".to_string(); // 警告
            println!("{}", msg.trim());
            file.write_all(msg.as_bytes()).unwrap();
        }
    }

    // --- output.txt冒頭に監査対象日時のみ出力 ---
    let mut file = std::fs::File::create("output.txt").expect("ファイル作成失敗"); // ファイル再作成
    let audit_range_msg = format!(
        ">>> イベント監査対象日時: {} ～ {}\n",
        start_time.with_timezone(&jst).format("%Y/%m/%d %H:%M:%S"),
        end_time.with_timezone(&jst).format("%Y/%m/%d %H:%M:%S")
    ); // 監査範囲
    file.write_all(audit_range_msg.as_bytes()).unwrap();

    Some((start_time, end_time, jst, cmdline_audit_enabled)) // 監査範囲・JST・監査ポリシー有効フラグを返す
}
