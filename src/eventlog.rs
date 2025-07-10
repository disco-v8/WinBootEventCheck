// --- 必要なクレートの説明 ---
// std::process::Command: 外部コマンド実行用（wevtutil等の呼び出しに使用）
// std::io::Write: ファイルへの書き込み用
// quick_xml: XMLパース用（イベントログの解析）
// chrono: 日時操作用（JST変換や期間指定）
// regex: コマンドラインからサービス名抽出用
//
// ※Cargo.tomlで quick-xml, chrono, regex を明示的に追加してください

use std::io::Write;        // ファイル書き込み用
use crate::event_types::EventRecord; // イベントレコード型
use crate::event_query::fetch_eventlog_xml; // イベントログXML取得関数
use crate::event_parse::parse_events; // XMLパース関数
use crate::event_filter::should_exclude; // 除外判定関数
use crate::event_util::utc_str_to_jst; // UTC→JST変換関数

// イベントログを解析し、output.txtに出力するメイン関数
pub fn analyze_and_output_events(
    start_time: chrono::DateTime<chrono::Utc>, // 監査開始時刻
    end_time: chrono::DateTime<chrono::Utc>,   // 監査終了時刻
    jst: chrono::FixedOffset,                  // JSTタイムゾーン
    cmdline_audit_enabled: bool,               // コマンドライン監査有効フラグ
    svchost_level: u8                          // svchost.exe出力レベル
) {
    // svchost出力レベルの説明文を決定
    let svchost_level_msg = match svchost_level {
        0 => "システムサービス関連(svchost.exe)の出力レベルは「全て出力（-s0）」です", // -s0: 全て出力
        1 => "システムサービス関連(svchost.exe)の出力レベルは「除外リスト方式（-s1）」です", // -s1: 除外リスト方式
        2 => "システムサービス関連(svchost.exe)の出力レベルは「全て除外（-s2）」です", // -s2: 全て除外
        _ => "システムサービス関連(svchost.exe)の出力レベルは「全て出力（デフォルト）」です", // デフォルト
    };
    // 監査対象日時の案内文を作成
    let date_range_msg = format!(
        ">>> イベント監査対象日時: {} ～ {}\n",
        start_time.with_timezone(&jst).format("%Y/%m/%d %H:%M:%S"), // JST変換
        end_time.with_timezone(&jst).format("%Y/%m/%d %H:%M:%S")    // JST変換
    );
    // svchost出力レベル案内文を作成
    let svchost_level_msg_line = format!(">>> {}\n", svchost_level_msg);
    // イベントIDごとのアクション・説明マップ
    let event_id_action_map = [
        ("6005", ("起動", "イベントログサービスの起動")), // サービス起動
        ("6006", ("終了", "イベントログサービスの終了")), // サービス終了
        ("1100", ("ログサービス停止", "イベントログサービスの停止")), // ログサービス停止
        ("1102", ("ログ消去", "イベントログの消去")), // ログ消去
        ("12",   ("起動", "システム起動")), // システム起動
        ("1074", ("シャットダウン/再起動", "ユーザーまたはプロセスによるシャットダウン/再起動")), // シャットダウン/再起動
        ("6009", ("起動", "システム起動(バージョン情報)")), // バージョン情報
        ("1000", ("起動", "アプリケーション起動")), // アプリ起動
        ("1001", ("終了", "アプリケーション終了")), // アプリ終了
        ("200",  ("起動", "タスクスケジューラ起動")), // タスクスケジューラ起動
        ("201",  ("終了", "タスクスケジューラ終了")), // タスクスケジューラ終了
        ("41",   ("予期せぬシャットダウン", "予期せぬシャットダウン")), // 予期せぬシャットダウン
        ("13",   ("予期せぬシャットダウン(電源)", "予期せぬシャットダウン(電源)")), // 電源系
        ("6008", ("予期しないシャットダウン", "予期しないシャットダウン")), // 予期しないシャットダウン
        ("4688", ("アプリ起動", "新しいプロセスの作成 (プロセス起動)")), // プロセス作成
        ("4624", ("ログオン", "アカウントの正常なログオン")), // ログオン
        ("4647", ("ログオフ", "ユーザーのログオフ")), // ログオフ
        // ...他にも必要に応じて追加...
    ];
    // ログ種別ごとの対象イベントIDリスト
    let event_id_map = [
        ("System", vec!["6005", "6006", "1100", "1102", "12", "1074", "6009", "13", "41", "6008"]), // システム系
        ("Application", vec!["1000", "1001"]), // アプリ系
        ("Microsoft-Windows-TaskScheduler/Operational", vec!["200", "201"]), // タスクスケジューラ
        ("Security", vec!["4688", "4624", "4647"]), // セキュリティ
        // ...他にも必要に応じて追加...
    ];
    // output.txtの先頭に案内2行を書き込む（毎回上書き）
    let file_path = "output.txt"; // 出力ファイル名
    let mut file = std::fs::OpenOptions::new()
        .write(true) // 書き込みモード
        .truncate(true) // 既存内容を消去
        .open(file_path) // ファイルを開く
        .expect("ファイルオープン失敗"); // エラー時
    file.write_all(date_range_msg.as_bytes()).unwrap(); // 日時案内を書き込む
    file.write_all(svchost_level_msg_line.as_bytes()).unwrap(); // svchost案内を書き込む
    // ここでfileは閉じる
    // イベントログ抽出範囲の文字列（UTC）を作成
    let start_str = start_time.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(); // 開始時刻文字列
    let end_str = end_time.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();   // 終了時刻文字列
    // appendでイベント出力用ファイルを再オープン
    let mut file = std::fs::OpenOptions::new()
        .append(true) // 追記モード
        .open("output.txt") // ファイルを開く
        .expect("ファイルオープン失敗"); // エラー時
    let mut all_events: Vec<EventRecord> = Vec::new(); // 全イベント格納用ベクタ
    for (log, ids) in &event_id_map { // 各ログ種別ごとに処理
        let query = format!(
            "*[System[TimeCreated[@SystemTime>='{}' and @SystemTime<='{}']]]",
            start_str, end_str
        ); // wevtutil用クエリ文字列
        // wevtutilでXML取得
        let xml_result = fetch_eventlog_xml(log, &query).unwrap_or_default(); // XML取得
        // XMLをパースしてイベント抽出
        let mut events = parse_events(&xml_result, &ids); // イベント抽出
        all_events.append(&mut events); // 全イベントに追加
    }
    // 日時順にソート
    all_events.sort_by(|a, b| a.datetime_utc.cmp(&b.datetime_utc)); // 日時で昇順ソート
    // 出力処理
    for mut event in all_events { // 各イベントごとに
        // イベントIDに応じてアクション・説明を付与
        if let Some((_, (action, desc))) = event_id_action_map.iter().find(|(id, _)| *id == event.event_id.as_str()) {
            event.action = action.to_string(); // アクション設定
            event.description = desc.to_string(); // 説明設定
        }
        if should_exclude(&event, svchost_level, cmdline_audit_enabled) {
            continue; // 除外対象は出力しない
        }
        let log_disp = match event.log_name.as_str() {
            "Microsoft-Windows-TaskScheduler/Operational" => "TaskSchd", // ログ名短縮
            _ => event.log_name.as_str(), // それ以外はそのまま
        };
        let log_disp = format!("{:<11}", log_disp); // ログ名整形
        let eventid_disp = format!("{:>5}", event.event_id); // イベントID整形
        let date_jst = utc_str_to_jst(&event.datetime_utc, jst); // JST変換
        let proc_disp = if event.event_id == "4688" && !event.command_line.is_empty() {
            format!("{} [CommandLine: {}]", event.proc_info, event.command_line) // コマンドライン付き
        } else if event.event_id == "4624" && !event.logon_type.is_empty() {
            format!("{} [LogonType={}]", event.proc_info, event.logon_type) // ログオンタイプ付き
        } else {
            event.proc_info.clone() // それ以外はそのまま
        };
        let line = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            date_jst, log_disp, event.user, eventid_disp, event.action, event.description, proc_disp
        ); // 出力行を作成
        file.write_all(line.as_bytes()).unwrap(); // ファイルに書き込み
    }
    println!("ℹ️ output.txt に出力しました"); // 完了案内
}
