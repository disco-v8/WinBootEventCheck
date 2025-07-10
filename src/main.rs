// =============================
// main.rs: Windowsイベントログ解析ツールのエントリポイント
//
// 本ツールはWindowsイベントログ（主にセキュリティログ）を解析し、
// プロセス生成・ログオンイベント等を抽出・整形出力します。
//
// --- 必要なクレート・モジュールの説明 ---
// std::env: コマンドライン引数の取得に使用
// mod init: 事前チェック・監査範囲・システム情報取得用
// mod eventlog: イベントログ解析・出力用
// mod event_types: イベントレコード型定義用
// mod event_query: wevtutil呼び出し・イベント取得用
// mod event_parse: XMLパース・イベント解析用
// mod event_filter: 除外判定・フィルタ用
// mod event_util: 共通ユーティリティ関数用
// use std::env: コマンドライン引数取得用
// use init::precheck_and_info: 監査範囲・JST・監査ポリシー取得関数
// =============================

mod init;      // 事前チェック・システム情報
mod eventlog;  // イベントログ解析
mod event_types; // イベントレコード型定義
mod event_query; // wevtutil呼び出し
mod event_parse; // XMLパース
mod event_filter; // 除外判定
mod event_util;   // 共通関数
use init::precheck_and_info; // 監査範囲・JST・監査ポリシー取得
use std::env; // コマンドライン引数取得用

fn main() {
    // --- svchost出力レベルのコマンドライン引数解析 ---
    let args: Vec<String> = env::args().collect(); // コマンドライン引数をベクタに格納
    let mut svchost_level: u8 = 0; // svchost出力レベル（デフォルト: 全出力）
    for arg in &args[1..] { // 1番目以降の引数を走査
        match arg.as_str() { // 文字列としてマッチ
            "-s0" => svchost_level = 0, // 全出力
            "-s1" => svchost_level = 1, // 除外リスト方式
            "-s2" => svchost_level = 2, // svchost.exe全除外
            _ => {}, // その他は無視
        }
    }
    // --- 事前チェック・情報出力 ---
    let (start_time, end_time, jst, cmdline_audit_enabled) = match precheck_and_info() {
        Some(t) => t, // 正常取得時は値を展開
        None => return, // エラー時は即終了
    };
    // --- イベントログ解析・出力 ---
    eventlog::analyze_and_output_events(start_time, end_time, jst, cmdline_audit_enabled, svchost_level); // イベントログ解析・出力関数を呼び出し
}
