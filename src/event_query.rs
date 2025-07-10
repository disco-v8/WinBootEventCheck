// --- 必要なクレートの説明 ---
// std::process::Command: 外部コマンド実行用（wevtutil呼び出し）

// wevtutilコマンドでイベントログを取得する関数群
// XML文字列を返す
use std::process::Command; // コマンド実行用

/// 指定ログ・クエリでwevtutilを実行し、XML文字列を返す関数
pub fn fetch_eventlog_xml(log: &str, query: &str) -> Result<String, String> {
    let mut cmd = Command::new("wevtutil"); // wevtutilコマンド生成
    cmd.args(&["qe", log, &format!("/q:{}", query), "/f:xml"]); // 引数セット
    let output = cmd.output().map_err(|e| format!("コマンド実行失敗: {}", e))?; // コマンド実行
    let result = String::from_utf8_lossy(&output.stdout).to_string(); // 標準出力を文字列化
    Ok(result) // XML文字列を返す
}
