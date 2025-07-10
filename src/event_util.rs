// --- 必要なクレートの説明 ---
// chrono: 日時操作・タイムゾーン変換用

// 日時変換や文字列整形などの共通ユーティリティ

/// UTCのISO8601文字列をJSTの"yyyy/MM/dd HH:mm:ss"形式に変換する関数
pub fn utc_str_to_jst(utc_str: &str, jst: chrono::FixedOffset) -> String {
    // 文字列をRFC3339形式でパースし、JSTタイムゾーンに変換
    chrono::DateTime::parse_from_rfc3339(utc_str)
        .map(|dt| dt.with_timezone(&jst).format("%Y/%m/%d %H:%M:%S").to_string()) // JST形式に整形
        .unwrap_or_else(|_| utc_str.to_string()) // パース失敗時は元の文字列を返す
}
