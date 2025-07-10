// --- 必要なクレートの説明 ---
// quick_xml: XMLパース用（イベントログの解析）
// crate::event_types::EventRecord: イベントレコード型

use crate::event_types::EventRecord; // イベントレコード型
use quick_xml::Reader;               // quick_xmlリーダー
use quick_xml::events::Event as XmlEvent; // quick_xmlイベント型

/// XML文字列からイベント情報を抽出し、EventRecordのベクタを返す関数
pub fn parse_events(xml: &str, ids: &[&str]) -> Vec<EventRecord> {
    let mut reader = Reader::from_str(xml); // XMLリーダー生成
    reader.trim_text(true); // 空白除去設定
    let mut buf = Vec::new(); // quick_xmlのバッファ
    let mut in_event = false; // <Event>タグ内かどうか
    let mut in_eventid = false; // <EventID>タグ内かどうか
    let mut in_system = false; // <System>タグ内かどうか
    let mut eventid_val = String::new(); // イベントID格納用
    let mut systemtime_val = String::new(); // イベント発生時刻格納用
    let mut proc_name_val = String::new(); // プロセス名格納用
    let mut user_name_val = String::new(); // ユーザー名（4688/4624/4647用）
    let mut _app_name_val = String::new(); // アプリ名（4688用）
    let mut logon_type_val = String::new(); // LogonType（4624用）
    let mut command_line_val = String::new(); // コマンドライン（4688用）
    let mut _parent_process_id_val = String::new(); // 親プロセスID（4688用）
    let mut _new_process_id_val = String::new();    // 新プロセスID（4688用）
    let mut log_name_val = String::new(); // ログ名
    let mut all_events = Vec::new(); // 結果格納用ベクタ
    while let Ok(ev) = reader.read_event_into(&mut buf) { // XMLイベントを順次取得
        match ev {
            XmlEvent::Start(ref e) if e.name().as_ref() == b"Event" => {
                in_event = true; // <Event>タグ開始
                eventid_val.clear(); // イベントID初期化
                systemtime_val.clear(); // 日時初期化
                proc_name_val.clear(); // プロセス名初期化
                user_name_val = String::new(); // ユーザー名初期化
                _app_name_val = String::new(); // アプリ名初期化
                logon_type_val = String::new(); // ログオンタイプ初期化
                command_line_val = String::new(); // コマンドライン初期化
                _parent_process_id_val = String::new(); // 親プロセスID初期化
                _new_process_id_val = String::new(); // 新プロセスID初期化
                log_name_val = String::new(); // ログ名初期化
            }
            XmlEvent::End(ref e) if e.name().as_ref() == b"Event" => {
                in_event = false; // <Event>タグ終了
                if !eventid_val.is_empty() && !systemtime_val.is_empty() && ids.contains(&eventid_val.as_str()) {
                    // 必要なイベントIDのみ格納
                    all_events.push(EventRecord {
                        datetime_utc: systemtime_val.clone(), // 発生日時
                        log_name: log_name_val.clone(),       // ログ名
                        user: user_name_val.clone(),          // ユーザー名
                        event_id: eventid_val.clone(),        // イベントID
                        action: String::new(),                // アクション（後で付与）
                        description: String::new(),           // 説明（後で付与）
                        proc_info: proc_name_val.clone(),     // プロセス情報
                        logon_type: logon_type_val.clone(),   // ログオンタイプ
                        command_line: command_line_val.clone(), // コマンドライン
                    });
                }
            }
            XmlEvent::Start(ref e) if in_event && e.name().as_ref() == b"EventID" => {
                in_eventid = true; // <EventID>タグ開始
            }
            XmlEvent::End(ref e) if in_event && e.name().as_ref() == b"EventID" => {
                in_eventid = false; // <EventID>タグ終了
            }
            XmlEvent::Text(e) if in_eventid => {
                eventid_val = e.unescape().unwrap_or_default().to_string(); // イベントID取得
            }
            XmlEvent::Start(ref e) if in_event && e.name().as_ref() == b"System" => {
                in_system = true; // <System>タグ開始
            }
            XmlEvent::End(ref e) if in_event && e.name().as_ref() == b"System" => {
                in_system = false; // <System>タグ終了
            }
            XmlEvent::Empty(ref e) if in_system && e.name().as_ref() == b"TimeCreated" => {
                for attr in e.attributes().flatten() { // 属性を走査
                    if attr.key.as_ref() == b"SystemTime" {
                        systemtime_val = attr.unescape_value().unwrap_or_default().to_string(); // 日時取得
                    }
                }
            }
            XmlEvent::Empty(ref e) if in_event && e.name().as_ref() == b"ProcessName" => {
                for attr in e.attributes().flatten() { // 属性を走査
                    if attr.key.as_ref() == b"Name" {
                        proc_name_val = attr.unescape_value().unwrap_or_default().to_string(); // プロセス名取得
                    }
                }
            }
            XmlEvent::Start(ref e) if in_event && e.name().as_ref() == b"ProcessName" => {
                if let Ok(XmlEvent::Text(e2)) = reader.read_event_into(&mut buf) {
                    proc_name_val = e2.unescape().unwrap_or_default().to_string(); // プロセス名取得
                }
            }
            XmlEvent::Start(ref e) if in_event && e.name().as_ref() == b"Data" => {
                if let Some(Ok(attr)) = e.attributes().next() { // 最初の属性のみ取得
                    if attr.key.as_ref() == b"Name" {
                        let name = attr.unescape_value().unwrap_or_default(); // DataタグのName属性
                        if eventid_val == "4688" {
                            // 4688イベント用の各種情報抽出
                            if name == "NewProcessName" {
                                let text_val = if let Ok(XmlEvent::Text(e2)) = reader.read_event_into(&mut buf) {
                                    let s = e2.unescape().unwrap_or_default().to_string();
                                    buf.clear();
                                    s
                                } else { String::new() };
                                _app_name_val = text_val; // 新プロセス名
                            } else if name == "SubjectUserName" {
                                let text_val = if let Ok(XmlEvent::Text(e2)) = reader.read_event_into(&mut buf) {
                                    let s = e2.unescape().unwrap_or_default().to_string();
                                    buf.clear();
                                    s
                                } else { String::new() };
                                user_name_val = text_val; // ユーザー名
                            } else if name == "CommandLine" {
                                let text_val = if let Ok(XmlEvent::Text(e2)) = reader.read_event_into(&mut buf) {
                                    let s = e2.unescape().unwrap_or_default().to_string();
                                    buf.clear();
                                    s
                                } else { String::new() };
                                command_line_val = text_val; // コマンドライン
                            } else if name == "ParentProcessId" {
                                let text_val = if let Ok(XmlEvent::Text(e2)) = reader.read_event_into(&mut buf) {
                                    let s = e2.unescape().unwrap_or_default().to_string();
                                    buf.clear();
                                    s
                                } else { String::new() };
                                _parent_process_id_val = text_val; // 親プロセスID
                            } else if name == "NewProcessId" {
                                let text_val = if let Ok(XmlEvent::Text(e2)) = reader.read_event_into(&mut buf) {
                                    let s = e2.unescape().unwrap_or_default().to_string();
                                    buf.clear();
                                    s
                                } else { String::new() };
                                _new_process_id_val = text_val; // 新プロセスID
                            }
                        } else if eventid_val == "4624" || eventid_val == "4647" {
                            // 4624/4647イベント用の各種情報抽出
                            if name == "SubjectUserName" {
                                let text_val = if let Ok(XmlEvent::Text(e2)) = reader.read_event_into(&mut buf) {
                                    let s = e2.unescape().unwrap_or_default().to_string();
                                    buf.clear();
                                    s
                                } else { String::new() };
                                user_name_val = text_val; // ユーザー名
                            } else if eventid_val == "4624" && name == "LogonType" {
                                let text_val = if let Ok(XmlEvent::Text(e2)) = reader.read_event_into(&mut buf) {
                                    let s = e2.unescape().unwrap_or_default().to_string();
                                    buf.clear();
                                    s
                                } else { String::new() };
                                logon_type_val = text_val; // ログオンタイプ
                            }
                        }
                    }
                }
            }
            XmlEvent::Eof => break, // EOFでループ終了
            _ => {} // その他は無視
        }
        buf.clear(); // バッファクリア
    }
    all_events // 結果ベクタを返す
}
