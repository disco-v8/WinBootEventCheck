# WinBootEventCheck

Windowsイベントログ解析ツール - セキュリティログからプロセス生成・ログオンイベント等を抽出・整形出力するRustアプリケーション

## 概要

WinBootEventCheckは、Windowsのセキュリティイベントログを解析し、システムの起動時からのプロセス生成やログオンイベントを抽出・整形して出力するコマンドラインツールです。

## 主な機能

- **イベントログ解析**: Windowsセキュリティログからイベントを抽出
- **プロセス生成監視**: プロセス生成イベント（Event ID 4688）の詳細分析
- **ログオンイベント**: ユーザーログオンイベントの追跡
- **フィルタリング**: svchost.exeなど特定プロセスの出力制御
- **時刻範囲指定**: システム起動時からの監査範囲自動設定
- **日本語対応**: JST（日本標準時）での時刻表示

## システム要件

- Windows 10/11 または Windows Server 2016以降
- 管理者権限（イベントログへのアクセスのため）
- Rust 1.70以降（開発時）

## インストール

### 事前コンパイル済みバイナリ（推奨）

1. [Releases](https://github.com/disco-v8/WinBootEventCheck/releases)から最新版をダウンロード
2. 任意のフォルダに展開
3. PowerShell/コマンドプロンプトを管理者権限で起動
4. 実行ファイルのパスに移動して実行

### ソースからビルド

```powershell
# Rustがインストールされている必要があります
git clone https://github.com/disco-v8/WinBootEventCheck.git
cd WinBootEventCheck
cargo build --release
```

## 使用方法

### 基本実行

```powershell
# 管理者権限のPowerShellで実行
.\win-boot-event-check.exe
```

### コマンドラインオプション

```powershell
# svchost.exe関連の出力制御
.\win-boot-event-check.exe -s0  # 全出力（デフォルト）
.\win-boot-event-check.exe -s1  # 除外リスト方式
.\win-boot-event-check.exe -s2  # svchost.exe全除外
```

## 出力例

```
=== Windows Boot Event Analysis ===
Audit Range: 2024-07-10 09:15:32 JST ～ 2024-07-10 10:30:45 JST
System: Windows 11 Pro (Build 22631)
Process Creation Audit: Enabled
Command Line Audit: Enabled

[2024-07-10 09:16:15] Process: notepad.exe (PID: 1234)
  Command: "C:\Windows\System32\notepad.exe" "document.txt"
  User: DOMAIN\username
  Parent: explorer.exe (PID: 856)

[2024-07-10 09:17:22] Logon Event: Interactive Logon
  User: DOMAIN\username
  Session: 2
  Logon Type: Interactive (2)
```

## ファイル構成

```
src/
├── main.rs           # エントリポイント
├── init.rs           # 事前チェック・システム情報取得
├── eventlog.rs       # イベントログ解析メイン処理
├── event_types.rs    # イベントレコード型定義
├── event_query.rs    # wevtutil呼び出し・イベント取得
├── event_parse.rs    # XMLパース・イベント解析
├── event_filter.rs   # 除外判定・フィルタ処理
└── event_util.rs     # 共通ユーティリティ関数
```

## 技術仕様

- **言語**: Rust 2021 Edition
- **依存関係**:
  - `chrono` 0.4 - 日時処理
  - `regex` 1.0 - 正規表現
  - `quick-xml` 0.31 - XMLパース
- **データソース**: Windows Event Log API (wevtutil経由)
- **対象ログ**: Security Event Log
- **主要イベントID**: 4688（プロセス生成）、4624（ログオン）

## セキュリティ考慮事項

- 本ツールは読み取り専用でシステムログを解析します
- 管理者権限が必要ですが、システムに変更を加えることはありません
- 機密情報を含む可能性のあるコマンドライン引数も出力対象となります

## ライセンス

MIT License - 詳細は[LICENSE](LICENSE)ファイルを参照

## 開発者向け

### ビルド手順

```powershell
# デバッグビルド
cargo build

# リリースビルド
cargo build --release

# テスト実行（管理者権限必要）
cargo test
```

### コントリビューション

1. このリポジトリをフォーク
2. フィーチャーブランチを作成 (`git checkout -b feature/amazing-feature`)
3. 変更をコミット (`git commit -m 'Add amazing feature'`)
4. ブランチにプッシュ (`git push origin feature/amazing-feature`)
5. Pull Requestを作成

## トラブルシューティング

### 一般的な問題

1. **"Access Denied"エラー**
   - 管理者権限でコマンドプロンプト/PowerShellを起動してください

2. **イベントが見つからない**
   - セキュリティ監査ポリシーが有効になっているか確認してください
   - `auditpol /get /category:*`で現在の設定を確認

3. **文字化け**
   - PowerShellのエンコーディングを確認してください
   - `chcp 65001`でUTF-8に設定

## 更新履歴

- v0.1.0 (2024-07-10): 初回リリース
  - 基本的なイベントログ解析機能
  - プロセス生成・ログオンイベント抽出
  - svchost.exe フィルタリング機能

## お問い合わせ

- GitHub Issues: [Issues](https://github.com/disco-v8/WinBootEventCheck/issues)
- GitHub Repository: https://github.com/disco-v8/WinBootEventCheck
