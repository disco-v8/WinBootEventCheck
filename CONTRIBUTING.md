# Contributing to WinBootEventCheck

WinBootEventCheckプロジェクトへのコントリビューションありがとうございます！

## 開発環境のセットアップ

### 必要なツール

- Rust 1.70以降
- Git
- Windows 10/11 または Windows Server 2016以降
- 管理者権限（テスト実行時）

### 環境構築

1. リポジトリをクローン:
```bash
git clone https://github.com/yourusername/WinBootEventCheck.git
cd WinBootEventCheck
```

2. 依存関係のインストール:
```bash
cargo build
```

3. テスト実行（管理者権限で）:
```bash
cargo test
```

## コントリビューションプロセス

### Issue報告

バグ報告や機能要望は[GitHub Issues](https://github.com/yourusername/WinBootEventCheck/issues)で受け付けています。

#### バグ報告時の情報

- Windowsバージョン
- 実行時のエラーメッセージ
- 再現手順
- 期待される動作と実際の動作

#### 機能要望時の情報

- 用途・目的
- 具体的な仕様
- 既存機能への影響

### Pull Request

1. **フォーク**: このリポジトリをフォークしてください
2. **ブランチ作成**: 機能名を含む分かりやすいブランチ名で作成
   ```bash
   git checkout -b feature/add-new-filter
   git checkout -b bugfix/fix-parsing-error
   ```
3. **開発**: コードを変更してください
4. **テスト**: 変更が既存機能に影響しないことを確認
5. **コミット**: 分かりやすいコミットメッセージで記録
6. **プッシュ**: フォークしたリポジトリにプッシュ
7. **PR作成**: 本リポジトリに対してPull Requestを作成

### コーディング規約

#### Rust スタイル

- `cargo fmt`でフォーマット
- `cargo clippy`でリント
- 関数・変数名は小文字スネークケース
- 構造体・列挙型は大文字キャメルケース
- コメントは日本語で詳細に記述

#### コメント

```rust
// 単行コメントは日本語で記述
/// ドキュメンテーションコメントも日本語
/// 
/// # 引数
/// * `event_id` - イベントID
/// 
/// # 戻り値
/// 処理結果のブール値
fn process_event(event_id: u32) -> bool {
    // 処理内容をコメントで説明
    true
}
```

#### エラーハンドリング

- `Result`型を適切に使用
- エラーメッセージは日本語で分かりやすく
- パニックは避け、適切にエラーを返す

### テスト

#### 単体テスト

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_parsing() {
        // テストケース
    }
}
```

#### 統合テスト

- `tests/`ディレクトリに配置
- 実際のイベントログを使用したテスト
- 管理者権限が必要

### ドキュメント

- 新機能は`README.md`に使用方法を追加
- APIドキュメントは`cargo doc`で生成
- 重要な変更は`CHANGELOG.md`（今後作成予定）に記録

## 質問・相談

開発に関する質問や相談は以下で受け付けています：

- GitHub Issues（一般的な質問）
- GitHub Discussions（今後設置予定）
- Email: your.email@example.com

## ライセンス

コントリビューションはすべてMITライセンスの下で公開されます。
