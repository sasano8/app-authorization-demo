# app-authorization-demo

Google ID トークンを検証して、アプリ専用 JWT アクセストークンを発行する認可デモです。
Google API のアクセストークンを取得するアプリではありません。

## ローカル起動

Python 3.14 を使用します。

```sh
python3.14 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
export APP_ALLOW_LOCAL_LOGIN=true
export APP_ACCESS_TOKEN_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
.venv/bin/uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8080
```

ブラウザーでポート 8080 にアクセスし、`demo` / `demo` でログインします。
「アクセストークン取得」→「リソースにアクセス」で認可成功のメッセージを確認できます。
トークンはブラウザーのメモリに保持します。ログアウトは画面のトークンを破棄しますが、
発行済み JWT は有効期限まで利用できます。SSO セッションは proxy のログアウト先が設定されている場合に終了します。

```sh
.venv/bin/python -m pytest -q
docker build -t app-authorization-demo:local .
docker run --rm -p 8080:8080 -e APP_ALLOW_LOCAL_LOGIN -e APP_ACCESS_TOKEN_SIGNING_KEY app-authorization-demo:local
```

## 設定と管理領域

| 領域 | 環境変数 | 内容 |
|---|---|---|
| SSO 共通 | `SSO_ID_TOKEN_HEADER` | ID トークンのヘッダー名。既定 `X-Forwarded-Id-Token`。実際の proxy 設定に合わせる |
| SSO 共通 | `SSO_GOOGLE_CLIENT_ID` | Google ID トークンの期待する `aud`。SSO-only では必須 |
| SSO 共通 | `SSO_LOGOUT_URL` | 任意。信頼する proxy のログアウト URL |
| アプリ専用 | `APP_ALLOW_LOCAL_LOGIN` | 既定 `false`。`true` のときヘッダーなしでデモログイン可能 |
| アプリ専用 | `APP_ACCESS_TOKEN_SIGNING_KEY` | 必須。32 バイト以上のランダムな秘密鍵 |
| アプリ専用 | `APP_ACCESS_TOKEN_ISSUER` | 既定 `app-authorization-demo` |
| アプリ専用 | `APP_ACCESS_TOKEN_AUDIENCE` | 既定 `app-authorization-demo-api` |
| アプリ専用 | `APP_ACCESS_TOKEN_TTL_SECONDS` | 既定 `300`、正の整数 |
| ランタイム | `PORT` | コンテナの待受ポート。既定 `8080` |

Infisical では `/sso/google` と `/apps/app-authorization-demo` などに分離し、
Kubernetes Secret 経由で Knative の環境変数に注入してください。
署名鍵は同一アプリの全レプリカで共有し、他アプリや開発環境とは分離します。
現在は単一鍵方式です。鍵の変更により旧トークンは無効になり、更新中のレプリカ間で失敗し得ます。
無停止ローテーションには後続の複数鍵対応が必要です。

## SSO 動作

proxy は外部からの同名ヘッダーを削除して、認証済み ID トークンで上書きしてください。
このヘッダーには Google の ID トークンそのもの（Bearer 接頭辞なし）を渡します。
Google の署名（RS256）、発行者、期限、対象クライアント ID をアプリで検証します。
Google の公開鍵取得には `https://www.googleapis.com/oauth2/v3/certs` への HTTPS 接続が必要です。
クライアントシークレットは不要です。

ヘッダーが存在して検証に失敗した場合は `401` を返し、ローカルへフォールバックしません。
本番では `APP_ALLOW_LOCAL_LOGIN=false` を設定します。デモ用 ID トークンも拒否されます。
`POST /api/token` は proxy ヘッダーを優先し、ヘッダーがなければ JSON の `id_token` を使用します。
アクセストークンは `token_use=access`、`scope=demo:read` を持ちます。
`GET /api/resource` は `Authorization: Bearer ...` を検証し、不正なトークンは `401`、
スコープ不足は `403` を返します。デモ ID トークンは用途と audience を分離しています。

`GET /healthz` はヘルスチェック、`GET /api/session` は画面用の認証状態取得です。
トークンを表示するデモなので、HTTPS を使用し、画面とリクエストヘッダーをログへ記録しないでください。

## CI とイメージ

GitHub Actions がテスト成功後、main への push で以下を GHCR に push します。

- `ghcr.io/sasano8/app-authorization-demo:latest`
- `ghcr.io/sasano8/app-authorization-demo:<commit SHA>`

認証には Actions の `GITHUB_TOKEN` と `packages: write` を使用します。
初回 push 後、GitHub のパッケージ設定で visibility を **public** にしてください。
CI の push は公開範囲の変更を自動では行いません。
Knative デプロイは別作業です。`PORT`、署名鍵、SSO 設定を渡し、`/healthz` を probe に利用できます。

## 検証範囲

自動テストはローカルログイン・交換・認可、およびテスト用 RSA 鍵による Google 検証を確認します。
実際の Google ID トークンと proxy 接続は、SSO 基盤へのデプロイ後に別途確認が必要です。
