import type { MessageKey } from "./en.js";

// The Japanese messages of the static pages.
export const ja: Readonly<Record<MessageKey, string>> = {
  language: "言語",
  error_type: "エラーの種類",
  unsupported_browser: "このブラウザはパスキーに対応していません。",
  failed: "うまくいきませんでした。もう一度お試しください。",
  signin_title: "サインイン",
  signin_button: "パスキーでサインイン",
  signin_working: "パスキーの操作を待っています…",
  enroll_title: "パスキーの登録",
  enroll_button: "パスキーを作成",
  enroll_done: "パスキーを登録しました。アプリに戻ってサインインしてください。",
  enroll_no_token: "この登録リンクは不完全です。管理者に新しいリンクを依頼してください。",
  enroll_lost: "登録は完了している可能性があります。アプリからサインインを試し、できなければ管理者に新しいリンクを依頼してください。",
  account_title: "パスキー",
  account_no_session: "サインインしていません。アプリからサインインしてから、このページを開き直してください。",
  account_add: "パスキーを追加",
  account_revoke: "削除",
  account_logout: "サインアウト",
  account_signed_out: "サインアウトしました。",
  account_created: "作成",
  account_last_used: "最終使用",
  account_synced: "同期型のパスキー",
  account_device_bound: "端末に固定のパスキー",
  account_never: "未使用",
};
