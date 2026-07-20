# `status`

Показать текущее состояние настройки GPG + GitHub с поэтапными индикаторами ✅ / ❌ / ⚠️.

## Синопсис

```
keysmith status [флаги]
```

`status` — инспектор только для чтения. Выполняет пять проверок и выводит одну таблицу с поэтапным индикатором. Каждая незелёная проверка выводит однострочную подсказку по исправлению.

## Пять проверок

| № | Проверка | Что инспектирует | Источник |
|---|---|---|---|
| 1 | GPG-ключи | Локальная связка ключей gpg | `gpg --list-secret-keys` |
| 2 | Git config | `user.signingkey` + `commit.gpgsign` в локальном репозитории | `git config --local --get` |
| 3 | Публичный ключ GitHub | GPG-ключи, загруженные в ваш аккаунт GitHub | REST API `users/gpg_keys` |
| 4 | Секреты репозитория | `GPG_PRIVATE_KEY` и `GPG_PASSPHRASE` в целевом репозитории | `gh secret list` |
| 5 | Сервер ключей | Публикация публичного ключа на сервере ключей (по fingerprint) | HTTPS GET на сервер ключей |

Если `--repo` опущен, проверка секретов репозитория деградирует в ⚠️ (пропуск, а не сбой).

## Разрешение токена

Токен берётся только из переменных окружения, никогда из флага:

1. Переменная окружения, имя которой задано в `config.github.token_env` (по умолчанию `GITHUB_TOKEN`)
2. `GH_TOKEN` как запасной вариант

## Флаги

| Флаг | Тип | По умолчанию | Описание |
|---|---|---|---|
| `--fingerprint` | string | `""` (выводится из первого ключа) | Fingerprint GPG-ключа (необязательно — выводится из первого ключа, если пусто) |
| `--keyserver` | string | `"keys.openpgp.org"` | Сервер ключей, на котором проверять публикацию |
| `--repo` | string | `""` | Целевой репозиторий как `owner/name` (необязательно — проверка секретов деградирует в ⚠️, если опущено) |
| `-h`, `--help` | bool | `false` | Вывести помощь для `status` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Путь к файлу конфигурации (глобальный флаг) |

## Примеры

### Полный статус (все пять проверок)

```bash
export GITHUB_TOKEN=ghp_...
keysmith status --repo owner/name
```

### Пропустить проверку секретов репозитория

```bash
keysmith status
```

Проверка секретов репозитория показывает ⚠️ (пропуск, а не сбой), когда `--repo` опущен.

### Проверить конкретный fingerprint на другом сервере ключей

```bash
keysmith status --repo owner/name \
  --fingerprint F49BE957CD553B1C1234567890ABCDEF12345678 \
  --keyserver keyserver.ubuntu.com
```

### Пример вывода (полностью настроено)

```
Status:

  1. GPG keys        ✅  1 key found (F49BE957CD553B1C)
  2. Git config      ✅  user.signingkey set, commit.gpgsign=true
  3. GitHub pubkey   ✅  1 GPG key uploaded
  4. Repo secrets    ✅  GPG_PRIVATE_KEY + GPG_PASSPHRASE set on owner/name
  5. Keyserver       ✅  key published to keys.openpgp.org
```

### Пример вывода (свежая машина)

```
Status:

  1. GPG keys        ❌  no keys found — run 'keysmith generate'
  2. Git config      ❌  user.signingkey not set — run 'keysmith git-config'
  3. GitHub pubkey   ❌  no GPG keys uploaded — run 'keysmith github'
  4. Repo secrets    ⚠️  --repo not given, skipping
  5. Keyserver       ❌  key not found on keyserver — run 'keysmith publish'
```

## Замечания

- **Только для чтения.** `status` ничего не модифицирует — только инспектирует и сообщает.
- **Однострочная подсказка.** Каждая незелёная проверка выводит одну строку с указанием команды для исправления.
- **Проверка сервера ключей.** Fingerprint проверяется на hex перед использованием в URL поиска на сервере ключей.
- **Токен для проверок GitHub.** Проверки 3 и 4 требуют GitHub PAT. Если токен отсутствует, эти проверки деградируют в ⚠️ (невозможно аутентифицироваться).
- **Runtime-зависимости.** Требуется `gpg` (проверки 1, 5), `git` (проверка 2), `gh` (проверка 4) и GitHub PAT (проверки 3, 4).

## Смотрите также

- [`detect`](./detect.md) — проверка GPG-ключей, которую `status` выполняет
- [`git-config`](./git-config.md) — исправить проверку git config
- [`github`](./github.md) — исправить проверки публичного ключа GitHub и секретов репозитория
- [`publish`](./publish.md) — исправить проверку сервера ключей
- [`wizard`](./wizard.md) — запустить полный поток, чтобы получить все зелёные индикаторы