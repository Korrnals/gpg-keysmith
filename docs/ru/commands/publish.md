# `publish`

Опубликовать GPG-публичный ключ на публичном сервере ключей через HTTPS submit endpoint'ы.

## Синопсис

```
keysmith publish [флаги]
```

`publish` загружает ASCII-armored публичный ключ на один или оба сервера:

- `keys.openpgp.org` — `https://keys.openpgp.org/vks/v1/upload` (предпочитаемый)
- `keyserver.ubuntu.com` — `https://keyserver.ubuntu.com/pks/submit` (запасной)

Сервер ключей по умолчанию — `all` (публикует на оба). Используйте `--keyserver=openpgp` только для первого, `--keyserver=ubuntu` только для второго.

Если `--keyid` пустой, ключ выбирается интерактивно из `gpg --list-secret-keys`. Если задан `--pubkey-file`, armored публичный ключ читается из файла вместо вызова `gpg --export`.

При успехе `publish` выводит URL проверки для каждого сервера ключей.

## Флаги

| Флаг | Тип | По умолчанию | Описание |
|---|---|---|---|
| `--keyid` | string | `""` | GPG key id для экспорта (если пусто — выбрать интерактивно из `detect`) |
| `--keyserver` | string | `"all"` | Целевой сервер ключей: `all`, `openpgp` или `ubuntu` |
| `--pubkey-file` | string | `""` | Прочитать armored публичный ключ из этого файла вместо вызова `gpg --export` |
| `-h`, `--help` | bool | `false` | Вывести помощь для `publish` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Путь к файлу конфигурации (глобальный флаг) |

## Примеры

### Опубликовать на оба сервера (по умолчанию)

```bash
keysmith publish
```

Выбирает ключ интерактивно из `gpg --list-secret-keys` и публикует на `keys.openpgp.org` + `keyserver.ubuntu.com`.

### Опубликовать конкретный ключ

```bash
keysmith publish --keyid F49BE957CD553B1C
```

### Опубликовать только на keys.openpgp.org

```bash
keysmith publish --keyid F49BE957CD553B1C --keyserver openpgp
```

### Опубликовать только на keyserver.ubuntu.com

```bash
keysmith publish --keyid F49BE957CD553B1C --keyserver ubuntu
```

### Опубликовать заранее экспортированный файл ключа

```bash
keysmith export --keyid F49BE957CD553B1C --pubkey ./gpg-public-key.asc
keysmith publish --pubkey-file ./gpg-public-key.asc
```

### Пример успешного вывода

```
Published to keys.openpgp.org
  Verification URL: https://keys.openpgp.org/vks/vby/F49BE957CD553B1C1234567890ABCDEF12345678
Published to keyserver.ubuntu.com
```

## Замечания

- **HTTPS POST, не HKP.** `publish` использует HTTPS submit endpoint'ы, а не устаревший протокол `hkp://`.
- **Валидация fingerprint.** Fingerprint проверяется на hex перед интерполяцией в URL проверки `https://keys.openpgp.org/vks/vby/<fingerprint>`. См. [Безопасность](../security.md).
- **Парольная фраза не нужна.** Публикация публичного ключа не требует приватного ключа или парольной фразы — только armor публичного ключа. Если `--pubkey-file` не задан, `publish` вызывает `gpg --armor --export` (парольная фраза не требуется).
- **Выбор сервера из конфига.** `--keyserver` перекрывает `config.keyserver.preferred`; значение `all` публикует и на `preferred`, и на `fallback`.
- **Runtime-зависимость.** Требуется бинарник `gpg`, если не задан `--pubkey-file`.

## Смотрите также

- [`export`](./export.md) — подготовить `--pubkey-file` заранее
- [`status`](./status.md) — проверить публикацию ключа по fingerprint
- [`wizard`](./wizard.md) — запускает `publish` шестым шагом полного потока
- [`config`](./config.md) — выставить сервер ключей по умолчанию