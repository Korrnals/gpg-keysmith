# `export`

Экспортировать публичный ключ в ASCII-armored файл и перехватить приватный ключ в память.

## Синопсис

```
keysmith export [флаги]
```

`export` запускает `gpg --armor --export <keyID>` и пишет публичный ключ в ASCII-armored файл (по умолчанию `gpg-public-key.asc`). Также запускает `gpg --armor --export-secret-keys --pinentry-mode loopback --passphrase-fd 0 <keyID>` и перехватывает приватный ключ только в память — он никогда не пишется на диск, не логируется и не печатается. Перехваченный приватный ключ хранится для использования командой `github` (M6), чтобы загрузить его как секрет репозитория для подписи в CI.

Парольная фраза собирается через маскированный промпт и подаётся в `gpg` через stdin. Она никогда не читается из флага (это утекало бы через историю shell / `ps`) и никогда не передаётся в `gpg` как аргумент CLI.

## Флаги

| Флаг | Тип | По умолчанию | Описание |
|---|---|---|---|
| `--email` | string | `""` | Email ключа для экспорта (альтернатива `--keyid`) |
| `--keyid` | string | `""` | Long-form key id или fingerprint для экспорта |
| `--pubkey` | string | `gpg-public-key.asc` | Путь вывода для ASCII-armored публичного ключа |
| `-h`, `--help` | bool | `false` | Вывести помощь для `export` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Путь к файлу конфигурации (глобальный флаг) |

Нужно задать либо `--keyid`, либо `--email`. Если задан `--email`, `export` разрешает его в key id через `DetectKeyForEmail`.

## Примеры

### Экспорт по key id

```bash
keysmith export --keyid F49BE957CD553B1C
```

Пишет публичный ключ в `gpg-public-key.asc` в текущем каталоге.

### Экспорт по email (разрешение через `detect`)

```bash
keysmith export --email korrnals@gmail.com
```

### Экспорт в свой путь

```bash
keysmith export --keyid F49BE957CD553B1C --pubkey ./keys/my-pubkey.asc
```

### Экспорт для использования командой `github`

```bash
keysmith export --keyid F49BE957CD553B1C --pubkey ./gpg-public-key.asc
keysmith github --repo owner/name --pubkey-file ./gpg-public-key.asc
```

Команда `github` может прочитать заранее экспортированный публичный ключ через `--pubkey-file` вместо вызова `gpg --export` самостоятельно.

## Замечания

- **Приватный ключ только в памяти.** Приватный ключ перехватывается в Go-срез `[]byte` и хранится для шага секретов команды `github`. Он никогда не пишется на диск, не логируется и не печатается. См. [Безопасность](../security.md).
- **Валидация key ID.** `ValidateKeyID` отвергает не-hex символы и длину больше 40 символов до того, как key id попадёт в argv `gpg`. Это не даёт `--keyid "ABCD; rm -rf ~"` пройти как один элемент argv.
- **Обработка парольной фразы.** Парольная фраза подаётся в `gpg` через `--passphrase-fd 0` stdin с `--pinentry-mode loopback`. Она никогда не появляется как аргумент CLI.
- **Режим файла публичного ключа.** Файл публичного ключа пишется в режиме `0644` (публичные ключи не секретны).
- **Runtime-зависимость.** Требуется бинарник `gpg` (GnuPG 2.x) в `PATH`.

## Смотрите также

- [`detect`](./detect.md) — найти key id или email для экспорта
- [`github`](./github.md) — загрузить публичный ключ и сохранить приватный как секрет репозитория
- [`publish`](./publish.md) — опубликовать экспортированный публичный ключ на сервере ключей
- [`wizard`](./wizard.md) — запускает `export` третьим шагом полного потока