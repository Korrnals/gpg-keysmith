# `git-config`

Настроить локальный репозиторий git (или `--global` пользовательский конфиг) на подпись коммитов и тегов GPG-ключом.

## Синопсис

```
keysmith git-config [флаги]
```

`git-config` устанавливает шесть ключей git config:

| Ключ конфига | Значение |
|---|---|
| `user.name` | настоящее имя для автора коммита |
| `user.email` | email для автора коммита |
| `user.signingkey` | GPG key id для подписи |
| `commit.gpgsign` | `true` (подписывать каждый коммит) |
| `gpg.format` | `openpgp` (только OpenPGP поддерживается) |
| `tag.gpgsign` | `true` (подписывать каждый тег) |

Если `--name` или `--email` не заданы, существующие `user.name` / `user.email` читаются из git config и сохраняются. Если они нигде не заданы, возвращается ошибка с подсказкой передать `--name` / `--email` или выставить их заранее.

Если `--keyid` не задан, существующий `user.signingkey` читается из git config; если и он не задан, сканируется `gpg --list-secret-keys` и предлагается выбрать ключ. Если GPG-ключей нет, команда завершается с ошибкой и подсказкой сначала запустить `keysmith generate`.

## Флаги

| Флаг | Тип | По умолчанию | Описание |
|---|---|---|---|
| `--email` | string | `""` | Email, который выставить как `user.email` (если пусто — сохранить существующий) |
| `--global` | bool | `false` | Писать в глобальный пользовательский конфиг вместо локального конфига репозитория |
| `--keyid` | string | `""` | GPG key id, который выставить как `user.signingkey` (если пусто — из существующего конфига или выбор интерактивно) |
| `--name` | string | `""` | Настоящее имя, которое выставить как `user.name` (если пусто — сохранить существующий) |
| `-h`, `--help` | bool | `false` | Вывести помощь для `git-config` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Путь к файлу конфигурации (глобальный флаг) |

## Примеры

### Полностью интерактивно (выбор ключа из `detect`)

```bash
keysmith git-config
```

Если `user.signingkey` не задан, команда сканирует `gpg --list-secret-keys` и предлагает выбрать ключ. Если `user.name` / `user.email` не заданы, завершается с ошибкой и подсказкой.

### Задать имя и email явно

```bash
keysmith git-config --name "Jane Doe" --email jane@example.com
```

### Задать конкретный подписной ключ неинтерактивно

```bash
keysmith git-config --name "Jane Doe" --email jane@example.com --keyid F49BE957CD553B1C
```

### Настроить глобальный git config (для всех репозиториев)

```bash
keysmith git-config --global --name "Jane Doe" --email jane@example.com --keyid F49BE957CD553B1C
```

### Сохранить существующие name/email, выставить только подписной ключ

```bash
keysmith git-config --keyid F49BE957CD553B1C
```

Если `user.name` и `user.email` уже заданы в git config, они сохраняются; пишутся только `user.signingkey`, `commit.gpgsign`, `gpg.format` и `tag.gpgsign`.

### Проверка после запуска

```bash
git config --local --list | grep -E 'user\.|gpg\.|commit\.gpgsign|tag\.gpgsign'
git commit -S --allow-empty -m "test: signed commit" && git verify-commit HEAD
```

## Замечания

- **Вызывает `git config`.** `internal/git` использует `exec.Command("git", "config", ...)`, а не [go-git](https://github.com/go-git/go-git). Поведение совпадает с тем, что вы получили бы, выполнив `git config` вручную.
- **Парольная фраза не нужна.** `git-config` только выставляет ключи конфига; ничего не подписывает. Парольная фраза понадобится самому `git` при следующем `git commit -S`.
- **`gpg.format=openpgp` — единственное значение.** Инструмент не поддерживает `gpg.format=ssh` или `gpg.format=x509`.
- **Runtime-зависимость.** Требуется бинарник `git` в `PATH`. Если `--keyid` пустой и `user.signingkey` не задан, также требуется `gpg` для сканирования ключей.

## Смотрите также

- [`detect`](./detect.md) — список ключей для выбора подписного
- [`generate`](./generate.md) — создать ключ, если его нет
- [`status`](./status.md) — проверить, что git config выставлен
- [`wizard`](./wizard.md) — запускает `git-config` четвёртым шагом полного потока