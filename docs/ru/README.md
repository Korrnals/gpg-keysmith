# gpg-keysmith

<p align="center">
  <img src="../assets/banner.svg" alt="баннер gpg-keysmith" width="100%"/>
</p>

[![English](https://img.shields.io/badge/lang-English-blue.svg)](../en/README.md) [![Русский](https://img.shields.io/badge/lang-Русский-red.svg)](./README.md)

[![Версия](https://img.shields.io/badge/version-1.0.0-0f766e.svg)](../../VERSION) [![Лицензия: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](../../LICENSE) [![Go](https://img.shields.io/badge/Go-1.22%2B-00add8.svg)](https://go.dev) [![Платформы](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](./installation.md)

`gpg-keysmith` — консольная утилита на Go, которая автоматизирует весь путь от «нет GPG-ключа» до «подписанные коммиты в GitHub». Одна команда `keysmith wizard` проводит разработчика по всем шагам: сгенерировать GPG-ключ, экспортировать публичный ключ, настроить `git` на подпись коммитов и тегов, загрузить публичный ключ в GitHub, сохранить приватный ключ как секрет репозитория для подписи в CI и опубликовать публичный ключ на сервере ключей.

Это полная русская документация. Сокращённый корневой [README](../../README.md) ведёт сюда.

## Ключевые свойства

- **Полная автоматизация.** `keysmith wizard` оркестрирует шесть этапов по порядку: detect → generate → export → git-config → github → publish. На каждом шаге запрашивается подтверждение, при сбое предлагается retry / skip / abort, а результат сохраняется в файл состояния, поэтому прерванный запуск возобновляется с последнего успешного шага.
- **Безопасность по умолчанию.** Парольная фраза через stdin, приватный ключ только в памяти, GitHub PAT из переменной окружения — см. [Безопасность](./security.md).
- **Опирается на проверенные инструменты.** Вызывает `gpg`, `git` и `gh` как внешние процессы, а не переизобретает криптографию. До внешних процессов доходят только провалидированные шестнадцатеричные key ID и имена owner/repo.
- **Инспектируемость.** `keysmith status` показывает поэтапные индикаторы ✅ / ❌ / ⚠️ с однострочной подсказкой по исправлению, что упрощает диагностику и возобновление частичной настройки.

## Быстрый старт

```bash
go install github.com/Korrnals/gpg-keysmith/cmd/keysmith@latest
export GITHUB_TOKEN=ghp_ваш_pat_с_правами_repo_admin_gpg_key
keysmith wizard
```

Мастер запрашивает подтверждение на каждом шаге. Любой флаг (`--name`, `--email`, `--repo owner/name` и т.д.) предзаполняет промпты и позволяет запустить часть шагов неинтерактивно.

## Разделы документации

| Тема | Документ |
|---|---|
| Установка, зависимости, автодополнение | [installation.md](./installation.md) |
| Архитектура, структура пакетов, модель интеграции | [architecture.md](./architecture.md) |
| Модель безопасности, угрозы, средства контроля | [security.md](./security.md) |
| Справочник по командам (9 команд) | [commands/](./commands/) |

## Обзор команд

| Команда | Что делает |
|---|---|
| [`wizard`](./commands/wizard.md) | Полный интерактивный мастер настройки (точка входа по умолчанию) |
| [`detect`](./commands/detect.md) | Список существующих приватных GPG-ключей текущего пользователя |
| [`generate`](./commands/generate.md) | Сгенерировать новый GPG-ключ через `gpg --gen-key` |
| [`export`](./commands/export.md) | Экспорт публичного ключа в файл; приватный ключ держится в памяти |
| [`git-config`](./commands/git-config.md) | Установить `user.signingkey`, `commit.gpgsign`, `gpg.format`, `tag.gpgsign` |
| [`github`](./commands/github.md) | Загрузить публичный ключ в GitHub, выставить секреты репозитория, открыть PR |
| [`publish`](./commands/publish.md) | Опубликовать публичный ключ на сервере ключей |
| [`status`](./commands/status.md) | Показать текущее состояние настройки с поэтапными индикаторами |
| [`config`](./commands/config.md) | Управлять файлом постоянной конфигурации (`init` / `show` / `path`) |

Каждая команда принимает `--help`:

```bash
keysmith <команда> --help
```

## Архитектура в двух словах

`gpg-keysmith` — консольная утилита на Go, построенная на [cobra](https://github.com/spf13/cobra) и [survey](https://github.com/AlecAivazis/survey). Это **не** библиотечная Go-привязка к GPG — только `internal/gpg` вызывает системный `gpg` с провалидированными key ID. `internal/git` вызывает `git config`. `internal/github` использует REST API GitHub (`net/http`) для загрузки публичного ключа, коммита файла и открытия PR, а для секретов репозитория вызывает `gh secret set`, чтобы шифрование libsodium осталось в проверенном `gh`. Публикация на сервере ключей — обычный HTTPS POST.

Подробности: [Архитектура](./architecture.md).

## Безопасность в двух словах

Три защищаемых актива — **парольная фраза**, **приватный ключ**, **GitHub PAT** — никогда не пересекают поверхность утечки. Парольная фраза подаётся в `gpg` через `--passphrase-fd 0` (stdin), а не через аргумент CLI и не в batch-файле. Приватный ключ экспортируется только в память и хранится в процессе для шага `github`. PAT читается из переменной окружения, имя которой задано в `config.github.token_env`; флаг `--token` удалён, потому что он утекал через `ps` и `/proc/cmdline`.

Полная модель угроз, средства контроля и явные нецели: [Безопасность](./security.md).

## Участие в разработке

Pull request'ы приветствуются. Перед отправкой запустите локальный CI:

```bash
make ci     # проверка модулей + fmt + vet + build + test — должно быть зелёным
```

Соблюдайте [Conventional Commits](https://www.conventionalcommits.org/) в сообщениях коммитов. Полное руководство для контрибьюторов — в [CONTRIBUTING.md](../../CONTRIBUTING.md); исходный 10-этапный план разработки — в [DEVELOPMENT.md](../../DEVELOPMENT.md).

## Лицензия

MIT — см. [LICENSE](../../LICENSE). Copyright © 2026 Leonid Golikhin.