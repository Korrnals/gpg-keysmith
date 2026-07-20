# `config`

Управление файлом конфигурации `gpg-keysmith` в `~/.config/gpg-keysmith/config.yaml` (или по пути, переданному через `--config`).

## Синопсис

```
keysmith config [команда]
```

Конфиг хранит постоянные значения по умолчанию для генерации ключа, выбора сервера ключей и имени переменной окружения с GitHub PAT. Подкоманды, читающие конфиг (`generate`, `publish`, `github`, `status`, `wizard`), используют его значения как значения по умолчанию; явные флаги всегда перекрывают конфиг.

### Безопасность

Конфиг **никогда** не хранит значение GitHub PAT — только имя переменной окружения, в которой оно лежит. Файл в режиме `0600`; родительский каталог — `0700`.

## Подкоманды

| Подкоманда | Что делает |
|---|---|
| [`config init`](#config-init) | Записать шаблон конфига с комментариями по пути конфига |
| [`config show`](#config-show) | Вывести текущий конфиг (загруженный из пути или значения по умолчанию) |
| [`config path`](#config-path) | Вывести путь к файлу конфига |

## `config init`

Записывает закомментированный шаблон `config.yaml` по пути конфига (`~/.config/gpg-keysmith/config.yaml` по умолчанию или по пути, переданному через `--config`). Шаблон объясняет каждое поле и безопасен для ручного редактирования.

Отказывается перезаписывать существующий файл, если не передан `--force`.

```
keysmith config init [флаги]
```

| Флаг | Тип | По умолчанию | Описание |
|---|---|---|---|
| `--force` | bool | `false` | Перезаписать существующий файл конфига |
| `-h`, `--help` | bool | `false` | Вывести помощь для `init` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Путь к файлу конфигурации (глобальный флаг) |

### Примеры

#### Записать шаблон (первый запуск)

```bash
keysmith config init
```

#### Перезаписать существующий конфиг

```bash
keysmith config init --force
```

#### Записать в свой путь

```bash
keysmith config init --config ~/my-keysmith-config.yaml
```

## `config show`

Выводит текущий конфиг. Если `config.yaml` существует по пути конфига (или по пути, переданному через `--config`), он загружается и печатается. Если файла нет, печатаются встроенные значения по умолчанию, чтобы вы увидели, что получили бы, запустив `keysmith config init`.

```
keysmith config show [флаги]
```

| Флаг | Тип | По умолчанию | Описание |
|---|---|---|---|
| `-h`, `--help` | bool | `false` | Вывести помощь для `show` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Путь к файлу конфигурации (глобальный флаг) |

### Примеры

#### Показать загруженный конфиг (или значения по умолчанию)

```bash
keysmith config show
```

#### Показать конкретный файл конфига

```bash
keysmith config show --config ~/my-keysmith-config.yaml
```

## `config path`

Выводит путь к файлу конфига, который читает `keysmith` (`~/.config/gpg-keysmith/config.yaml` по умолчанию или по пути, переданному через `--config`).

```
keysmith config path [флаги]
```

| Флаг | Тип | По умолчанию | Описание |
|---|---|---|---|
| `-h`, `--help` | bool | `false` | Вывести помощь для `path` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Путь к файлу конфигурации (глобальный флаг) |

### Примеры

#### Вывести путь к конфигу по умолчанию

```bash
keysmith config path
```

Вывод:

```
/home/user/.config/gpg-keysmith/config.yaml
```

#### Вывести путь, который разрешает `--config`

```bash
keysmith config path --config ~/my-keysmith-config.yaml
```

## Схема конфига

Файл конфига — YAML. Схема (со значениями по умолчанию, которые пишет `config init`):

```yaml
# Значения по умолчанию для генерации ключа (используются 'generate' и 'wizard').
key:
  type: RSA          # алгоритм ключа (поддерживается только RSA)
  length: 4096       # длина RSA-ключа в битах
  expire: "0"        # спецификация срока: 0 = бессрочно, 2y = 2 года

# Значения по умолчанию для интеграции с GitHub (используются 'github', 'status', 'wizard').
github:
  token_env: GITHUB_TOKEN  # имя переменной окружения с GitHub PAT (никогда не значение)
  repo: ""                 # целевой репозиторий по умолчанию как owner/name (пусто = запрос)

# Значения по умолчанию для сервера ключей (используются 'publish', 'wizard').
keyserver:
  preferred: keys.openpgp.org      # предпочитаемый сервер ключей
  fallback: keyserver.ubuntu.com   # запасной сервер ключей
```

### Справочник по полям

| Поле | Используется | По умолчанию | Замечания |
|---|---|---|---|
| `key.type` | `generate`, `wizard` | `RSA` | Поддерживается только `RSA` |
| `key.length` | `generate`, `wizard` | `4096` | Перекрывается флагом `--key-length` |
| `key.expire` | `generate`, `wizard` | `"0"` | Перекрывается флагом `--expiry` |
| `github.token_env` | `github`, `status`, `wizard` | `GITHUB_TOKEN` | **Имя** переменной окружения; не значение токена |
| `github.repo` | `github`, `status`, `wizard` | `""` | Пусто = запрос; перекрывается флагом `--repo` |
| `keyserver.preferred` | `publish`, `wizard` | `keys.openpgp.org` | Перекрывается флагом `--keyserver` (значения, отличные от `all`) |
| `keyserver.fallback` | `publish`, `wizard` | `keyserver.ubuntu.com` | Используется при `--keyserver=all` |

## Замечания

- **Режим файла.** `config.Save` и `config.Init` пишут в режиме `0600`; родительский каталог создаётся в режиме `0700`.
- **`token_env` обязателен.** `Save` отказывается писать конфиг с пустым `github.token_env` (`ErrEmptyTokenEnv`) — это не даёт случайно сохранить значение токена напрямую.
- **Отсутствие конфига — не ошибка.** `config.Load` возвращает `Default()` и nil-ошибку, если файла не существует — отсутствие конфига означает «использовать встроенные значения по умолчанию».
- **С учётом XDG.** Путь по умолчанию учитывает `$XDG_CONFIG_HOME`; если оно не задано, используется `~/.config/gpg-keysmith/config.yaml`.

## Смотрите также

- [`generate`](./generate.md) — читает `key.length` и `key.expire`
- [`github`](./github.md) — читает `github.token_env` и `github.repo`
- [`status`](./status.md) — читает `github.token_env`
- [`publish`](./publish.md) — читает `keyserver.preferred` и `keyserver.fallback`
- [`wizard`](./wizard.md) — читает все перечисленные поля
- [Установка](../installation.md) — расположение файла конфига и автодополнение