# `detect`

Список существующих приватных GPG-ключей текущего пользователя.

## Синопсис

```
keysmith detect [флаги]
```

`detect` разбирает вывод `gpg --list-secret-keys --keyid-format=long --with-colons` и выводит таблицу найденных ключей. Если ключей нет, печатает подсказку запустить `keysmith generate`.

## Флаги

| Флаг | Тип | По умолчанию | Описание |
|---|---|---|---|
| `-h`, `--help` | bool | `false` | Вывести помощь для `detect` |
| `--config` | string | `~/.config/gpg-keysmith/config.yaml` | Путь к файлу конфигурации (глобальный флаг) |

У `detect` нет собственных флагов команды — параметров не принимает.

## Примеры

### Вывести все GPG-ключи

```bash
keysmith detect
```

Пример вывода:

```
Found 1 GPG key(s):

  KEY ID              TYPE  CREATED             EXPIRES             USER ID
  F49BE957CD553B1C    sec   2026-07-17 12:25     2028-07-17 12:25    Leonid Golikhin (signing) <korrnals@gmail.com>
```

### Когда ключей нет

```bash
keysmith detect
```

```
No GPG keys found. Run 'gpg-keysmith generate' to create one.
```

### Проверить конкретный файл конфигурации

```bash
keysmith detect --config ~/.config/gpg-keysmith/config.yaml
```

## Замечания

- `detect` вызывает `gpg --list-secret-keys --keyid-format=long --with-colons`. Парольная фраза не требуется, связка ключей не модифицируется.
- Разобранный список ключей — вход для `git-config` и `wizard`, которые автоматически предлагают выбрать ключ, если он не задан явно.
- Экспортированная функция `DetectKeyForEmail(email)` (используется последующими этапами) возвращает ключ, чей user id совпадает с заданным email.

## Смотрите также

- [`generate`](./generate.md) — создать новый GPG-ключ, когда `detect` не находит ни одного
- [`git-config`](./git-config.md) — выставить подписной ключ из списка `detect`
- [`status`](./status.md) — объединить `detect` с остальными проверками настройки
- [`wizard`](./wizard.md) — запускает `detect` первым шагом полного потока