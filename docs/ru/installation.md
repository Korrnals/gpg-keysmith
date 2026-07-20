# Установка

Этот документ описывает зависимости, способы установки, расположение файла конфигурации и настройку автодополнения для `gpg-keysmith`.

## Зависимости

`gpg-keysmith` вызывает системные утилиты как внешние процессы. Все три должны быть установлены и находиться в `PATH`:

| Утилита | Версия | Нужна для | Проверка установки |
|---|---|---|---|
| `gpg` (GnuPG) | 2.x | все команды (генерация, экспорт, листинг) | `gpg --version` |
| `git` | любая свежая | `git-config`, `wizard`, `status` | `git --version` |
| `gh` (GitHub CLI) | любая свежая | `github`, `wizard`, `status` (только секреты репозитория) | `gh --version` |

`gh` нужен только для шага секретов репозитория в `github` (а значит, и в `wizard`, и в проверке секретов в `status`). Если вы не используете `github`, `gh` не требуется.

### Linux

```bash
# Debian / Ubuntu
sudo apt install gnupg git
# gh CLI (Debian/Ubuntu)
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install gh

# Fedora
sudo dnf install gnupg git gh
```

### macOS

```bash
brew install gnupg git gh
```

### Windows

Установите [Git for Windows](https://git-scm.com/download/win) (включает `git` и `gpg`), затем установите `gh` с [cli.github.com](https://cli.github.com/) или через `winget`:

```powershell
winget install --id GitHub.cli
```

## Установка keysmith

### Из исходников (рекомендуется для разработки)

```bash
git clone https://github.com/Korrnals/gpg-keysmith.git
cd gpg-keysmith
make install   # устанавливает в $GOBIN (или $GOPATH/bin)
```

Локальная сборка без установки:

```bash
make build     # собирает ./bin/keysmith (сжимается UPX, если upx доступен)
```

### Из релизного бинарника

1. Скачайте архив для вашей платформы с [GitHub Releases](https://github.com/Korrnals/gpg-keysmith/releases).
2. Проверьте SHA-256 по файлу `checksums.txt`, опубликованному рядом с релизом:

   ```bash
   sha256sum keysmith-*.tar.gz
   ```

3. Распакуйте и положите бинарник в `PATH`:

   ```bash
   tar xzf keysmith-linux-amd64.tar.gz
   chmod +x keysmith
   sudo mv keysmith /usr/local/bin/
   ```

### Через `go install`

```bash
go install github.com/Korrnals/gpg-keysmith/cmd/keysmith@latest
```

Устанавливает в `$GOBIN` (или `$GOPATH/bin`).

## Расположение файла конфигурации

`gpg-keysmith` читает конфигурацию из:

- пути, переданного через глобальный флаг `--config <путь>`, ИЛИ
- `$XDG_CONFIG_HOME/gpg-keysmith/config.yaml`, ИЛИ
- `~/.config/gpg-keysmith/config.yaml` (по умолчанию, если `XDG_CONFIG_HOME` не задан).

Конфиг хранит постоянные значения по умолчанию для генерации ключа, выбора сервера ключей и имени переменной окружения с GitHub PAT. Само значение PAT в конфиге **не** хранится — только имя переменной. Файл имеет режим `0600`.

Записать шаблон с комментариями:

```bash
keysmith config init
```

Вывести итоговый путь:

```bash
keysmith config path
```

Полная схема — в справочнике команды [`config`](./commands/config.md).

## Автодополнение

`gpg-keysmith` умеет генерировать скрипты автодополнения через встроенную команду cobra `completion`:

```bash
keysmith completion bash       # bash
keysmith completion zsh         # zsh
keysmith completion fish        # fish
keysmith completion powershell  # PowerShell
```

### bash

```bash
keysmith completion bash > ~/.local/share/bash-completion/completions/keysmith
# или для старых систем:
keysmith completion bash >> ~/.bashrc
```

### zsh

Если `~/.zsh/completions` находится в `$fpath`:

```bash
keysmith completion zsh > ~/.zsh/completions/_keysmith
```

Иначе добавьте вывод в `~/.zshrc` и перезагрузите.

### fish

```bash
keysmith completion fish > ~/.config/fish/completions/keysmith.fish
```

### PowerShell

```powershell
keysmith completion powershell | Out-String | Invoke-Expression
```

Либо сохраните в скрипт профиля и импортируйте его в `$PROFILE`.

## Проверка установки

```bash
keysmith --help          # выводит все подкоманды
keysmith detect          # показывает существующие GPG-ключи (или «ключи не найдены»)
keysmith config path     # выводит путь к файлу конфигурации
```

Если `detect` пишет `No GPG keys found`, запустите `keysmith generate` или `keysmith wizard`, чтобы создать ключ.