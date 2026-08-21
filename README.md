# Telegram Bot — управление WireGuard на MikroTik

Telegram-бот для управления WireGuard на маршрутизаторах MikroTik RouterOS v7 через REST API. Бот работает во встроенном контейнере RouterOS и управляет роутером напрямую.

---

## Возможности

### Пользователь
- Просмотр профиля (интерфейс, подсеть, порт, публичный ключ)
- Создание / удаление / переименование пиров
- Скачивание конфигурационного файла `.conf`
- Получение QR-кода для мобильного приложения WireGuard
- Включение / отключение пиров
- Перевыпуск ключей

### Администратор
- Одобрение / отклонение заявок на регистрацию
- Просмотр списка пользователей
- Просмотр и управление пирами любого пользователя
- Настройки роутера (IP, учётка, TLS, SSL) — прямо из бота
- Настройки бота (DNS, MTU, порт, keepalive)
- Двусторонняя синхронизация роутер ↔ база данных
- Изменение подсети для всех пользователей
- Управление статическими пирами (созданными вручную на роутере)
- Изменение даты регистрации пользователей
- Массовая рассылка сообщений пользователям

---

## Меню

| Кнопка | Назначение |
|---|---|
| 👤 Мой профиль | Данные интерфейса WireGuard |
| 📋 Мои пиры | Управление пирами |
| 🛠 Администрирование | Панель администратора |
| ❓ Помощь | Справка |

| Команда | Описание |
|---|---|
| `/start` | Приветствие и меню |
| `/menu` | Открыть меню |

---

## Требования

- **MikroTik RouterOS v7** с пакетом `container`
- **REST API** включён (`www` на порту 80 или `www-ssl` на порту 443)
- Пользователь RouterOS с правами `read`, `write`, `api`, `rest-api`
- Открытый **UDP-порт** для WireGuard
- **Telegram Bot Token** (получить у [@BotFather](https://t.me/BotFather))

---

## Установка

### Вариант 1: Контейнер RouterOS (рекомендуется)

Бот работает во встроенном контейнере RouterOS — отдельный Docker-хост не нужен.

#### Шаг 1. Включить контейнеры

```
/system device-mode update container=yes
```

> **Важно для CHR:** после этой команды **жёстко выключите VM** (power off через панель VPS-провайдера, НЕ restart), затем включите заново. Иначе контейнеры не запустятся.

#### Шаг 2. Настроить реестр образов

```
/container/config/set registry-url=https://ghcr.io tmpdir=disk1/tmp
```

> Если образ публичный, авторизация не нужна. Если приватный — добавьте credentials через `/container/config set username=... password=...` (PAT со scope `read:packages`).

#### Шаг 3. Настроить сеть контейнера

```
/interface/veth/add name=veth-bot address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/add name=bridge-containers
/ip/address/add address=172.17.0.1/24 interface=bridge-containers
/interface/bridge/port/add bridge=bridge-containers interface=veth-bot
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.0.0/24
```

#### Шаг 4. Настроить переменные окружения

Замените значения `TODO_*` на свои:

```
/container/envs/add list=ENV_BOT key=BOT_TOKEN value="ВАШ_ТОКЕН"
/container/envs/add list=ENV_BOT key=MT_HOST value="172.17.0.1"
/container/envs/add list=ENV_BOT key=MT_USER value="wg-bot"
/container/envs/add list=ENV_BOT key=MT_PASS value="ПАРОЛЬ_РОУТЕРА"
/container/envs/add list=ENV_BOT key=MT_PUBLIC_IP value="ПУБЛИЧНЫЙ_IP"
/container/envs/add list=ENV_BOT key=MT_USE_SSL value="false"
/container/envs/add list=ENV_BOT key=MT_VERIFY_TLS value="false"
/container/envs/add list=ENV_BOT key=WG_MTU value="1420"
/container/envs/add list=ENV_BOT key=WG_DNS value="router"
/container/envs/add list=ENV_BOT key=WG_LISTEN_PORT value="51820"
/container/envs/add list=ENV_BOT key=WG_CLIENT_LISTEN_PORT value="51820"
/container/envs/add list=ENV_BOT key=WG_SUBNET_PREFIX value="10.200"
/container/envs/add list=ENV_BOT key=WG_PERSISTENT_KEEPALIVE value="15"
```

> `MT_HOST` = `172.17.0.1` — адрес моста bridge-containers (роутер). `MT_PUBLIC_IP` — публичный IP, который видят VPN-клиенты в поле Endpoint.

#### Шаг 5. Создать хранилище

```
/container/mounts/add list=MOUNT_DATA src=disk1/volumes/bot/data dst=/data
```

> Путь `disk1` может отличаться (`sata1`, `usb1-part1` и т.д.) — проверьте `/disk/print`.

#### Шаг 6. Создать и запустить контейнер

```
/container/add name=bot remote-image=ghcr.io/bibibi-matrix/telegram-bot-project:latest interface=veth-bot root-dir=disk1/images/bot envlist=ENV_BOT mountlists=MOUNT_DATA start-on-boot=yes logging=yes
/container/start bot
```

Дождитесь загрузки образа (`/container/print`) и запустите.

#### Управление

```
/container/start bot       # запустить
/container/stop bot        # остановить
/container/remove bot      # удалить
/container/update bot      # обновить образ
/log print where topics~"container"  # логи
```

Готовый скрипт установки — [`routeros-setup.rsc`](routeros-setup.rsc).

---

### Вариант 2: Docker (на отдельном хосте)

```bash
git clone https://github.com/bibibi-Matrix/telegram-bot-project.git
cd telegram-bot-project
cp .env.example .env
# заполните .env
docker compose up -d
```

Или вручную:

```bash
docker build -t wg-bot .
docker run -d --name wg-bot --restart unless-stopped \
  -v wg-data:/data \
  --env-file .env \
  wg-bot
```

---

### Вариант 3: Локально

```bash
git clone https://github.com/bibibi-Matrix/telegram-bot-project.git
cd telegram-bot-project
python -m venv .venv
.venv\Scripts\activate       # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
cp .env.example .env
# заполните .env
python bot.py
```

---

## Настройки `.env`

| Переменная | По умолчанию | Описание |
|---|---|---|
| `BOT_TOKEN` | — | Токен Telegram-бота (обязательно) |
| `MT_HOST` | — | IP-адрес роутера (из контейнера: `172.17.0.1`) |
| `MT_USER` | — | Пользователь RouterOS |
| `MT_PASS` | — | Пароль RouterOS |
| `MT_PUBLIC_IP` | — | Публичный IP/домен роутера |
| `MT_USE_SSL` | `false` | HTTPS для REST API |
| `MT_VERIFY_TLS` | `false` | Проверка TLS-сертификата |
| `WG_MTU` | `1420` | MTU интерфейса WireGuard |
| `WG_DNS` | `router` | DNS для клиентов (`router` = DNS роутера в туннеле) |
| `WG_LISTEN_PORT` | `51820` | Базовый порт WireGuard |
| `WG_CLIENT_LISTEN_PORT` | `51820` | Порт на стороне клиента |
| `WG_SUBNET_PREFIX` | `10.200` | Префикс подсетей (`10.200.N.0/24`) |
| `WG_PERSISTENT_KEEPALIVE` | `15` | PersistentKeepalive (сек) |
| `DB_PATH` | `bot.db` | Путь к SQLite-базе (в контейнере: `/data/bot.db`) |
| `LOG_LEVEL` | `INFO` | Уровень логирования |

Настройки также можно менять прямо из бота (панель администратора).

---

## Как это работает

1. Первый пользователь, отправивший `/start`, автоматически становится **администратором**.
2. Новые пользователи отправляют **заявку на регистрацию** — администратор одобряет или отклоняет.
3. При одобрении создаётся интерфейс WireGuard (`wgXXXX`), назначается IP-адрес и подсеть `10.200.N.0/24`.
4. Пользователь управляет пирами: создаёт, скачивает конфиг/QR, включает/выключает, перевыпускает ключи.
5. Администратор может **синхронизировать** состояние роутера и базы, управлять настройками, выполнять рассылки.

---

## Структура проекта

```
├── bot.py                 # Telegram-бот: обработчики, меню, CRUD, синхронизация
├── config.py              # Загрузка настроек из .env
├── mikrotik.py            # Клиент RouterOS REST API
├── wireguard.py           # Генерация ключей X25519, конфиг-файл, QR-код
├── storage.py             # SQLite: пользователи, пиры, настройки
├── requirements.txt       # Зависимости Python
├── Dockerfile             # Сборка Docker-образа
├── routeros-setup.rsc     # Пошаговый скрипт установки на RouterOS
├── .env.example           # Пример конфигурации
└── .github/workflows/     # CI: автосборка Docker-образа → GHCR
```

---

## CI/CD

При пуше в `master` GitHub Actions собирает Docker-образ (`linux/amd64` + `linux/arm64`) и публикует в GHCR:

```
ghcr.io/bibibi-matrix/telegram-bot-project:latest
```

---

## Безопасность

- Токен бота и учётные данные роутера хранятся только в `.env` (исключён из git).
- Приватные ключи клиентов генерируются локально и хранятся в SQLite-базе.
- В RouterOS передаётся только публичный ключ.
- Если токен попал в репозиторий — отзовите его у @BotFather (`/revoke`).
