# ============================================================
# Telegram-бот для RouterOS 7 — управление WireGuard
# Установка во встроенный контейнер RouterOS (/container)
#
# ВАЖНО: Замените TODO_* значения на свои перед запуском!
# Если диск называется не disk1 — проверьте /disk/print
# ============================================================

# 1. Включить контейнеры
#    На CHR: после команды ЖЁСТКО выключите VM (power off),
#    затем включите заново. Иначе: not allowed by device-mode
/system device-mode update container=yes

# --- продолжите после перезагрузки VM ---

# 2. Реестр образов
/container/config/set registry-url=https://ghcr.io tmpdir=disk1/tmp

# 3. Сеть контейнера
/interface/veth/add name=veth-bot address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/add name=bridge-containers
/ip/address/add address=172.17.0.1/24 interface=bridge-containers
/interface/bridge/port/add bridge=bridge-containers interface=veth-bot
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.0.0/24

# 4. Переменные окружения (замените TODO_* на свои!)
/container/envs/add list=ENV_BOT key=BOT_TOKEN value="TODO_BOT_TOKEN"
/container/envs/add list=ENV_BOT key=MT_HOST value="172.17.0.1"
/container/envs/add list=ENV_BOT key=MT_USER value="wg-bot"
/container/envs/add list=ENV_BOT key=MT_PASS value="TODO_MT_PASS"
/container/envs/add list=ENV_BOT key=MT_PUBLIC_IP value="TODO_PUBLIC_IP"
/container/envs/add list=ENV_BOT key=MT_USE_SSL value="false"
/container/envs/add list=ENV_BOT key=MT_VERIFY_TLS value="false"
/container/envs/add list=ENV_BOT key=WG_MTU value="1420"
/container/envs/add list=ENV_BOT key=WG_DNS value="router"
/container/envs/add list=ENV_BOT key=WG_LISTEN_PORT value="51820"
/container/envs/add list=ENV_BOT key=WG_CLIENT_LISTEN_PORT value="51820"
/container/envs/add list=ENV_BOT key=WG_SUBNET_PREFIX value="10.200"
/container/envs/add list=ENV_BOT key=WG_PERSISTENT_KEEPALIVE value="15"

# 5. Хранилище данных (SQLite-база на диске роутера)
/container/mounts/add list=MOUNT_DATA src=disk1/volumes/bot/data dst=/data

# 6. Создать и запустить контейнер
/container/add name=bot remote-image=ghcr.io/bibibi-matrix/telegram-bot-project:latest \
  interface=veth-bot root-dir=disk1/images/bot envlist=ENV_BOT mountlists=MOUNT_DATA \
  start-on-boot=yes logging=yes

# 7. Дождитесь загрузки образа (/container/print → status=stopped)
#    и запустите:
# /container/start bot
# Логи: /log print where topics~"container"
