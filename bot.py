"""Telegram bot for managing WireGuard on MikroTik via RouterOS REST API."""

from __future__ import annotations

import asyncio
import html
import io
import logging
import os
import re
from datetime import datetime, timedelta

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, InputFile, Update
import telegram.error
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    PicklePersistence,
    filters,
)

from config import Config
from mikrotik import MikroTik, RouterOSError
from storage import Storage
from wireguard import build_client_config, build_qr_png, generate_keypair, derive_public_key

logger = logging.getLogger(__name__)

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,15}$")

_HTML_TOKEN_RE = re.compile(r"(<[^>]+>|\S+|\s+)")


def _wrap_html_text(text: str, width: int = 40) -> str:
    """Wrap text to `width` visible chars per line, keeping inline HTML tags intact."""
    out = []
    for line in text.split("\n"):
        cur = ""
        vis = 0
        space_pending = False
        for tok in _HTML_TOKEN_RE.findall(line):
            if not tok:
                continue
            if tok.startswith("<"):
                if space_pending and vis > 0:
                    cur += " "
                    vis += 1
                space_pending = False
                cur += tok
                continue
            if tok.isspace():
                if vis > 0 and not space_pending:
                    space_pending = True
                continue
            if vis > 0 and vis + (1 if space_pending else 0) + len(tok) > width:
                out.append(cur)
                cur = ""
                vis = 0
                space_pending = False
            if vis > 0 and space_pending:
                cur += " "
                vis += 1
                space_pending = False
            cur += tok
            vis += len(tok)
        out.append(cur)
    return "\n".join(out)

_CARD_WIDTH = 36
_CARD_SEP = "─" * _CARD_WIDTH


def _plain_wrap_pad(text: str, width: int = _CARD_WIDTH) -> list[str]:
    """Wrap plain text to `width` chars and pad every line to exactly `width`.

    Words longer than the width are hard-wrapped so no line exceeds `width`.
    """
    out = []
    for raw in text.split("\n"):
        if not raw:
            out.append(" " * width)
            continue
        cur = ""
        for word in raw.split(" "):
            while len(word) > width:
                if cur:
                    out.append(cur.ljust(width))
                    cur = ""
                out.append(word[:width])
                word = word[width:]
            if not cur:
                cur = word
            elif len(cur) + 1 + len(word) <= width:
                cur += " " + word
            else:
                out.append(cur.ljust(width))
                cur = word
        out.append(cur.ljust(width))
    return out


def _card(text: str, width: int = _CARD_WIDTH) -> str:
    """Render text as a uniform monospace card with space-padded lines."""
    body = "\n".join(html.escape(line) for line in _plain_wrap_pad(text, width))
    return f"<pre>{body}</pre>"

ROLE_ADMIN = "Администратор"
ROLE_USER = "Пользователь"

# user_data states
_AWAITING_NAME = "awaiting_name"  # {'action': 'add_peer' | 'rename_peer', 'router_id': ...}
_AWAITING_SETTING = "awaiting_setting"  # {'action': 'set_mt' | 'rename_user' | 'set_access', ...}
_AWAITING_BROADCAST = "awaiting_broadcast"  # {'action': 'broadcast_all' | 'broadcast_user', 'target': ...}
_MENU_MSG = "menu_msg_id"  # message id of the menu message replaced by an input prompt
_MENU_OPEN_MSG = "menu_open_msg_id"  # message id of the collapsed menu with the «open» button
_ADMIN_NOTIFY_MSG = "admin_notify_msg_id"  # message id of the last admin notification (dedup)
_REG_MSG = "reg_msg_id"  # message id of the user's registration message ("Заявка отправлена")

_EXPIRY_CHECK_INTERVAL = 3600  # seconds between automatic access-expiry checks
_DEADLINE_WARN_INTERVAL = 86400  # seconds between deadline-warning checks (once per day)
_DEADLINE_WARN_DAYS = 7  # warn this many days before the deadline
_DEADLINE_WARN_KEY = "last_deadline_warn"  # DB setting storing date of last warning

_STATUS_ICONS = {
    "active": "🟢 активен",
    "pending": "🕐 ожидает",
    "rejected": "❌ отклонён",
    "blocked": "🔴 заблокирован",
}

_DATE_FORMATS = ("%d.%m.%Y %H:%M", "%d.%m.%Y %H:%M:%S", "%d.%m.%Y", "%Y-%m-%d %H:%M", "%Y-%m-%d")


def _parse_int(value, default: int = 0) -> int:
    """Parse an int from a RouterOS value, stripping time suffixes like '15s'."""
    if isinstance(value, int):
        return value
    try:
        return int(str(value).rstrip("smhdw"))
    except (ValueError, TypeError):
        return default


def _parse_date(text: str) -> datetime | None:
    """Parse user-entered date. Date-only inputs mean midnight local time."""
    text = text.strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None

_MT_KEYS = ("host", "user", "pass", "public_ip", "ssl", "tls")
_MT_LABELS = {
    "host": "🌐 Хост",
    "ip": "📡 Публичный IP",
    "user": "👤 Логин",
    "pass": "🔑 Пароль",
    "public_ip": "📡 Публичный IP",
}

_WG_ISOLATE_COMMENT = "wg-isolate"
_WG_SUBNETS_LIST = "wg-subnets"
_WG_SUBNETS_COMMENT = "wg-bot"

# Consolidated rules (manually set up on the router): when present, the bot
# does NOT create per-user forward/return/nat rules since they are already
# covered by an interface-list / address-list based rule.
_WG_ALL_INPUT_COMMENT = "wg-all-input"
_WG_ALL_FORWARD_COMMENT = "wg-all-forward"
_WG_ALL_RETURN_COMMENT = "wg-all-return"
_WG_ALL_NAT_COMMENT = "wg-all-nat"

# Interface list that receives every WireGuard tunnel so a consolidated
# forward rule (wg-all-forward / wg-all-return) sees them automatically.
WG_LAN_INTERFACE_LIST = "LAN"

_SYNC_SECTION = "sync"

_MAX_BROADCAST_LEN = 4000
_MAX_NAME_LEN = 15
_DATE_FMT = "%Y-%m-%d %H:%M:%S"


class Bot:
    def __init__(self, cfg: Config, db: Storage, mt: MikroTik):
        self.cfg = cfg
        self.db = db
        self.mt = mt
        self.mt_settings = self._load_mt_settings()

    def _load_mt_settings(self) -> dict:
        defaults = {
            "host": self.cfg.MT_HOST,
            "user": self.cfg.MT_USER,
            "pass": self.cfg.MT_PASS,
            "public_ip": self.cfg.MT_PUBLIC_IP,
            "ssl": "true" if self.cfg.MT_USE_SSL else "false",
            "tls": "true" if self.cfg.MT_VERIFY_TLS else "false",
        }
        loaded = {}
        for key in _MT_KEYS:
            val = self.db.get_setting(key)
            if val is None:
                self.db.set_setting(key, defaults[key])
                val = defaults[key]
            loaded[key] = val
        return loaded

    def _mt_bool(self, key: str) -> bool:
        return self.mt_settings.get(key, "false").lower() in ("1", "true", "yes")

    def mt_ready(self) -> bool:
        return all(self.mt_settings.get(k) for k in ("host", "user", "pass", "public_ip"))

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _name_of(user_effective) -> str:
        return (
            user_effective.full_name
            or user_effective.username
            or str(user_effective.id)
        )

    async def _notify_admins(self, context: ContextTypes.DEFAULT_TYPE, text: str, kb=None) -> None:
        for admin in self.db.list_admins():
            await self._try_delete_message(
                context,
                admin["telegram_id"],
                context.application.user_data.get(admin["telegram_id"], {}).pop(
                    _ADMIN_NOTIFY_MSG, None
                ),
            )
            try:
                msg = await context.bot.send_message(
                    admin["telegram_id"], text, reply_markup=kb
                )
                data = context.application.user_data.setdefault(admin["telegram_id"], {})
                data[_ADMIN_NOTIFY_MSG] = msg.message_id
            except Exception as exc:  # noqa: BLE001
                logger.warning("Cannot notify admin %s: %s", admin["telegram_id"], exc)
            await self._clear_menu(context, admin["telegram_id"])

    async def _clear_menu(self, context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
        """Delete standalone messages of a chat (menu, notification) so they do not duplicate."""
        data = context.application.user_data.get(chat_id)
        if not data:
            return
        for key in (_MENU_MSG, _MENU_OPEN_MSG, _ADMIN_NOTIFY_MSG):
            mid = data.pop(key, None)
            if mid:
                await self._try_delete_message(context, chat_id, mid)

    async def _provision_user(self, uid: int, role: str) -> None:
        """Create the user's own WireGuard interface on the router."""
        if not self.mt_ready():
            raise RouterOSError(
                "Роутер не настроен: укажите MT_HOST, MT_USER, MT_PASS, MT_PUBLIC_IP в настройках"
            )
        idx = self._next_interface_index()
        iface = f"wg{uid}"
        subnet = f"{self.cfg.WG_SUBNET_PREFIX}.{idx}.0/24"
        listen_port = self.cfg.WG_LISTEN_PORT + idx
        gateway = f"{self.cfg.WG_SUBNET_PREFIX}.{idx}.1/24"

        iface_info = await self.mt.get_wireguard_interface(iface)
        if not iface_info:
            await self.mt.create_wireguard_interface(iface, listen_port, self.cfg.WG_MTU)
        else:
            port = iface_info.get("listen-port")
            if port:
                listen_port = int(port)
        if not await self.mt.get_ip_addresses(iface):
            await self.mt.add_ip_address(gateway, iface, comment=iface)
        await self._ensure_firewall(iface, listen_port, subnet)
        self.db.update_user(
            uid,
            wg_interface=iface,
            subnet=subnet,
            listen_port=listen_port,
            status="active",
            role=role,
        )
        await self._sync_wg_subnets()

    def _next_interface_index(self) -> int:
        """Smallest free subnet index, avoiding collisions with existing users.

        A subnet and a listen port must both be free: the subnet is derived
        from the index (`PREFIX.IDX.0/24`) and the port from `WG_LISTEN_PORT +
        IDX`. Checking only ports allowed two users to land on the same subnet
        when `WG_LISTEN_PORT` changed between allocations, so both interfaces
        ended up with the same gateway address.
        """
        used_subnets = {
            u["subnet"]
            for u in self.db.list_users()
            if u.get("subnet")
        }
        used_ports = {
            u["listen_port"]
            for u in self.db.list_users()
            if u.get("listen_port")
        }
        for i in range(1, 255):
            subnet = f"{self.cfg.WG_SUBNET_PREFIX}.{i}.0/24"
            port = self.cfg.WG_LISTEN_PORT + i
            if subnet not in used_subnets and port not in used_ports:
                return i
        raise RouterOSError("Все подсети WireGuard заняты")

    @staticmethod
    def _chain_drop_anchor(rules: list[dict], chain: str) -> str:
        """Id of the first drop rule in the chain to insert bot rules before."""
        for r in rules:
            if (
                r.get("chain") == chain
                and r.get("action") == "drop"
                and r.get("comment") != _WG_ISOLATE_COMMENT
            ):
                return r[".id"]
        return "0"

    async def _sync_wg_subnets(self) -> None:
        """Ensure the cross-user isolation rule and the wg-subnets address list.

        The isolate rule is placed at the very top of the forward chain so it
        runs BEFORE the consolidated wg-all-forward/wg-all-return rules — this
        is what actually blocks traffic between different WG subnets.
        """
        rules = await self.mt.get_firewall_rules()
        isolate = next((r for r in rules if r.get("comment") == _WG_ISOLATE_COMMENT), None)
        if not isolate:
            await self.mt.add_firewall_rule(
                _WG_ISOLATE_COMMENT,
                place_before="0",
                chain="forward",
                action="drop",
                **{
                    "src-address-list": _WG_SUBNETS_LIST,
                    "dst-address-list": _WG_SUBNETS_LIST,
                },
            )
        else:
            # Rule already exists. RouterOS REST does not support moving a rule
            # via PATCH (place-before is only accepted on create), so its
            # position must be ensured manually if needed.
            logger.debug("wg-isolate already present, position not moved")
        wanted = {u["subnet"] for u in self.db.list_users() if u.get("subnet")}
        entries = await self.mt.get_address_list_entries(_WG_SUBNETS_LIST)
        have = {e.get("address") for e in entries}
        for addr in sorted(wanted):
            if addr not in have:
                await self.mt.add_address_list_entry(
                    addr, _WG_SUBNETS_LIST, comment=_WG_SUBNETS_COMMENT
                )

    async def _remove_wg_subnet(self, subnet: str) -> None:
        for entry in await self.mt.get_address_list_entries(_WG_SUBNETS_LIST):
            if entry.get("address") == subnet:
                await self.mt.remove_address_list_entry(entry[".id"])

    @staticmethod
    def _find_rule_by_comment(rules: list[dict], chain: str, comment: str) -> dict | None:
        return next(
            (r for r in rules if r.get("chain") == chain and r.get("comment") == comment),
            None,
        )

    @staticmethod
    def _has_consolidated_filter(rules: list[dict], chain: str, comment: str) -> bool:
        """True if a filter rule with the given chain/comment already exists.

        Accepts any owner (created manually or by the bot) — bridge over to a
        matching rule when the comment differs (e.g. an older name) but the
        structure matches.
        """
        return Bot._find_rule_by_comment(rules, chain, comment) is not None

    @staticmethod
    def _has_consolidated_nat(nat_rules: list[dict]) -> bool:
        return any(
            r.get("chain") == "srcnat"
            and r.get("action") == "masquerade"
            and (r.get("comment") == _WG_ALL_NAT_COMMENT or r.get("src-address-list") == _WG_SUBNETS_LIST)
            for r in nat_rules
        )

    async def _ensure_consolidated_rules(self) -> None:
        """Create the shared wg-all-* rules only if they are not present yet.

        Consolidated scheme (single set of rules for every WG tunnel):
          - wg-all-input   : input    accept in-interface-list=LAN
          - wg-all-forward : forward  accept in-interface-list=LAN
          - wg-all-return  : forward  accept out-interface-list=LAN
                                              (connection-state=established,related)
          - wg-all-nat     : srcnat   masquerade src-address-list=wg-subnets
        The bot never duplicates these; manually created equivalents are left
        untouched.
        """
        rules = await self.mt.get_firewall_rules()
        input_anchor = self._chain_drop_anchor(rules, "input")
        forward_anchor = self._chain_drop_anchor(rules, "forward")

        if not self._has_consolidated_filter(rules, "input", _WG_ALL_INPUT_COMMENT):
            await self.mt.add_firewall_rule(
                _WG_ALL_INPUT_COMMENT,
                place_before=input_anchor,
                chain="input",
                action="accept",
                **{"in-interface-list": WG_LAN_INTERFACE_LIST},
            )

        if not self._has_consolidated_filter(rules, "forward", _WG_ALL_FORWARD_COMMENT):
            await self.mt.add_firewall_rule(
                _WG_ALL_FORWARD_COMMENT,
                place_before=forward_anchor,
                chain="forward",
                action="accept",
                **{"in-interface-list": WG_LAN_INTERFACE_LIST},
            )

        if not self._has_consolidated_filter(rules, "forward", _WG_ALL_RETURN_COMMENT):
            await self.mt.add_firewall_rule(
                _WG_ALL_RETURN_COMMENT,
                place_before=forward_anchor,
                chain="forward",
                action="accept",
                **{
                    "out-interface-list": WG_LAN_INTERFACE_LIST,
                    "connection-state": "established,related",
                },
            )

        nat_existing = await self.mt.get_firewall_nat_rules()
        if not self._has_consolidated_nat(nat_existing):
            await self.mt.add_firewall_nat_rule(
                comment=_WG_ALL_NAT_COMMENT,
                chain="srcnat",
                action="masquerade",
                **{"src-address-list": _WG_SUBNETS_LIST},
            )

    async def _ensure_lan_member(self, iface: str) -> None:
        """Add a WireGuard tunnel to the LAN interface list if not already there.

        The consolidated forward rules match in/out-interface-list=LAN, so every
        managed WG tunnel must be a member of that list for traffic to flow.
        """
        try:
            members = await self.mt.get_interface_list_members(WG_LAN_INTERFACE_LIST)
        except RouterOSError as exc:
            logger.warning("Cannot read interface list %s: %s", WG_LAN_INTERFACE_LIST, exc)
            return
        for m in members:
            if m.get("interface") == iface:
                return
        try:
            await self.mt.add_interface_to_list(iface, WG_LAN_INTERFACE_LIST, comment="wg-bot")
            logger.info("Added %s to interface list %s", iface, WG_LAN_INTERFACE_LIST)
        except RouterOSError as exc:
            logger.warning("Cannot add %s to interface list %s: %s", iface, WG_LAN_INTERFACE_LIST, exc)

    async def _remove_lan_member(self, iface: str) -> None:
        """Remove an interface from the LAN list (used when deleting a user)."""
        try:
            members = await self.mt.get_interface_list_members(WG_LAN_INTERFACE_LIST)
        except RouterOSError:
            return
        for m in members:
            if m.get("interface") == iface:
                try:
                    await self.mt.remove_interface_from_list(m[".id"])
                except RouterOSError as exc:
                    logger.warning("Cannot remove %s from %s: %s", iface, WG_LAN_INTERFACE_LIST, exc)
                return

    async def _ensure_firewall(self, iface: str, listen_port: int, subnet: str) -> None:
        """Ensure per-user and consolidated firewall rules for the user's WG.

        Per-user only the handshake rule is created (unique UDP listen port per
        tunnel). The shared wg-all-input / wg-all-forward / wg-all-return /
        wg-all-nat rules and the wg-isolate rule are created once and reused by
        every tunnel (via the LAN interface list / wg-subnets address list).
        """
        await self._ensure_consolidated_rules()
        await self._sync_wg_subnets()
        await self._ensure_lan_member(iface)
        existing = await self.mt.get_firewall_rules()
        comments = {r.get("comment") for r in existing}
        input_anchor = self._chain_drop_anchor(existing, "input")

        handshake_comment = f"wg-{iface}-handshake"
        if handshake_comment not in comments:
            await self.mt.add_firewall_rule(
                handshake_comment,
                place_before=input_anchor,
                chain="input",
                protocol="udp",
                action="accept",
                **{"dst-port": str(listen_port)},
            )
        else:
            cur = next((x for x in existing if x.get("comment") == handshake_comment), None)
            if cur and cur.get("dst-port") != str(listen_port):
                await self.mt.update_firewall_rule(
                    cur[".id"], **{"dst-port": str(listen_port)}
                )

    async def _reposition_user_rules(self, iface: str, listen_port: int) -> None:
        """Delete and recreate a user's per-user rules in the canonical position.

        Used to migrate rules created by older code. In the consolidated scheme
        only the per-user handshake is recreated; the shared wg-all-* rules and
        wg-isolate are ensured separately.
        """
        rules = await self.mt.get_firewall_rules()
        input_anchor = self._chain_drop_anchor(rules, "input")
        for r in rules:
            if (r.get("comment") or "").startswith(f"wg-{iface}-"):
                await self.mt.delete_firewall_rule(r[".id"])
        for nr in await self.mt.get_firewall_nat_rules():
            if (nr.get("comment") or "").startswith(f"wg-{iface}-"):
                await self.mt.delete_firewall_nat_rule(nr[".id"])
        await self._ensure_consolidated_rules()
        await self._sync_wg_subnets()
        await self._ensure_lan_member(iface)
        rules = await self.mt.get_firewall_rules()
        input_anchor = self._chain_drop_anchor(rules, "input")
        handshake_comment = f"wg-{iface}-handshake"
        if not any(r.get("comment") == handshake_comment for r in rules):
            await self.mt.add_firewall_rule(
                handshake_comment,
                place_before=input_anchor,
                chain="input",
                protocol="udp",
                action="accept",
                **{"dst-port": str(listen_port)},
            )

    def _next_peer_ip(self, subnet: str, used: set[str]) -> str | None:
        prefix = subnet.rsplit(".", 1)[0]
        for host in range(2, 255):
            ip = f"{prefix}.{host}"
            if ip not in used:
                return f"{ip}/32"
        return None

    def _router_dns(self, user: dict) -> str:
        dns = self.cfg.WG_DNS
        if dns.lower() == "router":
            prefix = ".".join(user["subnet"].split(".")[:3])
            return f"{prefix}.1"
        return dns

    async def _get_server_public_key(self, interface: str) -> str:
        srv = await self.mt.get_wireguard_interface(interface)
        if not srv:
            raise RouterOSError(f"Интерфейс {interface} не найден")
        return srv.get("public-key", "")

    # ------------------------------------------------------------- start / help
    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        eff = update.effective_user
        uid = eff.id
        user = self.db.get_user(uid)

        if user is None:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("📝 Зарегистрироваться", callback_data="reg:start")]]
            )
            await update.message.reply_text(
                "Привет! Вы не зарегистрированы.\n"
                "Нажмите кнопку, чтобы подать заявку на регистрацию.",
                reply_markup=kb,
            )
            await self._try_delete(update.message)
            return

        if user["status"] == "pending":
            if not self.db.list_admins():
                # Первый пользователь, чей интерфейс не удалось создать (роутер не был настроен)
                try:
                    await self._provision_user(uid, ROLE_ADMIN)
                except RouterOSError as exc:
                    await update.message.reply_text(
                        f"Не удалось создать интерфейс: {exc}\n"
                        "Заполните MT_HOST, MT_USER, MT_PASS, MT_PUBLIC_IP в .env и отправьте /start снова."
                    )
                    await self._try_delete(update.message)
                    return
                await update.message.reply_text(
                    "✅ Интерфейс создан. Вы Администратор.",
                )
                await self._try_delete(update.message)
                await self._show_menu(context, update.effective_chat.id, None)
            else:
                await update.message.reply_text("Ваша заявка ещё рассматривается администратором.")
                await self._try_delete(update.message)
        elif user["status"] == "rejected":
            await update.message.reply_text("Ваша заявка отклонена администратором.")
            await self._try_delete(update.message)
        elif user["status"] == "blocked":
            await update.message.reply_text("Ваш аккаунт заблокирован администратором.")
            await self._try_delete(update.message)
        else:
            await update.message.reply_text("👋 Добро пожаловать в WireGuard-менеджер!")
            await self._try_delete(update.message)
            await self._show_menu(context, update.effective_chat.id, user)

    # ------------------------------------------------------------------ menu
    async def _require_active(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> dict | None:
        """Return the active user record, or reply about registration/status."""
        user = self.db.get_user(update.effective_user.id)
        if user is None:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("📝 Зарегистрироваться", callback_data="reg:start")]]
            )
            await update.message.reply_text(
                "Вы не зарегистрированы.\nНажмите кнопку, чтобы подать заявку.",
                reply_markup=kb,
            )
            return None
        if user["status"] != "active":
            hint = self._status_hint(user["status"])
            if self._is_access_expired(user):
                hint = (
                    "Ваш срок доступа к VPN истёк ⏰. "
                    "Для продления свяжитесь с администратором."
                )
            await update.message.reply_text(hint)
            return None
        if self._is_access_expired(user):
            try:
                await self._block_user(None, user, context.bot, silent=True)
            except RouterOSError as exc:
                logger.warning("Expiry block failed for %s: %s", user["telegram_id"], exc)
            await update.message.reply_text(
                "Ваш срок доступа к VPN истёк ⏰. Для продления свяжитесь с администратором."
            )
            return None
        return user

    async def cmd_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = await self._require_active(update, context)
        if not user:
            return
        await self._show_menu(context, update.effective_chat.id, user)

    async def cmd_myinfo(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = await self._require_active(update, context)
        if not user:
            return
        try:
            text = await self._account_text(user)
        except RouterOSError as exc:
            await update.message.reply_text(f"Ошибка: {exc}")
            return
        await update.message.reply_text(text, parse_mode="HTML", reply_markup=self._back_kb())
        await self._ensure_menu(context, update.effective_chat.id)

    async def cmd_peers(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = await self._require_active(update, context)
        if not user:
            return
        try:
            peers = await self.mt.get_peers(user["wg_interface"])
        except RouterOSError as exc:
            await update.message.reply_text(f"Ошибка: {exc}")
            return
        peers = self._filter_db_peers(peers)
        await update.message.reply_text(
            self._peers_list_text(peers),
            parse_mode="HTML",
            reply_markup=self._peers_kb_with_back(peers),
        )
        await self._ensure_menu(context, update.effective_chat.id)

    async def cmd_admin(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        admin = await self._require_active(update, context)
        if not admin:
            return
        if admin["role"] != ROLE_ADMIN:
            await update.message.reply_text("Доступно только администратору.")
            return
        await update.message.reply_text(
            _card("🛠 АДМИНИСТРИРОВАНИЕ\n" + _CARD_SEP + "\n\nВыберите раздел ниже."),
            parse_mode="HTML",
            reply_markup=self._admin_menu_kb(),
        )
        await self._ensure_menu(context, update.effective_chat.id)

    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            self._help_text(), parse_mode="HTML", reply_markup=self._back_kb()
        )
        await self._ensure_menu(context, update.effective_chat.id)

    def _help_text(self) -> str:
        return _card(
            "❓ ПОМОЩЬ\n"
            f"{_CARD_SEP}\n"
            "Управление WireGuard — через кнопки меню.\n\n"
            "• 👤 Профиль — данные интерфейса\n"
            "• 📋 Пиры — конфиг, QR, вкл/выкл,\n"
            "  ключи, переименование, удаление\n"
            "• 🛠 Администрирование — заявки,\n"
            "  пользователи, настройки роутера"
        )

    @staticmethod
    def _status_hint(status: str) -> str:
        return {
            "pending": "Ваша заявка ещё рассматривается администратором.",
            "rejected": "Ваша заявка отклонена администратором.",
            "blocked": "Ваш аккаунт заблокирован администратором.",
        }.get(status, "")

    def _main_menu_text(self, user: dict) -> str:
        badge = "🛡 Администратор" if user["role"] == ROLE_ADMIN else "🙂 Пользователь"
        iface = user.get("wg_interface") or "—"
        return _card(
            f"☰ ГЛАВНОЕ МЕНЮ\n"
            f"{_CARD_SEP}\n"
            f"👋 Привет, {user['full_name']}!\n"
            f"{badge} · 🌐 {iface}\n\n"
            "Выберите раздел кнопками ниже. "
            "Все разделы открываются в этом же сообщении."
        )

    def _main_menu_kb(self, user: dict) -> InlineKeyboardMarkup:
        kb = [
            [
                InlineKeyboardButton("👤 Мой профиль", callback_data="menu:account"),
                InlineKeyboardButton("📋 Мои пиры", callback_data="menu:peers"),
            ],
        ]
        if user["role"] == ROLE_ADMIN:
            kb.append([InlineKeyboardButton("🛠 Администрирование", callback_data="menu:admin")])
        kb.append(
            [
                InlineKeyboardButton("❓ Помощь", callback_data="menu:help"),
                InlineKeyboardButton("✖ Закрыть", callback_data="menu:close"),
            ]
        )
        return InlineKeyboardMarkup(kb)

    @staticmethod
    def _menu_open_kb() -> InlineKeyboardMarkup:
        return InlineKeyboardMarkup(
            [[InlineKeyboardButton("☰ Меню", callback_data="menu:open")]]
        )

    @staticmethod
    def _back_kb(back: str = "menu:root") -> InlineKeyboardMarkup:
        return InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Назад", callback_data=back)]])

    @staticmethod
    async def _try_delete(msg) -> None:
        """Best-effort delete of a message (e.g. the user's /start or a peer name)."""
        try:
            await msg.delete()
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    async def _try_delete_message(context, chat_id, message_id) -> None:
        """Best-effort delete of a message by id."""
        if not chat_id or not message_id:
            return
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
        except Exception:  # noqa: BLE001
            pass

    async def _show_menu(self, context, chat_id: int, user: dict | None = None) -> None:
        if user is None:
            user = self.db.get_user(chat_id)
        collapsed = context.user_data.pop(_MENU_OPEN_MSG, None)
        if collapsed:
            try:
                await context.bot.delete_message(chat_id=chat_id, message_id=collapsed)
            except Exception:  # noqa: BLE001
                pass
        notify_msg = context.user_data.pop(_ADMIN_NOTIFY_MSG, None)
        if notify_msg and notify_msg != collapsed:
            try:
                await context.bot.delete_message(chat_id=chat_id, message_id=notify_msg)
            except Exception:  # noqa: BLE001
                pass
        old_id = context.user_data.pop(_MENU_MSG, None)
        if old_id:
            try:
                await context.bot.delete_message(chat_id=chat_id, message_id=old_id)
            except Exception:  # noqa: BLE001
                pass
        msg = await context.bot.send_message(
            chat_id,
            self._main_menu_text(user),
            parse_mode="HTML",
            reply_markup=self._main_menu_kb(user),
        )
        context.user_data[_MENU_MSG] = msg.message_id

    async def _ensure_menu(self, context, chat_id: int) -> None:
        """Keep exactly one menu message per chat: create it only if none exists."""
        if context.user_data.get(_MENU_MSG) or context.user_data.get(_MENU_OPEN_MSG):
            return
        user = self.db.get_user(chat_id)
        if not user or user["status"] != "active" or self._is_access_expired(user):
            return
        await self._show_menu(context, chat_id, user)

    async def _check_expirations(self, bot) -> None:
        """Block users whose VPN access deadline has passed."""
        now = datetime.now().strftime(_DATE_FMT)
        for user in self.db.list_expired(now):
            try:
                await self._block_user(
                    None,
                    user,
                    bot,
                    notify_text=(
                        "Ваш срок доступа к VPN истёк ⏰. "
                        "Для продления свяжитесь с администратором."
                    ),
                )
            except RouterOSError as exc:
                logger.warning(
                    "Expiry block failed for %s: %s", user["telegram_id"], exc
                )

    async def _check_deadline_warnings(self, bot) -> None:
        """Notify admins once per day about users whose deadline is within _DEADLINE_WARN_DAYS."""
        if self.db.get_setting("notify_deadline") != "true":
            return
        today = datetime.now().strftime("%Y-%m-%d")
        if self.db.get_setting(_DEADLINE_WARN_KEY) == today:
            return
        now = datetime.now()
        before = (now + timedelta(days=_DEADLINE_WARN_DAYS)).strftime(_DATE_FMT)
        expiring = self.db.list_expiring_soon(now.strftime(_DATE_FMT), before)
        if not expiring:
            return
        lines = []
        for u in expiring:
            days = (datetime.strptime(u["access_until"], _DATE_FMT) - now).days
            when = u["access_until"][:10]
            lines.append(f"• @{u['username'] or '-'} ({u['full_name']}) — {when} ({days} дн.)")
        text = (
            f"⏰ Срок доступа истекает у {len(expiring)} пользователей:\n\n"
            + "\n".join(lines)
            + "\n\nДля продления перейдите в Администрирование → Пользователи."
        )
        for admin in self.db.list_admins():
            try:
                await bot.send_message(admin["telegram_id"], text)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Cannot notify admin %s about deadlines: %s", admin["telegram_id"], exc)
        self.db.set_setting(_DEADLINE_WARN_KEY, today)

    async def on_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user = self.db.get_user(query.from_user.id)
        if not user:
            await query.message.edit_text("Доступно только зарегистрированным пользователям.")
            return
        if user["status"] != "active" or self._is_access_expired(user):
            if self._is_access_expired(user):
                await query.message.edit_text(
                    "Ваш срок доступа к VPN истёк ⏰. Для продления свяжитесь с администратором."
                )
            else:
                await query.message.edit_text(self._status_hint(user["status"]))
            return
        action = query.data.split(":", 1)[1]
        if action == "close":
            await query.message.edit_text(
                "Меню скрыто. Кнопка ниже вернёт его в любой момент.",
                reply_markup=self._menu_open_kb(),
            )
            context.user_data.pop(_MENU_MSG, None)
            context.user_data[_MENU_OPEN_MSG] = query.message.message_id
        elif action == "open":
            await self._show_menu(context, query.message.chat_id, user)
        elif action == "root":
            await query.message.edit_text(
                self._main_menu_text(user),
                parse_mode="HTML",
                reply_markup=self._main_menu_kb(user),
            )
        elif action == "account":
            await self._menu_account(query, user)
        elif action == "peers":
            await self._send_peers_list(query, user)
        elif action == "admin":
            if user["role"] != ROLE_ADMIN:
                await query.message.edit_text("Доступно только администратору.")
                return
            await query.message.edit_text(
                _card("🛠 АДМИНИСТРИРОВАНИЕ\n" + _CARD_SEP + "\n\nВыберите раздел ниже."),
                parse_mode="HTML",
                reply_markup=self._admin_menu_kb(),
            )
        elif action == "help":
            await query.message.edit_text(
                self._help_text(),
                parse_mode="HTML",
                reply_markup=self._back_kb(),
            )

    def _is_access_expired(self, user: dict) -> bool:
        raw = user.get("access_until")
        if not raw:
            return False
        try:
            dt = datetime.strptime(raw, _DATE_FMT)
        except ValueError:
            return False
        return dt <= datetime.now()

    def _access_label(self, user: dict) -> str:
        raw = user.get("access_until")
        if not raw:
            return "⏰ Доступ: без ограничений"
        try:
            dt = datetime.strptime(raw, _DATE_FMT)
        except ValueError:
            return f"⏰ Доступ до: {raw}"
        label = dt.strftime("%d.%m.%Y %H:%M")
        if user["status"] == "active":
            days = (dt - datetime.now()).days
            if days < 0:
                label += " (истёк)"
            elif days == 0:
                label += " (сегодня)"
            else:
                label += f" (осталось {days} дн.)"
        return f"⏰ Доступ до: {label}"

    async def _account_text(self, user: dict) -> str:
        srv = await self.mt.get_wireguard_interface(user["wg_interface"])
        pubkey = srv.get("public-key", "") if srv else ""
        role = "🛡 Администратор" if user["role"] == ROLE_ADMIN else "🙂 Пользователь"
        return _card(
            f"👤 МОЙ ПРОФИЛЬ\n"
            f"{_CARD_SEP}\n"
            f"Имя: {user['full_name']}\n"
            f"Username: @{user['username'] or '-'}\n"
            f"Роль: {role}\n\n"
            f"🌐 Интерфейс: {user['wg_interface']}\n"
            f"📡 Подсеть: {user['subnet']}\n"
            f"🔌 Порт: {user['listen_port']}\n"
            f"📍 Endpoint: {self.mt_settings['public_ip']}:{user['listen_port']}\n"
            f"🔑 Публичный ключ: {pubkey}\n"
            f"{self._access_label(user)}"
        )

    async def _menu_account(self, query, user: dict) -> None:
        try:
            text = await self._account_text(user)
        except RouterOSError as exc:
            await query.message.edit_text(f"Ошибка: {exc}", reply_markup=self._back_kb())
            return
        await query.message.edit_text(text, parse_mode="HTML", reply_markup=self._back_kb())

    def _admin_menu_kb(self) -> InlineKeyboardMarkup:
        kb = [
            [
                InlineKeyboardButton("📨 Заявки", callback_data="admin:pending"),
                InlineKeyboardButton("👥 Пользователи", callback_data="admin:users"),
            ],
            [
                InlineKeyboardButton("⚙️ Настройки роутера", callback_data="admin:settings"),
                InlineKeyboardButton("🤖 Настройки бота", callback_data="admin:bot_settings"),
            ],
            [
                InlineKeyboardButton("🔍 Проверка настроек", callback_data="admin:sync"),
                InlineKeyboardButton("📢 Рассылка", callback_data="admin:broadcast"),
            ],
            [InlineKeyboardButton("🔙 Назад", callback_data="menu:root")],
        ]
        return InlineKeyboardMarkup(kb)

    def _user_choice_kb(self, users: list[dict], action: str = "apeers") -> InlineKeyboardMarkup:
        kb = [
            [InlineKeyboardButton(
                f"{_STATUS_ICONS.get(u['status'], u['status'])} @{u['username'] or '-'} ({u['full_name']})",
                callback_data=f"{action}:{u['telegram_id']}",
            )]
            for u in users
        ]
        kb.append([InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")])
        return InlineKeyboardMarkup(kb)

    async def on_admin_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        await query.message.edit_text(
            _card("🛠 АДМИНИСТРИРОВАНИЕ\n" + _CARD_SEP + "\n\nВыберите раздел ниже."),
            parse_mode="HTML",
            reply_markup=self._admin_menu_kb(),
        )

    async def on_admin_pending(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        old_notify = context.application.user_data.get(query.from_user.id, {}).pop(
            _ADMIN_NOTIFY_MSG, None
        )
        if old_notify and old_notify != query.message.message_id:
            await self._try_delete_message(context, query.from_user.id, old_notify)
        pending = self.db.list_pending()
        if not pending:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")]]
            )
            await query.message.edit_text(
                _card("📨 ЗАЯВКИ\n" + _CARD_SEP + "\n\nНет ожидающих заявок."),
                parse_mode="HTML",
                reply_markup=kb,
            )
            return
        await self._render_pending_request(context, query, pending[0])

    async def _render_pending_request(self, context, query, req: dict) -> None:
        """Show one request with approve/reject and prev/next navigation."""
        pending = self.db.list_pending()
        total = len(pending)
        uid = req["telegram_id"]
        try:
            idx = next(i for i, p in enumerate(pending) if p["telegram_id"] == uid)
        except StopIteration:
            idx = 0
        kb = [
            [
                InlineKeyboardButton("✅ Одобрить", callback_data=f"reg:approve:{uid}"),
                InlineKeyboardButton("❌ Отклонить", callback_data=f"reg:reject:{uid}"),
            ]
        ]
        if total > 1:
            prev_uid = pending[(idx - 1) % total]["telegram_id"]
            next_uid = pending[(idx + 1) % total]["telegram_id"]
            kb.append(
                [
                    InlineKeyboardButton("◀", callback_data=f"admin:req:prev:{uid}"),
                    InlineKeyboardButton(f"{idx + 1}/{total}", callback_data=f"admin:req:noop:{uid}"),
                    InlineKeyboardButton("▶", callback_data=f"admin:req:next:{uid}"),
                ]
            )
        kb.append([InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")])
        title = f"👤 ЗАЯВКА ({idx + 1} из {total})" if total > 1 else "👤 ЗАЯВКА"
        await query.message.edit_text(
            _card(
                f"{title}\n{_CARD_SEP}\n"
                f"@{req['username'] or '-'}\n"
                f"Имя: {req['full_name']}\n"
                f"🕐 {req['created_at']}"
            ),
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup(kb),
        )
        context.application.user_data.setdefault(query.from_user.id, {})[
            _ADMIN_NOTIFY_MSG
        ] = query.message.message_id

    async def on_admin_req_nav(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        _, _, direction, uid_str = query.data.split(":", 3)
        if direction == "noop":
            return
        pending = self.db.list_pending()
        if not pending:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")]]
            )
            await query.message.edit_text(
                _card("📨 ЗАЯВКИ\n" + _CARD_SEP + "\n\nНет ожидающих заявок."),
                parse_mode="HTML",
                reply_markup=kb,
            )
            return
        try:
            idx = next(i for i, p in enumerate(pending) if p["telegram_id"] == int(uid_str))
        except StopIteration:
            idx = 0
        step = 1 if direction == "next" else -1
        await self._render_pending_request(context, query, pending[(idx + step) % len(pending)])

    async def on_admin_users(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        await self._show_admin_users(query)

    async def on_admin_user_peers(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        _, tg = query.data.split(":", 1)
        owner = self.db.get_user(int(tg))
        if not owner:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")]]
            )
            await query.message.edit_text("Пользователь не найден.", reply_markup=kb)
            return
        await self._send_owner_peers(query, owner, back="admin:users")

    # ----------------------------------------------------- user profile (admin)
    def _user_profile_text(self, user: dict) -> str:
        peers = self.db.count_peers(user["telegram_id"])
        return _card(
            f"👤 ПОЛЬЗОВАТЕЛЬ\n"
            f"{_CARD_SEP}\n"
            f"@{user['username'] or '-'}\n"
            f"Имя: {user['full_name']}\n"
            f"Роль: {user['role']}\n"
            f"Статус: {_STATUS_ICONS.get(user['status'], user['status'])}\n"
            f"🌐 Интерфейс: {user['wg_interface'] or '-'}\n"
            f"📡 Подсеть: {user['subnet'] or '-'}\n"
            f"🔌 Порт: {user['listen_port'] or '-'}\n"
            f"📍 Endpoint: {self.mt_settings['public_ip']}:{user['listen_port']}\n"
            f"📎 Пиров: {peers}\n"
            f"{self._access_label(user)}\n"
            f"🕐 Регистрация: {user['created_at']}"
        )

    def _user_profile_kb(self, user: dict) -> InlineKeyboardMarkup:
        tg = user["telegram_id"]
        block_lbl = (
            "✅ Разблокировать" if user["status"] == "blocked" else "🚫 Заблокировать"
        )
        block_cb = (
            f"uunblock:{tg}" if user["status"] == "blocked" else f"ublock:{tg}"
        )
        kb = [
            [InlineKeyboardButton("🔍 Пиры", callback_data=f"apeers:{tg}")],
            [
                InlineKeyboardButton(block_lbl, callback_data=block_cb),
                InlineKeyboardButton("✏️ Переименовать", callback_data=f"urename:{tg}"),
            ],
            [
                InlineKeyboardButton("⏰ Срок доступа", callback_data=f"uaccess:{tg}"),
                InlineKeyboardButton("📅 Дата регистрации", callback_data=f"ucdate:{tg}"),
            ],
            [InlineKeyboardButton("🗑 Удалить", callback_data=f"udelete:{tg}")],
            [InlineKeyboardButton("🔙 Назад", callback_data="admin:users")],
        ]
        if user.get("access_until"):
            kb[2].append(
                InlineKeyboardButton("⏱ Снять срок", callback_data=f"uaccess_clear:{tg}")
            )
        return InlineKeyboardMarkup(kb)

    async def on_user_view(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        _, tg = query.data.split(":", 1)
        user = self.db.get_user(int(tg))
        if not user:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data="admin:users")]]
            )
            await query.message.edit_text("Пользователь не найден.", reply_markup=kb)
            return
        await query.message.edit_text(
            self._user_profile_text(user),
            parse_mode="HTML",
            reply_markup=self._user_profile_kb(user),
        )

    async def _block_user(
        self,
        admin: dict | None,
        user: dict,
        bot,
        notify_text: str | None = None,
        silent: bool = False,
    ) -> None:
        """Disable interface + all peers, remember each peer's prior state."""
        if user["status"] != "active":
            return
        iface = user["wg_interface"]
        if iface:
            peers = await self.mt.get_peers(iface)
            for peer in peers:
                rec = self._find_db_peer(peer[".id"], peer.get("name", ""))
                was = 1 if self._is_disabled(peer) else 0
                if rec:
                    self.db.update_peer(rec["router_id"], was_disabled=was)
                await self.mt.set_peer_disabled(peer[".id"], True)
            await self.mt.set_interface_disabled(iface, True)
        self.db.update_user(
            user["telegram_id"],
            status="blocked",
            decided_by=admin["telegram_id"] if admin else None,
        )
        if silent:
            return
        text = notify_text or "Ваш аккаунт заблокирован администратором."
        try:
            await bot.send_message(user["telegram_id"], text)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot notify user %s: %s", user["telegram_id"], exc)

    async def _unblock_user(self, admin: dict, user: dict, context) -> None:
        """Enable interface, restore each peer's prior disabled state."""
        if user["status"] != "blocked":
            return
        iface = user["wg_interface"]
        if iface:
            peers = await self.mt.get_peers(iface)
            for peer in peers:
                rec = self._find_db_peer(peer[".id"], peer.get("name", ""))
                restore = bool(rec and rec.get("was_disabled")) if rec else False
                await self.mt.set_peer_disabled(peer[".id"], restore)
                if rec:
                    self.db.update_peer(rec["router_id"], was_disabled=0)
            await self.mt.set_interface_disabled(iface, False)
        self.db.update_user(
            user["telegram_id"],
            status="active",
            decided_by=admin["telegram_id"],
            access_until=None,
        )
        try:
            await context.bot.send_message(
                user["telegram_id"], "Ваш аккаунт разблокирован. Добро пожаловать! 🎉"
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot notify user %s: %s", user["telegram_id"], exc)

    async def on_user_block(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        _, tg = query.data.split(":", 1)
        tg = int(tg)
        if tg == admin["telegram_id"]:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data=f"uview:{tg}")]]
            )
            await query.message.edit_text("Нельзя заблокировать самого себя.", reply_markup=kb)
            return
        user = self.db.get_user(tg)
        if not user:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data="admin:users")]]
            )
            await query.message.edit_text("Пользователь не найден.", reply_markup=kb)
            return
        try:
            await self._block_user(admin, user, context.bot)
        except RouterOSError as exc:
            await query.message.edit_text(f"Ошибка при блокировке: {exc}")
            return
        user = self.db.get_user(tg)
        await query.message.edit_text(
            self._user_profile_text(user),
            parse_mode="HTML",
            reply_markup=self._user_profile_kb(user),
        )

    async def on_user_unblock(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        _, tg = query.data.split(":", 1)
        user = self.db.get_user(int(tg))
        if not user:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data="admin:users")]]
            )
            await query.message.edit_text("Пользователь не найден.", reply_markup=kb)
            return
        try:
            await self._unblock_user(admin, user, context)
        except RouterOSError as exc:
            await query.message.edit_text(f"Ошибка при разблокировке: {exc}")
            return
        user = self.db.get_user(int(tg))
        await query.message.edit_text(
            self._user_profile_text(user),
            parse_mode="HTML",
            reply_markup=self._user_profile_kb(user),
        )

    async def on_user_rename(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        _, tg = query.data.split(":", 1)
        user = self.db.get_user(int(tg))
        if not user:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data="admin:users")]]
            )
            await query.message.edit_text("Пользователь не найден.", reply_markup=kb)
            return
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="cancel")]])
        prompt = await query.message.reply_text(
            "Введите новое имя пользователя:", reply_markup=kb
        )
        context.user_data[_AWAITING_SETTING] = {
            "action": "rename_user",
            "telegram_id": int(tg),
            "profile_msg_id": query.message.message_id,
            "prompt_chat_id": prompt.chat_id,
            "prompt_msg_id": prompt.message_id,
        }

    async def on_user_access(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        _, tg = query.data.split(":", 1)
        user = self.db.get_user(int(tg))
        if not user:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data="admin:users")]]
            )
            await query.message.edit_text("Пользователь не найден.", reply_markup=kb)
            return
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="cancel")]])
        prompt = await query.message.reply_text(
            "Введите дату и время, когда отключится доступ к VPN, "
            "в формате ДД.ММ.ГГГГ ЧЧ:ММ (например, 31.12.2026 23:59).\n"
            "Время можно опустить — доступ отключится в 00:00.",
            reply_markup=kb,
        )
        context.user_data[_AWAITING_SETTING] = {
            "action": "set_access",
            "telegram_id": int(tg),
            "profile_msg_id": query.message.message_id,
            "prompt_chat_id": prompt.chat_id,
            "prompt_msg_id": prompt.message_id,
        }

    async def on_user_access_clear(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        _, tg = query.data.split(":", 1)
        tg = int(tg)
        user = self.db.get_user(tg)
        if not user:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data="admin:users")]]
            )
            await query.message.edit_text("Пользователь не найден.", reply_markup=kb)
            return
        self.db.update_user(tg, access_until=None)
        user = self.db.get_user(tg)
        await query.message.edit_text(
            self._user_profile_text(user),
            parse_mode="HTML",
            reply_markup=self._user_profile_kb(user),
        )

    async def on_user_created_at(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        _, tg = query.data.split(":", 1)
        tg_id = int(tg)
        user = self.db.get_user(tg_id)
        if not user:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data="admin:users")]]
            )
            await query.message.edit_text("Пользователь не найден.", reply_markup=kb)
            return
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data=f"uview:{tg_id}")]])
        prompt = await query.message.reply_text(
            f"Текущая дата регистрации: <code>{user['created_at']}</code>\n"
            "Введите новую дату в формате ДД.ММ.ГГГГ или ДД.ММ.ГГГГ ЧЧ:ММ",
            parse_mode="HTML",
            reply_markup=kb,
        )
        context.user_data[_AWAITING_SETTING] = {
            "action": "set_created_at",
            "telegram_id": tg_id,
            "profile_msg_id": query.message.message_id,
            "prompt_chat_id": prompt.chat_id,
            "prompt_msg_id": prompt.message_id,
        }

    async def on_user_delete(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        _, tg = query.data.split(":", 1)
        tg = int(tg)
        if tg == admin["telegram_id"]:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data=f"uview:{tg}")]]
            )
            await query.message.edit_text("Нельзя удалить самого себя.", reply_markup=kb)
            return
        user = self.db.get_user(tg)
        if not user:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data="admin:users")]]
            )
            await query.message.edit_text("Пользователь не найден.", reply_markup=kb)
            return
        kb = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton("🗑 Да, удалить", callback_data=f"udelete_conf:{tg}"),
                    InlineKeyboardButton("Отмена", callback_data=f"uview:{tg}"),
                ]
            ]
        )
        await query.message.edit_text(
            "Удалить пользователя? Будут удалены его интерфейс, пиры и firewall-правила с роутера.",
            reply_markup=kb,
        )

    async def _delete_user_router(self, user: dict) -> None:
        iface = user.get("wg_interface")
        if not iface:
            return
        for peer in await self.mt.get_peers(iface):
            await self.mt.delete_peer(peer[".id"])
        await self.mt.remove_ip_address(iface)
        for rule in await self.mt.get_firewall_rules():
            if (rule.get("comment") or "").startswith(f"wg-{iface}-"):
                await self.mt.delete_firewall_rule(rule[".id"])
        for rule in await self.mt.get_firewall_nat_rules():
            if (rule.get("comment") or "").startswith(f"wg-{iface}-"):
                await self.mt.delete_firewall_nat_rule(rule[".id"])
        if user.get("subnet"):
            await self._remove_wg_subnet(user["subnet"])
        try:
            await self._remove_lan_member(iface)
        except RouterOSError as exc:
            logger.warning("Cannot remove %s from LAN: %s", iface, exc)
        info = await self.mt.get_wireguard_interface(iface)
        if info:
            await self.mt.delete_wireguard_interface(info[".id"])

    async def on_user_delete_confirm(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        _, tg = query.data.split(":", 1)
        tg = int(tg)
        if tg == admin["telegram_id"]:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data=f"uview:{tg}")]]
            )
            await query.message.edit_text("Нельзя удалить самого себя.", reply_markup=kb)
            return
        user = self.db.get_user(tg)
        if not user:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data="admin:users")]]
            )
            await query.message.edit_text("Пользователь не найден.", reply_markup=kb)
            return
        try:
            await self._delete_user_router(user)
        except RouterOSError as exc:
            await query.message.edit_text(f"Ошибка удаления с роутера: {exc}")
            return
        self.db.delete_peers_for_owner(tg)
        self.db.delete_user(tg)
        try:
            await context.bot.send_message(
                tg, "Ваш аккаунт был удалён администратором."
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot notify user %s: %s", tg, exc)
        await self._show_admin_users(query)

    # --------------------------------------------------------- router settings
    def _settings_text(self) -> str:
        s = self.mt_settings
        return _card(
            "⚙️ НАСТРОЙКИ РОУТЕРА\n"
            f"{_CARD_SEP}\n"
            f"{_MT_LABELS['host']}: {s['host'] or '—'}\n"
            f"{_MT_LABELS['user']}: {s['user'] or '—'}\n"
            f"{_MT_LABELS['pass']}: {'••••••' if s['pass'] else '—'}\n"
            f"{_MT_LABELS['public_ip']}: {s['public_ip'] or '—'}\n"
            f"🔒 TLS verify: {'да' if self._mt_bool('tls') else 'нет'}\n"
            f"🔐 SSL: {'да' if self._mt_bool('ssl') else 'нет'}"
        )

    def _settings_kb(self) -> InlineKeyboardMarkup:
        kb = [
            [
                InlineKeyboardButton(f"✏️ {_MT_LABELS['host']}", callback_data="set:host"),
                InlineKeyboardButton(f"✏️ {_MT_LABELS['user']}", callback_data="set:user"),
            ],
            [
                InlineKeyboardButton(f"✏️ {_MT_LABELS['pass']}", callback_data="set:pass"),
                InlineKeyboardButton(
                    f"✏️ {_MT_LABELS['public_ip']}", callback_data="set:ip"
                ),
            ],
            [
                InlineKeyboardButton(
                    "🔒 TLS: да" if self._mt_bool("tls") else "🔒 TLS: нет",
                    callback_data="set:tls",
                ),
                InlineKeyboardButton(
                    "🔐 SSL: да" if self._mt_bool("ssl") else "🔐 SSL: нет",
                    callback_data="set:ssl",
                ),
            ],
            [InlineKeyboardButton("🧪 Проверить подключение", callback_data="set:test")],
            [InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")],
        ]
        return InlineKeyboardMarkup(kb)

    async def _send_settings(self, query) -> None:
        await query.message.edit_text(
            self._settings_text(),
            parse_mode="HTML",
            reply_markup=self._settings_kb(),
        )

    async def on_admin_settings(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        await self._send_settings(query)

    async def on_setting(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        key = query.data.split(":", 1)[1]
        if key in ("tls", "ssl"):
            current = self._mt_bool(key)
            self.db.set_setting(key, "false" if current else "true")
            self.mt_settings[key] = "false" if current else "true"
            await self._reconfigure_mt()
            await self._send_settings(query)
            return
        if key == "notify_deadline":
            current = self.db.get_setting("notify_deadline") == "true"
            self.db.set_setting("notify_deadline", "false" if current else "true")
            await self._send_bot_settings(query)
            return
        if key == "test":
            await query.message.edit_text("🧪 Проверяю подключение…")
            if not self.mt_ready():
                await query.message.edit_text(
                    "❌ Не все настройки заполнены (MT_HOST, MT_USER, MT_PASS, MT_PUBLIC_IP).",
                    reply_markup=self._settings_kb(),
                )
                return
            try:
                ok = await self.mt.ping()
            except Exception as exc:  # noqa: BLE001
                await query.message.edit_text(f"❌ Ошибка: {exc}", reply_markup=self._settings_kb())
                return
            text = self._settings_text() + f"\n\n{'✅' if ok else '❌'} Результат ping: {'успех' if ok else 'недоступен'}"
            await query.message.edit_text(text, parse_mode="HTML", reply_markup=self._settings_kb())
            return
        if key not in ("host", "user", "pass", "ip"):
            return
        context.user_data[_AWAITING_SETTING] = {
            "action": "set_mt",
            "key": key,
            "settings_msg_id": query.message.message_id,
        }
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="cancel")]])
        await query.message.reply_text(
            f"Введите новое значение: {_MT_LABELS[key]}", reply_markup=kb
        )

    async def _reconfigure_mt(self) -> None:
        await self.mt.reconfigure(
            host=self.mt_settings["host"],
            user=self.mt_settings["user"],
            password=self.mt_settings["pass"],
            verify_tls=self._mt_bool("tls"),
            use_ssl=self._mt_bool("ssl"),
        )

    # ------------------------------------------------------------- bot settings
    def _bot_settings_text(self) -> str:
        deadline = (
            "вкл" if self.db.get_setting("notify_deadline") == "true" else "выкл"
        )
        return _card(
            "🤖 НАСТРОЙКИ БОТА\n"
            f"{_CARD_SEP}\n"
            f"🔔 Уведомление о блокировке: {deadline}"
        )

    def _bot_settings_kb(self) -> InlineKeyboardMarkup:
        kb = [
            [
                InlineKeyboardButton(
                    "🔔 Уведомление о блокировке: вкл"
                    if self.db.get_setting("notify_deadline") == "true"
                    else "🔕 Уведомление о блокировке: выкл",
                    callback_data="set:notify_deadline",
                )
            ],
            [InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")],
        ]
        return InlineKeyboardMarkup(kb)

    async def _send_bot_settings(self, query) -> None:
        await query.message.edit_text(
            self._bot_settings_text(),
            parse_mode="HTML",
            reply_markup=self._bot_settings_kb(),
        )

    async def on_admin_bot_settings(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        await self._send_bot_settings(query)

    # ----------------------------------------------------------- synchronization
    async def _fetch_router_wg_state(self, managed_ifaces: set[str] | None = None) -> dict:
        """Return {interface_name: {listen_port, mtu, gateway_ips, nat_masquerade,
        peers: [{name, public_key, allowed_address, disabled,
        persistent_keepalive}]}}.

        If *managed_ifaces* is provided only interfaces present in that set are
        returned (others are ignored).
        """
        ifaces = await self.mt.get_wireguard_interfaces()
        result: dict[str, dict] = {}
        all_nat = await self.mt.get_firewall_nat_rules()
        for iface in ifaces:
            name = iface.get("name", "")
            if not name.startswith("wg"):
                continue
            if managed_ifaces is not None and name not in managed_ifaces:
                continue
            peers_data = await self.mt.get_peers(name)
            peers = []
            for p in peers_data:
                peers.append({
                    "router_id": p.get(".id", ""),
                    "name": p.get("name", ""),
                    "public_key": p.get("public-key", ""),
                    "allowed_address": p.get("allowed-address", ""),
                    "disabled": p.get("disabled", "false") == "true",
                    "persistent_keepalive": _parse_int(p.get("persistent-keepalive"), 0),
                })
            addrs = await self.mt.get_ip_addresses(name)
            gateway_ips = [a.get("address", "") for a in addrs]
            nat_comment = f"wg-{name}-nat"
            nat_masq = any(
                r.get("action") == "masquerade"
                and (
                    r.get("comment") == nat_comment
                    or r.get("out-interface") == name
                    or (r.get("src-address-list") == _WG_SUBNETS_LIST)
                )
                for r in all_nat
            )
            result[name] = {
                "listen_port": _parse_int(iface.get("listen-port"), 0),
                "mtu": _parse_int(iface.get("mtu"), 1420),
                "gateway_ips": gateway_ips,
                "nat_masquerade": nat_masq,
                "peers": peers,
            }
        return result

    def _managed_interfaces(self) -> set[str]:
        """Return set of interface names that are registered in the DB."""
        return {
            u["wg_interface"]
            for u in self.db.list_users()
            if u.get("wg_interface")
        }

    def _fetch_db_wg_state(self) -> dict:
        """Return {wg_interface: {listen_port, subnet, user_id, wg_mtu,
        wg_keepalive, peers: [{name, router_id, ip, allowed_ips, disabled}]}}."""
        result: dict[str, dict] = {}
        for u in self.db.list_users():
            iface = u.get("wg_interface")
            if not iface:
                continue
            db_peers = self.db.list_peers(u["telegram_id"])
            peers = []
            for p in db_peers:
                peers.append({
                    "name": p.get("name", ""),
                    "router_id": p.get("router_id", ""),
                    "ip": p.get("ip", ""),
                    "allowed_ips": p.get("allowed_ips", "0.0.0.0/0"),
                    "disabled": bool(p.get("was_disabled", 0)),
                })
            result[iface] = {
                "listen_port": u.get("listen_port"),
                "subnet": u.get("subnet"),
                "user_id": u["telegram_id"],
                "wg_mtu": self.cfg.WG_MTU,
                "wg_keepalive": self.cfg.WG_PERSISTENT_KEEPALIVE,
                "peers": peers,
            }
        return result

    def _compare_wg_state(self, router: dict, db: dict) -> dict:
        """Compare router and DB states. Returns summary dict."""
        summary = {
            "only_router": [],
            "only_db": [],
            "both": [],
            "ok": [],
        }
        all_names = sorted(set(list(router.keys()) + list(db.keys())))
        for name in all_names:
            r = router.get(name)
            d = db.get(name)
            if r and not d:
                summary["only_router"].append(name)
            elif d and not r:
                summary["only_db"].append(name)
            else:
                diffs = []
                if r["listen_port"] != d["listen_port"]:
                    diffs.append(f"listen_port: роутер={r['listen_port']} | база={d['listen_port']}")
                if r["mtu"] != d["wg_mtu"]:
                    diffs.append(f"MTU: роутер={r['mtu']} | база={d['wg_mtu']}")
                if not r["nat_masquerade"]:
                    diffs.append("NAT masquerade: отсутствует на роутере")
                # Gateway IP check: interface should have an IP from its subnet
                if d.get("subnet") and not r["gateway_ips"]:
                    diffs.append(f"IP-адрес: не назначен на интерфейсе {name} (ожидается из подсети {d['subnet']})")
                # Per-peer comparison
                r_names = {p["name"] for p in r["peers"]}
                d_names = {p["name"] for p in d["peers"]}
                for pname in sorted(r_names - d_names):
                    diffs.append(f"пир '{pname}' — только на роутере")
                for pname in sorted(d_names - r_names):
                    diffs.append(f"пир '{pname}' — только в базе")
                for pname in sorted(r_names & d_names):
                    rp = next(p for p in r["peers"] if p["name"] == pname)
                    dp = next(p for p in d["peers"] if p["name"] == pname)
                    if rp["disabled"] != dp["disabled"]:
                        state_r = "выкл" if rp["disabled"] else "вкл"
                        state_d = "выкл" if dp["disabled"] else "вкл"
                        diffs.append(f"пир '{pname}': роутер={state_r} | база={state_d}")
                    if rp["allowed_address"] != dp["allowed_ips"]:
                        diffs.append(
                            f"пир '{pname}' allowed-ips: "
                            f"роутер={rp['allowed_address']} | база={dp['allowed_ips']}"
                        )
                    if rp["persistent_keepalive"] != d["wg_keepalive"]:
                        diffs.append(
                            f"пир '{pname}' keepalive: "
                            f"роутер={rp['persistent_keepalive']}с | база={d['wg_keepalive']}с"
                        )
                if diffs:
                    summary["both"].append({"name": name, "diffs": diffs})
                else:
                    summary["ok"].append(name)
        return summary

    def _sync_text(self, summary: dict) -> str:
        lines = ["🔄 СИНХРОНИЗАЦИЯ\n" + _CARD_SEP + "\n"]
        total_diffs = len(summary["only_router"]) + len(summary["only_db"]) + len(summary["both"])
        if total_diffs == 0:
            lines.append("✅ Всё синхронизировано, расхождений нет.")
        else:
            if summary["only_router"]:
                lines.append("📥 Только на роутере (нет в базе):")
                for n in summary["only_router"]:
                    lines.append(f"  • {n}")
                lines.append("")
            if summary["only_db"]:
                lines.append("📤 Только в базе (нет на роутере):")
                for n in summary["only_db"]:
                    lines.append(f"  • {n}")
                lines.append("")
            if summary["both"]:
                lines.append("⚡ Расхождения:")
                for item in summary["both"]:
                    lines.append(f"  {item['name']}:")
                    for d in item["diffs"]:
                        lines.append(f"    – {d}")
                lines.append("")
            lines.append(f"Итого расхождений: {total_diffs}")
        if summary["ok"]:
            lines.append(f"✅ Совпадают: {', '.join(summary['ok'])}")
        return _card("\n".join(lines))

    def _sync_kb(self, summary: dict) -> InlineKeyboardMarkup:
        total = len(summary["only_router"]) + len(summary["only_db"]) + len(summary["both"])
        btns = []
        if total > 0:
            btns.append([
                InlineKeyboardButton("📥 Роутер → База", callback_data="sync:to_db"),
                InlineKeyboardButton("📤 База → Роутер", callback_data="sync:to_router"),
            ])
        btns.append([InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")])
        return InlineKeyboardMarkup(btns)

    async def _do_sync(self, query, direction: str) -> None:
        """Execute sync in the given direction ('to_db' or 'to_router')."""
        await query.message.edit_text("🔄 Выполняю синхронизацию…")
        try:
            router = await self._fetch_router_wg_state(self._managed_interfaces())
        except RouterOSError as exc:
            await query.message.edit_text(
                f"❌ Ошибка подключения к роутеру: {exc}",
                reply_markup=self._sync_kb({"only_router": [], "only_db": [], "both": [], "ok": []}),
            )
            return
        db = self._fetch_db_wg_state()
        report: list[str] = []
        if direction == "to_db":
            # Import from router to DB
            for name, rdata in router.items():
                user_row = self.db.get_user_by_interface(name)
                if not user_row:
                    report.append(f"⏭ {name} — нет пользователя в базе, пропущен")
                    continue
                if user_row.get("listen_port") != rdata["listen_port"]:
                    self.db.update_user(user_row["telegram_id"], listen_port=rdata["listen_port"])
                    report.append(f"✅ {name} — listen_port обновлён → {rdata['listen_port']}")
                else:
                    report.append(f"✅ {name} — listen_port совпадает")
                existing_peers = {p["name"]: p for p in self.db.list_peers(user_row["telegram_id"])}
                for rp in rdata["peers"]:
                    if rp["name"] in existing_peers:
                        ep = existing_peers[rp["name"]]
                        ep_rid = ep["router_id"]
                        # Fix stale router_id (old imports stored name instead of .id)
                        actual_rid = rp.get("router_id", "")
                        if actual_rid and ep_rid != actual_rid:
                            self.db.update_peer(ep_rid, router_id=actual_rid)
                            report.append(f"  ↻ пир '{rp['name']}' — router_id исправлен → {actual_rid}")
                            ep_rid = actual_rid
                        new_disabled = 1 if rp["disabled"] else 0
                        if ep.get("was_disabled", 0) != new_disabled:
                            self.db.update_peer(ep_rid, was_disabled=new_disabled)
                            report.append(f"  ↻ пир '{rp['name']}' — disabled обновлён")
                        router_allowed = rp.get("allowed_address", "")
                        db_allowed = ep.get("allowed_ips", "0.0.0.0/0")
                        if router_allowed and router_allowed != db_allowed:
                            self.db.update_peer(ep_rid, allowed_ips=router_allowed)
                            report.append(f"  ↻ пир '{rp['name']}' — allowed-ips → {router_allowed}")
                        # Import public_key from router if missing in DB
                        if not ep.get("public_key") and rp.get("public_key"):
                            self.db.update_peer(ep_rid, public_key=rp["public_key"])
                    else:
                        # Import peer from router into DB
                        rp_ip = rp.get("allowed_address", "")
                        self.db.add_peer(
                            router_id=rp.get("router_id", rp["name"]),
                            owner_id=user_row["telegram_id"],
                            name=rp["name"],
                            private_key="",
                            ip=rp_ip,
                            allowed_ips=rp_ip,
                            is_static=1,
                            public_key=rp.get("public_key", ""),
                        )
                        report.append(f"  ✅ пир '{rp['name']}' — импортирован в базу")
        else:
            # Apply from DB to router
            for name, ddata in db.items():
                if name not in router:
                    if not self.mt_ready():
                        report.append(f"❌ {name} — роутер недоступен, пропущен")
                        continue
                    try:
                        await self.mt.create_wireguard_interface(name, ddata["listen_port"], self.cfg.WG_MTU)
                        report.append(f"✅ {name} — создан на роутере (порт {ddata['listen_port']})")
                        await self._ensure_lan_member(name)
                    except RouterOSError as exc:
                        report.append(f"❌ {name} — ошибка создания: {exc}")
                        continue
                else:
                    rport = router[name]["listen_port"]
                    if rport != ddata["listen_port"]:
                        try:
                            await self.mt.update_wireguard_interface(name, **{"listen-port": ddata["listen_port"]})
                            report.append(f"✅ {name} — listen_port → {ddata['listen_port']}")
                        except RouterOSError as exc:
                            report.append(f"❌ {name} — ошибка обновления порта: {exc}")
                    else:
                        report.append(f"✅ {name} — порт совпадает")
                    r_mtu = router[name]["mtu"]
                    if r_mtu != ddata["wg_mtu"]:
                        try:
                            await self.mt.update_wireguard_interface(name, mtu=ddata["wg_mtu"])
                            report.append(f"✅ {name} — MTU → {ddata['wg_mtu']}")
                        except RouterOSError as exc:
                            report.append(f"❌ {name} — ошибка MTU: {exc}")
                    if ddata.get("subnet") and not router[name]["gateway_ips"]:
                        subnet_host = ddata["subnet"].rsplit(".", 1)[0] + ".1/24"
                        try:
                            await self.mt.add_ip_address(subnet_host, name, comment=f"wg-bot {name}")
                            report.append(f"✅ {name} — IP-адрес {subnet_host} назначен")
                        except RouterOSError as exc:
                            report.append(f"❌ {name} — ошибка назначения IP: {exc}")
                    if not router[name]["nat_masquerade"]:
                        try:
                            await self.mt.add_firewall_nat_rule(
                                comment=f"wg-{name}-nat",
                                chain="srcnat",
                                action="masquerade",
                                **{"out-interface": name},
                            )
                            report.append(f"✅ {name} — NAT masquerade создан")
                        except RouterOSError as exc:
                            report.append(f"❌ {name} — ошибка NAT: {exc}")
                if name in router:
                    rpeer_names = {p["name"]: p for p in router[name]["peers"]}
                    for dp in ddata["peers"]:
                        if dp["name"] in rpeer_names:
                            rp = rpeer_names[dp["name"]]
                            if rp["disabled"] != dp["disabled"]:
                                try:
                                    rpeers = await self.mt.get_peers(name)
                                    for rpeer in rpeers:
                                        if rpeer.get("name") == dp["name"]:
                                            await self.mt.set_peer_disabled(rpeer[".id"], dp["disabled"])
                                            state = "выкл" if dp["disabled"] else "вкл"
                                            report.append(f"  ↻ пир '{dp['name']}' → {state}")
                                            break
                                except RouterOSError as exc:
                                    report.append(f"  ❌ пир '{dp['name']}': {exc}")
                            if rp["persistent_keepalive"] != ddata["wg_keepalive"]:
                                try:
                                    rpeers = await self.mt.get_peers(name)
                                    for rpeer in rpeers:
                                        if rpeer.get("name") == dp["name"]:
                                            await self.mt.update_peer(rpeer[".id"], persistent_keepalive=ddata["wg_keepalive"])
                                            report.append(f"  ↻ пир '{dp['name']}' keepalive → {ddata['wg_keepalive']}с")
                                            break
                                except RouterOSError as exc:
                                    report.append(f"  ❌ пир '{dp['name']}' keepalive: {exc}")
                            if rp["allowed_address"] != dp["allowed_ips"]:
                                try:
                                    rpeers = await self.mt.get_peers(name)
                                    for rpeer in rpeers:
                                        if rpeer.get("name") == dp["name"]:
                                            await self.mt.update_peer(rpeer[".id"], **{"allowed-address": dp["allowed_ips"]})
                                            report.append(f"  ↻ пир '{dp['name']}' allowed-ips → {dp['allowed_ips']}")
                                            break
                                except RouterOSError as exc:
                                    report.append(f"  ❌ пир '{dp['name']}' allowed-ips: {exc}")
                        else:
                            # Restore peer from DB to router
                            db_peer = self.db.get_peer(dp["router_id"])
                            pub = db_peer["public_key"] if db_peer and db_peer.get("public_key") else ""
                            priv = db_peer["private_key"] if db_peer and db_peer.get("private_key") else ""
                            if not pub and priv:
                                try:
                                    pub = derive_public_key(priv)
                                except Exception:
                                    pub = ""
                            if pub:
                                try:
                                    user_row = self.db.get_user_by_interface(name)
                                    listen_port = ddata.get("listen_port", self.cfg.WG_LISTEN_PORT)
                                    await self.mt.create_peer(
                                        interface=name,
                                        name=dp["name"],
                                        public_key=pub,
                                        private_key=priv,
                                        allowed_address=dp["allowed_ips"],
                                        client_address=dp["allowed_ips"].replace("/32", "/24") if "/32" in dp["allowed_ips"] else dp["allowed_ips"],
                                        persistent_keepalive=ddata["wg_keepalive"],
                                        client_endpoint=f"{self.mt_settings['public_ip']}",
                                        client_keepalive=ddata["wg_keepalive"],
                                        client_listen_port=self.cfg.WG_CLIENT_LISTEN_PORT,
                                    )
                                    report.append(f"  ✅ пир '{dp['name']}' — восстановлен на роутере")
                                except RouterOSError as exc:
                                    report.append(f"  ❌ пир '{dp['name']}' — ошибка восстановления: {exc}")
                            else:
                                report.append(f"  ⚠ пир '{dp['name']}' — нет ключа, восстановление невозможно")
        # Show result
        text = _card("🔄 РЕЗУЛЬТАТ СИНХРОНИЗАЦИИ\n" + _CARD_SEP + "\n" + "\n".join(report))
        try:
            router2 = await self._fetch_router_wg_state(self._managed_interfaces())
        except RouterOSError:
            router2 = {}
        db2 = self._fetch_db_wg_state()
        summary2 = self._compare_wg_state(router2, db2)
        await query.message.edit_text(text, parse_mode="HTML", reply_markup=self._sync_kb(summary2))

    async def on_admin_sync(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        if not self.mt_ready():
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")]])
            await query.message.edit_text("❌ Роутер не настроен.", reply_markup=kb)
            return
        await query.message.edit_text("🔄 Загружаю состояние роутера…")
        try:
            router = await self._fetch_router_wg_state(self._managed_interfaces())
        except RouterOSError as exc:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")]])
            await query.message.edit_text(f"❌ Ошибка: {exc}", reply_markup=kb)
            return
        db = self._fetch_db_wg_state()
        summary = self._compare_wg_state(router, db)
        await query.message.edit_text(
            self._sync_text(summary),
            parse_mode="HTML",
            reply_markup=self._sync_kb(summary),
        )

    async def on_sync_action(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        direction = query.data.split(":", 1)[1]
        await self._do_sync(query, direction)

    # ----------------------------------------------------------------- broadcast
    async def on_admin_broadcast(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        users = self.db.list_users()
        active = [u for u in users if u["status"] == "active"]
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton(f"📢 Всем ({len(active)})", callback_data="broadcast:all")],
            [
                InlineKeyboardButton("👤 Одному", callback_data="broadcast:user_pick"),
            ],
            [InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")],
        ])
        await query.message.edit_text(
            _card("📢 РАССЫЛКА\n" + _CARD_SEP + "\nВыберите получателей:"),
            parse_mode="HTML",
            reply_markup=kb,
        )

    async def on_broadcast_all(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        context.user_data[_AWAITING_BROADCAST] = {
            "action": "broadcast_all",
            "prompt_chat_id": query.message.chat_id,
            "prompt_msg_id": query.message.message_id,
        }
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="cancel")]])
        await query.message.edit_text(
            "Введите текст рассылки (до 4000 символов):",
            reply_markup=kb,
        )

    async def on_broadcast_user_pick(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        users = self.db.list_users()
        active = [u for u in users if u["status"] == "active"]
        if not active:
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Назад", callback_data="admin:broadcast")]])
            await query.message.edit_text("Нет активных пользователей.", reply_markup=kb)
            return
        kb = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(
                        f"@{u['username'] or '-'} ({u['full_name']})",
                        callback_data=f"broadcast:send:{u['telegram_id']}",
                    )
                ]
                for u in active
            ]
            + [[InlineKeyboardButton("🔙 Назад", callback_data="admin:broadcast")]]
        )
        await query.message.edit_text(
            "Выберите пользователя:", reply_markup=kb
        )

    async def on_broadcast_user_send(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.message.edit_text("Доступно только администратору.")
            return
        parts = query.data.split(":")
        target_tg = int(parts[2])
        context.user_data[_AWAITING_BROADCAST] = {
            "action": "broadcast_user",
            "target": target_tg,
            "prompt_chat_id": query.message.chat_id,
            "prompt_msg_id": query.message.message_id,
        }
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="cancel")]])
        await query.message.edit_text(
            "Введите текст сообщения (до 4000 символов):",
            reply_markup=kb,
        )

    async def _do_broadcast(self, context: ContextTypes.DEFAULT_TYPE, text: str, target_ids: list[int]) -> tuple[int, int]:
        """Send text to a list of telegram IDs. Returns (sent, failed)."""
        sent = 0
        failed = 0
        for tg_id in target_ids:
            try:
                await context.bot.send_message(tg_id, text)
                sent += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning("Broadcast to %s failed: %s", tg_id, exc)
                failed += 1
        return sent, failed

    # ------------------------------------------------------------------- cancel
    async def on_cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        state_name = context.user_data.get(_AWAITING_NAME)
        state_setting = context.user_data.get(_AWAITING_SETTING)
        state_broadcast = context.user_data.get(_AWAITING_BROADCAST)
        if state_broadcast:
            context.user_data.pop(_AWAITING_BROADCAST, None)
            kb = InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("📢 Всем", callback_data="broadcast:all"),
                    InlineKeyboardButton("👤 Одному", callback_data="broadcast:user_pick"),
                ],
                [InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")],
            ])
            await query.message.edit_text(
                _card("📢 РАССЫЛКА\n" + _CARD_SEP + "\nВыберите получателей:"),
                parse_mode="HTML",
                reply_markup=kb,
            )
            return
        if state_name:
            await self._try_delete_message(
                context,
                state_name.get("prompt_chat_id"),
                state_name.get("prompt_msg_id"),
            )
            context.user_data.pop(_AWAITING_NAME, None)
            msg_id = context.user_data.pop(_MENU_MSG, None)
            if msg_id:
                user = self.db.get_user(query.from_user.id)
                if user and user["status"] == "active":
                    target_tg = state_name.get("target_tg")
                    if target_tg:
                        owner = self.db.get_user(target_tg)
                        if owner:
                            await self._render_owner_peers(
                                context, query.message.chat_id, msg_id, owner
                            )
                            return
                    router_id = state_name.get("router_id")
                    back = "menu:root"
                    if router_id:
                        target = self._peers_target_user(user, router_id)
                        if target["telegram_id"] != user["telegram_id"]:
                            back = f"apeers:{target['telegram_id']}"
                    await self._render_peers(
                        context,
                        query.message.chat_id,
                        msg_id,
                        user,
                        router_id=router_id,
                        back=back,
                    )
                    return
        if state_setting:
            action = state_setting.get("action")
            context.user_data.pop(_AWAITING_SETTING, None)
            chat_id = query.message.chat_id
            if action == "set_mt":
                msg_id = state_setting.get("settings_msg_id")
                if msg_id:
                    await self._render_settings_message(context, chat_id, msg_id)
                await self._try_delete_message(context, chat_id, query.message.message_id)
                return
            if action in ("rename_user", "set_access"):
                msg_id = state_setting.get("profile_msg_id")
                if msg_id:
                    await self._render_user_profile_message(
                        context, chat_id, msg_id, state_setting["telegram_id"]
                    )
                await self._try_delete_message(context, chat_id, query.message.message_id)
                return
        await query.message.edit_text("Отменено.")

    async def on_peer_add_click(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user = self.db.get_user(query.from_user.id)
        if not user or user["status"] != "active":
            return
        state = {"action": "add_peer"}
        parts = query.data.split(":", 1)
        if len(parts) > 1 and parts[1].isdigit():
            if user["role"] != ROLE_ADMIN:
                return
            target = self.db.get_user(int(parts[1]))
            if not target:
                await query.message.edit_text("Пользователь не найден.")
                return
            state["target_tg"] = target["telegram_id"]
        context.user_data[_AWAITING_NAME] = state
        context.user_data[_MENU_MSG] = query.message.message_id
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="cancel")]])
        await query.message.edit_text(
            "Введите имя пира (латиница, цифры, _ и -, до 15 символов):",
            reply_markup=kb,
        )

    # --------------------------------------------------------------- register
    async def on_register_click(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        await self._register_user(update, context)

    async def _register_user(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        eff = update.effective_user
        uid = eff.id
        msg = update.effective_message
        if self.db.get_user(uid):
            await msg.edit_text("Вы уже зарегистрированы.")
            return
        if self.db.user_count() == 0:
            self.db.add_user(uid, self._name_of(eff), eff.username, role=ROLE_ADMIN, status="pending")
            try:
                await self._provision_user(uid, ROLE_ADMIN)
            except RouterOSError as exc:
                await msg.edit_text(
                    f"Ошибка создания интерфейса: {exc}\n"
                    "Проверьте настройки MT_HOST/MT_USER/MT_PASS в .env."
                )
                return
            await msg.edit_text(
                "Вы зарегистрированы как <b>Администратор</b>.\n"
                f"Интерфейс WireGuard: <code>{self.db.get_user(uid)['wg_interface']}</code>",
                parse_mode="HTML",
                reply_markup=self._menu_open_kb(),
            )
        else:
            self.db.add_user(uid, self._name_of(eff), eff.username, role=ROLE_USER, status="pending")
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("📨 К заявкам", callback_data="admin:pending")]]
            )
            awaiting = len(self.db.list_pending())
            await self._notify_admins(
                context,
                f"Новая заявка на регистрацию 📨 Ожидают решения: {awaiting}",
                kb=kb,
            )
            context.application.user_data.setdefault(uid, {})[_REG_MSG] = msg.message_id
            await msg.edit_text(
                "Заявка на регистрацию отправлена администратору. Ожидайте подтверждения."
            )

    # --------------------------------------------------- registration callbacks
    async def on_reg_decision(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        admin = self.db.get_user(query.from_user.id)
        if not admin or admin["role"] != ROLE_ADMIN:
            await query.answer("Доступно только администратору.")
            await query.message.reply_text("Только администратор может это делать.")
            return

        async def _cleanup_admin_card() -> None:
            """Delete the request card (and any result it would become)."""
            admin_data = context.application.user_data.get(query.from_user.id, {})
            if admin_data.get(_ADMIN_NOTIFY_MSG) == query.message.message_id:
                admin_data.pop(_ADMIN_NOTIFY_MSG, None)
            await self._try_delete_message(
                context, query.from_user.id, query.message.message_id
            )

        async def _cleanup_user_dialog() -> None:
            """Delete the user's «Заявка отправлена» message."""
            user_data = context.application.user_data.get(uid, {})
            reg_msg_id = user_data.pop(_REG_MSG, None)
            if reg_msg_id:
                await self._try_delete_message(context, uid, reg_msg_id)

        _, action, uid_str = query.data.split(":", 2)
        uid = int(uid_str)
        user = self.db.get_user(uid)
        if not user or user["status"] != "pending":
            await query.answer("Заявка уже обработана.")
            await _cleanup_admin_card()
            return

        if action == "approve":
            try:
                await self._provision_user(uid, ROLE_USER)
            except RouterOSError as exc:
                await query.answer("Не удалось создать интерфейс")
                await query.message.edit_text(f"Не удалось создать интерфейс: {exc}")
                return
            self.db.update_user(uid, decided_by=admin["telegram_id"])
            await query.answer("Заявка одобрена ✅")
            await _cleanup_admin_card()
            try:
                result = await context.bot.send_message(
                    uid,
                    "Ваша заявка одобрена! 🎉\n"
                    f"Создан интерфейс WireGuard: <code>{self.db.get_user(uid)['wg_interface']}</code>",
                    parse_mode="HTML",
                )
                await _cleanup_user_dialog()
                await self._try_delete_message(context, uid, result.message_id)
                await context.bot.send_message(
                    uid,
                    "Доступ открыт.",
                    reply_markup=self._menu_open_kb(),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Cannot notify user %s: %s", uid, exc)
        else:
            self.db.update_user(uid, status="rejected", decided_by=admin["telegram_id"])
            await query.answer("Заявка отклонена ❌")
            await _cleanup_admin_card()
            try:
                result = await context.bot.send_message(
                    uid, "Ваша заявка отклонена администратором."
                )
                await _cleanup_user_dialog()
                await self._try_delete_message(context, uid, result.message_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Cannot notify user %s: %s", uid, exc)

    # ------------------------------------------------------------------- peers
    def _peer_owner(self, router_id: str, peer_name: str = "") -> dict | None:
        """Owner user of a peer (by router_id or name), if known in DB."""
        rec = self._find_db_peer(router_id, peer_name)
        if not rec:
            return None
        return self.db.get_user(rec["owner_id"])

    def _peer_interface(self, user: dict, router_id: str) -> str:
        """Interface a peer belongs to. Admins may operate on others' peers."""
        if user["role"] == ROLE_ADMIN:
            owner = self._peer_owner(router_id)
            if owner and owner.get("wg_interface"):
                return owner["wg_interface"]
        return user["wg_interface"]

    def _peer_config_owner(self, user: dict, router_id: str) -> dict:
        """User record used to build a peer config (endpoint, DNS, subnet)."""
        if user["role"] == ROLE_ADMIN:
            owner = self._peer_owner(router_id)
            if owner and owner.get("wg_interface"):
                return owner
        return user

    def _peer_back(self, user: dict, router_id: str) -> str:
        """Back callback target for a peer card."""
        if user["role"] == ROLE_ADMIN:
            owner = self._peer_owner(router_id)
            if owner and owner["telegram_id"] != user["telegram_id"]:
                return f"apeers:{owner['telegram_id']}"
        return "menu:peers"

    async def _send_owner_peers(self, query, owner: dict, back: str) -> None:
        try:
            peers = await self.mt.get_peers(owner["wg_interface"])
        except RouterOSError as exc:
            await query.message.edit_text(f"Ошибка: {exc}")
            return
        peers = self._filter_db_peers(peers)
        text, kb = self._owner_peers_view(peers, owner, back)
        await query.message.edit_text(text, parse_mode="HTML", reply_markup=kb)

    def _owner_peers_view(
        self, peers: list[dict], owner: dict, back: str
    ) -> tuple[str, InlineKeyboardMarkup]:
        add_cb = f"addpeer:{owner['telegram_id']}"
        if not peers:
            kb = InlineKeyboardMarkup(
                [
                    [InlineKeyboardButton("➕ Создать пир", callback_data=add_cb)],
                    [InlineKeyboardButton("🔙 Назад", callback_data=back)],
                ]
            )
            text = _card(
                f"🔍 ПИРЫ ПОЛЬЗОВАТЕЛЯ\n{_CARD_SEP}\n"
                f"@{owner['username'] or '-'} ({owner['full_name']})\n\n"
                "Пиров пока нет."
            )
            return text, kb
        rows = list(self._peers_kb(peers, add_callback=add_cb).inline_keyboard)
        rows.append([InlineKeyboardButton("🔙 Назад", callback_data=back)])
        enabled = sum(1 for p in peers if not self._is_disabled(p))
        text = _card(
            f"🔍 ПИРЫ ПОЛЬЗОВАТЕЛЯ\n{_CARD_SEP}\n"
            f"@{owner['username'] or '-'} ({owner['full_name']})\n"
            f"🟢 Включено: {enabled} · 🚫 Отключено: {len(peers) - enabled}"
        )
        return text, InlineKeyboardMarkup(rows)

    async def _render_owner_peers(
        self,
        context,
        chat_id: int,
        msg_id: int,
        owner: dict,
        back: str = "admin:users",
    ) -> None:
        try:
            peers = await self.mt.get_peers(owner["wg_interface"])
        except RouterOSError:
            return
        peers = self._filter_db_peers(peers)
        text, kb = self._owner_peers_view(peers, owner, back)
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=msg_id,
                text=text,
                parse_mode="HTML",
                reply_markup=kb,
            )
        except Exception:  # noqa: BLE001
            pass

    async def on_peer_open(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user = self.db.get_user(query.from_user.id)
        if not user or user["status"] != "active":
            return
        router_id = query.data.split(":", 1)[1]
        iface = self._peer_interface(user, router_id)
        try:
            peer = await self.mt.get_peer(iface, router_id)
        except RouterOSError as exc:
            await query.message.edit_text(f"Ошибка: {exc}")
            return
        if not peer:
            back = self._peer_back(user, router_id)
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data=back)]]
            )
            await query.message.edit_text("Пир не найден (возможно удалён).", reply_markup=kb)
            return
        await query.message.edit_text(
            self._peer_card_text(peer, router_id),
            parse_mode="HTML",
            reply_markup=self._peer_view_kb(peer, user, router_id),
        )

    async def on_peer_config(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user = self.db.get_user(query.from_user.id)
        if not user or user["status"] != "active":
            return
        router_id = query.data.split(":", 1)[1]
        peer_name = ""
        try:
            iface = self._peer_interface(user, router_id)
            raw_peer = await self.mt.get_peer(iface, router_id)
            if raw_peer:
                peer_name = raw_peer.get("name", "")
        except RouterOSError:
            pass
        rec = self._find_db_peer(router_id, peer_name)
        if not rec:
            await query.message.reply_text("Пир не найден в базе данных.")
            return
        if not rec.get("private_key"):
            back = self._peer_back(user, router_id)
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Назад", callback_data=back)]])
            await query.message.reply_text(
                "⚠️ Конфигурация недоступна: приватный ключ отсутствует.\n"
                "Пир был импортирован с роутера без ключа.",
                reply_markup=kb,
            )
            return
        try:
            owner = self._peer_config_owner(user, router_id)
            cfg_text = await self._build_config(owner, rec)
        except RouterOSError as exc:
            await query.message.reply_text(f"Ошибка: {exc}")
            return
        short = self._peer_short_name(rec["name"], owner.get("wg_interface", ""))
        await query.message.reply_document(
            document=InputFile(io.BytesIO(cfg_text.encode()), filename=f"{short}.conf"),
            caption=f"Конфигурация пира {rec['name']}",
        )
        await self._ensure_menu(context, query.message.chat_id)

    async def on_peer_qr(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user = self.db.get_user(query.from_user.id)
        if not user or user["status"] != "active":
            return
        router_id = query.data.split(":", 1)[1]
        peer_name = ""
        try:
            iface = self._peer_interface(user, router_id)
            raw_peer = await self.mt.get_peer(iface, router_id)
            if raw_peer:
                peer_name = raw_peer.get("name", "")
        except RouterOSError:
            pass
        rec = self._find_db_peer(router_id, peer_name)
        if not rec:
            await query.message.reply_text("Пир не найден в базе данных.")
            return
        if not rec.get("private_key"):
            back = self._peer_back(user, router_id)
            kb = InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Назад", callback_data=back)]])
            await query.message.reply_text(
                "⚠️ QR-код недоступен: приватный ключ отсутствует.\n"
                "Пир был импортирован с роутера без ключа.",
                reply_markup=kb,
            )
            return
        try:
            owner = self._peer_config_owner(user, router_id)
            cfg_text = await self._build_config(owner, rec)
        except RouterOSError as exc:
            await query.message.reply_text(f"Ошибка: {exc}")
            return
        short = self._peer_short_name(rec["name"], owner.get("wg_interface", ""))
        png = build_qr_png(cfg_text)
        await query.message.reply_photo(
            photo=InputFile(io.BytesIO(png), filename=f"{short}.png"),
            caption=f"QR-код для пира {rec['name']}. Отсканируйте в приложении WireGuard.",
        )
        await self._ensure_menu(context, query.message.chat_id)

    async def _build_config(self, user: dict, rec: dict) -> str:
        srv_pub = await self._get_server_public_key(user["wg_interface"])
        return build_client_config(
            client_private_key=rec["private_key"],
            client_address=rec["ip"],
            server_public_key=srv_pub,
            server_endpoint=f"{self.mt_settings['public_ip']}:{user['listen_port']}",
            dns=self._router_dns(user),
            persistent_keepalive=self.cfg.WG_PERSISTENT_KEEPALIVE,
        )

    async def on_peer_toggle(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user = self.db.get_user(query.from_user.id)
        if not user or user["status"] != "active":
            return
        router_id = query.data.split(":", 1)[1]
        iface = self._peer_interface(user, router_id)
        try:
            peer = await self.mt.get_peer(iface, router_id)
        except RouterOSError as exc:
            await query.message.edit_text(f"Ошибка роутера: {exc}")
            return
        if not peer:
            back = self._peer_back(user, router_id)
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data=back)]]
            )
            await query.message.edit_text("Пир не найден.", reply_markup=kb)
            return
        await self.mt.set_peer_disabled(router_id, not self._is_disabled(peer))
        await self._refresh_peer_view(query, user, router_id)

    async def on_peer_rotate(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user = self.db.get_user(query.from_user.id)
        if not user or user["status"] != "active":
            return
        router_id = query.data.split(":", 1)[1]
        peer_name = ""
        try:
            iface = self._peer_interface(user, router_id)
            raw_peer = await self.mt.get_peer(iface, router_id)
            if raw_peer:
                peer_name = raw_peer.get("name", "")
        except RouterOSError:
            pass
        rec = self._find_db_peer(router_id, peer_name)
        if not rec:
            await query.message.reply_text("Запись о пире не найдена.")
            return
        priv, pub = generate_keypair()
        await self.mt.update_peer(router_id, **{"public-key": pub, "private-key": priv})
        self.db.update_peer(rec["router_id"], private_key=priv, public_key=pub)
        await self._refresh_peer_view(query, user, router_id)
        await query.message.reply_text("Ключи пира обновлены. Обновите конфигурацию у клиента.")

    async def on_peer_rename(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user = self.db.get_user(query.from_user.id)
        if not user or user["status"] != "active":
            return
        router_id = query.data.split(":", 1)[1]
        kb = InlineKeyboardMarkup([[InlineKeyboardButton("Отмена", callback_data="cancel")]])
        prompt = await query.message.reply_text("Введите новое имя пира:", reply_markup=kb)
        context.user_data[_AWAITING_NAME] = {
            "action": "rename_peer",
            "router_id": router_id,
            "prompt_chat_id": prompt.chat_id,
            "prompt_msg_id": prompt.message_id,
        }

    async def on_peer_delete(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user = self.db.get_user(query.from_user.id)
        if not user or user["status"] != "active":
            return
        router_id = query.data.split(":", 1)[1]
        back = self._peer_back(user, router_id)
        kb = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton("🗑 Да, удалить", callback_data=f"pdel_conf:{router_id}"),
                    InlineKeyboardButton("Отмена", callback_data=back),
                ]
            ]
        )
        await query.message.edit_text("Удалить пир? Это действие необратимо.", reply_markup=kb)

    async def on_peer_delete_confirm(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user = self.db.get_user(query.from_user.id)
        if not user or user["status"] != "active":
            return
        router_id = query.data.split(":", 1)[1]
        owner = self._peer_owner(router_id) if user["role"] == ROLE_ADMIN else None
        back = self._peer_back(user, router_id)
        await self.mt.delete_peer(router_id)
        self.db.delete_peer(router_id)
        if owner and owner["telegram_id"] != user["telegram_id"]:
            await self._send_owner_peers(query, owner, back)
        else:
            await self._send_peers_list(query, user)

    async def on_peer_list(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user = self.db.get_user(query.from_user.id)
        if not user or user["status"] != "active":
            return
        await self._send_peers_list(query, user)

    @staticmethod
    def _is_disabled(peer: dict) -> bool:
        return str(peer.get("disabled", "false")).lower() == "true"

    def _find_db_peer(self, router_id: str, peer_name: str = "") -> dict | None:
        """Look up DB peer by router_id, falling back to name."""
        rec = self.db.get_peer(router_id)
        if rec:
            return rec
        if peer_name:
            return self.db.get_peer_by_name(peer_name)
        return None

    def _filter_db_peers(self, router_peers: list[dict]) -> list[dict]:
        """Only keep peers that have a DB record (managed by the bot)."""
        return [p for p in router_peers if self._find_db_peer(p[".id"], p.get("name", ""))]

    @staticmethod
    def _handshake_seconds(value) -> float | None:
        if not value:
            return None
        units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
        total = 0.0
        for num, unit in re.findall(r"(\d+)([wdhms])", value):
            total += int(num) * units[unit]
        return total if total > 0 else None

    def _connection_state(self, peer: dict) -> str:
        elapsed = self._handshake_seconds(peer.get("last-handshake"))
        if elapsed is None:
            return "⚪ не подключён"
        keepalive = int(self.cfg.WG_PERSISTENT_KEEPALIVE or 0)
        threshold = keepalive * 3 if keepalive > 0 else 120
        return "🟢 подключён" if elapsed <= threshold else "⚪ не подключён"

    def _peer_card_text(self, peer: dict, router_id: str) -> str:
        state = "🚫 отключён" if self._is_disabled(peer) else "🟢 включён"
        lines = [
            "🔗 ПИР",
            _CARD_SEP,
            f"Имя: {peer.get('name', router_id)}",
            f"Статус: {state}",
            f"Соединение: {self._connection_state(peer)}",
            f"Адрес: {peer.get('allowed-address', '')}",
        ]
        rec = self._find_db_peer(router_id, peer.get("name", ""))
        if rec:
            lines.append(f"IP: {rec['ip']}")
            if not rec.get("private_key"):
                lines.append("⚠️ Приватный ключ отсутствует — конфиг недоступен")
        lines.append(f"Handshake: {peer.get('last-handshake', '-') or '-'}")
        return _card("\n".join(lines))

    @staticmethod
    def _peer_short_name(peer_name: str, iface: str = "") -> str:
        """Strip interface prefix from peer name for config filenames.
        e.g. ``wg123_Matrix_lan_Router_peer1`` -> ``peer1``
        """
        prefix = f"{iface}_" if iface else ""
        if prefix and peer_name.startswith(prefix):
            return peer_name[len(prefix):]
        return peer_name

    def _peer_view_kb(self, peer: dict, user: dict, router_id: str) -> InlineKeyboardMarkup:
        rec = self._find_db_peer(router_id, peer.get("name", ""))
        has_key = bool(rec and rec.get("private_key"))
        kb = [
            [
                InlineKeyboardButton("📄 Конфигурационный файл", callback_data=f"pcfg:{router_id}"),
                InlineKeyboardButton("🔳 QR код", callback_data=f"pqr:{router_id}"),
            ],
            [
                InlineKeyboardButton(
                    "🚫 Отключить" if not self._is_disabled(peer) else "✅ Включить",
                    callback_data=f"ptoggle:{router_id}",
                ),
                InlineKeyboardButton("🔄 Обновить ключи", callback_data=f"protate:{router_id}"),
            ],
            [
                InlineKeyboardButton("✏️ Переименовать", callback_data=f"prename:{router_id}"),
                InlineKeyboardButton("🗑 Удалить", callback_data=f"pdel:{router_id}"),
            ],
            [InlineKeyboardButton("🔙 Назад", callback_data=self._peer_back(user, router_id))],
        ]
        return InlineKeyboardMarkup(kb)

    def _peer_button_label(self, peer: dict) -> str:
        icon = "🚫" if self._is_disabled(peer) else "🟢"
        name = peer.get("name", peer[".id"])
        addr = peer.get("allowed-address", "").split("/")[0]
        return f"{icon} {name} · {addr}" if addr else f"{icon} {name}"

    def _peers_list_text(self, peers: list[dict]) -> str:
        if not peers:
            return _card(
                "📋 МОИ ПИРЫ\n"
                f"{_CARD_SEP}\n"
                "У вас пока нет пиров.\nСоздайте первый через кнопку ниже."
            )
        enabled = sum(1 for p in peers if not self._is_disabled(p))
        disabled = len(peers) - enabled
        return _card(
            "📋 МОИ ПИРЫ\n"
            f"{_CARD_SEP}\n"
            f"🟢 Включено: {enabled} · 🚫 Отключено: {disabled}\n\n"
            "Нажмите на пир, чтобы управлять им."
        )

    def _peers_kb(
        self,
        peers: list[dict],
        show_add: bool = True,
        add_callback: str = "addpeer",
    ) -> InlineKeyboardMarkup:
        kb = [
            [InlineKeyboardButton(
                self._peer_button_label(p),
                callback_data=f"peer:{p['.id']}",
            )]
            for p in peers
        ]
        if show_add:
            kb.append([InlineKeyboardButton("➕ Создать пир", callback_data=add_callback)])
        return InlineKeyboardMarkup(kb)

    def _peers_kb_with_back(
        self, peers: list[dict], back: str = "menu:root"
    ) -> InlineKeyboardMarkup:
        rows = list(self._peers_kb(peers).inline_keyboard)
        rows.append([InlineKeyboardButton("🔙 Назад", callback_data=back)])
        return InlineKeyboardMarkup(rows)

    async def _send_peers_list(self, query, user: dict) -> None:
        try:
            peers = await self.mt.get_peers(user["wg_interface"])
        except RouterOSError as exc:
            await query.message.edit_text(f"Ошибка: {exc}")
            return
        peers = self._filter_db_peers(peers)
        await query.message.edit_text(
            self._peers_list_text(peers),
            parse_mode="HTML",
            reply_markup=self._peers_kb_with_back(peers),
        )

    async def _refresh_peer_view(self, query, user: dict, router_id: str) -> None:
        iface = self._peer_interface(user, router_id)
        peer = await self.mt.get_peer(iface, router_id)
        if not peer:
            back = self._peer_back(user, router_id)
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data=back)]]
            )
            await query.message.edit_text("Пир не найден.", reply_markup=kb)
            return
        await query.message.edit_text(
            self._peer_card_text(peer, router_id),
            parse_mode="HTML",
            reply_markup=self._peer_view_kb(peer, user, router_id),
        )

    # -------------------------------------------------------------- text input
    async def on_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        text = update.message.text.strip()
        state = context.user_data.get(_AWAITING_SETTING)
        if state:
            if state["action"] == "set_access":
                dt = _parse_date(text)
                if not dt:
                    await update.message.reply_text(
                        "Не удалось распознать дату. Формат: ДД.ММ.ГГГГ [ЧЧ:ММ]."
                    )
                    return
                if dt <= datetime.now():
                    await update.message.reply_text(
                        "Дата должна быть в будущем. Попробуйте ещё раз."
                    )
                    return
                self.db.update_user(
                    state["telegram_id"],
                    access_until=dt.strftime(_DATE_FMT),
                )
                context.user_data.pop(_AWAITING_SETTING, None)
                await self._try_delete_message(
                    context, state.get("prompt_chat_id"), state.get("prompt_msg_id")
                )
                await self._try_delete(update.message)
                profile_msg_id = state.get("profile_msg_id")
                if profile_msg_id:
                    await self._render_user_profile_message(
                        context, update.effective_chat.id, profile_msg_id,
                        state["telegram_id"],
                    )
                return
            if state["action"] == "set_created_at":
                dt = _parse_date(text)
                if not dt:
                    await update.message.reply_text(
                        "Не удалось распознать дату. Формат: ДД.ММ.ГГГГ [ЧЧ:ММ]."
                    )
                    return
                self.db.update_user(
                    state["telegram_id"],
                    created_at=dt.strftime(_DATE_FMT),
                )
                context.user_data.pop(_AWAITING_SETTING, None)
                await self._try_delete_message(
                    context, state.get("prompt_chat_id"), state.get("prompt_msg_id")
                )
                await self._try_delete(update.message)
                profile_msg_id = state.get("profile_msg_id")
                if profile_msg_id:
                    await self._render_user_profile_message(
                        context, update.effective_chat.id, profile_msg_id,
                        state["telegram_id"],
                    )
                return
            if state["action"] == "rename_user":
                if not text or len(text) > 64:
                    await update.message.reply_text("Имя не должно быть пустым и длиннее 64 символов.")
                    return
                self.db.update_user(state["telegram_id"], full_name=text)
                context.user_data.pop(_AWAITING_SETTING, None)
                await self._try_delete_message(
                    context, state.get("prompt_chat_id"), state.get("prompt_msg_id")
                )
                await self._try_delete(update.message)
                profile_msg_id = state.get("profile_msg_id")
                if profile_msg_id:
                    await self._render_user_profile_message(
                        context, update.effective_chat.id, profile_msg_id,
                        state["telegram_id"],
                    )
                return
            if state["action"] == "set_mt":
                key = state["key"]
                if key == "ip":
                    if not text or len(text) > 64:
                        await update.message.reply_text("Введите корректный IP-адрес.")
                        return
                    self.mt_settings["public_ip"] = text
                    self.db.set_setting("public_ip", text)
                elif key == "pass":
                    self.mt_settings["pass"] = text
                    self.db.set_setting("pass", text)
                elif key == "host":
                    if not text:
                        await update.message.reply_text("Хост не должен быть пустым.")
                        return
                    self.mt_settings["host"] = text
                    self.db.set_setting("host", text)
                elif key == "user":
                    if not text:
                        await update.message.reply_text("Логин не должен быть пустым.")
                        return
                    self.mt_settings["user"] = text
                    self.db.set_setting("user", text)
                try:
                    await self._reconfigure_mt()
                except RouterOSError as exc:
                    await update.message.reply_text(f"Не удалось применить настройки: {exc}")
                    return
                context.user_data.pop(_AWAITING_SETTING, None)
                settings_msg_id = state.get("settings_msg_id")
                if settings_msg_id:
                    await self._render_settings_message(
                        context, update.effective_chat.id, settings_msg_id
                    )
                await update.message.reply_text(
                    f"{_MT_LABELS[key]} обновлён: <code>{text}</code>\n"
                    "Проверьте подключение через 🧪 Проверить.",
                    parse_mode="HTML",
                )
                return
        state = context.user_data.get(_AWAITING_BROADCAST)
        if state:
            if not text or len(text) > _MAX_BROADCAST_LEN:
                await update.message.reply_text(
                    f"Текст не должен быть пустым и длиннее {_MAX_BROADCAST_LEN} символов."
                )
                return
            if state["action"] == "broadcast_all":
                users = self.db.list_users()
                target_ids = [u["telegram_id"] for u in users if u["status"] == "active"]
                label = f"всем ({len(target_ids)})"
            else:
                target_ids = [state["target"]]
                u = self.db.get_user(state["target"])
                label = f"@{u['username']}" if u and u.get("username") else str(state["target"])
            try:
                await self._try_delete_message(
                    context, state.get("prompt_chat_id"), state.get("prompt_msg_id")
                )
                await self._try_delete(update.message)
                await update.message.reply_text(f"📨 Отправляю {label}…")
                sent, failed = await self._do_broadcast(context, text, target_ids)
            finally:
                context.user_data.pop(_AWAITING_BROADCAST, None)
            result_kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("📢 Ещё рассылка", callback_data="admin:broadcast")],
                [InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")],
            ])
            await update.message.reply_text(
                _card(f"📢 РЕЗУЛЬТАТ РАССЫЛКИ\n{_CARD_SEP}\n"
                       f"✅ Доставлено: {sent}\n❌ Ошибок: {failed}"),
                parse_mode="HTML",
                reply_markup=result_kb,
            )
            return
        state = context.user_data.get(_AWAITING_NAME)
        if not state:
            await update.message.reply_text(
                "Используйте меню — отправьте /menu."
            )
            return
        name = text
        if not NAME_RE.match(name):
            await update.message.reply_text(
                "Некорректное имя. Допустимы латиница, цифры, _ и -, до 15 символов."
            )
            return
        user = self.db.get_user(update.effective_user.id)
        if not user or user["status"] != "active":
            context.user_data.pop(_AWAITING_NAME, None)
            return
        try:
            if state["action"] == "add_peer":
                target = user
                target_tg = state.get("target_tg")
                if target_tg:
                    target = self.db.get_user(target_tg) or user
                await self._create_peer(update, context, target, name)
            elif state["action"] == "rename_peer":
                target = self._peers_target_user(user, state["router_id"])
                iface = target["wg_interface"]
                router_name = f"{iface}_{name}"
                await self.mt.update_peer(state["router_id"], **{"name": router_name})
                self.db.update_peer(state["router_id"], name=router_name)
                await self._try_delete_message(
                    context, state.get("prompt_chat_id"), state.get("prompt_msg_id")
                )
                msg_id = context.user_data.get(_MENU_MSG)
                if msg_id:
                    await self._render_peer_card(
                        context, update.effective_chat.id, msg_id,
                        user, state["router_id"],
                    )
        except RouterOSError as exc:
            await update.message.reply_text(f"Ошибка: {exc}")
        finally:
            await self._try_delete(update.message)
            context.user_data.pop(_AWAITING_NAME, None)
            if state["action"] == "add_peer":
                msg_id = context.user_data.pop(_MENU_MSG, None)
                if msg_id:
                    owner = None
                    target_tg = state.get("target_tg")
                    if target_tg:
                        owner = self.db.get_user(target_tg)
                    if owner:
                        await self._render_owner_peers(
                            context, update.effective_chat.id, msg_id, owner
                        )
                    else:
                        await self._render_peers(
                            context, update.effective_chat.id, msg_id, user
                        )

    def _peers_target_user(self, user: dict, router_id: str | None) -> dict:
        """User whose peer list/card should be shown (owner for admin ops)."""
        if user["role"] == ROLE_ADMIN and router_id:
            owner = self._peer_owner(router_id)
            if owner and owner.get("wg_interface"):
                return owner
        return user

    async def _render_peers(
        self,
        context,
        chat_id: int,
        msg_id: int,
        user: dict,
        router_id: str | None = None,
        back: str = "menu:root",
    ) -> None:
        target = self._peers_target_user(user, router_id)
        try:
            peers = await self.mt.get_peers(target["wg_interface"])
        except RouterOSError:
            return
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=msg_id,
                text=self._peers_list_text(peers),
                parse_mode="HTML",
                reply_markup=self._peers_kb_with_back(peers, back=back),
            )
        except Exception:  # noqa: BLE001
            pass

    async def _render_peer_card(
        self, context, chat_id: int, msg_id: int, user: dict, router_id: str
    ) -> None:
        iface = self._peer_interface(user, router_id)
        try:
            peer = await self.mt.get_peer(iface, router_id)
        except RouterOSError:
            return
        if not peer:
            return
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=msg_id,
                text=self._peer_card_text(peer, router_id),
                parse_mode="HTML",
                reply_markup=self._peer_view_kb(peer, user, router_id),
            )
        except Exception:  # noqa: BLE001
            pass

    async def _render_settings_message(self, context, chat_id: int, msg_id: int) -> None:
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=msg_id,
                text=self._settings_text(),
                parse_mode="HTML",
                reply_markup=self._settings_kb(),
            )
        except Exception:  # noqa: BLE001
            pass

    async def _render_user_profile_message(
        self, context, chat_id: int, msg_id: int, telegram_id: int
    ) -> None:
        user = self.db.get_user(telegram_id)
        if not user:
            return
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=msg_id,
                text=self._user_profile_text(user),
                parse_mode="HTML",
                reply_markup=self._user_profile_kb(user),
            )
        except Exception:  # noqa: BLE001
            pass

    async def _show_admin_users(self, query) -> None:
        users = self.db.list_users()
        if not users:
            kb = InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔙 Назад", callback_data="admin:menu")]]
            )
            await query.message.edit_text(
                _card("👥 ПОЛЬЗОВАТЕЛИ\n" + _CARD_SEP + "\n\nНет пользователей."),
                parse_mode="HTML",
                reply_markup=kb,
            )
            return
        await query.message.edit_text(
            _card(
                "👥 ПОЛЬЗОВАТЕЛИ\n"
                + _CARD_SEP
                + f"\n\nВсего: {len(users)}\nНажмите на пользователя, чтобы открыть профиль."
            ),
            parse_mode="HTML",
            reply_markup=self._user_choice_kb(users, action="uview"),
        )

    async def _create_peer(self, update, context, user: dict, name: str) -> None:
        peers = await self.mt.get_peers(user["wg_interface"])
        used = {
            p["allowed-address"].split("/")[0]
            for p in peers
            if p.get("allowed-address")
        }
        ip = self._next_peer_ip(user["subnet"], used)
        if not ip:
            await update.message.reply_text("Подсеть переполнена.")
            return
        client_addr = ip.rsplit("/", 1)[0] + "/24"
        router_name = f"{user['wg_interface']}_{name}"
        priv, pub = generate_keypair()
        created = await self.mt.create_peer(
            interface=user["wg_interface"],
            name=router_name,
            public_key=pub,
            private_key=priv,
            allowed_address=ip,
            client_address=client_addr,
            persistent_keepalive=self.cfg.WG_PERSISTENT_KEEPALIVE,
            client_dns=self._router_dns(user),
            client_endpoint=f"{self.mt_settings['public_ip']}",
            client_keepalive=self.cfg.WG_PERSISTENT_KEEPALIVE,
            client_listen_port=self.cfg.WG_CLIENT_LISTEN_PORT,
            client_allowed_address="0.0.0.0/0",
        )
        self.db.add_peer(
            router_id=created[".id"],
            owner_id=user["telegram_id"],
            name=router_name,
            private_key=priv,
            ip=client_addr,
            allowed_ips=ip,
            public_key=pub,
        )
        cfg_text = await self._build_config(user, self.db.get_peer(created[".id"]))
        short = self._peer_short_name(router_name, user["wg_interface"])
        png = build_qr_png(cfg_text)
        await update.message.reply_text(
            f"Пир <b>{router_name}</b> создан. IP: <code>{client_addr}</code>",
            parse_mode="HTML",
        )
        await update.message.reply_photo(
            photo=InputFile(io.BytesIO(png), filename=f"{short}.png"),
            caption="QR-код подключения. Отсканируйте в приложении WireGuard.",
        )
        await update.message.reply_document(
            document=InputFile(io.BytesIO(cfg_text.encode()), filename=f"{short}.conf"),
            caption="Файл конфигурации WireGuard.",
        )

async def _setup_ui(app: Application) -> None:
    """No commands menu near the input line; the menu is a chat message."""
    await app.bot.set_my_commands([])


def build_app(cfg: Config) -> tuple[Application, Bot]:
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=cfg.LOG_LEVEL,
    )
    # http clients log every request at INFO — silence them (spams router logs).
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    missing = cfg.validate()
    if missing:
        logger.error("Отсутствуют настройки в .env: %s", ", ".join(missing))
        raise SystemExit(1)

    db = Storage(cfg.DB_PATH)
    mt = MikroTik(cfg.MT_HOST, cfg.MT_USER, cfg.MT_PASS, cfg.MT_VERIFY_TLS, cfg.MT_USE_SSL)
    bot = Bot(cfg, db, mt)

    async def _post_init(application: Application) -> None:
        await _setup_ui(application)
        await bot._reconfigure_mt()
        try:
            await bot._ensure_consolidated_rules()
            await bot._sync_wg_subnets()
            if db.get_setting("fw_v3") != "1":
                # Migrate: drop stale per-user forward/return/nat rules and
                # recreate only the per-user handshake under the consolidated
                # wg-all-* scheme.
                for u in db.list_users():
                    if u.get("wg_interface"):
                        await bot._reposition_user_rules(
                            u["wg_interface"], u.get("listen_port") or 0
                        )
                db.set_setting("fw_v3", "1")
        except RouterOSError as exc:
            logger.warning("Не удалось синхронизировать правила firewall: %s", exc)

        async def _expiry_loop() -> None:
            while True:
                try:
                    await bot._check_expirations(application.bot)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Expiry check failed: %s", exc)
                await asyncio.sleep(_EXPIRY_CHECK_INTERVAL)

        async def _deadline_warn_loop() -> None:
            while True:
                try:
                    await bot._check_deadline_warnings(application.bot)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Deadline warning check failed: %s", exc)
                await asyncio.sleep(_DEADLINE_WARN_INTERVAL)

        background_tasks: set[asyncio.Task] = set()
        t1 = asyncio.create_task(_expiry_loop())
        t2 = asyncio.create_task(_deadline_warn_loop())
        background_tasks.add(t1)
        background_tasks.add(t2)
        t1.add_done_callback(background_tasks.discard)
        t2.add_done_callback(background_tasks.discard)

    app = (
        Application.builder()
        .token(cfg.BOT_TOKEN)
        .post_init(_post_init)
        .persistence(
            PicklePersistence(filepath=os.path.splitext(cfg.DB_PATH)[0] + "_state.pickle")
        )
        .build()
    )

    async def _error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
        err = context.error
        if isinstance(err, telegram.error.BadRequest) and "Query is too old" in str(err):
            logger.debug("Stale callback ignored: %s", err)
            return
        logger.warning("Handler error: %s", err, exc_info=err)

    app.add_error_handler(_error_handler)
    app.add_handler(CommandHandler("start", bot.cmd_start))
    app.add_handler(CommandHandler("menu", bot.cmd_menu))
    app.add_handler(CommandHandler("myinfo", bot.cmd_myinfo))
    app.add_handler(CommandHandler("peers", bot.cmd_peers))
    app.add_handler(CommandHandler("admin", bot.cmd_admin))
    app.add_handler(CommandHandler("help", bot.cmd_help))

    app.add_handler(CallbackQueryHandler(bot.on_menu, pattern=r"^menu:"))
    app.add_handler(CallbackQueryHandler(bot.on_admin_menu, pattern=r"^admin:menu$"))
    app.add_handler(CallbackQueryHandler(bot.on_admin_pending, pattern=r"^admin:pending$"))
    app.add_handler(CallbackQueryHandler(bot.on_admin_req_nav, pattern=r"^admin:req:(prev|next|noop):\d+$"))
    app.add_handler(CallbackQueryHandler(bot.on_admin_users, pattern=r"^admin:users$"))
    app.add_handler(CallbackQueryHandler(bot.on_admin_user_peers, pattern=r"^apeers:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.on_admin_settings, pattern=r"^admin:settings$"))
    app.add_handler(CallbackQueryHandler(bot.on_admin_bot_settings, pattern=r"^admin:bot_settings$"))
    app.add_handler(CallbackQueryHandler(bot.on_admin_sync, pattern=r"^admin:sync$"))
    app.add_handler(CallbackQueryHandler(bot.on_sync_action, pattern=r"^sync:(to_db|to_router)$"))
    app.add_handler(CallbackQueryHandler(bot.on_admin_broadcast, pattern=r"^admin:broadcast$"))
    app.add_handler(CallbackQueryHandler(bot.on_broadcast_all, pattern=r"^broadcast:all$"))
    app.add_handler(CallbackQueryHandler(bot.on_broadcast_user_pick, pattern=r"^broadcast:user_pick$"))
    app.add_handler(CallbackQueryHandler(bot.on_broadcast_user_send, pattern=r"^broadcast:send:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.on_setting, pattern=r"^set:"))
    app.add_handler(CallbackQueryHandler(bot.on_user_view, pattern=r"^uview:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.on_user_block, pattern=r"^ublock:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.on_user_unblock, pattern=r"^uunblock:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.on_user_rename, pattern=r"^urename:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.on_user_access, pattern=r"^uaccess:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.on_user_access_clear, pattern=r"^uaccess_clear:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.on_user_created_at, pattern=r"^ucdate:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.on_user_delete, pattern=r"^udelete:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.on_user_delete_confirm, pattern=r"^udelete_conf:\d+$"))
    app.add_handler(CallbackQueryHandler(bot.on_reg_decision, pattern=r"^reg:(approve|reject):\d+$"))
    app.add_handler(CallbackQueryHandler(bot.on_register_click, pattern=r"^reg:start$"))
    app.add_handler(CallbackQueryHandler(bot.on_cancel, pattern=r"^cancel$"))
    app.add_handler(CallbackQueryHandler(bot.on_peer_add_click, pattern=r"^addpeer(?::\d+)?$"))
    app.add_handler(CallbackQueryHandler(bot.on_peer_open, pattern=r"^peer:"))
    app.add_handler(CallbackQueryHandler(bot.on_peer_config, pattern=r"^pcfg:"))
    app.add_handler(CallbackQueryHandler(bot.on_peer_qr, pattern=r"^pqr:"))
    app.add_handler(CallbackQueryHandler(bot.on_peer_toggle, pattern=r"^ptoggle:"))
    app.add_handler(CallbackQueryHandler(bot.on_peer_rotate, pattern=r"^protate:"))
    app.add_handler(CallbackQueryHandler(bot.on_peer_rename, pattern=r"^prename:"))
    app.add_handler(CallbackQueryHandler(bot.on_peer_delete, pattern=r"^pdel:"))
    app.add_handler(CallbackQueryHandler(bot.on_peer_delete_confirm, pattern=r"^pdel_conf:"))

    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.on_text))

    return app, bot


def main():
    cfg = Config()
    app, _ = build_app(cfg)
    app.run_polling()


if __name__ == "__main__":
    main()
