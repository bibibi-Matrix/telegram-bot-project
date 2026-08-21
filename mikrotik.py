"""RouterOS REST API client (MikroTik v7+)."""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_REST = "interface/wireguard"
_REST_PEERS = "interface/wireguard/peers"
_REST_IP_ADDR = "ip/address"


class RouterOSError(Exception):
    """Raised on RouterOS API errors."""


class MikroTik:
    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        verify_tls: bool = False,
        use_ssl: bool = False,
        timeout: float = 15.0,
    ):
        scheme = "https" if use_ssl else "http"
        self._client = httpx.AsyncClient(
            base_url=f"{scheme}://{host}/rest",
            auth=(user, password),
            verify=verify_tls,
            timeout=timeout,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def reconfigure(
        self,
        host: str,
        user: str,
        password: str,
        verify_tls: bool = False,
        use_ssl: bool = False,
        timeout: float = 15.0,
    ) -> None:
        """Point the client at a different router without recreating it."""
        await self.aclose()
        scheme = "https" if use_ssl else "http"
        self._client = httpx.AsyncClient(
            base_url=f"{scheme}://{host}/rest",
            auth=(user, password),
            verify=verify_tls,
            timeout=timeout,
        )

    async def _request(self, method: str, path: str, data: dict | None = None) -> Any:
        try:
            resp = await self._client.request(method, path, json=data)
        except httpx.HTTPError as exc:
            raise RouterOSError(f"RouterOS недоступен: {exc}") from exc
        if resp.status_code >= 400:
            raise RouterOSError(
                f"RouterOS [{resp.status_code}] {path}: {resp.text[:300]}"
            )
        if not resp.text:
            return None
        try:
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            raise RouterOSError(f"Некорректный ответ RouterOS: {resp.text[:300]}") from exc

    # ------------------------------------------------------------ interfaces
    async def get_wireguard_interfaces(self) -> list[dict]:
        return await self._request("GET", _REST)

    async def get_wireguard_interface(self, name: str) -> dict | None:
        data = await self._request("GET", f"{_REST}?name={name}")
        return data[0] if data else None

    async def create_wireguard_interface(
        self, name: str, listen_port: int, mtu: int = 1420
    ) -> dict:
        return await self._request(
            "PUT", _REST, {"name": name, "listen-port": listen_port, "mtu": mtu}
        )

    async def delete_wireguard_interface(self, interface_id: str) -> None:
        await self._request("DELETE", f"{_REST}/{interface_id}")

    async def set_interface_disabled(self, name: str, disabled: bool) -> None:
        iface = await self.get_wireguard_interface(name)
        if iface:
            await self._request(
                "PATCH", f"{_REST}/{iface['.id']}", {"disabled": bool(disabled)}
            )

    async def update_wireguard_interface(self, name: str, **fields) -> None:
        """Update fields on a WireGuard interface (listen-port, mtu, etc.)."""
        iface = await self.get_wireguard_interface(name)
        if iface:
            await self._request("PATCH", f"{_REST}/{iface['.id']}", fields)

    # ------------------------------------------------------------------- peers
    async def get_peers(self, interface: str | None = None) -> list[dict]:
        path = _REST_PEERS if interface is None else f"{_REST_PEERS}?interface={interface}"
        return await self._request("GET", path)

    async def get_peer(self, interface: str, peer_id: str) -> dict | None:
        data = await self._request("GET", f"{_REST_PEERS}?interface={interface}&.id={peer_id}")
        return data[0] if data else None

    async def create_peer(
        self,
        interface: str,
        name: str,
        public_key: str,
        allowed_address: str,
        client_address: str,
        private_key: str = "",
        persistent_keepalive: int = 15,
        responder: bool = True,
        client_dns: str = "",
        client_endpoint: str = "",
        client_keepalive: int = 15,
        client_listen_port: int = 51820,
        client_allowed_address: str = "0.0.0.0/0",
        comment: str = "",
    ) -> dict:
        payload: dict[str, Any] = {
            "name": name,
            "interface": interface,
            "public-key": public_key,
            "allowed-address": allowed_address,
            "client-address": client_address,
            "persistent-keepalive": persistent_keepalive,
            "responder": "yes" if responder else "no",
            "client-allowed-address": client_allowed_address,
            "client-keepalive": client_keepalive,
            "client-listen-port": client_listen_port,
        }
        if private_key:
            payload["private-key"] = private_key
        if client_dns:
            payload["client-dns"] = client_dns
        if client_endpoint:
            payload["client-endpoint"] = client_endpoint
        if comment:
            payload["comment"] = comment
        return await self._request("PUT", _REST_PEERS, payload)

    async def update_peer(self, peer_id: str, **fields: Any) -> None:
        await self._request("PATCH", f"{_REST_PEERS}/{peer_id}", fields)

    async def set_peer_disabled(self, peer_id: str, disabled: bool) -> None:
        await self.update_peer(peer_id, disabled=bool(disabled))

    async def delete_peer(self, peer_id: str) -> None:
        await self._request("DELETE", f"{_REST_PEERS}/{peer_id}")

    # -------------------------------------------------------------- ip address
    async def add_ip_address(self, address: str, interface: str, comment: str = "") -> dict:
        payload: dict[str, Any] = {"address": address, "interface": interface}
        if comment:
            payload["comment"] = comment
        return await self._request("PUT", _REST_IP_ADDR, payload)

    async def get_ip_addresses(self, interface: str) -> list[dict]:
        return await self._request("GET", f"{_REST_IP_ADDR}?interface={interface}")

    async def remove_ip_address(self, interface: str) -> None:
        for addr in await self.get_ip_addresses(interface):
            await self._request("DELETE", f"{_REST_IP_ADDR}/{addr['.id']}")

    # --------------------------------------------------------------- firewall
    async def get_firewall_rules(self) -> list[dict]:
        return await self._request("GET", "ip/firewall/filter")

    async def add_firewall_rule(
        self, comment: str, place_before: str = "0", **fields
    ) -> dict:
        payload: dict[str, Any] = {"comment": comment, "place-before": place_before}
        payload.update(fields)
        return await self._request("PUT", "ip/firewall/filter", payload)

    async def update_firewall_rule(self, rule_id: str, **fields: Any) -> None:
        await self._request("PATCH", f"ip/firewall/filter/{rule_id}", fields)

    async def delete_firewall_rule(self, rule_id: str) -> None:
        await self._request("DELETE", f"ip/firewall/filter/{rule_id}")

    async def get_firewall_nat_rules(self) -> list[dict]:
        return await self._request("GET", "ip/firewall/nat")

    async def add_firewall_nat_rule(
        self, comment: str, place_before: str = "0", **fields
    ) -> dict:
        payload: dict[str, Any] = {"comment": comment, "place-before": place_before}
        payload.update(fields)
        return await self._request("PUT", "ip/firewall/nat", payload)

    async def delete_firewall_nat_rule(self, rule_id: str) -> None:
        await self._request("DELETE", f"ip/firewall/nat/{rule_id}")

    # --------------------------------------------------------- address lists
    async def get_address_list_entries(self, list_name: str) -> list[dict]:
        return await self._request(
            "GET", f"ip/firewall/address-list?list={list_name}"
        )

    async def add_address_list_entry(
        self, address: str, list_name: str, comment: str = ""
    ) -> dict:
        payload: dict[str, Any] = {"address": address, "list": list_name}
        if comment:
            payload["comment"] = comment
        return await self._request("PUT", "ip/firewall/address-list", payload)

    async def remove_address_list_entry(self, entry_id: str) -> None:
        await self._request("DELETE", f"ip/firewall/address-list/{entry_id}")

    # ------------------------------------------------------------------ system
    async def get_identity(self) -> str:
        data = await self._request("GET", "system/identity")
        return data[0].get("name", "") if isinstance(data, list) else ""

    async def ping(self) -> bool:
        """Verify credentials and connectivity."""
        try:
            await self.get_identity()
            return True
        except RouterOSError:
            return False
