"""In-memory contact storage compatible with MeshNode's contacts interface."""

from __future__ import annotations

from typing import Iterable, Iterator, Optional, Tuple

from .constants import ADV_TYPE_NONE, DEFAULT_MAX_CONTACTS, MAX_ANON_CONTACTS
from .models import Contact


class ContactProxy:
    """Wraps a Contact to provide the interface expected by MeshNode handlers.

    The existing handlers expect contacts with:
    - public_key as a hex string (not bytes)
    - name as a string
    - out_path as a list
    - type as an int
    """

    def __init__(self, contact: Contact):
        self._contact = contact
        self.public_key = contact.public_key.hex()
        self.name = contact.name
        self.type = contact.adv_type
        self.flags = contact.flags
        self.out_path = list(contact.out_path) if contact.out_path else []
        self.out_path_len = contact.out_path_len
        self.sync_since = contact.sync_since
        self.last_advert_timestamp = contact.last_advert_timestamp
        self.lastmod = contact.lastmod
        self.gps_lat = contact.gps_lat
        self.gps_lon = contact.gps_lon

    @property
    def public_key_bytes(self) -> bytes:
        """Public key as raw bytes (the proxy stores it as a hex string)."""
        return bytes.fromhex(self.public_key)

    @property
    def dest_hash(self) -> int:
        """First public-key byte — the destination hash used on the wire."""
        return self.public_key_bytes[0]


class ContactStore:
    """In-memory contact storage compatible with MeshNode's contacts interface.

    Provides both the interface expected by MeshNode/Dispatcher (contacts property,
    get_by_name, list_contacts) and companion radio CRUD operations (add, update,
    remove, get_by_key, etc.).

    The store can be populated from external sources using load_from() or
    load_from_dicts() for easy integration with databases and configuration files.
    """

    def __init__(self, max_contacts: int = DEFAULT_MAX_CONTACTS):
        self._contacts: dict[bytes, Contact] = {}  # keyed by public_key bytes
        self._proxies: dict[bytes, ContactProxy] = {}  # cached proxies
        self._max_contacts = max_contacts

    @property
    def max_contacts(self) -> int:
        """Maximum number of contacts (read-only). Used by companion protocol device info."""
        return self._max_contacts

    # ------------------------------------------------------------------
    # Interface expected by MeshNode/Dispatcher/Handlers
    # ------------------------------------------------------------------

    @property
    def contacts(self) -> list:
        """Return contacts as list of proxy objects with hex public_key attribute."""
        return list(self._proxies.values())

    def list_contacts(self) -> list:
        """Return contacts list (used by ProtocolResponseHandler)."""
        return self.contacts

    def get_by_name(self, name: str) -> Optional[ContactProxy]:
        """Lookup by name (required by MeshNode._get_contact_or_raise)."""
        for proxy in self._proxies.values():
            if proxy.name == name:
                return proxy
        return None

    def get_proxy_by_key(self, public_key: bytes) -> Optional[ContactProxy]:
        """Lookup the ContactProxy by full 32-byte public key.

        Preferred over get_by_name for transient/anon contacts, whose name is
        empty and would otherwise collide with any other empty-named contact.
        """
        return self._proxies.get(public_key)

    # ------------------------------------------------------------------
    # Companion radio CRUD operations
    # ------------------------------------------------------------------

    def add(self, contact: Contact) -> bool:
        """Add a new contact. Returns False if store is full or key already exists."""
        if contact.public_key in self._contacts:
            return self.update(contact)
        if len(self._contacts) >= self._max_contacts:
            return False
        self._contacts[contact.public_key] = contact
        self._proxies[contact.public_key] = ContactProxy(contact)
        return True

    def add_or_overwrite(self, contact: Contact) -> Tuple[bool, Optional[bytes]]:
        """Add a contact, overwriting the oldest non-favourite if store is full.

        Mirrors C++ BaseChatMesh::allocateContactSlot (BaseChatMesh.cpp:70-90).

        Returns:
            (success, overwritten_pubkey_or_None)
        """
        if contact.public_key in self._contacts:
            return self.update(contact), None
        if len(self._contacts) >= self._max_contacts:
            # Find oldest non-favourite
            oldest_key: Optional[bytes] = None
            oldest_lastmod = 0xFFFFFFFF
            for key, c in self._contacts.items():
                # Exclude transient/anon entries: real contacts never evict an
                # anon slot, mirroring firmware allocateContactSlot (non-transient).
                if (
                    not c.is_favourite
                    and c.adv_type != ADV_TYPE_NONE
                    and c.lastmod < oldest_lastmod
                ):
                    oldest_lastmod = c.lastmod
                    oldest_key = key
            if oldest_key is None:
                return False, None  # all contacts are favourites
            overwritten = oldest_key
            self.remove(oldest_key)
            self._contacts[contact.public_key] = contact
            self._proxies[contact.public_key] = ContactProxy(contact)
            return True, overwritten
        self._contacts[contact.public_key] = contact
        self._proxies[contact.public_key] = ContactProxy(contact)
        return True, None

    def add_transient(self, contact: Contact) -> bool:
        """Add a transient (ADV_TYPE_NONE) anon-request contact.

        Mirrors firmware allocateContactSlot(transient_only=True): the anon pool
        is capped at MAX_ANON_CONTACTS, reusing the oldest transient slot (by
        lastmod) when full. Real contacts are never evicted.

        Returns True on success, False only if the call is somehow misused.
        """
        if contact.public_key in self._contacts:
            return self.update(contact)
        anon_keys = [k for k, c in self._contacts.items() if c.adv_type == ADV_TYPE_NONE]
        if len(anon_keys) >= MAX_ANON_CONTACTS:
            oldest_key = min(anon_keys, key=lambda k: self._contacts[k].lastmod)
            self.remove(oldest_key)
        self._contacts[contact.public_key] = contact
        self._proxies[contact.public_key] = ContactProxy(contact)
        return True

    def update(self, contact: Contact) -> bool:
        """Update an existing contact. Returns False if not found."""
        if contact.public_key not in self._contacts:
            return self.add(contact)
        self._contacts[contact.public_key] = contact
        self._proxies[contact.public_key] = ContactProxy(contact)
        return True

    def remove(self, public_key: bytes) -> bool:
        """Remove a contact by public key. Returns False if not found."""
        if public_key not in self._contacts:
            return False
        del self._contacts[public_key]
        del self._proxies[public_key]
        return True

    def get_by_key(self, public_key: bytes) -> Optional[Contact]:
        """Lookup a contact by full 32-byte public key."""
        return self._contacts.get(public_key)

    def get_by_key_prefix(self, prefix: bytes) -> Optional[Contact]:
        """Lookup a contact by public key prefix (1-32 bytes)."""
        for key, contact in self._contacts.items():
            if key[: len(prefix)] == prefix:
                return contact
        return None

    def get_all(self, since: int = 0) -> list[Contact]:
        """Get all contacts, optionally filtered by lastmod >= since."""
        if since == 0:
            return list(self._contacts.values())
        return [c for c in self._contacts.values() if c.lastmod >= since]

    def get_count(self) -> int:
        """Return the number of stored contacts."""
        return len(self._contacts)

    def count(self) -> int:
        """Return the real contact count for CONTACTS_START (firmware getNumContacts()).

        Excludes transient/anon (ADV_TYPE_NONE) entries, matching get_all()/
        get_contacts filtering: firmware has no transient contacts, so the total
        must equal the number of contacts actually emitted on a full sync.
        """
        return sum(1 for c in self._contacts.values() if c.adv_type != ADV_TYPE_NONE)

    def is_full(self) -> bool:
        """Check if the contact store is at capacity."""
        return len(self._contacts) >= self._max_contacts

    def clear(self) -> None:
        """Remove all contacts."""
        self._contacts.clear()
        self._proxies.clear()

    # ------------------------------------------------------------------
    # Bulk loading from external sources
    # ------------------------------------------------------------------

    def load_from(self, contacts: Iterable[Contact]) -> None:
        """Bulk-load contacts from any iterable of Contact objects.

        Replaces all existing contacts.
        """
        self.clear()
        for contact in contacts:
            if len(self._contacts) >= self._max_contacts:
                break
            self._contacts[contact.public_key] = contact
            self._proxies[contact.public_key] = ContactProxy(contact)

    def load_from_dicts(self, records: Iterable[dict]) -> None:
        """Bulk-load contacts from dicts.

        Each dict must have 'public_key' (hex string or bytes) and 'name' keys.
        Optional keys: 'adv_type', 'flags', 'out_path', 'out_path_len',
        'last_advert_timestamp', 'lastmod', 'gps_lat', 'gps_lon', 'sync_since',
        'last_advert_packet' (hex string of raw ADVERT wire bytes for CMD_SHARE_CONTACT).

        Replaces all existing contacts.
        """
        self.clear()
        for rec in records:
            if len(self._contacts) >= self._max_contacts:
                break

            pub_key = rec["public_key"]
            if isinstance(pub_key, str):
                pub_key = bytes.fromhex(pub_key)

            out_path = rec.get("out_path", b"")
            if isinstance(out_path, str):
                out_path = bytes.fromhex(out_path)
            elif isinstance(out_path, list):
                out_path = bytes(out_path)

            lap = rec.get("last_advert_packet")
            if isinstance(lap, str) and lap:
                try:
                    last_advert_packet = bytes.fromhex(lap)
                except ValueError:
                    last_advert_packet = None
            elif isinstance(lap, (bytes, bytearray)):
                last_advert_packet = bytes(lap)
            else:
                last_advert_packet = None
            contact = Contact(
                public_key=pub_key,
                name=rec.get("name", ""),
                adv_type=rec.get("adv_type", 0),
                flags=rec.get("flags", 0),
                out_path_len=(
                    -1 if rec.get("out_path_len", -1) in (-1, 255) else rec.get("out_path_len", -1)
                ),
                out_path=out_path,
                last_advert_timestamp=rec.get("last_advert_timestamp", 0),
                lastmod=rec.get("lastmod", 0),
                gps_lat=rec.get("gps_lat", 0.0),
                gps_lon=rec.get("gps_lon", 0.0),
                sync_since=rec.get("sync_since", 0),
                last_advert_packet=last_advert_packet,
            )
            self._contacts[pub_key] = contact
            self._proxies[pub_key] = ContactProxy(contact)

    def to_dicts(self) -> list[dict]:
        """Export all contacts as a list of plain dicts for serialization."""
        result = []
        for c in self._contacts.values():
            # Transient/anon entries are never persisted (firmware save_filter).
            if c.adv_type == ADV_TYPE_NONE:
                continue
            result.append(
                {
                    "public_key": c.public_key.hex(),
                    "name": c.name,
                    "adv_type": c.adv_type,
                    "flags": c.flags,
                    "out_path_len": c.out_path_len,
                    "out_path": c.out_path.hex() if c.out_path else "",
                    "last_advert_timestamp": c.last_advert_timestamp,
                    "lastmod": c.lastmod,
                    "gps_lat": c.gps_lat,
                    "gps_lon": c.gps_lon,
                    "sync_since": c.sync_since,
                    "last_advert_packet": (
                        c.last_advert_packet.hex() if c.last_advert_packet else ""
                    ),
                }
            )
        return result

    # ------------------------------------------------------------------
    # Iterator (matches firmware's iterator pattern)
    # ------------------------------------------------------------------

    def iterate(self, since: int = 0) -> Iterator[Contact]:
        """Iterate over contacts, optionally filtered by lastmod >= since."""
        for contact in self._contacts.values():
            if since == 0 or contact.lastmod >= since:
                yield contact
