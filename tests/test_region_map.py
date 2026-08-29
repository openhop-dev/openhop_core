"""Tests for the lightweight RegionMap helper."""

from __future__ import annotations

from openhop_core.protocol import LocalIdentity, Packet, PacketBuilder
from openhop_core.protocol.constants import ROUTE_TYPE_TRANSPORT_FLOOD
from openhop_core.protocol.region_map import REGION_DENY_FLOOD, RegionEntry, RegionMap
from openhop_core.protocol.transport_keys import calc_transport_code, get_auto_key_for


def _make_scoped_packet(region_name: str) -> Packet:
    """Create a transport-flood advert tagged for the given public region."""
    identity = LocalIdentity()
    pkt = PacketBuilder.create_advert(
        local_identity=identity,
        name="test",
        route_type="flood",
    )
    # Derive key/code exactly as CompanionBase._apply_flood_scope does
    if not region_name.startswith("#"):
        region_name = f"#{region_name}"
    key = get_auto_key_for(region_name)
    code = calc_transport_code(key, pkt)
    pkt.transport_codes[0] = code
    pkt.transport_codes[1] = 0
    pkt.header = (pkt.header & ~0x03) | ROUTE_TYPE_TRANSPORT_FLOOD
    return pkt


class TestRegionMapMatching:
    def test_match_explicit_hashtag_name(self):
        region = RegionEntry(id=1, name="#nl-li")
        rmap = RegionMap([region])
        pkt = _make_scoped_packet("#nl-li")

        match = rmap.find_match(pkt)

        assert match is not None
        assert match.id == 1
        assert match.name == "#nl-li"

    def test_match_implicit_hashtag_name(self):
        # Firmware treats "name" and "#name" the same for auto regions.
        region = RegionEntry(id=2, name="nl-li")
        rmap = RegionMap([region])
        pkt = _make_scoped_packet("nl-li")

        match = rmap.find_match(pkt)

        assert match is not None
        assert match.id == 2
        assert match.name == "nl-li"

    def test_respects_region_deny_flag(self):
        """Region with REGION_DENY_FLOOD is ignored when mask requests flood filtering."""
        allowed = RegionEntry(id=3, name="#allowed")
        denied = RegionEntry(id=4, name="#denied", flags=REGION_DENY_FLOOD)
        rmap = RegionMap([denied, allowed])

        pkt = _make_scoped_packet("#denied")

        # With mask=0, the denied region is still eligible and should match.
        match_any = rmap.find_match(pkt, mask=0)
        assert match_any is not None
        assert match_any.id == 4

        # With REGION_DENY_FLOOD mask, denied region is skipped → no match.
        match_filtered = rmap.find_match(pkt, mask=REGION_DENY_FLOOD)
        assert match_filtered is None


class TestWildcardRegion:
    """The root Region, mirroring firmware ``RegionMap::getWildcard``."""

    def test_wildcard_defaults_allow_flood(self):
        rmap = RegionMap([RegionEntry(id=1, name="#region-a")])
        wildcard = rmap.wildcard
        assert wildcard.is_wildcard() is True
        assert wildcard.id == 0
        assert wildcard.name == "*"
        assert wildcard.flags & REGION_DENY_FLOOD == 0

    def test_wildcard_is_not_part_of_the_region_list(self):
        """Firmware holds it outside ``regions[]`` and ``findMatch`` never
        returns it, so an unresolved transport code stays unresolved."""
        rmap = RegionMap([RegionEntry(id=1, name="#region-a")])
        assert all(not r.is_wildcard() for r in rmap.regions)

        pkt = _make_scoped_packet("#not-in-map")
        assert rmap.find_match(pkt, mask=REGION_DENY_FLOOD) is None

    def test_wildcard_flags_are_configurable(self):
        rmap = RegionMap()
        rmap.wildcard.flags = REGION_DENY_FLOOD
        assert rmap.wildcard.flags & REGION_DENY_FLOOD

    def test_ordinary_regions_are_not_wildcards(self):
        assert RegionEntry(id=7, name="#region-a").is_wildcard() is False

    def test_a_registered_id_zero_region_is_treated_as_the_wildcard(self):
        """Firmware tests ``isWildcard()`` on a ``findMatch`` result before it
        resolves any key. Its ids come from ``next_id`` so id 0 never reaches
        ``regions[]``, but nothing here stops an application registering one --
        so the same precedence has to hold, or a reply firmware sends plain
        would go out scoped."""
        from openhop_core.protocol.region_map import capture_recv_region

        rmap = RegionMap([RegionEntry(id=0, name="#looks-ordinary")])
        pkt = _make_scoped_packet("#looks-ordinary")
        assert rmap.find_match(pkt, mask=REGION_DENY_FLOOD) is not None

        capture_recv_region(rmap, pkt)
        assert pkt._recv_region_key is None
        assert pkt._recv_region_unscoped is True
