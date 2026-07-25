from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree
from xml.parsers import expat

from rechnungsprobe.security import SecurityError, open_regular_file

_XINCLUDE_NAMESPACE = "http://www.w3.org/2001/XInclude"
_ATTACHMENT_LOCAL_NAME = "EmbeddedDocumentBinaryObject"


@dataclass(frozen=True, slots=True)
class XmlLimits:
    max_bytes: int = 2 * 1024 * 1024
    max_depth: int = 64
    max_elements: int = 20_000
    max_attributes: int = 50_000
    max_attributes_per_element: int = 100
    max_attribute_text: int = 64 * 1024
    max_text: int = 2 * 1024 * 1024
    max_attachment_text: int = 512 * 1024


@dataclass(frozen=True, slots=True)
class XmlDocument:
    data: bytes
    root: ElementTree.Element
    sha256: str


def _namespace_and_local(name: str) -> tuple[str, str]:
    if "}" not in name:
        return "", name
    return tuple(name.rsplit("}", 1))  # type: ignore[return-value]


def parse_xml_bytes(data: bytes, limits: XmlLimits | None = None) -> XmlDocument:
    """Parse a bounded XML document after a fail-closed Expat preflight."""

    limits = limits or XmlLimits()
    if len(data) > limits.max_bytes:
        raise SecurityError("XML exceeds the size limit")

    depth = 0
    element_count = 0
    attribute_count = 0
    text_count = 0
    element_names: list[str] = []
    element_text: list[int] = []
    parser = expat.ParserCreate(namespace_separator="}")
    parser.buffer_text = True
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)

    def reject_active_feature(*_args: object) -> int:
        raise SecurityError("DTD and entity features are not allowed")

    def start_element(name: str, attributes: dict[str, str]) -> None:
        nonlocal depth, element_count, attribute_count
        depth += 1
        element_count += 1
        attribute_count += len(attributes)
        if depth > limits.max_depth:
            raise SecurityError("XML exceeds the depth limit")
        if element_count > limits.max_elements:
            raise SecurityError("XML has too many elements")
        if len(attributes) > limits.max_attributes_per_element:
            raise SecurityError("XML element has too many attributes")
        if attribute_count > limits.max_attributes:
            raise SecurityError("XML has too many attributes")
        if any(len(value) > limits.max_attribute_text for value in attributes.values()):
            raise SecurityError("XML attribute exceeds the text limit")
        namespace, local = _namespace_and_local(name)
        if namespace == _XINCLUDE_NAMESPACE and local in {"include", "fallback"}:
            raise SecurityError("XInclude is not allowed")
        element_names.append(local)
        element_text.append(0)

    def end_element(_name: str) -> None:
        nonlocal depth
        element_names.pop()
        element_text.pop()
        depth -= 1

    def character_data(value: str) -> None:
        nonlocal text_count
        length = len(value)
        text_count += length
        if text_count > limits.max_text:
            raise SecurityError("XML exceeds the text limit")
        if element_text:
            element_text[-1] += length
            if (
                element_names[-1] == _ATTACHMENT_LOCAL_NAME
                and element_text[-1] > limits.max_attachment_text
            ):
                raise SecurityError("XML attachment exceeds the text limit")

    parser.StartDoctypeDeclHandler = reject_active_feature
    parser.EntityDeclHandler = reject_active_feature
    parser.UnparsedEntityDeclHandler = reject_active_feature
    parser.ExternalEntityRefHandler = reject_active_feature
    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element
    parser.CharacterDataHandler = character_data
    try:
        parser.Parse(data, True)
    except SecurityError:
        raise
    except expat.ExpatError as error:
        raise SecurityError(f"malformed XML: {error}") from error

    try:
        # Expat has already rejected DTD/entity/XInclude features and enforced
        # structural limits before ElementTree sees the same bounded bytes.
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as error:
        raise SecurityError(f"malformed XML: {error}") from error
    return XmlDocument(
        data=data,
        root=root,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def load_xml(path: Path, limits: XmlLimits | None = None) -> XmlDocument:
    """Read one regular, non-link XML file without crossing the size bound."""

    limits = limits or XmlLimits()
    with open_regular_file(path, max_bytes=limits.max_bytes) as source:
        data = source.read(limits.max_bytes + 1)
    return parse_xml_bytes(data, limits)
