"""Static extraction of URL references from HTML, robots.txt and XML sitemaps.

Uses only the standard-library HTML tokenizer, which tolerates broken markup.
No JavaScript is parsed or executed here (that belongs to the JavaScript
recursive crawler); inline ``<script>`` bodies are skipped entirely.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from html.parser import HTMLParser

VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "param", "source", "track", "wbr", "keygen", "command",
}
# element -> attributes carrying a single URL
URL_ATTRIBUTES = {
    "a": ("href",),
    "area": ("href",),
    "link": ("href",),
    "iframe": ("src",),
    "frame": ("src",),
    "img": ("src", "longdesc", "lowsrc", "data-src", "data-original", "data-lazy-src"),
    "script": ("src",),
    "source": ("src",),
    "video": ("src", "poster"),
    "audio": ("src",),
    "track": ("src",),
    "embed": ("src",),
    "object": ("data",),
    "input": ("src", "formaction"),
    "button": ("formaction",),
    "blockquote": ("cite",),
    "q": ("cite",),
    "ins": ("cite",),
    "del": ("cite",),
    "body": ("background",),
    "table": ("background",),
    "td": ("background",),
    "html": ("manifest",),
    "use": ("href", "xlink:href"),
    "image": ("href", "xlink:href"),
}
SRCSET_ELEMENTS = {"img", "source"}
GENERIC_DATA_ATTRIBUTES = ("data-href", "data-url", "data-link", "data-target-url", "data-redirect", "data-action")
PAGINATION_HINT = re.compile(r"pagination|pager|page-numbers|paging|next|prev|older|newer", re.IGNORECASE)
URL_LIKE_VALUE = re.compile(r"^(https?:)?//|^/[^/\s]|^\.{1,2}/|^[\w\-./]+\.(html?|php|aspx?|jsp)(\?|$)", re.IGNORECASE)


@dataclass
class ExtractedReference:
    raw_reference: str
    discovery_method: str
    element: str
    attribute: str
    context: dict = field(default_factory=dict)


@dataclass
class ExtractedForm:
    action: str
    method: str
    enctype: str
    field_names: list[str]
    hidden_fields: list[str]


class HtmlReferenceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[ExtractedReference] = []
        self.forms: list[ExtractedForm] = []
        self.base_href: str | None = None
        self.title_parts: list[str] = []
        self.meta_robots: str | None = None
        self._stack: list[tuple[str, str]] = []  # (tag, class+id hints)
        self._current_form: dict | None = None
        self._in_title = False

    # -- helpers -------------------------------------------------------------
    def _ancestor_tags(self) -> set[str]:
        return {tag for tag, _hints in self._stack}

    def _ancestor_hints(self) -> str:
        return " ".join(hints for _tag, hints in self._stack)

    def _add(self, raw: str | None, method: str, element: str, attribute: str, **context) -> None:
        if raw is None:
            return
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            return
        self.references.append(ExtractedReference(raw, method, element, attribute, context))

    def _anchor_method(self, attributes: dict[str, str | None]) -> str:
        rel = (attributes.get("rel") or "").lower()
        if "next" in rel.split() or "prev" in rel.split() or "previous" in rel.split():
            return "pagination_link"
        own_hints = f"{attributes.get('class') or ''} {attributes.get('id') or ''} {attributes.get('aria-label') or ''}"
        if PAGINATION_HINT.search(own_hints) or re.search(r"pagination|pager|page-numbers|paging", self._ancestor_hints(), re.IGNORECASE):
            return "pagination_link"
        ancestors = self._ancestor_tags()
        if "nav" in ancestors or "menu" in ancestors or re.search(r"\b(nav|navbar|menu|breadcrumb)", self._ancestor_hints(), re.IGNORECASE):
            return "navigation_link"
        if "header" in ancestors:
            return "header_link"
        if "footer" in ancestors:
            return "footer_link"
        return "anchor_link"

    # -- tokenizer callbacks -------------------------------------------------
    def handle_starttag(self, tag: str, attribute_list) -> None:
        attributes = {name.lower(): value for name, value in attribute_list}
        hints = f"{attributes.get('class') or ''} {attributes.get('id') or ''} {attributes.get('role') or ''}".strip()

        if tag == "base" and attributes.get("href") and self.base_href is None:
            self.base_href = attributes["href"].strip()
        if tag == "title":
            self._in_title = True

        if tag in ("a", "area"):
            self._add(attributes.get("href"), self._anchor_method(attributes) if tag == "a" else "image_map_area",
                      tag, "href", rel=attributes.get("rel"), text_hint=attributes.get("title") or attributes.get("aria-label"))
        elif tag == "link":
            rel = (attributes.get("rel") or "").lower().strip()
            method = "link_" + (re.sub(r"[^a-z0-9]+", "_", rel).strip("_") or "unspecified")
            if rel in ("next", "prev", "previous"):
                method = "pagination_link"
            self._add(attributes.get("href"), method, tag, "href", rel=rel, hreflang=attributes.get("hreflang"),
                      type=attributes.get("type"))
        elif tag == "meta":
            http_equivalent = (attributes.get("http-equiv") or "").lower()
            content = attributes.get("content") or ""
            if http_equivalent == "refresh":
                match = re.search(r"url\s*=\s*['\"]?([^'\";]+)", content, re.IGNORECASE)
                if match:
                    self._add(match.group(1), "meta_refresh", tag, "content")
            name = (attributes.get("name") or attributes.get("property") or "").lower()
            if name == "robots":
                self.meta_robots = content
            if name in ("og:url", "og:image", "og:video", "og:audio", "twitter:image", "twitter:url",
                        "msapplication-tileimage", "msapplication-config") and content:
                self._add(content, "meta_" + re.sub(r"[^a-z0-9]+", "_", name), tag, "content")
        elif tag == "form":
            self._current_form = {
                "action": (attributes.get("action") or "").strip(),
                "method": (attributes.get("method") or "GET").upper(),
                "enctype": attributes.get("enctype") or "application/x-www-form-urlencoded",
                "field_names": [],
                "hidden_fields": [],
            }
        else:
            for attribute in URL_ATTRIBUTES.get(tag, ()):
                if attribute in attributes:
                    method = {
                        "iframe": "iframe_source", "frame": "frame_source", "script": "script_source_reference",
                        "img": "image_source", "embed": "embedded_object", "object": "embedded_object",
                        "button": "form_button_action", "input": "form_button_action" if attribute == "formaction" else "image_input_source",
                        "html": "application_cache_manifest",
                    }.get(tag, f"{tag}_{attribute.replace(':', '_')}")
                    if tag in ("video", "audio", "source", "track"):
                        method = "media_source"
                    self._add(attributes.get(attribute), method, tag, attribute)

        if tag in SRCSET_ELEMENTS:
            for attribute in ("srcset", "data-srcset"):
                for candidate in (attributes.get(attribute) or "").split(","):
                    candidate = candidate.strip().split(" ")[0]
                    self._add(candidate, "image_srcset", tag, attribute)

        for attribute in GENERIC_DATA_ATTRIBUTES:
            value = attributes.get(attribute)
            if value and URL_LIKE_VALUE.search(value.strip()):
                self._add(value, "data_attribute", tag, attribute)

        if tag in ("input", "select", "textarea", "button") and self._current_form is not None:
            name = attributes.get("name")
            if name:
                self._current_form["field_names"].append(name)
                if (attributes.get("type") or "").lower() == "hidden":
                    self._current_form["hidden_fields"].append(name)

        if tag not in VOID_ELEMENTS:
            self._stack.append((tag, hints))

    def handle_startendtag(self, tag, attribute_list) -> None:
        self.handle_starttag(tag, attribute_list)
        if tag not in VOID_ELEMENTS and self._stack and self._stack[-1][0] == tag:
            self._stack.pop()

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag == "form" and self._current_form is not None:
            form = self._current_form
            self.forms.append(ExtractedForm(form["action"], form["method"], form["enctype"],
                                            list(dict.fromkeys(form["field_names"])),
                                            list(dict.fromkeys(form["hidden_fields"]))))
            self._current_form = None
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index][0] == tag:
                del self._stack[index:]
                break

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)

    def close(self) -> None:
        super().close()
        if self._current_form is not None:  # unclosed form
            self.handle_endtag("form")

    @property
    def title(self) -> str:
        return " ".join("".join(self.title_parts).split())[:300]


def extract_from_html(html: str) -> HtmlReferenceParser:
    parser = HtmlReferenceParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - the stdlib tokenizer can raise on pathological input
        pass
    return parser


def extract_from_robots(text: str) -> list[ExtractedReference]:
    references = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        directive, value = line.split(":", 1)
        directive, value = directive.strip().lower(), value.strip()
        if not value:
            continue
        if directive == "sitemap":
            references.append(ExtractedReference(value, "robots_sitemap", "robots.txt", "Sitemap"))
        elif directive in ("allow", "disallow"):
            # Strip robots wildcards; keep the literal prefix as a path reference.
            literal = re.split(r"[*$]", value, maxsplit=1)[0]
            if literal and literal != "/":
                references.append(ExtractedReference(literal, f"robots_{directive}", "robots.txt", directive.capitalize()))
    return references


def extract_from_sitemap(text: str) -> tuple[list[ExtractedReference], bool]:
    """Return references and whether the document was a sitemap index."""
    references: list[ExtractedReference] = []
    try:
        root = ElementTree.fromstring(text.strip().encode("utf-8"))
    except ElementTree.ParseError:
        # Plain-text sitemaps: one URL per line.
        for line in text.splitlines():
            line = line.strip()
            if line.startswith(("http://", "https://")):
                references.append(ExtractedReference(line, "sitemap_text_entry", "sitemap", "line"))
        return references, False
    is_index = root.tag.lower().endswith("sitemapindex")
    for element in root.iter():
        tag = element.tag.split("}", 1)[-1].lower()
        if tag == "loc" and element.text:
            references.append(ExtractedReference(element.text.strip(), "sitemap_index_entry" if is_index else "sitemap_entry",
                                                 "sitemap", "loc"))
        elif tag == "link" and element.get("href"):
            references.append(ExtractedReference(element.get("href"), "sitemap_alternate", "sitemap", "xhtml:link"))
    return references, is_index
