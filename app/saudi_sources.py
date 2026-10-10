"""Public-source connectors using only Python's standard library.

External text is untrusted data. This module never evaluates JavaScript, invokes
an LLM, follows arbitrary links, logs in, or bypasses access controls. No cloud
API or payment is required. Fetches are opt-in by calling ``refresh``.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import html
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urljoin, urlsplit, urlunsplit, unquote
from urllib.robotparser import RobotFileParser

USER_AGENT = "SaudiBidPilot/1.0 (+public-procurement-research; GET-only)"
ZERO_COST_ONLY = True
MAX_BYTES = 2 * 1024 * 1024
SOURCE_STATUSES = {"LIVE", "AUTH_REQUIRED", "BLOCKED", "DEGRADED", "MANUAL_IMPORT", "UNAVAILABLE"}
ALLOWED_HOSTS = frozenset({"tenders.etimad.sa", "ncp.gov.sa", "jazanpl.rcjy.gov.sa", "taqeem.gov.sa", "ksau-hs.edu.sa", "www.geosa.gov.sa"})


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    url: str
    hosts: tuple[str, ...]
    connector: str


SOURCES = (
    Source("etimad", "اعتماد", "https://tenders.etimad.sa/Tender/AllTendersForVisitor", ("tenders.etimad.sa",), "etimad"),
    Source("ncp", "المركز الوطني للتخصيص", "https://ncp.gov.sa/en/MediaCenter/News/Pages/default.aspx", ("ncp.gov.sa",), "ncp"),
    Source("rcjy-jazan", "الهيئة الملكية — جازان", "https://jazanpl.rcjy.gov.sa/Brochures", ("jazanpl.rcjy.gov.sa",), "rcjy"),
    Source("taqeem", "الهيئة السعودية للمقيمين المعتمدين", "https://taqeem.gov.sa/en/tenders?status=current", ("taqeem.gov.sa",), "taqeem"),
    Source("ksau-hs", "جامعة الملك سعود بن عبدالعزيز للعلوم الصحية", "https://ksau-hs.edu.sa/Arabic/UniversityBiddings/Pages/default.aspx", ("ksau-hs.edu.sa",), "ksau"),
    Source("geosa", "الهيئة العامة للمساحة والمعلومات الجيومكانية", "https://www.geosa.gov.sa/ar/Pages/Tenders.aspx", ("www.geosa.gov.sa",), "geosa"),
)


class FetchError(Exception):
    def __init__(self, status: str, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def safe_url(url: str, hosts: tuple[str, ...] | frozenset[str] = ALLOWED_HOSTS) -> str:
    """Allow only HTTPS and exact configured hosts; no credentials or custom port."""
    if not isinstance(url, str) or len(url) > 4096 or any(ord(x) < 32 for x in url):
        raise FetchError("BLOCKED", "invalid_url")
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise FetchError("BLOCKED", "invalid_port") from exc
    if parsed.scheme != "https" or parsed.hostname not in hosts or parsed.username or parsed.password or port not in (None, 443):
        raise FetchError("BLOCKED", "url_not_allowlisted")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


@dataclass
class Node:
    tag: str
    attrs: dict[str, str] = field(default_factory=dict)
    parent: "Node | None" = None
    children: list["Node | str"] = field(default_factory=list)

    def text(self) -> str:
        if self.tag in {"script", "style", "noscript"}:
            return ""
        return normalize(" ".join(c.text() if isinstance(c, Node) else c for c in self.children))

    def nodes(self):
        yield self
        for child in self.children:
            if isinstance(child, Node):
                yield from child.nodes()

    def has_class(self, class_name: str) -> bool:
        return class_name in self.attrs.get("class", "").split()


class Document(HTMLParser):
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self, value: str):
        super().__init__(convert_charrefs=True)
        self.root = Node("document")
        self.stack = [self.root]
        self.feed(value)

    def handle_starttag(self, tag, attrs):
        node = Node(tag, dict((k, v or "") for k, v in attrs), self.stack[-1])
        self.stack[-1].children.append(node)
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                self.stack = self.stack[:i]
                return

    def handle_data(self, data):
        self.stack[-1].children.append(data)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Pin the public DNS address and retain TLS certificate/SNI host validation."""

    def __init__(self, hostname: str, address: str, timeout: float):
        super().__init__(hostname, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, 443), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


@dataclass
class Response:
    url: str
    body: str
    http_status: int
    content_type: str


class PublicFetcher:
    """Small, bounded HTTP client. Every redirect rechecks DNS, URL, and robots."""

    def __init__(self, timeout: float = 12, interval: float = 2, retries: int = 1):
        self.timeout = min(max(timeout, 1), 30)
        self.interval = max(interval, 1)
        self.retries = min(max(retries, 0), 2)
        self.last_requests: dict[str, float] = {}
        self.robots: dict[str, RobotFileParser] = {}

    def _request(self, url: str, hosts) -> tuple[int, dict[str, str], bytes]:
        url = safe_url(url, hosts)
        parsed = urlsplit(url)
        hostname = parsed.hostname
        try:
            addresses = {x[4][0] for x in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise FetchError("UNAVAILABLE", "dns_resolution_failed") from exc
        if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
            raise FetchError("BLOCKED", "non_public_dns_address")
        elapsed = time.monotonic() - self.last_requests.get(hostname, 0)
        if elapsed < self.interval:
            if self.interval - elapsed > 30:
                raise FetchError("DEGRADED", "crawl_delay_requires_later_run")
            time.sleep(self.interval - elapsed)
        self.last_requests[hostname] = time.monotonic()
        last_error = None
        for attempt in range(self.retries + 1):
            connection = PinnedHTTPSConnection(hostname, sorted(addresses)[0], self.timeout)
            try:
                connection.request("GET", urlunsplit(("", "", parsed.path or "/", parsed.query, "")), headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/json,text/plain;q=0.8", "Accept-Encoding": "identity"})
                response = connection.getresponse()
                headers = {k.lower(): v for k, v in response.getheaders()}
                if int(headers.get("content-length", "0")) > MAX_BYTES:
                    raise FetchError("DEGRADED", "response_too_large")
                body = response.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise FetchError("DEGRADED", "response_too_large")
                if response.status in (429, 500, 502, 503, 504) and attempt < self.retries:
                    retry_after = headers.get("retry-after", "")
                    if retry_after.isdigit() and int(retry_after) > 4:
                        raise FetchError("DEGRADED", "retry_after_requires_later_run")
                    time.sleep(min(max(int(retry_after or 0) if retry_after.isdigit() else 0, 2 ** attempt), 4))
                    continue
                return response.status, headers, body
            except (OSError, http.client.HTTPException, ValueError) as exc:
                last_error = exc
                if attempt < self.retries:
                    time.sleep(2 ** attempt)
            finally:
                connection.close()
        raise FetchError("UNAVAILABLE", "network_or_tls_failure") from last_error

    def _check_robots(self, url: str, hosts):
        origin = "https://" + urlsplit(url).hostname
        if origin not in self.robots:
            status, headers, body = self._request(origin + "/robots.txt", hosts)
            parser = RobotFileParser()
            parser.set_url(origin + "/robots.txt")
            if status in (404, 410):
                parser.parse([])
            elif status == 200:
                parser.parse(body.decode("utf-8", "replace").splitlines())
            elif status in (401, 403):
                raise FetchError("BLOCKED", "robots_access_denied")
            else:
                raise FetchError("DEGRADED", "robots_policy_unavailable")
            self.robots[origin] = parser
        parser = self.robots[origin]
        if not parser.can_fetch(USER_AGENT, url):
            raise FetchError("BLOCKED", "robots_disallow")
        delay = parser.crawl_delay(USER_AGENT)
        if delay is not None:
            self.interval = max(self.interval, delay)

    def fetch(self, url: str, hosts=ALLOWED_HOSTS) -> Response:
        url = safe_url(url, hosts)
        for _ in range(4):
            self._check_robots(url, hosts)
            status, headers, body = self._request(url, hosts)
            if status in (301, 302, 303, 307, 308):
                url = safe_url(urljoin(url, headers.get("location", "")), hosts)
                if re.search(r"/(login|sign[-_]?in|auth)(?:[/?.]|$)", urlsplit(url).path, re.I):
                    raise FetchError("AUTH_REQUIRED", "redirect_to_authentication")
                continue
            if status == 401:
                raise FetchError("AUTH_REQUIRED", "http_401")
            if status in (403, 451):
                raise FetchError("BLOCKED", "http_" + str(status))
            if status == 429:
                raise FetchError("DEGRADED", "rate_limited")
            if status < 200 or status >= 300:
                raise FetchError("UNAVAILABLE", "http_" + str(status))
            content_type = headers.get("content-type", "text/html").split(";")[0].lower()
            if content_type not in ("text/html", "application/xhtml+xml", "application/json", "text/plain"):
                raise FetchError("DEGRADED", "unsupported_content_type")
            charset = re.search(r"charset=([\w-]+)", headers.get("content-type", ""), re.I)
            try:
                value = body.decode(charset.group(1) if charset else "utf-8", "replace")
            except LookupError:
                value = body.decode("utf-8", "replace")
            if re.search(r"<title>\s*(Just a moment|Access Denied|Attention Required)|id=[\"']challenge-form", value, re.I):
                raise FetchError("BLOCKED", "access_challenge")
            return Response(url, value, status, content_type)
        raise FetchError("DEGRADED", "too_many_redirects")


def node_pairs(root: Node, label_class: str) -> dict[str, str]:
    values = {}
    for node in root.nodes():
        if not node.has_class(label_class) or not node.parent:
            continue
        siblings = [c for c in node.parent.children if isinstance(c, Node)]
        pos = siblings.index(node)
        if pos + 1 < len(siblings):
            values[node.text().rstrip(":")] = siblings[pos + 1].text()
    return values


MONTHS = {name.lower(): i for i, name in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
MONTHS.update({"يناير": 1, "فبراير": 2, "مارس": 3, "أبريل": 4, "ابريل": 4, "مايو": 5, "يونيو": 6, "يوليو": 7, "أغسطس": 8, "اغسطس": 8, "سبتمبر": 9, "أكتوبر": 10, "اكتوبر": 10, "نوفمبر": 11, "ديسمبر": 12})


def parse_date(value: str | None) -> str | None:
    """Only explicit Gregorian dates. No inferred year or Hijri conversion."""
    if not value:
        return None
    value = value.translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789"))
    iso = re.search(r"\b(20\d{2})-(\d{1,2})-(\d{1,2})\b", value)
    written = re.search(r"\b(\d{1,2})\s+([A-Za-z\u0600-\u06ff]+)\s+(20\d{2})\b", value)
    numeric = re.search(r"\b(\d{1,2})[/-](\d{1,2})[/-](20\d{2})\b", value)
    try:
        if iso:
            year, month, day = map(int, iso.groups())
        elif written and written.group(2).lower() in MONTHS:
            day, year = int(written.group(1)), int(written.group(3))
            month = MONTHS[written.group(2).lower()]
        elif numeric:
            day, month, year = map(int, numeric.groups())
        else:
            return None
        date = dt.date(year, month, day)
        clock = re.search(r"\b(\d{1,2}):(\d{2})\s*(AM|PM|ص|م)\b", value, re.I)
        if clock:
            hour, minute = int(clock.group(1)), int(clock.group(2))
            if hour > 12 or hour < 1 or minute > 59:
                return None
            hour = hour % 12 + (12 if clock.group(3).upper() in ("PM", "م") else 0)
            return dt.datetime(year, month, day, hour, minute, tzinfo=dt.timezone(dt.timedelta(hours=3))).isoformat()
        return date.isoformat()
    except ValueError:
        return None


def opportunity_status(raw: str | None, deadline: str | None, today: str | None = None) -> str:
    raw = (raw or "").casefold()
    if any(x in raw for x in ("cancel", "إلغاء", "الإلغاء", "ملغ")):
        return "cancelled"
    if any(x in raw for x in ("award", "ترسيت", "الترسية")):
        return "awarded"
    if any(x in raw for x in ("closed", "ended", "منتهي", "انتهى", "إنتهى", "مغلق")):
        return "closed"
    if deadline and deadline[:10] < (today or dt.date.today().isoformat()):
        return "closed"
    if deadline and "T" in deadline and today is None:
        try:
            when = dt.datetime.fromisoformat(deadline)
            if when.tzinfo and when < dt.datetime.now(dt.timezone.utc):
                return "closed"
        except ValueError:
            pass
    if any(x in raw for x in ("active", "نشط", "تقديم العروض")) or (raw.strip()=="معتمدة" and deadline):
        return "open"
    return "unknown"


def classify_sector(title: str, description: str = "") -> str:
    """Deterministic transparent classification, not a claim of legal eligibility."""
    value = (title + " " + description).casefold()
    keywords = (
        ("housekeeping", ("housekeeping", "تدبير فندق", "تنظيف الغرف")),
        ("manpower", ("manpower", "توريد العمالة", "توفير العمالة", "القوى العاملة")),
        ("hotel", ("hotel", "resort", "فندق", "فنادق", "منتجع", "ضيافة")),
        ("maintenance", ("صيانة", "تشغيل", "maintenance", "operation", "facility", "مرافق")),
        ("construction", ("إنشاء", "انشاء", "مقاولات", "construction", "infrastructure", "تشطيب", "بنية تحتية")),
        ("cleaning", ("تنظيف", "نظافة", "cleaning")),
        ("catering", ("إعاشة", "اعاشة", "تموين", "catering")),
        ("security", ("حراسة", "security", "أمن", "امن")),
        ("laundry", ("مغاسل", "غسيل", "laundry")),
        ("logistics", ("نقل", "لوجست", "logistic", "transport")),
        ("waste", ("نفايات", "waste")),
        ("landscaping", ("حدائق", "landscap")),
    )
    return next((sector for sector, words in keywords if any(word in value for word in words)), "services")


def empty_record(source: Source, title: str, url: str, verified: str) -> dict:
    return {"title": title, "organization": source.name, "kind": "tender", "sector": classify_sector(title), "city": None, "published_at": None, "deadline": None, "status": "unknown", "reference": None, "description": None, "requirements": None, "documents": [], "fee": None, "source_url": safe_url(url, source.hosts), "apply_url": None, "registration_url": None, "login_required": False, "last_verified": verified, "confidence": 0.75, "source_id": source.id}


def parse_taqeem_list(value: str, url: str, verified: str) -> list[dict]:
    source = next(s for s in SOURCES if s.id == "taqeem")
    root = Document(value).root
    records = []
    seen = set()
    for link in root.nodes():
        href = link.attrs.get("href", "")
        if link.tag != "a" or not re.fullmatch(r"/(?:en/|ar/)?tenders/(?:[\w-]+-)?\d+", href):
            continue
        candidate = link.parent
        title_node = None
        for _ in range(8):
            if candidate is None:
                break
            title_node = next((n for n in candidate.nodes() if n.has_class("ot-overflow")), None)
            if title_node:
                break
            candidate = candidate.parent
        if not candidate or not title_node:
            continue
        title = title_node.text()
        detail_url = safe_url(urljoin(url, href), source.hosts)
        if detail_url in seen or not title or "{{" in title:
            continue
        seen.add(detail_url)
        record = empty_record(source, title, detail_url, verified)
        publication = next((n for n in candidate.nodes() if n.attrs.get("data-oe-expression") == "tender.publish_date"), None)
        deadline = next((n for n in candidate.nodes() if n.attrs.get("data-oe-expression") == "tender.deadline_submitting_offers"), None)
        status_node = next((n for n in candidate.nodes() if any(n.has_class(c) for c in ("ot-rec-active", "ot-rec-cancelled", "ot-rec-ended"))), None)
        reference = re.search(r"\bPRCOMP\d+\b", candidate.text())
        description = next((n for n in candidate.nodes() if n.has_class("text-lg-1-webkit")), None)
        record.update(published_at=parse_date(publication.parent.text()) if publication else None, deadline=parse_date(deadline.parent.text()) if deadline else None, reference=reference.group() if reference else None, description=description.text() if description else None)
        record["status"] = opportunity_status(status_node.text() if status_node else None, record["deadline"])
        record["sector"] = classify_sector(title, record["description"] or "")
        records.append(record)
    return records


def parse_taqeem_detail(value: str, url: str, verified: str) -> list[dict]:
    source = next(s for s in SOURCES if s.id == "taqeem")
    root = Document(value).root
    main = next((n for n in root.nodes() if n.tag == "main"), root)
    title_node = next((n for n in main.nodes() if n.has_class("text-l-bold") and n.has_class("text-dark")), None)
    if not title_node:
        return []
    title = title_node.text()
    if title in ("Tenders", "المنافسات") or "{{" in title:
        return []
    pairs = node_pairs(main, "bg-card")
    record = empty_record(source, title, url, verified)
    def get(*labels):
        return next((pairs[x] for x in labels if pairs.get(x)), None)
    record.update(reference=get("Tender number", "رقم المنافسة"), description=get("Purpose of the tender", "الغرض من المنافسة"), deadline=parse_date(get("Deadline for submitting offers", "آخر موعد لتقديم العروض", "الموعد النهائي لتقديم العروض", "آخر موعد لاستلام العروض")), requirements=get("Mechanism for submitting offers", "آلية تقديم العروض"), fee=get("Documents fees", "قيمة وثائق المنافسة"), confidence=0.94)
    record["status"] = opportunity_status(get("Tender status", "حالة المنافسة"), record["deadline"])
    record["sector"] = classify_sector(title, record["description"] or "")
    for n in main.nodes():
        if n.tag == "a" and "/web/content/portal.tender/" in n.attrs.get("href", ""):
            doc_url = safe_url(urljoin(url, n.attrs["href"]), source.hosts)
            record["documents"].append({"title": unquote(urlsplit(doc_url).path.rsplit("/", 1)[-1]), "url": doc_url})
    # A published email submission procedure is preserved in requirements.
    # It is never converted into a fabricated online application URL.
    return [record]


def parse_etimad_detail(value: str, url: str, verified: str) -> list[dict]:
    source = next(s for s in SOURCES if s.id == "etimad")
    root = Document(value).root
    pairs = node_pairs(root, "etd-item-title")
    title = pairs.get("اسم المنافسة")
    if not title or "{{" in title:
        return []
    record = empty_record(source, title, url, verified)
    purpose_node = next((n for n in root.nodes() if n.attrs.get("id") == "purposeSpan"), None)
    record.update(organization=pairs.get("الجهة الحكوميه") or pairs.get("الجهة الحكومية") or source.name, reference=pairs.get("الرقم المرجعي") or pairs.get("رقم المنافسة"), description=purpose_node.text() if purpose_node else pairs.get("الغرض من المنافسة"), fee=pairs.get("قيمة وثائق المنافسة"), deadline=parse_date(pairs.get("آخر موعد لتقديم العروض")), published_at=parse_date(pairs.get("تاريخ النشر")), login_required=True, confidence=0.90)
    original_deadline=next((n.attrs.get('value') for n in root.nodes() if n.tag=='input' and n.attrs.get('id')=='lastOfferPresentationDate'),None)
    if original_deadline:record['deadline']=parse_date(original_deadline)
    record["status"] = opportunity_status(pairs.get("حالة المنافسة"), record["deadline"])
    record["sector"] = classify_sector(title, record["description"] or "")
    record["requirements"] = "\n".join(f"{k}: {v}" for k, v in pairs.items() if k in ("طريقة تقديم العروض", "مطلوب ضمان الإبتدائي", "عنوان الضمان الإبتدائى")) or None
    return [record]


def parse_ksau_list(value: str, url: str, verified: str) -> list[dict]:
    source = next(s for s in SOURCES if s.id == "ksau-hs")
    root = Document(value).root
    table = next((n for n in root.nodes() if n.tag == "table" and n.attrs.get("id") == "tenderTable"), None)
    if not table:
        return []
    records = []
    for row in table.nodes():
        if row.tag != "tr":
            continue
        cells = [n for n in row.children if isinstance(n, Node) and n.tag == "td"]
        if len(cells) != 11:
            continue
        title = cells[1].text()
        reference = cells[3].text()
        if not title or not re.fullmatch(r"\d{12}", reference):
            continue
        record = empty_record(source, title, url, verified)
        deadline = parse_date(cells[7].text())
        record.update(reference=reference, deadline=deadline, status=opportunity_status("active" if deadline else None, deadline), fee=cells[4].text(), description=title, login_required=True, confidence=0.92)
        record["requirements"] = f"رقم المنافسة: {cells[2].text()}. آخر موعد للاستفسارات: {cells[6].text()}. مسؤول المنافسة: {cells[9].text()}. الهاتف المنشور: {cells[10].text()}. لا يعرض المصدر رابط تقديم مباشر؛ استخدم الرقم المرجعي للبحث في اعتماد."
        # The official table publishes no tender-specific href: never invent one.
        records.append(record)
    return records


def parse_geosa_list(value: str, url: str, verified: str) -> list[dict]:
    source = next(s for s in SOURCES if s.id == "geosa")
    root = Document(value).root
    records = []
    for section in root.nodes():
        if section.tag != "section" or not section.has_class("privacy-sec"):
            continue
        table = next((n for n in section.nodes() if n.tag == "table" and n.has_class("privacy-table")), None)
        heading = next((n for n in section.nodes() if n.tag == "h2"), None)
        if not table or not heading:
            continue
        pairs = {}
        for row in table.nodes():
            cells = [n for n in row.children if isinstance(n, Node) and n.tag == "td"]
            if row.tag == "tr" and len(cells) == 3:
                pairs[cells[1].text()] = cells[2].text()
        title = re.sub(r"^\d+\s+", "", heading.text())
        record = empty_record(source, title, url, verified)
        info = pairs.get("المعلومات الأساسية", "")
        reference = re.search(r"(?:رقم المنافسة|الرقم المرجعي|الرقم المنافسة)\s*:\s*([\d/]+)", info)
        deadline_value = next((v for k, v in pairs.items() if "العروض" in k and ("آخر موعد" in k or "اخر موعد" in k)), None)
        deadline = parse_date(deadline_value)
        record.update(organization=pairs.get("الجهة الحكومية") or source.name, reference=reference.group(1) if reference else None, deadline=deadline, status=opportunity_status(None, deadline), description=pairs.get("الغاية من المنافسة") or pairs.get("الغرض من المنافسة"), fee=pairs.get("قيمة المنافسة"), confidence=0.92, login_required="اعتماد" in section.text())
        record["sector"] = classify_sector(title, record["description"] or "")
        records.append(record)
    return records


def parse_public_html(source: Source, value: str, url: str, verified: str) -> list[dict]:
    if source.connector == "taqeem":
        return parse_taqeem_list(value, url, verified) if re.fullmatch(r"/(?:en/|ar/)?tenders/?", urlsplit(url).path) else parse_taqeem_detail(value, url, verified)
    if source.connector == "etimad" and "DetailsForVisitor" in url:
        return parse_etimad_detail(value, url, verified)
    if source.connector == "ksau":
        return parse_ksau_list(value, url, verified)
    if source.connector == "geosa":
        return parse_geosa_list(value, url, verified)
    # No untested selectors: NCP/RCJY remain DEGRADED until an actual snapshot
    # supports a source-specific, independently tested parser.
    return []


def probe(source: Source, fetcher: PublicFetcher | None = None, detail_limit: int = 12, known_urls=None) -> dict:
    """Refresh public listings and previously verified detail URLs independently.

    A failed detail is never promoted to verified by a shallow listing. Discovery
    health is distinct from refreshing known records, and every failure is saved.
    """
    verified=utc_now();fetcher=fetcher or PublicFetcher()
    result={"source_id":source.id,"name":source.name,"url":source.url,"status":"UNAVAILABLE",
      "last_checked":verified,"last_successful_update":None,"reason":None,"records":[],
      "extracted_count":0,"listing_status":"UNAVAILABLE","verification_failures":[]}
    listing=[];response=None
    try:
        response=fetcher.fetch(source.url,source.hosts)
        listing=parse_public_html(source,response.body,response.url,verified)
        if listing:result["listing_status"]="LIVE"
        else:
            auth_notice="لاستعراض تفاصيل المنافسة نرجو الدخول" in response.body
            result["listing_status"]="AUTH_REQUIRED" if auth_notice else "DEGRADED"
            result["reason"]="public_list_requires_unified_portal" if auth_notice else "no_verified_records_extracted"
    except FetchError as exc:
        result["listing_status"]=exc.status;result["reason"]=exc.reason
    result["discovery_status"]=result["listing_status"]
    candidates=[];seen=set();by_url={}
    for record in listing:by_url[record["source_url"]]=record
    requested=([r["source_url"] for r in listing] if source.connector=="taqeem" else [])+list(known_urls or [])
    for candidate in requested:
        try:candidate=safe_url(candidate,source.hosts)
        except FetchError:continue
        if candidate in seen:continue
        seen.add(candidate)
        if candidate==source.url:
            # A successful full official table already verifies all its rows.
            continue
        if source.connector=="etimad" and "DetailsForVisitor" not in urlsplit(candidate).path:continue
        candidates.append(candidate)
        if len(candidates)>=40:break
    records=[] if source.connector in ("taqeem","etimad") else list(listing)
    for candidate in candidates:
        try:
            detail=fetcher.fetch(candidate,source.hosts)
            extracted=parse_public_html(source,detail.body,detail.url,verified)
            if not extracted:raise FetchError("DEGRADED","no_verified_records_extracted")
            for record in extracted:
                shallow=by_url.get(candidate,{})
                if not record.get("published_at"):record["published_at"]=shallow.get("published_at")
                records.append(record)
        except FetchError as exc:
            result["verification_failures"].append({"source_url":candidate,"status":exc.status,"reason":exc.reason,"last_checked":verified})
    unique={}
    for record in records:
        record["verification_method"]="live_public_fetch";record["verification_status"]="verified"
        record["last_verified"]=verified
        unique[record.get("reference") or record["source_url"]]=record
    records=list(unique.values())
    result.update(records=records,extracted_count=len(records))
    if records:
        complete=result["listing_status"]=="LIVE" and not result["verification_failures"]
        result["status"]="LIVE" if complete else "DEGRADED"
        result["last_successful_update"]=verified
        if result["verification_failures"]:result["reason"]="some_detail_fetches_failed"
    else:
        result["status"]="DEGRADED" if result["listing_status"]=="LIVE" else result["listing_status"]
        if result["listing_status"]!="LIVE" and not candidates:
            result["verification_failures"].append({"source_url":source.url,"status":result["listing_status"],"reason":result["reason"],"last_checked":verified})
    return result


def refresh(fetcher: PublicFetcher | None = None) -> dict:
    fetcher = fetcher or PublicFetcher()
    return {"zero_cost_only": ZERO_COST_ONLY, "generated_at": utc_now(), "sources": [probe(source, fetcher) for source in SOURCES]}


def import_tinyfish_snapshot(filename: str, verified: str, source_id: str) -> dict:
    """Import evidence transparently. Snapshot import is never labeled LIVE."""
    source = next(s for s in SOURCES if s.id == source_id)
    with open(filename, encoding="utf-8") as handle:
        evidence = json.load(handle)
    if "content" in evidence:
        evidence = json.loads("\n".join(x["text"] for x in evidence["content"] if x.get("type") == "text"))
    records = []
    for response in evidence.get("results", []):
        url = response.get("final_url") or response["url"]
        if urlsplit(url).hostname not in source.hosts:
            continue
        records.extend(parse_public_html(source, response.get("text", ""), url, verified))
    by_identity = {}
    for record in records:
        key = record["reference"] or record["source_url"]
        if key in by_identity:
            original = by_identity[key]
            best = record if record["confidence"] >= original["confidence"] else original
            other = original if best is record else record
            by_identity[key] = {k: v if v is not None and v != [] else other.get(k) for k, v in best.items()}
        else:
            by_identity[key] = record
    records = list(by_identity.values())
    with open(filename, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    return {"source_id": source_id, "status": "MANUAL_IMPORT", "last_checked": verified, "last_successful_update": verified if records else None, "extracted_count": len(records), "records": records, "evidence_sha256": digest}


if __name__ == "__main__":
    print(json.dumps(refresh(), ensure_ascii=False, indent=2))
