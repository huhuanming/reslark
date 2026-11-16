"""Bundled mitmdump addon. Loaded by mitmdump; no separate Python install needed."""
import hashlib
import asyncio
import json
import os
from pathlib import Path
import re
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from mitmproxy import ctx, http
from mitmproxy.net import encoding

PREFIX = "RESLARK:"


def emit(kind, **values):
    print(PREFIX + json.dumps({"type": kind, **values}, ensure_ascii=True), flush=True)


def absolute(value, base):
    value = unescape(value.strip().replace("\\/", "/"))
    try:
        parts = urlsplit(urljoin(base, value))
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            return None
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
    except ValueError:
        return None


class References(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.items = []

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "base" and attrs.get("href"):
            self.base = absolute(attrs["href"], self.base) or self.base
        # Navigation links are candidates, not recursively followed as assets.
        for attribute in ("src", "poster", "data-src"):
            if attrs.get(attribute):
                self.items.append((attrs[attribute], "html-reference"))
        if tag in ("link", "image", "use"):
            value = attrs.get("href") or attrs.get("xlink:href")
            if value:
                self.items.append((value, "html-reference"))
        for candidate in (attrs.get("srcset") or "").split(","):
            pieces = candidate.strip().split()
            if pieces and not pieces[0].startswith("data:"):
                self.items.append((pieces[0], "html-srcset"))
        for value in re.findall(r"url\(\s*['\"]?([^)'\"]+)", attrs.get("style", ""), re.I):
            self.items.append((value, "css-reference"))


def extract_references(text, base, content_type):
    items = []
    limitations = []
    lowered = content_type.lower()
    if "html" in lowered:
        parser = References(base)
        try:
            parser.feed(text)
            items.extend((value, relation, parser.base) for value, relation in parser.items)
        except Exception:
            limitations.append("HTML_REFERENCE_PARSE_FAILED")
    if "json" in lowered:
        def visit(value, depth=0):
            if depth > 40:
                return
            if isinstance(value, dict):
                for child in value.values():
                    visit(child, depth + 1)
            elif isinstance(value, list):
                for child in value[:10000]:
                    visit(child, depth + 1)
            elif isinstance(value, str) and (value.startswith(("http://", "https://", "//", "/"))):
                items.append((value, "json-reference", base))
        try:
            visit(json.loads(text))
        except (ValueError, RecursionError):
            limitations.append("JSON_REFERENCE_PARSE_FAILED")
    if "css" in lowered or "html" in lowered:
        for value in re.findall(r"url\(\s*['\"]?([^)'\"]+)", text, re.I):
            items.append((value, "css-reference", base))
        for value in re.findall(r"@import\s+['\"]([^'\"]+)", text, re.I):
            items.append((value, "css-import", base))
    if "mpegurl" in lowered or text.lstrip().startswith("#EXTM3U"):
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                items.append((line, "hls-reference", base))
            for value in re.findall(r'URI="([^\"]+)"', line):
                items.append((value, "hls-reference", base))
        if "#EXT-X-BYTERANGE" in text:
            limitations.append("HLS_BYTERANGE_REQUIRES_MEDIA_BACKEND")
        if "SAMPLE-AES" in text or "KEYFORMAT=" in text:
            limitations.append("ENCRYPTED_MEDIA_MAY_REQUIRE_DRM")
    if "dash+xml" in lowered or "<MPD" in text[:1000]:
        try:
            root = ET.fromstring(text)
            def walk(element, current_base):
                base_elements = [child for child in element if child.tag.split("}")[-1] == "BaseURL"]
                for child in base_elements:
                    if child.text:
                        current_base = absolute(child.text, current_base) or current_base
                        items.append((current_base, "dash-base", base))
                for key in ("media", "sourceURL", "initialization"):
                    value = element.attrib.get(key)
                    if value and "$" not in value:
                        items.append((value, "dash-reference", current_base))
                    elif value:
                        limitations.append("DASH_TEMPLATE_REQUIRES_MEDIA_BACKEND")
                for child in element:
                    if child.tag.split("}")[-1] != "BaseURL":
                        walk(child, current_base)
            walk(root, base)
            if any(element.tag.split("}")[-1] == "ContentProtection" for element in root.iter()):
                limitations.append("DASH_CONTENT_PROTECTION")
        except (ET.ParseError, RecursionError):
            limitations.append("DASH_REFERENCE_PARSE_FAILED")
    # Absolute URLs in scripts and text remain useful even without executing JS.
    for value in re.findall(r"https?://[^\s\"'<>\\`]+", unescape(text.replace("\\/", "/"))):
        items.append((value.rstrip(",);"), "text-reference", base))
    seen = set()
    result = []
    for value, relation, origin in items:
        url = absolute(value, origin)
        if url and url != base and url not in seen:
            seen.add(url)
            result.append({"url": url, "relation": relation})
            if len(result) >= 10000:
                limitations.append("REFERENCE_LIMIT_REACHED")
                break
    return result, list(set(limitations))


class Reslark:
    def __init__(self):
        self.config = {}
        self.open_files = {}
        self.active_flows = {}
        self.spool_bytes = 0

    def load(self, loader):
        config_path = os.environ.get("RESLARK_CONFIG")
        if config_path:
            self.config = json.loads(Path(config_path).read_text())

    def running(self):
        emit("backend.ready", pid=os.getpid())
        if os.environ.get("RESLARK_CERT_ONLY"):
            ctx.master.shutdown()
        elif self.config.get("targets"):
            self.targets_task = asyncio.create_task(self.update_targets())

    async def update_targets(self):
        previous = None
        while True:
            try:
                targets = json.loads(Path(self.config["targets"]).read_text())
                spec = ",".join(targets)
                if previous is not None and previous != spec:
                    ctx.options.update(mode=["local:" + spec])
                previous = spec
            except (OSError, ValueError) as error:
                emit("backend.warning", code="PROCESS_TARGET_UPDATE_FAILED", message=str(error))
            await asyncio.sleep(0.25)

    def request(self, flow: http.HTTPFlow):
        if not self.config:
            return
        # Downloader requests bypass this backend and are never replayed as POST.
        flow.metadata["reslark_request_time"] = flow.request.timestamp_start

    def responseheaders(self, flow: http.HTTPFlow):
        if not self.config:
            return
        spool = Path(self.config["spool"])
        file_path = spool / (flow.id + ".part")
        state = {"path": str(file_path), "bytes": 0, "observed_bytes": 0, "prefix": bytearray(), "truncated": False, "digest": hashlib.sha256()}
        try:
            handle = file_path.open("xb")
            os.chmod(file_path, 0o600)
            self.open_files[flow.id] = handle
        except OSError as error:
            handle = None
            state["truncated"] = True
            emit("backend.warning", code="SPOOL_WRITE_FAILED", message=str(error))
        flow.metadata["reslark"] = state
        self.active_flows[flow.id] = flow

        def stream(chunk):
            state["observed_bytes"] += len(chunk)
            if len(state["prefix"]) < self.config["scan_bytes"]:
                state["prefix"].extend(chunk[:self.config["scan_bytes"] - len(state["prefix"])])
            if handle and not state["truncated"]:
                # Account for files removed by the Node controller as they finish.
                if self.spool_bytes + len(chunk) > self.config["max_spool_bytes"]:
                    total = 0
                    for item in spool.glob("*.part"):
                        try:
                            total += item.stat().st_size
                        except FileNotFoundError:
                            pass
                    self.spool_bytes = total
                if state["bytes"] + len(chunk) > self.config["max_body_bytes"] or self.spool_bytes + len(chunk) > self.config["max_spool_bytes"]:
                    state["truncated"] = True
                else:
                    try:
                        handle.write(chunk)
                        state["digest"].update(chunk)
                        state["bytes"] += len(chunk)
                        self.spool_bytes += len(chunk)
                    except OSError as error:
                        state["truncated"] = True
                        emit("backend.warning", code="SPOOL_WRITE_FAILED", message=str(error))
            return chunk
        flow.response.stream = stream

    def response(self, flow: http.HTTPFlow):
        self.active_flows.pop(flow.id, None)
        state = flow.metadata.pop("reslark", None)
        if not state:
            return
        self.close_file(flow.id)
        content_type = flow.response.headers.get("content-type", "")
        prefix = bytes(state["prefix"])
        references = []
        limitations = []
        inspectable = any(part in content_type.lower() for part in ("text/", "json", "javascript", "xml", "mpegurl"))
        if inspectable:
            if state["observed_bytes"] > len(prefix):
                limitations.append("REFERENCE_SCAN_TRUNCATED")
            try:
                decoded = encoding.decode(prefix, flow.response.headers.get("content-encoding", "identity"))
                if len(decoded) > self.config["scan_bytes"]:
                    decoded = decoded[:self.config["scan_bytes"]]
                    limitations.append("REFERENCE_SCAN_TRUNCATED")
                references, notes = extract_references(decoded.decode("utf-8", errors="replace"), flow.request.pretty_url, content_type)
                limitations.extend(notes)
            except Exception:
                limitations.append("CONTENT_DECODE_FAILED")
        if flow.response.headers.get("location"):
            target = absolute(flow.response.headers["location"], flow.request.pretty_url)
            if target:
                references.append({"url": target, "relation": "redirect"})
        emit("flow", flow={
            "flow_id": flow.id, "url": flow.request.pretty_url, "method": flow.request.method,
            "request_headers": dict(flow.request.headers), "response_headers": dict(flow.response.headers),
            "status": flow.response.status_code, "http_version": flow.response.http_version,
            "started_at": flow.request.timestamp_start, "finished_at": flow.response.timestamp_end,
            "client_address": list(flow.client_conn.peername or []),
            "body_path": state["path"], "bytes": state["bytes"], "observed_bytes": state["observed_bytes"],
            "sha256": state["digest"].hexdigest(), "truncated": state["truncated"],
            "references": references, "limitations": limitations,
        })

    def error(self, flow: http.HTTPFlow):
        self.close_file(flow.id)
        state = flow.metadata.get("reslark")
        if state:
            state["truncated"] = True
            self.response(flow)
            emit("flow.error", url=flow.request.pretty_url, message=str(flow.error))
        else:
            emit("backend.warning", code="FLOW_ERROR", message=str(flow.error), url=flow.request.pretty_url)

    def websocket_message(self, flow: http.HTTPFlow):
        message = flow.websocket.messages[-1]
        content = message.content[:self.config.get("scan_bytes", 2097152)]
        emit("websocket.message", url=flow.request.pretty_url, from_client=message.from_client,
             timestamp=message.timestamp, bytes=len(message.content), sha256=hashlib.sha256(message.content).hexdigest(),
             text=content.decode("utf-8", errors="replace") if message.is_text else None,
             truncated=len(content) < len(message.content))

    def close_file(self, flow_id):
        handle = self.open_files.pop(flow_id, None)
        if handle:
            handle.close()

    def done(self):
        for flow in list(self.active_flows.values()):
            flow.metadata["reslark"]["truncated"] = True
            self.response(flow)
        for flow_id in list(self.open_files):
            self.close_file(flow_id)


addons = [Reslark()]
