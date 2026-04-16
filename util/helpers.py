import base64
from io import BytesIO
from typing import Any

from PIL import Image


def safe_b64decode(data_b64: str | bytes | bytearray) -> bytes:
    try:
        if isinstance(data_b64, (bytes, bytearray)):
            return bytes(data_b64)
        return base64.b64decode(data_b64)
    except Exception:
        return b""


def image_resize(image_bytes: bytes, max_width: int = 900, max_height: int = 600) -> bytes:
    try:
        img = Image.open(BytesIO(image_bytes))
        ratio = min(max_width / img.width, max_height / img.height, 1.0)
        new_w = int(img.width * ratio)
        new_h = int(img.height * ratio)
        if ratio < 1.0:
            img = img.resize((new_w, new_h), Image.LANCZOS)
        out = BytesIO()
        img.save(out, format="PNG")
        return out.getvalue()
    except Exception:
        return image_bytes


def resize_image_b64(data: Any, max_width: int = 900, max_height: int = 600) -> str:
    try:
        img_bytes = data if isinstance(data, (bytes, bytearray)) else base64.b64decode(data)
        resized_bytes = image_resize(img_bytes, max_width=max_width, max_height=max_height)
        return base64.b64encode(resized_bytes).decode()
    except Exception:
        try:
            if isinstance(data, (bytes, bytearray)):
                return base64.b64encode(data).decode()
            return str(data)
        except Exception:
            return ""


def format_multiline(text: str) -> str:
    if not text:
        return ""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("\n", "<br/>")


def preformat(text: str) -> str:
    if not text:
        return ""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def pdf_safe_image(b64_string: str, max_width_mm=150):
    try:
        img_data = base64.b64decode(b64_string)
        img = Image.open(BytesIO(img_data))
        max_w_px = int(max_width_mm * 3.78)
        w, h = img.size
        scale = min(max_w_px / w, 1.0)
        new_w = int(w * scale)
        new_h = int(h * scale)
        img = img.resize((new_w, new_h))
        out = BytesIO()
        img.save(out, format="PNG")
        out.seek(0)
        return out, new_w, new_h
    except Exception:
        return None, None, None


def normalize_image_item(item: Any, default_name: str = "Image") -> dict | None:
    if isinstance(item, str):
        data = item.strip()
        return {"data": data, "name": default_name} if data else None

    if isinstance(item, dict):
        data = str(item.get("data") or item.get("b64") or item.get("image") or "").strip()
        if not data:
            return None
        name = str(item.get("name") or item.get("caption") or item.get("title") or default_name).strip()
        return {"data": data, "name": name or default_name}

    return None


def normalize_images(items: Any, default_prefix: str = "Image") -> list[dict]:
    normalized = []
    seen = set()
    for idx, raw in enumerate(items or [], start=1):
        item = normalize_image_item(raw, default_name=f"{default_prefix} {idx}")
        if not item:
            continue
        key = (item["data"], item["name"])
        if key in seen:
            continue
        seen.add(key)
        normalized.append(item)
    return normalized


def image_b64_list(items: Any, default_prefix: str = "Image") -> list[str]:
    return [item["data"] for item in normalize_images(items, default_prefix=default_prefix)]
