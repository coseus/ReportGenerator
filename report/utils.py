# report/utils.py
import base64

def decode_b64_image(b64_string: str):
    try:
        return base64.b64decode(b64_string)
    except Exception:
        return None
