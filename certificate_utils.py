# certificate_utils.py

import json
import hashlib
import datetime
import base64
import qrcode
import os
import re
from io import BytesIO

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors

TEAL_BLUE = colors.HexColor('#008080')
LIGHT_SILVER = colors.HexColor('#E0E0E0')
LIGHT_BLUE_BG = colors.HexColor('#F0FFFF')
DARK_TEXT = colors.HexColor('#333333')

def canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode('utf-8')

def _extract_device_model(device_string: str) -> str:
    match = re.search(r'[\d\s\(\):]+([a-zA-Z0-9\s\-_]+(?:SSD|HDD|USB Device|Storage|Media|Drive|Disk))', device_string, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    match_fallback = re.search(r'^[\\/\w\.]+[\s\(\):]+(.*)', device_string)
    if match_fallback:
        cleaned = re.sub(r'^\d+\s*|\(Index:\d+\)\s*', '', match_fallback.group(1)).strip()
        if cleaned:
            return cleaned
    return device_string

def generate_certificate(device_info: dict, private_key, output_dir: str):
    timestamp_str = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    base_filename = f"CertiWipe-{timestamp_str}"
    json_path = os.path.join(output_dir, f"{base_filename}.json")
    pdf_path = os.path.join(output_dir, f"{base_filename}.pdf")

    cert_data = {
        "certificateId": f"CW-{int(datetime.datetime.utcnow().timestamp())}",
        "toolVersion": "CertiWipe v1.0 Pro",
        "timestampUTC": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "deviceInfo": device_info,
        "wipeStandard": "NIST SP 800-88 Rev. 1",
    }
    cert_bytes = canonical_json_bytes(cert_data)
    data_hash = hashlib.sha256(cert_bytes).digest()
    signature = private_key.sign(data_hash, padding.PKCS1v15(), hashes.SHA256())
    cert_data["verification"] = {
        "hash_sha256": data_hash.hex(),
        "signature_sha256_rsa_b64": base64.b64encode(signature).decode('ascii')
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(cert_data, f, indent=4)

    verification_url = f"http://127.0.0.1:5000/verify/{cert_data['certificateId']}"
    save_pdf_from_json(cert_data, pdf_path, verification_url)
    return cert_data, json_path, pdf_path

def save_pdf_from_json(cert_data: dict, pdf_filename: str, verification_url: str):
    c = canvas.Canvas(pdf_filename, pagesize=letter)
    width, height = letter
    c.setFillColor(TEAL_BLUE)
    c.setStrokeColor(TEAL_BLUE)
    c.setLineWidth(5)
    c.line(0, height - 0.75*inch, width, height - 0.75*inch)
    c.setLineWidth(1)
    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica-Bold", 24)
    c.drawCentredString(width / 2, height - 0.5*inch, "SECURE DATA SANITIZATION CERTIFICATE")
    y_current, margin_x, label_width = height - 2.0*inch, 1.2*inch, 2.0*inch
    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(margin_x, y_current, "Verification and Device Details")
    c.setStrokeColor(LIGHT_SILVER)
    c.line(margin_x, y_current - 0.05*inch, width - margin_x, y_current - 0.05*inch)
    
    device_full_string = cert_data['deviceInfo'].get('deviceString', 'N/A')
    data_points = [
        ("Certificate ID:", cert_data.get('certificateId', 'N/A')),
        ("Timestamp (UTC):", cert_data.get('timestampUTC', 'N/A')),
        ("Cleaning Standard:", cert_data.get('wipeStandard', 'N/A')),
        ("Device Wiped:", _extract_device_model(device_full_string)),
        ("Wipe Method:", cert_data['deviceInfo'].get('wipeMethod', 'N/A')),
        ("Tool Used:", cert_data.get('toolVersion', 'N/A')),
    ]
    y_current -= 0.5*inch
    for label, value in data_points:
        c.setFont("Helvetica-Bold", 12)
        c.setFillColor(TEAL_BLUE)
        c.drawString(margin_x, y_current, label)
        text_object = c.beginText(margin_x + label_width + 0.1*inch, y_current)
        text_object.setFont("Helvetica", 12)
        text_object.setFillColor(DARK_TEXT)
        lines = [value]
        text_object.textLines(lines)
        c.drawText(text_object)
        y_current -= 0.35*inch

    qr_section_y, box_height = 1.5*inch, 2.0*inch
    c.setStrokeColor(TEAL_BLUE)
    c.setLineWidth(1.5)
    c.setFillColor(LIGHT_BLUE_BG)
    c.roundRect(margin_x, qr_section_y, width - 2*margin_x, box_height, 10, stroke=1, fill=1)
    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(width / 2, qr_section_y + box_height - 0.3*inch, "ONLINE VERIFICATION")
    
    qr_image = qrcode.make(verification_url)
    buffer = BytesIO()
    qr_image.save(buffer, format="PNG")
    buffer.seek(0)
    qr_reader = ImageReader(buffer)
    qr_size = 1.4*inch
    c.drawImage(qr_reader, margin_x + 0.2*inch, qr_section_y + 0.3*inch, width=qr_size, height=qr_size)
    text_x = margin_x + qr_size + 0.5*inch
    c.setFont("Helvetica", 10)
    c.setFillColor(DARK_TEXT)
    c.drawString(text_x, qr_section_y + 1.1*inch, "Scan this code or use the link below")
    c.drawString(text_x, qr_section_y + 0.9*inch, "to confirm this certificate's registration:")
    c.setFont("Helvetica-Oblique", 10)
    c.setFillColor(colors.blue)
    link_y = qr_section_y + 0.6*inch
    c.drawString(text_x, link_y, verification_url)
    text_width = c.stringWidth(verification_url, "Helvetica-Oblique", 10)
    link_rect = (text_x, link_y, text_x + text_width, link_y + 10)
    c.linkURL(verification_url, link_rect, relative=1)
    c.setFillColor(DARK_TEXT)
    c.setFont("Helvetica-Bold", 10)
    c.drawCentredString(width / 2, 0.5*inch, "CERTIFICATION VALIDATED BY CRYPTOGRAPHIC SIGNATURE (Verify offline using CertiWipe Pro)")
    c.save()

def verify_certificate(json_path: str, public_key):
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            cert = json.load(f)
        verif = cert.get("verification")
        if not verif or "hash_sha256" not in verif or "signature_sha256_rsa_b64" not in verif:
            return False, "Verification block is missing or incomplete."
        stored_hash = bytes.fromhex(verif["hash_sha256"])
        signature = base64.b64decode(verif["signature_sha256_rsa_b64"])
        cert_without_verif = dict(cert)
        del cert_without_verif["verification"]
        recomputed_hash = hashlib.sha256(canonical_json_bytes(cert_without_verif)).digest()
        if stored_hash != recomputed_hash:
            return False, "Hash mismatch! Certificate content has been altered."
        public_key.verify(signature, recomputed_hash, padding.PKCS1v15(), hashes.SHA256())
        return True, "Certificate is authentic and content is valid."
    except InvalidSignature:
        return False, "Invalid signature. The certificate was not signed by the correct private key."
    except Exception as e:
        return False, f"An unexpected error occurred: {e}"

def verify_certificate_data(cert_data: dict, public_key):
    try:
        cert = dict(cert_data)
        verif = cert.pop("verification", None)
        if not verif or "hash_sha256" not in verif or "signature_sha256_rsa_b64" not in verif:
            return False, "Verification block is missing or incomplete."
        stored_hash = bytes.fromhex(verif["hash_sha256"])
        signature = base64.b64decode(verif["signature_sha256_rsa_b64"])
        recomputed_hash = hashlib.sha256(canonical_json_bytes(cert)).digest()
        if stored_hash != recomputed_hash:
            return False, "Hash mismatch! Certificate content has been altered."
        public_key.verify(signature, recomputed_hash, padding.PKCS1v15(), hashes.SHA256())
        return True, "Certificate is authentic and content is valid."
    except InvalidSignature:
        return False, "Invalid signature. The certificate was not signed by the correct private key."
    except Exception as e:
        return False, f"An unexpected error occurred during verification: {e}"