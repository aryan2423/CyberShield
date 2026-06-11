from flask import Flask, render_template, request
import os
import hashlib
from signatures import SIGNATURES

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

total_scans = 0
safe_files = 0
suspicious_files = 0
scan_history = []


def identify_file(filepath):

    with open(filepath, "rb") as file:
        header = file.read(8)

    hex_header = header.hex().upper()

    for signature, filetype in SIGNATURES.items():
        if hex_header.startswith(signature):
            return filetype

    return "Unknown"


def calculate_hashes(filepath):

    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as file:
        while chunk := file.read(4096):
            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


def get_risk(file_type):

    if "Executable" in file_type:
        return "High"

    elif "ZIP" in file_type:
        return "Medium"

    elif "PDF" in file_type:
        return "Medium"

    return "Low"


@app.route("/", methods=["GET", "POST"])
def home():

    global total_scans
    global safe_files
    global suspicious_files
    global scan_history

    result = None
    warning = None

    if request.method == "POST":

        uploaded_file = request.files["file"]

        if uploaded_file:

            filepath = os.path.join(
                UPLOAD_FOLDER,
                uploaded_file.filename
            )

            uploaded_file.save(filepath)

            actual_type = identify_file(filepath)

            md5_hash, sha256_hash = calculate_hashes(filepath)

            size = os.path.getsize(filepath)
            size_mb = round(size / (1024 * 1024), 2)

            with open(filepath, "rb") as f:
                header = f.read(16)

            header_hex = header.hex().upper()

            header_hex = " ".join(
                header_hex[i:i+2]
                for i in range(0, len(header_hex), 2)
            )

            risk = get_risk(actual_type)

            extension = uploaded_file.filename.split(".")[-1].lower()

            result = {
                "filename": uploaded_file.filename,
                "extension": extension,
                "actual_type": actual_type,
                "size": size_mb,
                "risk": risk,
                "md5": md5_hash,
                "sha256": sha256_hash,
                "header": header_hex
            }

            expected = {
                "jpg": "JPEG Image",
                "jpeg": "JPEG Image",
                "png": "PNG Image",
                "pdf": "PDF Document",
                "gif": "GIF Image",
                "exe": "Windows Executable"
            }

            if extension in expected:
                if expected[extension] != actual_type:
                    warning = "⚠ Extension Mismatch Detected"

            total_scans += 1

            if warning:
                suspicious_files += 1
            else:
                safe_files += 1

            scan_history.append({
                "name": uploaded_file.filename,
                "type": actual_type,
                "risk": risk
            })

    return render_template(
        "index.html",
        result=result,
        warning=warning,
        total=total_scans,
        safe=safe_files,
        suspicious=suspicious_files,
        history=scan_history
    )


if __name__ == "__main__":
    app.run(debug=True)