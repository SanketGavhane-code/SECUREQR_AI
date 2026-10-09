import os

from flask import Flask, render_template, request

from detector import decode_qr
from analyzer import analyze_url
from database import save_scan


app = Flask(__name__)


# =========================================================
# UPLOAD CONFIGURATION
# =========================================================

UPLOAD_FOLDER = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "uploads"
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Maximum upload size: 5 MB
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Create uploads folder if it does not exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Allowed QR image formats
ALLOWED_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "webp"
}


# =========================================================
# HELPER FUNCTION
# =========================================================

def allowed_file(filename):
    """
    Check whether the uploaded file has an allowed extension.
    """

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    return render_template("index.html")


# =========================================================
# QR SCAN
# =========================================================

@app.route("/scan", methods=["POST"])
def scan():

    # -----------------------------------------------------
    # STEP 1: Check uploaded file
    # -----------------------------------------------------

    if "qr_image" not in request.files:

        return """
        <h2>QR Scan Failed</h2>
        <p>No QR image was uploaded.</p>
        <a href="/">Go Back</a>
        """, 400


    file = request.files["qr_image"]


    # -----------------------------------------------------
    # STEP 2: Check filename
    # -----------------------------------------------------

    if file.filename == "":

        return """
        <h2>QR Scan Failed</h2>
        <p>Please select a QR image.</p>
        <a href="/">Go Back</a>
        """, 400


    # -----------------------------------------------------
    # STEP 3: Check file extension
    # -----------------------------------------------------

    if not allowed_file(file.filename):

        return """
        <h2>QR Scan Failed</h2>
        <p>
            Unsupported file type.
            Please upload PNG, JPG, JPEG or WEBP.
        </p>
        <a href="/">Go Back</a>
        """, 400


    # -----------------------------------------------------
    # STEP 4: Create safe filename
    # -----------------------------------------------------

    filename = file.filename.replace(" ", "_")


    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )


    # -----------------------------------------------------
    # STEP 5: Save uploaded image
    # -----------------------------------------------------

    try:

        file.save(file_path)

    except Exception as error:

        return f"""
        <h2>Upload Failed</h2>
        <p>{error}</p>
        <a href="/">Go Back</a>
        """, 500


    # -----------------------------------------------------
    # STEP 6: Decode QR code
    # -----------------------------------------------------

    try:

        decoded_data = decode_qr(file_path)

    except ValueError as error:

        return f"""
        <h2>QR Scan Failed</h2>

        <p>{error}</p>

        <a href="/">
            Scan Another QR
        </a>
        """, 400


    # -----------------------------------------------------
    # STEP 7: Get decoded QR content
    # -----------------------------------------------------

    qr_content = decoded_data[0]


    # -----------------------------------------------------
    # STEP 8: Analyze URL
    # -----------------------------------------------------

    try:

        analysis = analyze_url(qr_content)

    except ValueError as error:

        return f"""
        <h2>Analysis Failed</h2>

        <p>{error}</p>

        <a href="/">
            Scan Another QR
        </a>
        """, 400


    # -----------------------------------------------------
    # STEP 9: Get analysis results
    # -----------------------------------------------------

    verdict = analysis["verdict"]

    score = analysis["score"]

    flags = analysis["flags"]

    url = analysis["url"]

    save_scan(url, verdict, score, flags)


    # -----------------------------------------------------
    # STEP 10: Show professional result page
    # -----------------------------------------------------

    return render_template(
        "result.html",
        verdict=verdict,
        score=score,
        flags=flags,
        url=url
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )