import cv2


def decode_qr(image_path):
    """
    Decode QR code data from an image.

    Returns:
        list[str]: Decoded QR contents.
    """

    image = cv2.imread(image_path)

    if image is None:
        raise ValueError("The uploaded image could not be read.")

    detector = cv2.QRCodeDetector()

    results = []

    # Try detecting multiple QR codes
    try:
        success, decoded_info, points, _ = detector.detectAndDecodeMulti(image)

        if success and decoded_info:
            for data in decoded_info:
                if data and data.strip():
                    results.append(data.strip())

    except Exception:
        pass

    # If multiple detection didn't work, try single QR detection
    if not results:
        try:
            data, points, _ = detector.detectAndDecode(image)

            if data and data.strip():
                results.append(data.strip())

        except Exception:
            pass

    if not results:
        raise ValueError(
            "No readable QR code was detected in the uploaded image."
        )

    return results