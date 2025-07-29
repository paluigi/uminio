# uminio

`uminio` is a MicroPython library designed to facilitate uploading files directly from a MicroPython-enabled device (like an ESP32 or ESP8266) to MinIO object storage. It implements the necessary AWS Signature Version 4 for an S3 PUT Object request. This allows you to store data, sensor readings, images, or any other files from your microcontroller projects in the cloud.

Forked from `uboto3` [https://github.com/DanielMilstein/uboto3](https://github.com/DanielMilstein/uboto3) 

## Features

* **Direct S3 Upload:** Upload files directly to an MinIO bucket without needing an intermediary server.
* **AWS Signature V4:** Implements the required request signing process.
* **HMAC-SHA256:** Includes a MicroPython-compatible HMAC-SHA256 implementation for signing.
* **Time Synchronization:** Includes a helper function to synchronize the device's time using NTP, which is crucial for MinIO request signing.
* **Minimal Dependencies:** Built with standard MicroPython libraries like `urequests`, `uhashlib`, `ubinascii`, `utime`, and `network`.

## Requirements

* MicroPython firmware flashed on your device.
* Network connectivity (WiFi) configured on the device.
* The following MicroPython libraries:
    * `urequests`
    * `uhashlib`
    * `ubinascii`
    * `utime`
    * `network`
    * `ntptime` (for time synchronization)

## Setup

1.  **Copy `uminio.py`:** Place the `uminio.py` file into the filesystem of your MicroPython device (e.g., in the `/lib` directory or the root).
2.  **MinIO Credentials & Configuration:**
    Open `uminio.py` and **configure the following constants** at the top of the file with your MinIO details:
    ```python
    # --- MinIO Configuration ---
    MINIO_ENDPOINT = "192.168.1.100:9000"  # Your MinIO server IP address and port
    MINIO_ACCESS_KEY = "YOUR_ACCESS_KEY"      # Your MinIO access key
    MINIO_SECRET_KEY = "YOUR_SECRET_KEY"      # Your MinIO secret key
    MINIO_BUCKET = "micropython-uploads"  # The bucket you want to upload to
    MINIO_USE_HTTPS = False               # Set to True if your MinIO server uses HTTPS
    ```
    **Important Security Note:** Hardcoding credentials directly into the script is generally not recommended for production environments. Consider alternative methods for managing secrets on your device if security is a major concern.

3.  **IAM Permissions:**
    Ensure the MinIO user associated with the `MINIO_ACCESS_KEY` and `MINIO_SECRET_KEY` has the necessary permissions to put objects into the specified bucket.


## Usage Example

Here's how to use `uminio` to upload a local file from your MicroPython device to MinIO:

```python
import network
import time
import uminio

# --- Network Configuration (Example for ESP32/ESP8266) ---
WIFI_SSID = "YOUR_WIFI_SSID"
WIFI_PASSWORD = "YOUR_WIFI_PASSWORD"

def connect_wifi():
    sta_if = network.WLAN(network.STA_IF) #
    if not sta_if.isconnected():
        print("Connecting to WiFi...")
        sta_if.active(True)
        sta_if.connect(WIFI_SSID, WIFI_PASSWORD)
        while not sta_if.isconnected():
            time.sleep(1)
    print("Network Config:", sta_if.ifconfig())

# --- Main Application ---
def main():
    # 1. Connect to WiFi
    connect_wifi()

    # 2. Synchronize time (critical for MinIO authentication)
    # uminio.py already has MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY, MINIO_BUCKET configured
    uminio.sync_time() #

    # 3. Create a dummy file to upload (or use an existing file)
    local_file_to_upload = "data.txt"
    s3_object_name = "my_device_data/data.txt" # Desired path and name in S3
    content_type = "text/plain" #

    try:
        with open(local_file_to_upload, "w") as f:
            f.write("Hello from MicroPython!\n")
            f.write(f"Timestamp: {time.time()}\n")
        print(f"Created dummy file: {local_file_to_upload}")
    except OSError as e:
        print(f"Error creating file: {e}")
        return

    # 4. Upload the file
    print(f"Attempting to upload '{local_file_to_upload}' to S3 bucket '{uminio.MINIO_BUCKET}' as '{s3_object_name}'...")
    if uminio.upload_to_s3(local_file_to_upload, s3_object_name, content_type): #
        print("Upload successful!")
    else:
        print("Upload failed.")

if __name__ == "__main__":
    main()
```

## Contributing
Feel free to fork this repository, submit issues, and create pull requests if you have improvements or bug fixes.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
