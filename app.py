import sys
from pathlib import Path
from uuid import uuid4

from flask import Flask, render_template, request, send_from_directory, url_for
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "src"))

from netanomaly.detect import AnomalyDetector
from netanomaly.features import extract
from netanomaly.report import save_reports

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

UPLOAD_DIR = BASE_DIR / "uploads"
RESULT_DIR = BASE_DIR / "web_results"
BASELINE = BASE_DIR / "data" / "baseline.pcap"

UPLOAD_DIR.mkdir(exist_ok=True)
RESULT_DIR.mkdir(exist_ok=True)


@app.route("/", methods=["GET", "POST"])
def index():

    if request.method == "POST":

        file = request.files.get("pcap_file")

        if not file or not file.filename:
            return render_template("index.html", error="Please select a PCAP file.")

        filename = secure_filename(file.filename)

        if not filename.lower().endswith(".pcap"):
            return render_template("index.html", error="Please upload a .pcap file.")

        job_id = str(uuid4())
        upload_path = UPLOAD_DIR / f"{job_id}.pcap"
        output_path = RESULT_DIR / job_id

        file.save(upload_path)

        try:
            test_data = extract(upload_path)

            if test_data.empty:
                raise ValueError("No IP packets found in the uploaded PCAP.")

            if not BASELINE.exists():
                raise FileNotFoundError("Baseline PCAP is missing.")

            baseline_data = extract(BASELINE)

            if baseline_data.empty:
                raise ValueError("Baseline PCAP contains no usable IP packets.")

            detector = AnomalyDetector(contamination=0.02)
            detector.fit(baseline_data)

            results = detector.predict(test_data)

            alerts = save_reports(results, output_path)

            summary = {
                "total_windows": len(results),
                "total_alerts": len(alerts),
                "normal_windows": int((~results["anomaly"]).sum()),
            }

            alert_records = alerts[
                ["src", "likely_type", "score", "reason", "wireshark_filter"]
            ].to_dict("records")

            return render_template(
                "results.html",
                summary=summary,
                alerts=alert_records,
                job_id=job_id
            )

        except Exception as error:
            return render_template("index.html", error=str(error))

        finally:
            upload_path.unlink(missing_ok=True)

    return render_template("index.html")


@app.route("/download/<job_id>/<filename>")
def download(job_id, filename):

    if filename not in ["alerts.csv", "alerts.json", "all_windows.csv", "anomalies.png"]:
        return "Invalid file", 404

    folder = RESULT_DIR / job_id

    if not folder.is_dir():
        return "Result not found", 404

    return send_from_directory(folder, filename, as_attachment=True)


@app.route("/chart/<job_id>")
def chart(job_id):

    folder = RESULT_DIR / job_id

    if not folder.is_dir() or not (folder / "anomalies.png").exists():
        return "Chart not found", 404

    return send_from_directory(folder, "anomalies.png")


@app.errorhandler(413)
def file_too_large(error):
    return "File too large. Maximum upload size is 50 MB.", 413


if __name__ == "__main__":
    app.run(debug=True)