from flask import Flask, jsonify
import json
import random

app = Flask(__name__)


def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)


def get_random_cve(data):
    all_cves = []
    for year, cve_list in data.items():
        if isinstance(cve_list, list):
            all_cves.extend(cve_list)
    if all_cves:
        return random.choice(all_cves)
    return None

json_file_path = "allcve.json"
try:
    data = load_json(json_file_path)
except Exception as e:
    print(f"Error loading JSON file: {e}")
    data = {}

@app.route("/", methods=["GET"])
def random_cve():
    cve = get_random_cve(data)
    if cve:
        return jsonify(cve)
    return jsonify({"error": "No CVE entries found"}), 404
if __name__ == "__main__":
    app.run()