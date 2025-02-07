import os
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    send_file,
    flash,
)
from flask_bcrypt import Bcrypt
from flask_session import Session
from pymongo import MongoClient
import requests
import re
from flask_mail import Mail, Message
import random
import ipinfo as ipinfo
import json
from io import BytesIO
from dotenv import load_dotenv
import phonenumbers
from phonenumbers import geocoder, carrier, NumberParseException
import qrcode
import base64
import dicttoxml
from xml.dom.minidom import parseString
import xmltodict
import pandas as pd
import io
import csv
import yaml
import string
import math
from Cryptodome.Cipher import AES, DES3
import hashlib
import codecs

load_dotenv()

app = Flask(__name__)

app_key = os.getenv("SECRET_KEY")
bcrypt = Bcrypt(app)

client = MongoClient("mongodb://localhost:27017/")
db = client["user_db"]
users_collection = db["users"]

app.config["SESSION_TYPE"] = "mongodb"
app.config["SESSION_MONGODB"] = client
app.config["SESSION_MONGODB_COLLECT"] = "sessions"
Session(app)

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAILUSERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAILPASSWORD")
mail = Mail(app)


def fetch_cve_details():
    url = os.getenv("CVE_API_URL")
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            cve_id = data.get("cve", {}).get("CVE_data_meta", {}).get("ID", "No data")
            assigner = (
                data.get("cve", {}).get("CVE_data_meta", {}).get("ASSIGNER", "No data")
            )
            problemtype_data = (
                data.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])
            )
            if problemtype_data and "description" in problemtype_data[0]:
                description_list = problemtype_data[0]["description"]
                problem_type = (
                    description_list[0].get("value", "No data")
                    if description_list
                    else "No data"
                )
            else:
                problem_type = "No data"

            description_data = (
                data.get("cve", {}).get("description", {}).get("description_data", [])
            )
            description = (
                description_data[0].get("value", "No data")
                if description_data
                else "No data"
            )

            references = [
                ref.get("url", "No data")
                for ref in data.get("cve", {})
                .get("references", {})
                .get("reference_data", [])
            ]

            cvss_base_score = (
                data.get("impact", {})
                .get("baseMetricV3", {})
                .get("cvssV3", {})
                .get("baseScore", "No data")
            )
            cvss_severity = (
                data.get("impact", {})
                .get("baseMetricV3", {})
                .get("cvssV3", {})
                .get("baseSeverity", "No data")
            )

            published_date = data.get("publishedDate", "No data")
            last_modified_date = data.get("lastModifiedDate", "No data")

            return {
                "cve_id": cve_id,
                "assigner": assigner,
                "problem_type": problem_type,
                "description": description,
                "references": references,
                "cvss_base_score": cvss_base_score,
                "cvss_severity": cvss_severity,
                "published_date": published_date,
                "last_modified_date": last_modified_date,
            }
        else:
            return {"error": f"Error fetching data: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}


@app.route("/")
def home():
    if "username" in session:
        data = fetch_cve_details()
        return render_template("index.html", data=data)
    return redirect(url_for("login"))


def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True


def generate_otp():
    return random.randint(100000, 999999)


def get_user_ip():
    ipurl = "https://api64.ipify.org?format=json"
    response = requests.get(ipurl)
    ip_data = response.json()
    return ip_data["ip"]


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]

        if users_collection.find_one({"username": username}):
            return render_template("register.html", error="Username already exists")
        if users_collection.find_one({"email": email}):
            return render_template("register.html", error="Email already exists")

        if not is_valid_password(password):
            return render_template(
                "register.html",
                error="Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.",
            )

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        otp = generate_otp()
        users_collection.insert_one(
            {
                "username": username,
                "password": hashed_password,
                "email": email,
                "verified": False,
                "otp": otp,
            }
        )

        msg = Message(
            "Email OTP Verification",
            sender="your-email@example.com",
            recipients=[email],
        )
        msg.body = f"Your OTP for email verification is: {otp}"
        mail.send(msg)

        return redirect(url_for("verify_otp", email=email))

    return render_template("register.html")


@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        email = request.form.get("email")
        otp = request.form.get("otp")

        if not email or not otp:
            return render_template(
                "verify_otp.html", error="All fields are required.", email=email
            )

        user = users_collection.find_one({"email": email})
        if user and user.get("otp") == int(otp):
            users_collection.update_one({"email": email}, {"$set": {"verified": True}})
            return redirect(url_for("login"))
        else:
            return render_template("verify_otp.html", error="Invalid OTP", email=email)

    email = request.args.get("email")
    return render_template("verify_otp.html", email=email)


@app.route("/verify_email/<token>")
def verify_email(token):
    users_collection.update_one({"email": email}, {"$set": {"verified": True}})
    return "Email verified successfully", 200


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = users_collection.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            session["username"] = username
            session_collection = db["sessions"]
            session_collection.insert_one(
                {"username": username, "session_id": session.sid}
            )
            return redirect(url_for("home"))
        return "Invalid credentials"
    return render_template("login.html")


@app.route("/logout")
def logout():
    user_ip = get_user_ip()
    session.pop("username", None)
    session_collection = db["sessions"]
    session_collection.delete_one({"session_id": session.sid})
    ip_collection = db["user_ips"]
    ip_collection.insert_one({"ip": user_ip, "action": "logout"})
    return redirect(url_for("login"))


@app.route("/profile")
def profile():
    if "username" in session:
        user = users_collection.find_one({"username": session["username"]})
        if user:
            user_ip = get_user_ip()
            ip_collection = db["user_ips"]
            ip_collection.insert_one({"ip": user_ip, "action": "profile_view"})
            return render_template("profile.html", user=user)
    return redirect(url_for("login"))


@app.route("/cybersecurity_tools/ip_lookup", methods=["GET", "POST"])
def ip_lookup():
    if request.method == "POST":
        ip = request.form["ip"]
        access_token = os.getenv("IPINFO_ACCESS_TOKEN")
        handler = ipinfo.getHandler(access_token)
        details = handler.getDetails(ip)
        dict = {
            "ip": details.ip,
            "hostname": getattr(details, "hostname", "No hostname"),
            "city": getattr(details, "city", "No Data"),
            "region": getattr(details, "region", "No Data"),
            "country": getattr(details, "country", "No Data"),
            "loc": getattr(details, "loc", "No Data"),
            "postal": getattr(details, "postal", "No Data"),
            "timezone": getattr(details, "timezone", "No Data"),
            "asn": details.asn
            if hasattr(details, "asn")
            else {
                "asn": "No Data",
                "name": "No Data",
                "domain": "No Data",
                "route": "No Data",
                "type": "No Data",
            },
            "company": details.company
            if hasattr(details, "company")
            else {"name": "No Data", "domain": "No Data", "type": "No Data"},
            "privacy": details.privacy
            if hasattr(details, "privacy")
            else {
                "vpn": "No Data",
                "proxy": "No Data",
                "tor": "No Data",
                "relay": "No Data",
                "hosting": "No Data",
                "service": "No Data",
            },
            "abuse": details.abuse
            if hasattr(details, "abuse")
            else {
                "address": "No Data",
                "country": "No Data",
                "email": "No Data",
                "name": "No Data",
                "network": "No Data",
                "phone": "No Data",
            },
            "domains": details.domains
            if hasattr(details, "domains")
            else {"ip": "No Data", "total": "No Data", "domains": ["No Data"]},
        }
        return render_template("ip_lookup.html", data=dict)

    return render_template("ip_lookup.html", data=None)


@app.route("/cybersecurity_tools")
def cybersecurity_tools():
    return render_template("cybersecurity_tools.html")


@app.route("/general_tools")
def general_tools():
    return render_template("general_tools.html")


@app.route("/cheatsheet")
def cheatsheet():
    return render_template("cheatsheet.html")


@app.route("/cybersecurity_tools/phonenumber_parser", methods=["GET", "POST"])
def phonenumber_parser():
    if request.method == "POST":
        phone_number = request.form["phone_number"]
        try:
            parsed_number = phonenumbers.parse(phone_number, "IN")
            carrier_name = (
                carrier.name_for_number(parsed_number, "en") or "Unknown Carrier"
            )
            country = geocoder.description_for_number(parsed_number, "en")
            country_code = parsed_number.country_code
            is_valid = phonenumbers.is_valid_number(parsed_number)
            is_possible = phonenumbers.is_possible_number(parsed_number)
            number_type = phonenumbers.number_type(parsed_number)
            international_format = phonenumbers.format_number(
                parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
            national_format = phonenumbers.format_number(
                parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL
            )
            e164_format = phonenumbers.format_number(
                parsed_number, phonenumbers.PhoneNumberFormat.E164
            )
            rfc3966_format = phonenumbers.format_number(
                parsed_number, phonenumbers.PhoneNumberFormat.RFC3966
            )

            return render_template(
                "phonenumber_parser.html",
                country=country,
                country_code=country_code,
                is_valid=is_valid,
                is_possible=is_possible,
                number_type=number_type,
                international_format=international_format,
                national_format=national_format,
                e164_format=e164_format,
                rfc3966_format=rfc3966_format,
                carrier_name=carrier_name,
            )
        except NumberParseException:
            return render_template(
                "phonenumber_parser.html", error="Invalid phone number"
            )
    else:
        return render_template("phonenumber_parser.html")


def is_valid_mac(mac):
    mac = mac.strip()
    regex = r"^([0-9A-Fa-f]{2}([-:])){5}([0-9A-Fa-f]{2})$|^[0-9A-Fa-f]{12}$"
    return re.match(regex, mac) is not None


@app.route("/cybersecurity_tools/mac_address_lookup", methods=["GET", "POST"])
def mac_address_lookup():
    if request.method == "POST":
        mac_address = request.form["mac_address"]
        if mac_address:
            headers = {
                "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImp0aSI6IjA0NzAxMjU2LWNjNzEtNDgwNi1iY2I3LTllNTYyMmY4NmMwYiJ9.eyJpc3MiOiJtYWN2ZW5kb3JzIiwiYXVkIjoibWFjdmVuZG9ycyIsImp0aSI6IjA0NzAxMjU2LWNjNzEtNDgwNi1iY2I3LTllNTYyMmY4NmMwYiIsImlhdCI6MTczODQ5NjAyMywiZXhwIjoyMDUyOTkyMDIzLCJzdWIiOiIxNTUxMCIsInR5cCI6ImFjY2VzcyJ9.bssgbO1N7L3KkQHHsGqx843dsrfn4YlcLAJMS-X2hEe-eHJKRPQQFUa0i1rn8MaCWSzYSY7lGRVVKiSLY2aVrw"
            }
            response = requests.get(
                f"https://api.macvendors.com/v1/lookup/{mac_address}", headers=headers
            )
            if response.status_code == 200:
                data = response.json()
                return render_template("mac_address_lookup.html", data=data)
            else:
                flash("Error: Unable to perform MAC address lookup.")
                return redirect(url_for("mac_address_lookup"))
        else:
            flash("Error: Please enter a MAC address.")
            return redirect(url_for("mac_address_lookup"))
    return render_template("mac_address_lookup.html")


@app.route("/general_tools/text_to_ascii", methods=["GET", "POST"])
def text_to_ascii():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "text_to_ascii":
            text = request.form.get("text")
            if text:
                ascii_result = " ".join(str(ord(char)) for char in text)
                return render_template(
                    "text_to_ascii.html", ascii_result=ascii_result, original_text=text
                )
            else:
                flash("Error: Please enter some text for conversion.")
        elif action == "ascii_to_text":
            ascii_text = request.form.get("ascii_text")
            if ascii_text:
                try:
                    text_result = "".join(chr(int(num)) for num in ascii_text.split())
                    return render_template(
                        "text_to_ascii.html",
                        text_result=text_result,
                        original_ascii=ascii_text,
                    )
                except ValueError:
                    flash(
                        "Error: Invalid ASCII input. Please enter valid ASCII codes separated by spaces."
                    )
            else:
                flash("Error: Please enter some ASCII codes for conversion.")
    return render_template("text_to_ascii.html")


@app.route("/general_tools/text_to_unicode", methods=["GET", "POST"])
def text_to_unicode():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "text_to_unicode":
            text = request.form.get("text")
            if text:
                unicode_result = " ".join(f"U+{ord(char):04X}" for char in text)
                return render_template(
                    "text_to_unicode.html",
                    unicode_result=unicode_result,
                    original_text=text,
                )
            else:
                flash("Error: Please enter some text for conversion.")
        elif action == "unicode_to_text":
            unicode_input = request.form.get("unicode_input")
            if unicode_input:
                try:
                    code_points = unicode_input.strip().split()
                    text_result = "".join(
                        chr(int(code_point[2:], 16)) for code_point in code_points
                    )
                    return render_template(
                        "text_to_unicode.html",
                        text_result=text_result,
                        original_unicode=unicode_input,
                    )
                except ValueError:
                    flash(
                        'Error: Invalid Unicode input. Please use format like "U+0041 U+0042".'
                    )
            else:
                flash("Error: Please enter Unicode code points for conversion.")
    return render_template("text_to_unicode.html")


@app.route("/general_tools/qr_code_generator", methods=["GET", "POST"])
def generate_qr_code():
    qr_code_img = None
    if request.method == "POST":
        data = request.form.get("data")
        if data:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(data)
            qr.make(fit=True)
            img = qr.make_image(fill="black", back_color="white")

            img_io = BytesIO()
            img.save(img_io, "PNG")
            img_io.seek(0)

            img_base64 = base64.b64encode(img_io.getvalue()).decode("utf-8")
            qr_code_img = f"data:image/png;base64,{img_base64}"

    return render_template("qr_code_generator.html", qr_code_img=qr_code_img)


@app.route("/cheatsheet/linux")
def linux_cheatsheet():
    return render_template("linux_cheatsheet.html")


@app.route("/cheatsheet/git")
def git_cheatsheet():
    return render_template("git_cheatsheet.html")


@app.route("/cheatsheet/regex")
def regex_cheatsheet():
    return render_template("regex_cheatsheet.html")


@app.route("/cheatsheet/docker")
def docker_cheatsheet():
    return render_template("docker_cheatsheet.html")


@app.route("/cheatsheet/kubernetes")
def kubernetes_cheatsheet():
    return render_template("kubernetes_cheatsheet.html")


@app.route("/cheatsheet/windows")
def windows_cheatsheet():
    return render_template("windows_cheatsheet.html")


@app.route("/general_tools/json_to_xml", methods=["GET", "POST"])
def json_to_xml():
    if request.method == "POST":
        try:
            if "json_data" in request.form:
                json_data = json.loads(request.form["json_data"])
                xml_data = dicttoxml.dicttoxml(json_data).decode()
                pretty_xml = parseString(xml_data).toprettyxml()
                return render_template("json_to_xml.html", xml_data=pretty_xml)
            elif "xml_data" in request.form:
                xml_data = request.form["xml_data"]
                json_data = json.dumps(xmltodict.parse(xml_data), indent=4)
                return render_template("json_to_xml.html", json_data=json_data)
        except Exception as e:
            return render_template("json_to_xml.html", error=str(e))
    else:
        return render_template("json_to_xml.html")


@app.route("/general_tools/json_to_csv", methods=["GET", "POST"])
def json_to_csv():
    if request.method == "POST":
        try:
            if "json_data" in request.form:
                json_data = json.loads(request.form["json_data"])
                if isinstance(json_data, dict):
                    json_data = [json_data]  # Convert single dictionary to list
                if isinstance(json_data, list):
                    output = io.StringIO()
                    csv_writer = csv.DictWriter(output, fieldnames=json_data[0].keys())
                    csv_writer.writeheader()
                    csv_writer.writerows(json_data)
                    csv_data = output.getvalue()
                    return render_template("json_to_csv.html", csv_data=csv_data)
                else:
                    return render_template(
                        "json_to_csv.html",
                        error="JSON data must be a list of dictionaries or a single dictionary.",
                    )
            elif "csv_data" in request.form:
                csv_data = request.form["csv_data"]
                csv_reader = csv.DictReader(io.StringIO(csv_data))
                json_data = json.dumps([row for row in csv_reader], indent=4)
                return render_template("json_to_csv.html", json_data=json_data)
        except Exception as e:
            return render_template("json_to_csv.html", error=str(e))
    else:
        return render_template("json_to_csv.html")


@app.route("/general_tools/json_to_yaml", methods=["GET", "POST"])
def json_to_yaml():
    if request.method == "POST":
        try:
            if "json_data" in request.form:
                json_data = json.loads(request.form["json_data"])
                yaml_data = yaml.dump(json_data, default_flow_style=False)
                return render_template("json_to_yaml.html", yaml_data=yaml_data)
            elif "yaml_data" in request.form:
                yaml_data = request.form["yaml_data"]
                json_data = json.dumps(yaml.safe_load(yaml_data), indent=4)
                return render_template("json_to_yaml.html", json_data=json_data)
        except Exception as e:
            return render_template("json_to_yaml.html", error=str(e))
    else:
        return render_template("json_to_yaml.html")


def password_strength_checker(password):
    length = len(password)

    if length == 0:
        return {"score": 0, "entropy": 0, "charset_size": 0, "crack_time": "Instantly"}

    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += len(string.punctuation)

    entropy = math.log2(charset_size**length) if charset_size > 0 else 0

    # Score Calculation (Realistic)
    score = min(100, int((entropy / 7) * 10))  # Normalized to 100

    # Crack Time Estimation
    if entropy < 14:
        crack_time = "Instantly"
    elif entropy < 28:
        crack_time = "Minutes"
    elif entropy < 40:
        crack_time = "Hours"
    elif entropy < 50:
        crack_time = "Days"
    elif entropy < 60:
        crack_time = "Months"
    elif entropy < 70:
        crack_time = "Years"
    else:
        crack_time = "Centuries"

    return {
        "score": score,
        "entropy": round(entropy, 2),
        "charset_size": charset_size,
        "crack_time": crack_time,
    }


@app.route("/cybersecurity_tools/password_strength", methods=["GET", "POST"])
def password_strength():
    if request.method == "POST":
        password = request.form.get("password", "")
        result = password_strength_checker(password)
        return jsonify(result)
    return render_template("password_strength.html")


def pad(text, block_size=16):
    return text + (block_size - len(text) % block_size) * chr(
        block_size - len(text) % block_size
    )


def unpad(text):
    return text[: -ord(text[-1])]


def encrypt_aes(text, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(text).encode())
    return base64.b64encode(encrypted_text).decode()


def decrypt_aes(text, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(text)).decode()
    return unpad(decrypted_text)


def encrypt_tripledes(text, key):
    key = hashlib.md5(key.encode()).digest()
    cipher = DES3.new(key, DES3.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(text, 8).encode())
    return base64.b64encode(encrypted_text).decode()


def decrypt_tripledes(text, key):
    key = hashlib.md5(key.encode()).digest()
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(text)).decode()
    return unpad(decrypted_text)


def encrypt_rc4(text, key):
    cipher = codecs.getencoder("rot_13")
    return cipher(text)[0]


def decrypt_rc4(text, key):
    cipher = codecs.getdecoder("rot_13")
    return cipher(text)[0]


@app.route("/cybersecurity_tools/ecrypt_decrypt_text", methods=["GET", "POST"])
def encrypt_decrypt():
    encrypted_text = decrypted_text = ""
    if request.method == "POST":
        text = request.form.get("text", "")
        key = request.form.get("key", "")
        algorithm = request.form.get("algorithm", "AES")
        action = request.form.get("action", "encrypt")

        try:
            if algorithm == "AES":
                if action == "encrypt":
                    encrypted_text = encrypt_aes(text, key)
                else:
                    decrypted_text = decrypt_aes(text, key)
            elif algorithm == "TripleDES":
                if action == "encrypt":
                    encrypted_text = encrypt_tripledes(text, key)
                else:
                    decrypted_text = decrypt_tripledes(text, key)
            elif algorithm == "RC4":
                if action == "encrypt":
                    encrypted_text = encrypt_rc4(text, key)
                else:
                    decrypted_text = decrypt_rc4(text, key)
        except Exception as e:
            decrypted_text = str(e)

    return render_template(
        "encrypt_decrypt.html",
        encrypted_text=encrypted_text,
        decrypted_text=decrypted_text,
    )


def normalize_email(email):
    email = email.strip().lower()
    if "@" not in email:
        return email
    username, domain = email.split("@", 1)
    if "+" in username:
        username = username.split("+", 1)[0]
    if domain in ["gmail.com", "googlemail.com", "hotmail.com", "outlook.com"]:
        username = username.replace(".", "")
    return f"{username}@{domain}"


@app.route("/general_tools/email_normalizer", methods=["GET", "POST"])
def email_normalizer():
    normalized_emails = []
    if request.method == "POST":
        input_emails = request.form.get("emails")
        if input_emails:
            emails = re.split(r"[\s,;]+", input_emails)
            normalized_emails = [
                normalize_email(email) for email in emails if email.strip()
            ]
    return render_template("email_normalizer.html", normalized_emails=normalized_emails)

@app.route("/cheatsheet/python" , methods=["GET", "POST"])

def python_cheatsheet():
    return render_template("python_cheatsheet.html")
if __name__ == "__main__":
    app.run(port=1100, debug=True)
