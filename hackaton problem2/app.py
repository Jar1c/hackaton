from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from supabase import create_client
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from functools import wraps
import os
import hashlib
import uuid

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supporttrack-secret-2024")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ── Guard: i-redirect sa admin login kung hindi naka-login ──
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login_page"))
        return f(*args, **kwargs)
    return decorated


# ==========================================
# AUTHENTICATION ROUTES (LOGIN / SIGNUP)
# ==========================================

@app.route("/") 
def login_page():
    return render_template("login.html")

@app.route("/signup")
def signup_page():
    return render_template("signup.html")

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    
    firstname = data.get("firstname")
    lastname = data.get("lastname")
    student_id = data.get("student_id")
    program = data.get("program")
    email = data.get("email")
    password = hash_password(data["password"])

    try:
        supabase.table("users").insert({
            "first_name": firstname,
            "last_name": lastname,
            "student_id": student_id,
            "program": program,
            "email": email,
            "password": password
        }).execute()
        
        return jsonify({"message": "Account created successfully", "status": "success"})
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}", "status": "error"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data["email"]
    password = hash_password(data["password"])

    res = supabase.table("users").select("*").eq("email", email).eq("password", password).execute()

    if res.data:
        user = res.data[0]
        return jsonify({
            "message": "Login success", 
            "status": "success",
            "student_id": user.get("student_id"), 
            "program": user.get("program")
        })
    else:
        return jsonify({"message": "Invalid credentials", "status": "error"})


# ==========================================
# STUDENT CONCERN ROUTES
# ==========================================

@app.route("/student_dashboard")
def student_dashboard():
    return render_template("student_dashboard.html")

@app.route("/submit_concern", methods=["POST"])
def submit_concern():
    student_id = request.form.get("student_id")
    program = request.form.get("program")
    category = request.form.get("category")
    description = request.form.get("description")
    is_anonymous = str(request.form.get("is_anonymous")).lower() == "true"

    assigned_dept = "General Support"
    if category == "Academic":
        if program in ["BSIT", "BSCS"]: assigned_dept = "CCS Dean's Office"
        elif program == "BSBA": assigned_dept = "CBA Dean's Office"
        else: assigned_dept = "Registrar's Office"
    elif category == "Financial": assigned_dept = "Accounting & Cashier"
    elif category == "Student Welfare" or category == "Welfare": assigned_dept = "Guidance Office"

    attachment_path = None

    try:
        if "attachment" in request.files:
            file = request.files["attachment"]
            if file and file.filename != "":
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                file_content = file.read()
                supabase.storage.from_("attachments").upload(unique_filename, file_content, {"content-type": file.content_type})
                attachment_path = supabase.storage.from_("attachments").get_public_url(unique_filename)

        res_count = supabase.table("concerns").select("id", count="exact").eq("category", category).execute()
        current_count = res_count.count if res_count.count is not None else 0
        next_number = current_count + 1
        formatted_number = str(next_number).zfill(3)

        prefixes = {"Academic": "A", "Financial": "F", "Student Welfare": "SW"}
        custom_id = f"{prefixes.get(category, 'GEN')}-{formatted_number}"

        supabase.table("concerns").insert({
            "id": custom_id, 
            "student_id": student_id,
            "program": program,
            "category": category,
            "description": description,
            "is_anonymous": is_anonymous,
            "assigned_dept": assigned_dept,
            "attachment_path": attachment_path,
            "status": "Routed"
        }).execute()

        actor_name = "Anonymous Student" if is_anonymous else student_id
        supabase.table("audit_logs").insert({
            "concern_id": custom_id,
            "actor": actor_name,
            "action": f"Submitted {custom_id} and Auto-Routed to {assigned_dept}"
        }).execute()

        return jsonify({"status": "success", "tracking_id": custom_id})
        
    except Exception as e:
        print(f"Error detail: {e}")
        return jsonify({"message": str(e), "status": "error"})


# ==========================================
# ADMIN AUTH ROUTES
# ==========================================

@app.route("/admin/login")
def admin_login_page():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_login.html")

@app.route("/admin/login", methods=["POST"])
def admin_login():
    data = request.json
    username = data.get("username", "").strip()
    password = hash_password(data.get("password", ""))

    try:
        res = supabase.table("admins") \
            .select("*") \
            .eq("username", username) \
            .eq("password", password) \
            .execute()

        if res.data:
            admin = res.data[0]
            session["admin_logged_in"] = True
            session["admin_username"]  = admin["username"]
            session["admin_role"]      = admin["role"]

            return jsonify({
                "status":   "success",
                "username": admin["username"],
                "role":     admin["role"]
            })
        else:
            return jsonify({"status": "error", "message": "Invalid username or password."})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login_page"))


# ==========================================
# ADMIN DASHBOARD ROUTES (protected)
# ==========================================

@app.route("/admin")
@admin_required
def admin_dashboard():
    return render_template("admin_dashboard.html")

@app.route("/admin/concerns", methods=["GET"])
@admin_required
def admin_get_concerns():
    try:
        res = supabase.table("concerns").select("*").order("created_at", desc=True).execute()
        return jsonify({"status": "success", "concerns": res.data})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/admin/update_status", methods=["POST"])
@admin_required
def admin_update_status():
    data = request.json
    concern_id = data.get("concern_id")
    new_status = data.get("status")

    allowed = ["Routed", "In Progress", "Resolved", "Closed"]
    if new_status not in allowed:
        return jsonify({"status": "error", "message": "Invalid status value."})

    try:
        supabase.table("concerns").update({"status": new_status}).eq("id", concern_id).execute()
        supabase.table("audit_logs").insert({
            "concern_id": concern_id,
            "actor":      session.get("admin_username", "Admin"),
            "action":     f"Status updated to '{new_status}' for concern {concern_id}"
        }).execute()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/admin/audit_logs", methods=["GET"])
@admin_required
def admin_get_audit_logs():
    try:
        res = supabase.table("audit_logs").select("*").order("created_at", desc=True).execute()
        return jsonify({"status": "success", "logs": res.data})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/admin/students", methods=["GET"])
@admin_required
def admin_get_students():
    try:
        res = supabase.table("users").select(
            "student_id, first_name, last_name, program, email, created_at"
        ).order("created_at", desc=True).execute()
        return jsonify({"status": "success", "students": res.data})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# ── NEW: Fetch full name of a student by student_id ──
@app.route("/admin/student_info/<student_id>", methods=["GET"])
@admin_required
def admin_get_student_info(student_id):
    try:
        res = supabase.table("users").select(
            "first_name, last_name"
        ).eq("student_id", student_id).execute()

        if res.data:
            user = res.data[0]
            return jsonify({
                "status": "success",
                "full_name": user["first_name"] + " " + user["last_name"]
            })
        return jsonify({"status": "not_found", "full_name": "Unknown"})
    except Exception as e:
        return jsonify({"status": "error", "full_name": "Unknown"})


# ==========================================
# APP EXECUTION
# ==========================================
if __name__ == '__main__':
    app.run(debug=True)