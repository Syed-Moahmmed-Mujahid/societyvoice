from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import traceback
import os
import secrets
from werkzeug.utils import secure_filename
import json

app = Flask(__name__)
CORS(app)
DB_NAME = "societyvoice.db"
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    print(f"✅ Created directory: {UPLOAD_FOLDER}")

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            house_number TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            status TEXT DEFAULT 'Open',
            user_id INTEGER NOT NULL,
            image_path TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS polls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT NOT NULL,
            description TEXT,
            options_json TEXT,
            created_by INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS poll_votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            poll_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            vote TEXT NOT NULL,
            FOREIGN KEY(poll_id) REFERENCES polls(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS registration_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            house_number TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS complaint_likes (
            complaint_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            PRIMARY KEY (complaint_id, user_id),
            FOREIGN KEY(complaint_id) REFERENCES complaints(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS house_change_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            requested_house_number TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )""")
        
        # --- Payments Table ---
        c.execute("""CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            utr_number TEXT NOT NULL,
            payment_type TEXT DEFAULT 'Maintenance',
            description TEXT,
            payment_date DATETIME NOT NULL,
            screenshot_path TEXT,
            status TEXT DEFAULT 'Pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_hidden INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")

        # --- MIGRATION CHECK ---
        # Ensure new columns exist if the table was created previously
        try:
            c.execute("ALTER TABLE payments ADD COLUMN payment_type TEXT DEFAULT 'Maintenance'")
            print("✅ Added 'payment_type' column to payments table.")
        except sqlite3.OperationalError:
            pass 

        try:
            c.execute("ALTER TABLE payments ADD COLUMN description TEXT")
            print("✅ Added 'description' column to payments table.")
        except sqlite3.OperationalError:
            pass 
        
        try:
            c.execute("ALTER TABLE payments ADD COLUMN user_hidden INTEGER DEFAULT 0")
            print("✅ Added 'user_hidden' column to payments table.")
        except sqlite3.OperationalError:
            pass 

        admin_check = c.execute("SELECT COUNT(*) as count FROM users WHERE role = 'admin'").fetchone()
        if admin_check['count'] == 0:
            c.execute("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
                     ("Admin", "admin@society.com", "admin123", "admin"))
        conn.commit()
        print("✅ Database tables checked/created successfully.")
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        traceback.print_exc()
    finally:
        conn.close()

init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- USER & AUTHENTICATION ROUTES ---

@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.json
        name, email, password, house_number = data.get("name"), data.get("email"), data.get("password"), data.get("house_number")
        if not all([name, email, password, house_number]):
            return jsonify({"error": "Missing required fields"}), 400
        conn = get_db_connection()
        conn.execute("INSERT INTO registration_requests (name, email, password, role, house_number) VALUES (?, ?, ?, ?, ?)",
                    (name, email, password, "resident", house_number))
        conn.commit()
        conn.close()
        print(f"✅ Registration request submitted for {email}")
        return jsonify({"message": "Registration request submitted successfully. Awaiting admin approval."})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists as a registration request or a user"}), 409
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        email, password = data.get("email"), data.get("password")
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()
        if user and user['password'] == password:
            print(f"✅ Login successful for {email} with role {user['role']}")
            return jsonify(dict(user))
        else:
            print(f"❌ Invalid login attempt for {email}")
            return jsonify({"error": "Invalid email or password"}), 401
    except Exception as e:
        print(f"❌ Login error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/change_password", methods=["POST"])
def change_password():
    try:
        data = request.json
        user_id, current_password, new_password = data.get("id"), data.get("current_password"), data.get("new_password")
        if not all([user_id, current_password, new_password]):
            return jsonify({"error": "Missing required fields"}), 400
        conn = get_db_connection()
        user = conn.execute("SELECT password FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            conn.close()
            return jsonify({"error": "User not found"}), 404
        if user['password'] != current_password:
            conn.close()
            return jsonify({"error": "Current password is incorrect"}), 400
        conn.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user_id))
        conn.commit()
        conn.close()
        print(f"✅ Password changed for user ID {user_id}")
        return jsonify({"message": "Password updated successfully"})
    except Exception as e:
        print(f"❌ Change password error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# --- COMPLAINT ROUTES ---

@app.route("/submit_complaint", methods=["POST"])
def submit_complaint():
    try:
        title, description, category, user_id = request.form.get("title"), request.form.get("description"), request.form.get("category"), request.form.get("user_id")
        if not all([title, description, category, user_id]):
            return jsonify({"error": "Missing required fields"}), 400
        image_path = None
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file and allowed_file(image_file.filename):
                file_extension = image_file.filename.rsplit('.', 1)[1].lower()
                unique_filename = f"{secrets.token_hex(16)}.{file_extension}"
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                image_path = unique_filename
        conn = get_db_connection()
        conn.execute("INSERT INTO complaints (title, description, category, user_id, image_path) VALUES (?, ?, ?, ?, ?)",
                    (title, description, category, user_id, image_path))
        conn.commit()
        conn.close()
        print(f"✅ Complaint submitted by user ID {user_id}")
        return jsonify({"message": "Complaint submitted successfully."})
    except Exception as e:
        print(f"❌ Submit complaint error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/get_complaints", methods=["GET"])
def get_complaints():
    try:
        user_id, view_type = request.args.get("user_id"), request.args.get("view_type", "all")
        conn = get_db_connection()
        query = "SELECT c.*, u.name as user_name, u.house_number FROM complaints c JOIN users u ON c.user_id = u.id"
        params = []
        if view_type == 'my' and user_id:
            query += " WHERE c.user_id = ?"
            params.append(user_id)
        query += " ORDER BY c.created_at DESC"
        
        complaints_raw = conn.execute(query, params).fetchall()
        
        complaints_list = []
        for complaint in complaints_raw:
            complaint_dict = dict(complaint)
            complaint_id = complaint_dict['id']
            
            likes = conn.execute("SELECT COUNT(*) as count FROM complaint_likes WHERE complaint_id = ?", (complaint_id,)).fetchone()
            complaint_dict['like_count'] = likes['count'] if likes else 0
            
            user_has_liked = False
            if user_id:
                liked = conn.execute("SELECT 1 FROM complaint_likes WHERE complaint_id = ? AND user_id = ?", (complaint_id, user_id)).fetchone()
                if liked:
                    user_has_liked = True
            complaint_dict['user_has_liked'] = user_has_liked
            
            complaints_list.append(complaint_dict)

        conn.close()
        return jsonify(complaints_list)
    except Exception as e:
        print(f"❌ Get complaints error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/update_complaint_status", methods=["POST"])
def update_complaint_status():
    try:
        data = request.json
        complaint_id = data.get("complaint_id")
        new_status = data.get("new_status")
        user_role = data.get("user_role")

        if not all([complaint_id, new_status, user_role]):
            return jsonify({"error": "Missing required fields"}), 400
        
        conn = get_db_connection()

        if user_role in ['admin', 'worker']:
            conn.execute("UPDATE complaints SET status = ? WHERE id = ?", (new_status, complaint_id))
            conn.commit()
            conn.close()
            print(f"✅ Complaint ID {complaint_id} status updated to {new_status} by {user_role}")
            return jsonify({"message": "Status updated successfully"})

        elif user_role == 'resident':
            user_id = data.get("user_id")
            if not user_id:
                conn.close()
                return jsonify({"error": "User ID is required for this action"}), 400
            
            if new_status != 'Open':
                conn.close()
                return jsonify({"error": "Residents can only reopen complaints."}), 403

            complaint = conn.execute("SELECT user_id, status FROM complaints WHERE id = ?", (complaint_id,)).fetchone()

            if not complaint:
                conn.close()
                return jsonify({"error": "Complaint not found"}), 404
            
            if int(complaint['user_id']) != int(user_id):
                conn.close()
                return jsonify({"error": "You can only reopen your own complaints."}), 403
            
            if complaint['status'] != 'resolved':
                conn.close()
                return jsonify({"error": "Only resolved complaints can be reopened."}), 400
            
            conn.execute("UPDATE complaints SET status = ? WHERE id = ?", (new_status, complaint_id))
            conn.commit()
            conn.close()
            print(f"✅ Complaint ID {complaint_id} reopened by resident ID {user_id}")
            return jsonify({"message": "Complaint reopened successfully."})

        else:
            conn.close()
            return jsonify({"error": "Unauthorized role"}), 403

    except Exception as e:
        print(f"❌ Update complaint status error: {e}")
        return jsonify({"error": "Internal server error"}), 500
        
@app.route("/like_complaint", methods=["POST"])
def like_complaint():
    try:
        data = request.json
        complaint_id, user_id = data.get("complaint_id"), data.get("user_id")
        if not all([complaint_id, user_id]):
            return jsonify({"error": "Missing required fields"}), 400

        conn = get_db_connection()
        existing_like = conn.execute("SELECT 1 FROM complaint_likes WHERE complaint_id = ? AND user_id = ?", 
                                      (complaint_id, user_id)).fetchone()
        
        if existing_like:
            conn.execute("DELETE FROM complaint_likes WHERE complaint_id = ? AND user_id = ?", (complaint_id, user_id))
            action = "unliked"
        else:
            conn.execute("INSERT INTO complaint_likes (complaint_id, user_id) VALUES (?, ?)", (complaint_id, user_id))
            action = "liked"
            
        conn.commit()
        new_count = conn.execute("SELECT COUNT(*) as count FROM complaint_likes WHERE complaint_id = ?", (complaint_id,)).fetchone()['count']
        conn.close()
        
        return jsonify({"message": f"Complaint {action} successfully.", "new_like_count": new_count, "action": action})

    except Exception as e:
        print(f"❌ Like complaint error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/delete_complaint", methods=["POST"])
def delete_complaint():
    try:
        data = request.json
        complaint_id, user_role = data.get("complaint_id"), data.get("user_role")
        if not all([complaint_id, user_role]):
            return jsonify({"error": "Missing required fields"}), 400
        if user_role not in ['admin', 'worker']:
            return jsonify({"error": "Unauthorized"}), 403
        conn = get_db_connection()
        cursor = conn.cursor()
        image_record = cursor.execute("SELECT image_path FROM complaints WHERE id = ?", (complaint_id,)).fetchone()
        cursor.execute("DELETE FROM complaints WHERE id = ?", (complaint_id,))
        conn.commit()
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"error": "Complaint not found"}), 404
        if image_record and image_record['image_path']:
            try:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], image_record['image_path'])
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as file_error:
                print(f"⚠️ Error deleting image file: {file_error}")
        conn.close()
        return jsonify({"message": "Complaint deleted successfully"})
    except Exception as e:
        print(f"❌ Delete complaint error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# --- POLL ROUTES ---
@app.route("/create_poll", methods=["POST"])
def create_poll():
    try:
        data = request.json
        question, description, options_list, created_by = data.get("question"), data.get("description"), data.get("options"), data.get("created_by")
        if not all([question, options_list, created_by]):
            return jsonify({"error": "Missing required fields"}), 400
        if not isinstance(options_list, list) or len(options_list) < 2:
            return jsonify({"error": "Poll must have at least two options"}), 400
        conn = get_db_connection()
        conn.execute("INSERT INTO polls (question, description, options_json, created_by) VALUES (?, ?, ?, ?)",
                    (question, description, json.dumps(options_list), created_by))
        conn.commit()
        conn.close()
        return jsonify({"message": "Poll created successfully"})
    except Exception as e:
        print(f"❌ Create poll error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/get_polls", methods=["GET"])
def get_polls():
    try:
        user_id = request.args.get("user_id")
        conn = get_db_connection()
        polls = conn.execute("SELECT p.*, u.name as created_by_name FROM polls p JOIN users u ON p.created_by = u.id ORDER BY p.created_at DESC").fetchall()
        result_polls = []
        for poll in polls:
            poll_dict = dict(poll)
            poll_id = poll_dict['id']
            poll_dict['options'] = json.loads(poll_dict['options_json'])
            votes = conn.execute("SELECT vote, COUNT(*) as count FROM poll_votes WHERE poll_id = ? GROUP BY vote", (poll_id,)).fetchall()
            poll_dict['vote_counts'] = {v['vote']: v['count'] for v in votes}
            poll_dict['total_votes'] = sum(poll_dict['vote_counts'].values())
            if user_id:
                user_vote = conn.execute("SELECT vote FROM poll_votes WHERE poll_id = ? AND user_id = ?", (poll_id, user_id)).fetchone()
                poll_dict['has_voted'] = user_vote is not None
                poll_dict['user_vote'] = user_vote['vote'] if user_vote else None
            result_polls.append(poll_dict)
        conn.close()
        return jsonify(result_polls)
    except Exception as e:
        print(f"❌ Get polls error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/vote_poll", methods=["POST"])
def vote_poll():
    try:
        data = request.json
        poll_id, user_id, vote = data.get("poll_id"), data.get("user_id"), data.get("option")
        if not all([poll_id, user_id, vote]):
            return jsonify({"error": "Missing required fields"}), 400
        conn = get_db_connection()
        if conn.execute("SELECT 1 FROM poll_votes WHERE poll_id = ? AND user_id = ?", (poll_id, user_id)).fetchone():
             return jsonify({"error": "You have already voted in this poll"}), 409
        conn.execute("INSERT INTO poll_votes (poll_id, user_id, vote) VALUES (?, ?, ?)", (poll_id, user_id, vote))
        conn.commit()
        conn.close()
        return jsonify({"message": "Vote recorded successfully"})
    except Exception as e:
        print(f"❌ Vote poll error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/delete_poll", methods=["POST"])
def delete_poll():
    try:
        data = request.json
        poll_id, user_role = data.get("poll_id"), data.get("user_role")
        if user_role != 'admin':
            return jsonify({"error": "Unauthorized"}), 403
        if not poll_id:
            return jsonify({"error": "Poll ID required"}), 400
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM poll_votes WHERE poll_id = ?", (poll_id,))
        cursor.execute("DELETE FROM polls WHERE id = ?", (poll_id,))
        conn.commit()
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"error": "Poll not found"}), 404
        conn.close()
        return jsonify({"message": "Poll deleted successfully"})
    except Exception as e:
        print(f"❌ Delete poll error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# --- ADMIN-ONLY USER MANAGEMENT ROUTES ---

@app.route("/get_users", methods=["GET"])
def get_users():
    try:
        conn = get_db_connection()
        users = conn.execute("SELECT id, name, email, role, house_number FROM users ORDER BY role, name").fetchall()
        conn.close()
        return jsonify([dict(u) for u in users])
    except Exception as e:
        print(f"❌ Get users error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/add_user", methods=["POST"])
def add_user():
    try:
        data = request.json
        name, email, password, role, house_number = data.get("name"), data.get("email"), data.get("password"), data.get("role"), data.get("house_number")
        if not all([name, email, password, role]):
            return jsonify({"error": "Missing required fields"}), 400
        if role == 'resident' and not house_number:
            return jsonify({"error": "House number is required for residents"}), 400
        conn = get_db_connection()
        conn.execute("INSERT INTO users (name, email, password, role, house_number) VALUES (?, ?, ?, ?, ?)",
                    (name, email, password, role, house_number if role == 'resident' else None))
        conn.commit()
        conn.close()
        print(f"✅ New user added by admin: {email} with role {role}")
        return jsonify({"message": "User added successfully"})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists"}), 409
    except Exception as e:
        print(f"❌ Add user error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/get_registration_requests", methods=["GET"])
def get_registration_requests():
    try:
        conn = get_db_connection()
        requests = conn.execute("SELECT * FROM registration_requests ORDER BY created_at ASC").fetchall()
        conn.close()
        return jsonify([dict(r) for r in requests])
    except Exception as e:
        print(f"❌ Get registration requests error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/process_registration_request", methods=["POST"])
def process_registration_request():
    try:
        data = request.json
        request_id, action = data.get("request_id"), data.get("action")
        if not all([request_id, action]) or action not in ['approve', 'reject']:
            return jsonify({"error": "Missing or invalid required fields"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        if action == 'approve':
            req_data = cursor.execute("SELECT * FROM registration_requests WHERE id = ?", (request_id,)).fetchone()
            if not req_data:
                conn.close()
                return jsonify({"error": "Request not found"}), 404
            try:
                cursor.execute("INSERT INTO users (name, email, password, role, house_number) VALUES (?, ?, ?, ?, ?)",
                              (req_data['name'], req_data['email'], req_data['password'], req_data['role'], req_data['house_number']))
            except sqlite3.IntegrityError:
                cursor.execute("DELETE FROM registration_requests WHERE id = ?", (request_id,))
                conn.commit()
                conn.close()
                return jsonify({"error": "User with this email already exists. The request has been removed."}), 409
        
        cursor.execute("DELETE FROM registration_requests WHERE id = ?", (request_id,))
        conn.commit()

        if cursor.rowcount == 0 and action == 'reject':
             conn.close()
             return jsonify({"error": "Request not found"}), 404

        conn.close()
        return jsonify({"message": f"Registration request {action}d successfully."})

    except Exception as e:
        print(f"❌ Process registration error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/delete_user", methods=["POST"])
def delete_user():
    try:
        data = request.json
        user_id = data.get("user_id")
        if not user_id:
            return jsonify({"error": "User ID is required"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM complaints WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM poll_votes WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"error": "User not found or already deleted"}), 404

        conn.close()
        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        print(f"❌ Delete user error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# --- HOUSE NUMBER CHANGE ROUTES ---

@app.route("/request_house_change", methods=["POST"])
def request_house_change():
    try:
        data = request.json
        user_id, new_house_number = data.get("user_id"), data.get("new_house_number")
        if not all([user_id, new_house_number]):
            return jsonify({"error": "Missing required fields"}), 400
        
        conn = get_db_connection()
        existing_request = conn.execute("SELECT 1 FROM house_change_requests WHERE user_id = ? AND status = 'pending'", (user_id,)).fetchone()
        if existing_request:
            conn.close()
            return jsonify({"error": "You already have a pending house number change request."}), 409
            
        conn.execute("INSERT INTO house_change_requests (user_id, requested_house_number) VALUES (?, ?)", (user_id, new_house_number))
        conn.commit()
        conn.close()
        return jsonify({"message": "House number change request submitted successfully."})
    except Exception as e:
        print(f"❌ House change request error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/get_house_change_requests", methods=["GET"])
def get_house_change_requests():
    try:
        conn = get_db_connection()
        requests = conn.execute("""
            SELECT hcr.id, u.id as user_id, u.name, u.email, u.house_number as current_house_number, hcr.requested_house_number, hcr.created_at
            FROM house_change_requests hcr
            JOIN users u ON hcr.user_id = u.id
            WHERE hcr.status = 'pending'
            ORDER BY hcr.created_at ASC
        """).fetchall()
        conn.close()
        return jsonify([dict(r) for r in requests])
    except Exception as e:
        print(f"❌ Get house change requests error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/process_house_change_request", methods=["POST"])
def process_house_change_request():
    try:
        data = request.json
        request_id, action = data.get("request_id"), data.get("action")
        if not all([request_id, action]) or action not in ['approve', 'reject']:
            return jsonify({"error": "Missing or invalid required fields"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        if action == 'approve':
            req_data = cursor.execute("SELECT user_id, requested_house_number FROM house_change_requests WHERE id = ?", (request_id,)).fetchone()
            if not req_data:
                conn.close()
                return jsonify({"error": "Request not found"}), 404
            
            cursor.execute("UPDATE users SET house_number = ? WHERE id = ?", (req_data['requested_house_number'], req_data['user_id']))
        
        cursor.execute("DELETE FROM house_change_requests WHERE id = ?", (request_id,))
        conn.commit()

        if cursor.rowcount == 0:
             conn.close()
             return jsonify({"error": "Request not found or already processed"}), 404

        conn.close()
        return jsonify({"message": f"House number change request {action}d successfully."})
    except Exception as e:
        print(f"❌ Process house change request error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# --- ALERT ROUTES ---

@app.route("/create_alert", methods=["POST"])
def create_alert():
    try:
        data = request.json
        message, user_id, user_role = data.get("message"), data.get("user_id"), data.get("user_role")
        if not all([message, user_id, user_role]):
            return jsonify({"error": "Missing required fields"}), 400
        if user_role != 'admin':
            return jsonify({"error": "Unauthorized"}), 403
        
        conn = get_db_connection()
        conn.execute("INSERT INTO alerts (message, created_by) VALUES (?, ?)", (message, user_id))
        conn.commit()
        conn.close()
        return jsonify({"message": "Alert created successfully"})
    except Exception as e:
        print(f"❌ Create alert error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/get_alerts", methods=["GET"])
def get_alerts():
    try:
        conn = get_db_connection()
        alerts = conn.execute("SELECT a.*, u.name as created_by_name FROM alerts a JOIN users u ON a.created_by = u.id ORDER BY a.created_at DESC").fetchall()
        conn.close()
        return jsonify([dict(a) for a in alerts])
    except Exception as e:
        print(f"❌ Get alerts error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/delete_alert", methods=["POST"])
def delete_alert():
    try:
        data = request.json
        alert_id, user_role = data.get("alert_id"), data.get("user_role")
        if not all([alert_id, user_role]):
            return jsonify({"error": "Missing required fields"}), 400
        if user_role != 'admin':
            return jsonify({"error": "Unauthorized"}), 403

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
        conn.commit()

        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"error": "Alert not found"}), 404

        conn.close()
        return jsonify({"message": "Alert deleted successfully"})
    except Exception as e:
        print(f"❌ Delete alert error: {e}")
        return jsonify({"error": "Internal server error"}), 500

# --- PAYMENT ROUTES (UPDATED) ---

@app.route("/submit_payment", methods=["POST"])
def submit_payment():
    try:
        user_id = request.form.get("user_id")
        amount = request.form.get("amount")
        utr_number = request.form.get("utr_number")
        payment_date = request.form.get("payment_date")
        
        payment_type = request.form.get("payment_type", "Maintenance")
        description = request.form.get("description", "")
        
        if not all([user_id, amount, utr_number, payment_date]):
            return jsonify({"error": "Missing required fields"}), 400

        screenshot_path = None
        if 'screenshot' in request.files:
            file = request.files['screenshot']
            if file and allowed_file(file.filename):
                file_extension = file.filename.rsplit('.', 1)[1].lower()
                unique_filename = f"pay_{secrets.token_hex(8)}.{file_extension}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                screenshot_path = unique_filename
        
        conn = get_db_connection()
        conn.execute("""INSERT INTO payments 
                        (user_id, amount, utr_number, payment_date, screenshot_path, payment_type, description) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (user_id, amount, utr_number, payment_date, screenshot_path, payment_type, description))
        conn.commit()
        conn.close()
        print(f"✅ Payment submitted by user ID {user_id}")
        return jsonify({"message": "Payment details submitted successfully. Pending verification."})
    except Exception as e:
        print(f"❌ Submit payment error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/get_my_payments", methods=["GET"])
def get_my_payments():
    try:
        user_id = request.args.get("user_id")
        if not user_id:
            return jsonify({"error": "User ID required"}), 400
            
        conn = get_db_connection()
        # Filter out payments that the user has hidden
        payments = conn.execute("""
            SELECT * FROM payments 
            WHERE user_id = ? AND (user_hidden = 0 OR user_hidden IS NULL)
            ORDER BY created_at DESC
        """, (user_id,)).fetchall()
        conn.close()
        return jsonify([dict(p) for p in payments])
    except Exception as e:
        print(f"❌ Get payments error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/get_all_payments", methods=["GET"])
def get_all_payments():
    """Fetch all payments for the admin dashboard"""
    try:
        conn = get_db_connection()
        query = """
            SELECT p.*, u.name as user_name, u.house_number 
            FROM payments p 
            JOIN users u ON p.user_id = u.id 
            ORDER BY p.created_at DESC
        """
        payments = conn.execute(query).fetchall()
        conn.close()
        return jsonify([dict(p) for p in payments])
    except Exception as e:
        print(f"❌ Get all payments error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/update_payment_status", methods=["POST"])
def update_payment_status():
    """Admin approves or rejects a payment"""
    try:
        data = request.json
        payment_id = data.get("payment_id")
        status = data.get("status") # 'Approved' or 'Rejected'
        
        if not all([payment_id, status]):
            return jsonify({"error": "Missing fields"}), 400
            
        conn = get_db_connection()
        conn.execute("UPDATE payments SET status = ? WHERE id = ?", (status, payment_id))
        conn.commit()
        conn.close()
        return jsonify({"message": f"Payment marked as {status}"})
    except Exception as e:
        print(f"❌ Update payment status error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/delete_payment", methods=["POST"])
def delete_payment():
    """Delete a payment (Resident can delete Pending; Admin can delete any)"""
    try:
        data = request.json
        payment_id = data.get("payment_id")
        user_id = data.get("user_id")
        user_role = data.get("user_role")

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if payment exists and get its status/owner
        payment = cursor.execute("SELECT user_id, status, screenshot_path FROM payments WHERE id = ?", (payment_id,)).fetchone()
        
        if not payment:
            conn.close()
            return jsonify({"error": "Payment not found"}), 404

        # Authorization Logic
        if user_role == 'resident':
            # Resident can only delete their own PENDING payments
            if payment['user_id'] != int(user_id):
                conn.close()
                return jsonify({"error": "Unauthorized"}), 403
            if payment['status'] != 'Pending':
                conn.close()
                return jsonify({"error": "Cannot delete processed payments"}), 400
        elif user_role != 'admin':
            conn.close()
            return jsonify({"error": "Unauthorized"}), 403

        # Proceed with deletion
        cursor.execute("DELETE FROM payments WHERE id = ?", (payment_id,))
        conn.commit()
        
        # Cleanup image file if it exists
        if payment['screenshot_path']:
            try:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], payment['screenshot_path'])
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as ex:
                print(f"⚠️ Error deleting screenshot: {ex}")

        conn.close()
        return jsonify({"message": "Payment record deleted successfully"})
    except Exception as e:
        print(f"❌ Delete payment error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/hide_payment", methods=["POST"])
def hide_payment():
    """Allows resident to hide approved/rejected payments from their view (Soft Delete)"""
    try:
        data = request.json
        payment_id = data.get("payment_id")
        user_id = data.get("user_id")

        if not all([payment_id, user_id]):
            return jsonify({"error": "Missing required fields"}), 400

        conn = get_db_connection()
        # Only hide if the payment belongs to the user
        cursor = conn.execute("UPDATE payments SET user_hidden = 1 WHERE id = ? AND user_id = ?", (payment_id, user_id))
        conn.commit()
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"error": "Payment not found or unauthorized"}), 404

        conn.close()
        return jsonify({"message": "Payment removed from your history."})
    except Exception as e:
        print(f"❌ Hide payment error: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(debug=True)