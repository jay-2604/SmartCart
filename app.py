# app.py
# ---------------------------------------------------------
# DAY 2: Admin Signup + OTP + Password Hash
# ---------------------------------------------------------

from flask import Flask, render_template, request, redirect, session, flash, make_response, url_for
from flask_mail import Mail, Message
from utils.pdf_generator import generate_pdf
import mysql.connector
import bcrypt
import random
import config
import secrets
import os
import time
from werkzeug.utils import secure_filename

import razorpay
import traceback


razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)


# ---------------- DB CONNECTION FUNCTION --------------
def get_db_connection():
    return mysql.connector.connect(
        host=config.DB_HOST,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME
    )


# =================================================================
# ROOT ROUTE: REDIRECT TO USER LOGIN
# =================================================================
@app.route('/')
def home():
    return redirect('/user-login')


# ---------------------------------------------------------
# ROUTE 1: ADMIN SIGNUP (SEND OTP)
# ---------------------------------------------------------
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    # Show form
    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    # POST → Process signup
    name = request.form['name']
    email = request.form['email']

    # 1️⃣ Check if admin email already exists
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT admin_id FROM admin WHERE email=%s", (email,))
    existing_admin = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')

    # 2️⃣ Save user input temporarily in session
    session['signup_name'] = name
    session['signup_email'] = email

    # 3️⃣ Generate OTP and store in session
    otp = random.randint(100000, 999999)
    session['otp'] = otp

    # 4️⃣ Send OTP Email
    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')


# ---------------------------------------------------------
# ROUTE 2: DISPLAY OTP PAGE
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
    return render_template("admin/verify_otp.html")


# ---------------------------------------------------------
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():

    # User submitted OTP + Password
    user_otp = request.form['otp']
    password = request.form['password']

    # Compare OTP
    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    # Hash password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert admin into database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (%s, %s, %s)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Clear temporary session data
    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)

    flash("Admin Registered Successfully!", "success")
    return redirect('/admin-login')


# =================================================================
# ROUTE 4: ADMIN LOGIN PAGE (GET + POST)
# =================================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    # Show login page
    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    # POST → Validate login
    email = request.form['email']
    password = request.form['password']

    # Step 1: Check if admin email exists
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE email=%s", (email,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    # Step 2: Compare entered password with hashed password
    stored_hashed_password = admin['password'].encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    # Step 5: If login success → Create admin session
    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']
    session['admin_profile_image'] = admin.get('profile_image')  # 🔹 store image in session

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')


# =================================================================
# ROUTE 5: ADMIN DASHBOARD (PROTECTED ROUTE)
# =================================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    # Protect dashboard → Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    # Send admin name to dashboard UI
    return render_template("admin/dashboard.html", admin_name=session['admin_name'])


# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():

    # Clear admin session
    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)
    session.pop('admin_profile_image', None)  # 🔹 clear profile image from session

    flash("Logged out successfully.", "success")
    return redirect('/admin-login')


# ------------------- IMAGE UPLOAD PATH -------------------
# Use absolute paths based on app.root_path and auto-create folders
BASE_UPLOAD_PATH = os.path.join(app.root_path, 'static', 'uploads')

PRODUCT_UPLOAD_FOLDER = os.path.join(BASE_UPLOAD_PATH, 'product_images')
ADMIN_UPLOAD_FOLDER = os.path.join(BASE_UPLOAD_PATH, 'admin_profiles')

# Ensure the folders exist
os.makedirs(PRODUCT_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ADMIN_UPLOAD_FOLDER, exist_ok=True)

# Save into config
app.config['UPLOAD_FOLDER'] = PRODUCT_UPLOAD_FOLDER          # for products
app.config['ADMIN_UPLOAD_FOLDER'] = ADMIN_UPLOAD_FOLDER      # for admin profile images


# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

    # Only logged-in admin can access
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    return render_template("admin/add_item.html")


# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE  (NOW WITH QUANTITY)
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']

    # NEW: quantity
    try:
        quantity = int(request.form.get('quantity', 0))
        if quantity < 0:
            quantity = 0
    except ValueError:
        quantity = 0

    image_file = request.files['image']

    # 2️⃣ Validate image upload
    if image_file.filename == "":
        flash("Please upload a product image!", "danger")
        return redirect('/admin/add-item')

    # 3️⃣ Secure the file name
    filename = secure_filename(image_file.filename)

    # 4️⃣ Create full path
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # 5️⃣ Save image into folder
    image_file.save(image_path)

    # 6️⃣ Insert product into database (with quantity)
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO products (name, description, category, price, quantity, image) VALUES (%s, %s, %s, %s, %s, %s)",
        (name, description, category, price, quantity, filename)
    )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin/add-item')


# =================================================================
# ROUTE 9: DISPLAY ALL PRODUCTS (Admin)
# =================================================================
@app.route('/admin/item-list')
def item_list():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1️⃣ Fetch category list for dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # 2️⃣ Build dynamic query based on filters
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin/item_list.html", products=products, categories=categories)


# =================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

    # Check admin session
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)


# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

    # Check login
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # Fetch product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)


# =================================================================
# ROUTE 12: UPDATE PRODUCT + OPTIONAL IMAGE REPLACE (NOW WITH QUANTITY)
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    # 1️⃣ Get updated form data
    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']

    # NEW: quantity
    try:
        quantity = int(request.form.get('quantity', 0))
        if quantity < 0:
            quantity = 0
    except ValueError:
        quantity = 0

    new_image = request.files['image']

    # 2️⃣ Fetch old product data
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id = %s", (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        cursor.close()
        conn.close()
        return redirect('/admin/item-list')

    old_image_name = product['image']

    # 3️⃣ If admin uploaded a new image → replace it
    if new_image and new_image.filename != "":

        new_filename = secure_filename(new_image.filename)

        # Save new image
        new_image_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        new_image.save(new_image_path)

        # Delete old image file
        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_image_path):
            os.remove(old_image_path)

        final_image_name = new_filename

    else:
        # No new image uploaded → keep old one
        final_image_name = old_image_name

    # 4️⃣ Update product in the database (with quantity)
    cursor.execute("""
        UPDATE products
        SET name=%s, description=%s, category=%s, price=%s, quantity=%s, image=%s
        WHERE product_id=%s
    """, (name, description, category, price, quantity, final_image_name, item_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Product updated successfully!", "success")
    return redirect('/admin/item-list')


@app.route('/about')
def about_page():
    return render_template("admin/about.html")


@app.route('/contact')
def contact_page():
    return render_template("admin/contact.html")


# ======================================================
#  ROUTE 14: DELETE PRODUCT (DELETE DB ROW + DELETE IMAGE FILE)
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1️⃣ Fetch product to get image name
    cursor.execute("SELECT image FROM products WHERE product_id=%s", (item_id,))
    product = cursor.fetchone()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/admin/item-list')

    image_name = product['image']

    # Delete image from folder
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
    if os.path.exists(image_path):
        os.remove(image_path)

    # 2️⃣ Delete product from DB
    cursor.execute("DELETE FROM products WHERE product_id=%s", (item_id,))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Product deleted successfully!", "success")
    return redirect('/admin/item-list')


# =================================================================
# ROUTE 15: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)


# =================================================================
# ROUTE 16: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    admin_id = session['admin_id']

    # 1️⃣ Get form data
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files.get('profile_image')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 2️⃣ Fetch old admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id = %s", (admin_id,))
    admin = cursor.fetchone()

    if not admin:
        cursor.close()
        conn.close()
        flash("Admin not found.", "danger")
        return redirect('/admin-login')

    old_image_name = admin['profile_image']

    # 3️⃣ Update password only if entered
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    else:
        hashed_password = admin['password']  # keep old password

    # 4️⃣ Process new profile image if uploaded
    if new_image and new_image.filename.strip() != "":
        # Create a unique filename to prevent browser caching issues
        _, ext = os.path.splitext(new_image.filename)
        ext = ext.lower()
        if ext not in ['.jpg', '.jpeg', '.png', '.gif', '.webp']:
            ext = '.jpg'

        new_filename = secure_filename(f"admin_{admin_id}_{int(time.time())}{ext}")
        image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], new_filename)

        # Save new image
        new_image.save(image_path)

        # Delete old image if exists
        if old_image_name:
            old_image_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_image_path):
                try:
                    os.remove(old_image_path)
                except OSError:
                    pass

        final_image_name = new_filename
    else:
        final_image_name = old_image_name

    # 5️⃣ Update database
    cursor.execute("""
        UPDATE admin
        SET name=%s, email=%s, password=%s, profile_image=%s
        WHERE admin_id=%s
    """, (name, email, hashed_password, final_image_name, admin_id))

    conn.commit()
    cursor.close()
    conn.close()

    # Update session for UI consistency
    session['admin_name'] = name
    session['admin_email'] = email
    session['admin_profile_image'] = final_image_name  # 🔹 keep navbar avatar in sync

    flash("Profile updated successfully!", "success")
    return redirect('/admin/profile')



# =================================================================
# ROUTE 17: USER REGISTRATION WITH OTP (UPDATED)
# =================================================================
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    # Show form
    if request.method == "GET":
        return render_template("user/user_register.html")

    # POST → Process registration (send OTP)
    name = request.form['name']
    email = request.form['email']

    # 1️⃣ Check if user email already exists
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT user_id FROM users WHERE email=%s", (email,))
    existing_user = cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_user:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/user-register')

    # 2️⃣ Save user input temporarily in session
    session['user_signup_name'] = name
    session['user_signup_email'] = email

    # 3️⃣ Generate OTP and store in session
    otp = random.randint(100000, 999999)
    session['user_otp'] = otp

    # 4️⃣ Send OTP Email
    message = Message(
        subject="SmartCart - Email Verification OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"""Hello {name},

Your OTP for SmartCart Registration is: {otp}

This OTP is valid for 10 minutes.

Regards,
SmartCart Team"""
    try:
        mail.send(message)
        flash("OTP sent to your email!", "success")
        return redirect('/user-verify-otp')
    except Exception as e:
        flash("Failed to send OTP. Please try again.", "danger")
        return redirect('/user-register')


# =================================================================
# ROUTE 18: USER OTP VERIFICATION PAGE (GET)
# =================================================================
@app.route('/user-verify-otp', methods=['GET'])
def user_verify_otp_get():
    if 'user_signup_email' not in session:
        flash("Please register first!", "danger")
        return redirect('/user-register')
    return render_template("user/user_verify_otp.html")


# =================================================================
# ROUTE 19: USER OTP VERIFICATION + ACCOUNT CREATION (POST)
# =================================================================
@app.route('/user-verify-otp', methods=['POST'])
def user_verify_otp_post():

    # User submitted OTP + Password
    user_otp = request.form['otp']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    # Check if passwords match
    if password != confirm_password:
        flash("Passwords do not match!", "danger")
        return redirect('/user-verify-otp')

    # Compare OTP
    if str(session.get('user_otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/user-verify-otp')

    # Hash password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert user into database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
        (session['user_signup_name'], session['user_signup_email'], hashed_password)
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Clear temporary session data
    session.pop('user_otp', None)
    session.pop('user_signup_name', None)
    session.pop('user_signup_email', None)

    flash("Registration Successful! Please login.", "success")
    return redirect('/user-login')


# =================================================================
# ROUTE 20: USER LOGIN
# =================================================================
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    # Create user session
    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user-dashboard')


# =================================================================
# ROUTE 21: USER DASHBOARD
# =================================================================
@app.route('/user-dashboard')
def user_dashboard():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # Read search & filter values
    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    # DB connection
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch all categories for dropdown
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # Build query dynamically
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE %s"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    # Execute final query
    cursor.execute(query, params)
    products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/user_home.html",
        user_name=session['user_name'],
        products=products,
        categories=categories
    )


# =================================================================
# ROUTE 22: USER LOGOUT
# =================================================================
@app.route('/user-logout')
def user_logout():

    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_email', None)

    flash("Logged out successfully!", "success")
    return redirect('/user-login')


# =================================================================
# ROUTE 23: USER PRODUCT DETAILS PAGE
# =================================================================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM products WHERE product_id = %s", (product_id,))
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)


# =================================================================
# ROUTE 24: USER - FORGOT PASSWORD (WITH EXPLICIT SENDER)
# =================================================================
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'POST':
        email = request.form['email'].strip()

        if not email:
            flash("Please enter your email.", "warning")
            return redirect('/forgot-password')

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            token = secrets.token_urlsafe(32)

            # Save token in DB
            cur.execute("UPDATE users SET reset_token = %s WHERE email = %s", (token, email))
            conn.commit()

            # Create reset link
            reset_link = url_for('reset_password', token=token, _external=True)

            # Send email with explicit sender
            msg = Message(
                subject="SmartCart - Password Reset",
                sender=config.MAIL_USERNAME,  # Explicitly set sender
                recipients=[email]
            )
            msg.body = f"""
Hello {user['name']},

We received a password reset request for your SmartCart account.

Click the link below to reset your password:
{reset_link}

If you did NOT request this, simply ignore this email.

Regards,
SmartCart Team
"""
            try:
                mail.send(msg)
                flash("A password reset link has been sent to your email.", "info")
            except Exception as e:
                flash(f"Failed to send email: {str(e)}", "danger")
                app.logger.error(f"Email send error: {str(e)}")

        else:
            flash("No account found with that email.", "danger")

        cur.close()
        conn.close()
        return redirect('/forgot-password')

    # GET request - show the form
    return render_template('user/forgot_password.html')


# =================================================================
# ROUTE 25: USER - RESET PASSWORD
# =================================================================
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM users WHERE reset_token = %s", (token,))
    user = cur.fetchone()

    if not user:
        flash("Invalid or expired reset link.", "danger")
        cur.close()
        conn.close()
        return redirect('/user-login')

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not new_password or not confirm_password:
            flash("Please fill all fields.", "danger")
            return redirect(request.url)

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(request.url)

        # Hash new password
        hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        # Update user password and clear token
        cur.execute(
            "UPDATE users SET password = %s, reset_token = NULL WHERE user_id = %s",
            (hashed_pw, user['user_id'])
        )
        conn.commit()

        flash("Password updated successfully! Please login.", "success")

        cur.close()
        conn.close()
        return redirect('/user-login')

    cur.close()
    conn.close()
    return render_template('user/reset_password.html', token=token)


# =================================================================
# ROUTE 26: ADD ITEM TO CART
# =================================================================
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # Create cart if doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer)

    pid = str(product_id)

    # If exists → increase quantity
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart

    flash("Item added to cart!", "success")
    return redirect('/user/cart')


# =================================================================
# ROUTE 27: VIEW CART PAGE
# =================================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    # Calculate total
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)


# =================================================================
# ROUTE 28: INCREASE QUANTITY
# =================================================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] += 1

    session['cart'] = cart
    return redirect('/user/cart')


# =================================================================
# ROUTE 29: DECREASE QUANTITY
# =================================================================
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] -= 1

        # If quantity becomes 0 → remove item
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)

    session['cart'] = cart
    return redirect('/user/cart')


# =================================================================
# ROUTE 30: REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart'] = cart

    flash("Item removed!", "success")
    return redirect('/user/cart')


# =================================================================
# ROUTE 31: BUY NOW WITH QUANTITY
# =================================================================
@app.route('/user/buy-now-quantity/<int:product_id>', methods=['POST'])
def buy_now_quantity(product_id):
    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    quantity = int(request.form.get('quantity', 1))

    # Validate quantity
    if quantity < 1:
        quantity = 1
    if quantity > 10:
        quantity = 10

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect('/user-dashboard')

    # Create cart with only this product and selected quantity
    session['cart'] = {
        str(product_id): {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': quantity
        }
    }

    flash(f"Added {quantity} {product['name']} for immediate purchase!", "success")
    return redirect('/user/checkout')


# =================================================================
# ROUTE 32: BUY NOW - ADD SINGLE PRODUCT TO CART & GO TO CHECKOUT
# =================================================================
@app.route('/user/buy-now/<int:product_id>')
def buy_now(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE product_id=%s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found!", "danger")
        return redirect('/user-dashboard')

    # Create cart with only this product
    session['cart'] = {
        str(product_id): {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }
    }

    flash("Product added for purchase!", "success")
    return redirect('/user/checkout')


# =================================================================
# ROUTE 33: UPDATE: MODIFIED PAYMENT ROUTE TO CHECK ADDRESS
# =================================================================
@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    # Check if address is saved
    if 'delivery_address' not in session:
        flash("Please provide delivery address first!", "warning")
        return redirect('/user/checkout')

    cart = session.get('cart', {})

    if not cart:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    # Calculate total amount
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())
    razorpay_amount = int(total_amount * 100)  # convert to paise

    # Create Razorpay order
    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )


# =================================================================
# ROUTE 34: TEMP SUCCESS PAGE (Verification in Day 13)
# =================================================================
@app.route('/payment-success')
def payment_success():

    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )


# =================================================================
# ROUTE 35: PAYMENT FAILED PAGE (UPDATED)
# =================================================================
@app.route('/payment-failed')
def payment_failed():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    payment_id = request.args.get('payment_id', 'N/A')
    order_id = request.args.get('order_id', 'N/A')
    reason = request.args.get('reason', '')

    # Optional: Log the failure to database for tracking
    # You can add database logging here if needed

    return render_template(
        "user/payment_failed.html",
        payment_id=payment_id,
        order_id=order_id,
        reason=reason
    )


# ------------------------------
# Route 36: Verify Payment and Store Order (AND DECREASE STOCK)
# ------------------------------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    # Read values posted from frontend
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    # Build verification payload required by Razorpay client.utility
    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        # This will raise an error if signature invalid
        razorpay_client.utility.verify_payment_signature(payload)

    except Exception as e:
        # Verification failed
        app.logger.error("Razorpay signature verification failed: %s", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    # Signature verified — now store order and items into DB
    user_id = session['user_id']
    cart = session.get('cart', {})

    if not cart:
        flash("Cart is empty. Cannot create order.", "danger")
        return redirect('/user/products')

    # Calculate total amount (ensure same as earlier)
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

    # DB insert: orders and order_items
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Insert into orders table
        cursor.execute("""
            INSERT INTO orders (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, razorpay_order_id, razorpay_payment_id, total_amount, 'paid'))

        order_db_id = cursor.lastrowid  # newly created order's primary key

        # Insert all items AND DECREASE STOCK
        for pid_str, item in cart.items():
            product_id = int(pid_str)

            # Insert order item
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (%s, %s, %s, %s, %s)
            """, (order_db_id, product_id, item['name'], item['quantity'], item['price']))

            # Decrease stock (never go below 0)
            cursor.execute("""
                UPDATE products
                SET quantity = GREATEST(quantity - %s, 0)
                WHERE product_id = %s
            """, (item['quantity'], product_id))

        # Commit transaction
        conn.commit()

        # Clear cart and temporary razorpay order id
        session.pop('cart', None)
        session.pop('razorpay_order_id', None)

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        # Rollback and log error
        conn.rollback()
        app.logger.error("Order storage failed: %s\n%s", str(e), traceback.format_exc())
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()


@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE order_id=%s AND user_id=%s", (order_db_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_db_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    return render_template("user/order_success.html", order=order, items=items)


@app.route('/user/my-orders')
def my_orders():
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE user_id=%s ORDER BY created_at DESC", (session['user_id'],))
    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)


# ----------------------------
# ROUTE 37: GENERATE INVOICE PDF
# ----------------------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    # Fetch order
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM orders WHERE order_id=%s AND user_id=%s",
                   (order_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=%s", (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/my-orders')

    # Render invoice HTML
    html = render_template("user/invoice.html", order=order, items=items)

    pdf = generate_pdf(html)
    if not pdf:
        flash("Error generating PDF", "danger")
        return redirect('/user/my-orders')

    # Prepare response
    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f"attachment; filename=invoice_{order_id}.pdf"

    return response


# =================================================================
# ROUTE 38: CHECKOUT ADDRESS PAGE (GET) - WITH SAVED ADDRESSES
# =================================================================
@app.route('/user/checkout', methods=['GET'])
def checkout_address():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    if not cart:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    # Calculate total amount
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    # Fetch saved addresses for this user
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT * FROM user_addresses 
        WHERE user_id = %s 
        ORDER BY is_default DESC, created_at DESC
    """, (session['user_id'],))

    saved_addresses = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "user/checkout_address.html",
        cart=cart,
        grand_total=grand_total,
        user_email=session.get('user_email', ''),
        saved_addresses=saved_addresses
    )


# =================================================================
# ROUTE 39: SAVE ADDRESS & PROCEED TO PAYMENT (POST)
# =================================================================
@app.route('/user/checkout', methods=['POST'])
def save_address_and_pay():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    # Check if user selected an existing address
    selected_address_id = request.form.get('selected_address_id')

    if selected_address_id:
        # User selected a saved address
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT * FROM user_addresses 
            WHERE address_id = %s AND user_id = %s
        """, (selected_address_id, user_id))

        address = cursor.fetchone()
        cursor.close()
        conn.close()

        if not address:
            flash("Invalid address selected!", "danger")
            return redirect('/user/checkout')

        # Save address to session
        session['delivery_address'] = {
            'address_id': address['address_id'],
            'full_name': address['full_name'],
            'phone': address['phone'],
            'email': address['email'],
            'address_line1': address['address_line1'],
            'address_line2': address['address_line2'],
            'city': address['city'],
            'state': address['state'],
            'pincode': address['pincode'],
            'landmark': address['landmark'],
            'address_type': address['address_type']
        }

        flash("Address selected successfully!", "success")
        return redirect('/user/pay')

    else:
        # User is adding a new address
        full_name = request.form.get('full_name', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        address_line1 = request.form.get('address_line1', '').strip()
        address_line2 = request.form.get('address_line2', '').strip()
        city = request.form.get('city', '').strip()
        state = request.form.get('state', '').strip()
        pincode = request.form.get('pincode', '').strip()
        landmark = request.form.get('landmark', '').strip()
        address_type = request.form.get('address_type', 'Home')
        save_address = request.form.get('save_address', '0')

        # Validate required fields
        if not all([full_name, phone, email, address_line1, city, state, pincode]):
            flash("Please fill all required fields!", "danger")
            return redirect('/user/checkout')

        address_data = {
            'full_name': full_name,
            'phone': phone,
            'email': email,
            'address_line1': address_line1,
            'address_line2': address_line2,
            'city': city,
            'state': state,
            'pincode': pincode,

            'landmark': landmark,
            'address_type': address_type
        }

        # Save to database if user checked the "save address" option
        if save_address == '1':
            conn = get_db_connection()
            cursor = conn.cursor()

            # Check if this is user's first address - make it default
            cursor.execute("SELECT COUNT(*) as count FROM user_addresses WHERE user_id = %s", (user_id,))
            count_result = cursor.fetchone()
            is_first_address = count_result[0] == 0

            cursor.execute("""
                INSERT INTO user_addresses 
                (user_id, full_name, phone, email, address_line1, address_line2, 
                 city, state, pincode, landmark, address_type, is_default)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                user_id, full_name, phone, email, address_line1, address_line2,
                city, state, pincode, landmark, address_type, is_first_address
            ))

            conn.commit()
            address_id = cursor.lastrowid

            cursor.close()
            conn.close()

            address_data['address_id'] = address_id

        # Save address to session
        session['delivery_address'] = address_data

        flash("Address saved successfully!", "success")
        return redirect('/user/pay')


# =================================================================
# ROUTE 40: SAVE ADDRESS TO DATABASE (MORE PERMANENT)
# =================================================================
def save_address_to_database(user_id, address_data):
    """
    Optional function to save address permanently to database
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO user_addresses 
        (user_id, full_name, phone, email, address_line1, address_line2, 
         city, state, pincode, landmark, address_type, is_default)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        user_id,
        address_data['full_name'],
        address_data['phone'],
        address_data['email'],
        address_data['address_line1'],
        address_data['address_line2'],
        address_data['city'],
        address_data['state'],
        address_data['pincode'],
        address_data['landmark'],
        address_data['address_type'],
        True  # is_default
    ))

    conn.commit()
    address_id = cursor.lastrowid

    cursor.close()
    conn.close()

    return address_id


# =================================================================
# ROUTE 41: MANAGE ADDRESSES PAGE
# =================================================================
@app.route('/user/addresses')
def user_addresses():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT * FROM user_addresses 
        WHERE user_id = %s 
        ORDER BY is_default DESC, created_at DESC
    """, (session['user_id'],))

    addresses = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/manage_addresses.html", addresses=addresses)


# =================================================================
# ROUTE 42: SET DEFAULT ADDRESS
# =================================================================
@app.route('/user/address/set-default/<int:address_id>')
def set_default_address(address_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Remove default from all user addresses
    cursor.execute("UPDATE user_addresses SET is_default = 0 WHERE user_id = %s", (user_id,))

    # Set this address as default
    cursor.execute("""
        UPDATE user_addresses 
        SET is_default = 1 
        WHERE address_id = %s AND user_id = %s
    """, (address_id, user_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Default address updated!", "success")
    return redirect('/user/addresses')


# =================================================================
# ROUTE 43: DELETE ADDRESS
# =================================================================
@app.route('/user/address/delete/<int:address_id>')
def delete_address(address_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM user_addresses 
        WHERE address_id = %s AND user_id = %s
    """, (address_id, session['user_id']))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Address deleted successfully!", "success")
    return redirect('/user/addresses')


# ------------------------- RUN APP ------------------------
if __name__ == '__main__':
    app.run(debug=True)
