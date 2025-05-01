from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from neo4j import GraphDatabase

app = Flask(__name__)
app.secret_key = "super_secret_key"  # Use env vars in production

URI = "bolt://localhost:7687"
USERNAME = "neo4j"
PASSWORD = "fuuckyouu"

driver = GraphDatabase.driver(URI, auth=(USERNAME, PASSWORD))

def close_driver():
    driver.close()

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        raw_password = request.form['password']
        hashed_password = generate_password_hash(raw_password)

        with driver.session() as session_neo:
            result = session_neo.run("""
                MATCH (u:User {email: $email}) RETURN u
            """, email=email)

            if result.single():
                flash("Email already registered. Try logging in.", "error")
                return redirect(url_for('signup'))

            # Admin flag is False by default
            session_neo.run("""
                CREATE (u:User {username: $username, email: $email, password: $password, is_admin: false})
            """, username=username, email=email, password=hashed_password)

        flash("Signup successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        raw_password = request.form['password']

        with driver.session() as session_neo:
            result = session_neo.run("""
                MATCH (u:User {email: $email})
                RETURN u.password AS password, u.username AS username, u.is_admin AS is_admin
            """, email=email)
            record = result.single()

            if record and check_password_hash(record["password"], raw_password):
                session['email'] = email 
                session['user'] = record["username"]
                session['is_admin'] = record["is_admin"]
                flash("Login successful!", "success")
                return redirect(url_for('home'))
            else:
                flash("Invalid credentials", "error")

    return render_template('login.html')



def validate_admin(username, password):
    with driver.session() as session:
        result = session.run(
            "MATCH (a:Admin {username: $username, password: $password}) RETURN a",
            username=username,
            password=password
        )
        return result.single() is not None

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        if validate_admin(uname, pwd):
            session['admin'] = uname
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials')
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin' in session:
        return render_template('admin.html', admin=session['admin'])
    return redirect(url_for('admin_login'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for('login'))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/recommendations')
def recommendations():
    return render_template('recommendations.html')

@app.route('/profile')
def profile():
    if 'email' not in session:
        return redirect(url_for('login'))

    email = session['email']

    with driver.session() as db:
        result = db.run("""
            MATCH (u:User {email: $email})
            RETURN u.username AS username, u.email AS email
        """, email=email)

        record = result.single()

        if record:
            user = {
                "username": record["username"],
                "email": record["email"]
            }
            return render_template('profile.html', user=user)
        else:
            return "User not found", 404


@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/search')
def search():
    return render_template('search.html')


@app.route('/home', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        income = int(request.form['income'])
        expenditure = int(request.form['expenditure'])
        down_payment = int(request.form['down_payment'])
        loan_tenure = int(request.form['loan_tenure'])
        buffer = int(request.form['buffer'])

        user_email = session.get('email')

        if user_email:
            with driver.session() as session_db:
                session_db.run("""
                    MERGE (p:Person {email: $email})
                    SET p.income = $income,
                        p.expenditure = $expenditure,
                        p.down_payment = $down_payment,
                        p.loan_tenure = $loan_tenure,
                        p.buffer = $buffer
                """,
                email=user_email,
                income=income,
                expenditure=expenditure,
                down_payment=down_payment,
                loan_tenure=loan_tenure,
                buffer=buffer)

            return redirect('/home')
        else:
            return "User not logged in", 401

    return render_template('home.html')


# === Admin-only route ===
@app.route('/admin')
def admin():
    if not session.get('is_admin'):
        flash("Unauthorized access.", "error")
        return redirect(url_for('home'))
    return render_template('admin.html')
@app.route('/add_car', methods=['POST'])
def add_car():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    make = request.form['make']
    model = request.form['model']
    price = float(request.form['price'])
    year = int(request.form['year'])
    kilometer = int(request.form['kilometer'])
    fuel_type = request.form['fuel_type']
    transmission = request.form['transmission']
    location = request.form['location']
    engine = request.form['engine']

    with driver.session() as session_db:
        session_db.run("""
            CREATE (:Car {
                make: $make,
                model: $model,
                price: $price,
                year: $year,
                kilometer: $kilometer,
                fuel_type: $fuel_type,
                transmission: $transmission,
                location: $location,
                engine: $engine
            })
        """, make=make, model=model, price=price, year=year,
             kilometer=kilometer, fuel_type=fuel_type, transmission=transmission,
             location=location, engine=engine)

    flash('Car added successfully!')
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    app.run(debug=True)
