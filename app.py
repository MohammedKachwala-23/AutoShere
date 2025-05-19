from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from neo4j import GraphDatabase
import pandas as pd
import random 

app = Flask(__name__)
app.secret_key = "super_secret_key"  # Use env vars in production

URI = "bolt://localhost:7687"
USERNAME = "neo4j"
PASSWORD = "hello101"

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


def calculate_emi(price, down_payment, months):
    """ Helper function to calculate EMI """
    principal = price - down_payment
    if principal <= 0:
        return 0
    return principal / months


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

@app.route("/search", methods=["GET", "POST"])
def search():
    if request.method == "POST":
        make = request.form.get("make", "").strip()
        model = request.form.get("model", "").strip()
        year = request.form.get("year", "").strip()

        # Build dynamic Cypher query
        query = "MATCH (Car:Car) WHERE 1=1"
        params = {}

        if make:
            query += " AND toLower(Car.make) CONTAINS toLower($make)"
            params["make"] = make

        if model:
            query += " AND toLower(Car.model) CONTAINS toLower($model)"
            params["model"] = model

        if year:
            try:
                params["year"] = int(year)
                query += " AND Car.year = $year"
            except ValueError:
                flash("Invalid year format. Please enter a number.", "error")
                return render_template("search.html", cars=[])

        query += " RETURN Car"

        # Run query and format results
        with driver.session() as session:
            result = session.run(query, params)
            cars = [dict(record["Car"].items()) for record in result]

        return render_template("search.html", cars=cars)

    # GET request: show empty search form
    return render_template("search.html", cars=[])


@app.route("/home", methods=["GET", "POST"])
def home():
    if "email" not in session:
        flash("Please log in to access this page.", "error")
        return redirect(url_for("login"))

    email = session["email"]
    salary = down_payment = loan_months = 0  # Initialize variables

    if request.method == 'POST':
        # Capture form data
        salary = float(request.form.get("income", 0))
        expenditure = float(request.form.get("expenditure", 0))
        down_payment = float(request.form.get("down_payment", 0))
        loan_years = int(request.form.get("loan_tenure", 1))
        loan_months = loan_years * 12  # Convert years to months

    # Fetch user data from the database
    with driver.session() as db:
        user_query = """
            MATCH (u:User {email: $email})
            RETURN u.salary AS salary, u.down_payment AS down_payment, u.loan_tenure AS loan_tenure
        """
        user_result = db.run(user_query, email=email).single()

        if not user_result:
            flash("User data not found.", "error")
            return redirect(url_for("login"))

        # Safely extract user data if not set by the form
        salary = salary or float(user_result.get("salary") or 0)
        down_payment = down_payment or float(user_result.get("down_payment") or 0)
        loan_months = loan_months or int(user_result.get("loan_tenure") or 1)

        # EMI affordability and price cap logic
        available_emi = salary * 0.25  # 25% of salary
        max_price = down_payment + (available_emi * loan_months)

        car_query = """
            MATCH (c:Car)
            WHERE c.price IS NOT NULL
            RETURN c ORDER BY c.price ASC
        """
        result = db.run(car_query)

        recommended_cars = []

        def calculate_emi(price, down_payment, months):
            principal = price - down_payment
            if principal <= 0:
                return 0
            rate = 0.01  # Monthly interest rate (1%)
            if months == 0:
                return principal
            emi = (principal * rate * (1 + rate) ** months) / ((1 + rate) ** months - 1)
            return emi

        for record in result:
            car = record["c"]
            price = car.get("price")

            if not price or price <= 0 or price > max_price:
                continue

            emi = calculate_emi(price, down_payment, loan_months)

            if emi <= available_emi:
                comfort_score = (max_price - price) / price
                recommended_cars.append({
                    "make": car.get("make"),
                    "model": car.get("model"),
                    "price": price,
                    "year": car.get("year"),
                    "fuel_type": car.get("fuel_type"),
                    "transmission": car.get("transmission"),
                    "owner": car.get("owner", "Unknown"),
                    "estimated_emi": round(emi, 2),
                    "comfort_score": round(comfort_score, 2),
                    "id": car.element_id
                })

        # Randomly shuffle and return up to 15 cars
        random.shuffle(recommended_cars)
        recommended_cars = recommended_cars[:15]

    return render_template("home.html", cars=recommended_cars)

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

@app.route('/inventory')
def view_inventory():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    with driver.session() as session_db:
        result = session_db.run("MATCH (c:Car) RETURN c ORDER BY c.name")
        cars = [record["c"] for record in result]

    return render_template('inventory.html', cars=cars)

@app.route('/delete_car', methods=['GET', 'POST'])
def delete_car():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        car_id = int(request.form['car_id'])  # Getting car_id from the form
        with driver.session() as session_db:
            session_db.run("""
                MATCH (c:Car)
                WHERE id(c) = $car_id
                DETACH DELETE c
            """, car_id=car_id)

        flash("Car deleted successfully!")
        return redirect(url_for('admin_dashboard'))

    # For GET request: fetch car details and their Neo4j IDs
    with driver.session() as session_db:
        result = session_db.run("MATCH (c:Car) RETURN c")
        cars = []
        for record in result:
            car_node = record["c"]
            cars.append({
                "id": car_node.id,
                "make": car_node.get("make", ""),
                "model": car_node.get("model", ""),
                "year": car_node.get("year", "")
            })

    return render_template('delete_car.html', cars=cars)

@app.route('/edit_car/<int:car_id>', methods=['GET', 'POST'])
def edit_car(car_id):
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    with driver.session() as db:
        if request.method == 'POST':
            updated_fields = {
                "make": request.form['make'],
                "model": request.form['model'],
                "price": float(request.form['price']),
                "year": int(request.form['year']),
                "kilometer": int(request.form['kilometer']),
                "fuel_type": request.form['fuel_type'],
                "transmission": request.form['transmission'],
                "location": request.form['location'],
                "engine": request.form['engine']
            }

            db.run("""
                MATCH (c:Car)
                WHERE id(c) = $car_id
                SET c += $fields
            """, car_id=car_id, fields=updated_fields)

            flash("Car details updated.", "success")
            return redirect(url_for('inventory'))

        result = db.run("MATCH (c:Car) WHERE id(c) = $car_id RETURN c", car_id=car_id)
        record = result.single()
        if not record:
            flash("Car not found", "error")
            return redirect(url_for('inventory'))

        car = record["c"]
        return render_template("edit_car.html", car=dict(car.items()), car_id=car.id)




@app.route('/change_password', methods=['POST'])
def change_password():
    if 'email' not in session:
        return redirect(url_for('login'))

    email = session['email']
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if new_password != confirm_password:
        flash("New passwords do not match.", "error")
        return redirect(url_for('profile'))

    with driver.session() as db:
        result = db.run("""
            MATCH (u:User {email: $email})
            RETURN u.password AS password
        """, email=email)

        record = result.single()

        if record and check_password_hash(record["password"], current_password):
            hashed_new_password = generate_password_hash(new_password)
            db.run("""
                MATCH (u:User {email: $email})
                SET u.password = $new_password
            """, email=email, new_password=hashed_new_password)
            flash("Password updated successfully.", "success")
        else:
            flash("Current password is incorrect.", "error")

    return redirect(url_for('profile'))

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'email' not in session:
        return redirect(url_for('login'))

    new_username = request.form['username']
    new_email = request.form['email']
    old_email = session['email']

    with driver.session() as db:
        db.run("""
            MATCH (u:User {email: $old_email})
            SET u.username = $new_username, u.email = $new_email
        """, old_email=old_email, new_username=new_username, new_email=new_email)

    session['email'] = new_email
    session['user'] = new_username
    flash("Profile updated successfully", "success")
    return redirect(url_for('profile'))

@app.template_filter('inr')
def inr_format(value):
    try:
        return f"{int(value):,}"
    except (ValueError, TypeError):
        return value

@app.route('/car/<int:car_id>', methods=['GET'])
def get_car(car_id):
    with driver.session() as db:
        result = db.run("MATCH (c:Car) WHERE id(c) = $car_id RETURN c", car_id=car_id)
        record = result.single()
        if not record:
            return {"error": "Car not found"}, 404
        return dict(record["c"].items())
    
@app.route('/save_car/<int:car_id>', methods=['POST'])
def save_car(car_id):
    if 'email' not in session:
        flash("Please log in to save cars.", "error")
        return redirect(url_for('login'))
    # …code that creates a relationship or stores the saved car…
    flash("Car saved!", "success")
    return redirect(url_for('home'))
@app.route("/api/recommend", methods=["POST"])
def recommend_cars():
    income = float(request.form['income'])
    expenditure = float(request.form['expenditure'])
    down_payment = float(request.form['down_payment'])
    loan_years = int(request.form['loan_tenure'])
    buffer = float(request.form['buffer'])

    loan_months = loan_years * 12
    disposable_income = income - expenditure - buffer
    available_emi = disposable_income * 0.5  # user can spend up to 50% of free income

    max_price = (available_emi * loan_months) + down_payment

    def calculate_emi(price, down_payment, months):
        principal = price - down_payment
        if principal <= 0:
            return 0
        rate = 0.01  # 1% monthly interest
        emi = (principal * rate * (1 + rate) ** months) / ((1 + rate) ** months - 1)
        return emi

    with driver.session() as session:
        result = session.run("""
            MATCH (c:Car)
            WHERE c.price <= $max_price
            RETURN c ORDER BY c.price ASC
        """, max_price=max_price)

        cars = []
        for record in result:
            car = record["c"]
            price = car["price"]
            emi = calculate_emi(price, down_payment, loan_months)

            if emi <= available_emi:
                comfort_score = (max_price - price) / price
                cars.append({
                    "make": car["make"],
                    "model": car["model"],
                    "price": price,
                    "year": car["year"],
                    "fuel_type": car["fuel_type"],
                    "transmission": car["transmission"],
                    "estimated_emi": round(emi),
                    "comfort_score": round(comfort_score, 2)
                })

        cars = sorted(cars, key=lambda x: x["comfort_score"], reverse=True)[:10]

    return render_template("home.html", cars=cars)

if __name__ == '__main__':
    app.run(debug=True)
