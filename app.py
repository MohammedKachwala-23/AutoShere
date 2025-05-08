from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from neo4j import GraphDatabase
import pandas as pd

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

@app.route('/search', methods=['GET', 'POST'])
def search():
    cars = []

    if request.method == 'POST':
        make = request.form.get('make')
        model = request.form.get('model')
        year = request.form.get('year')

        query = "MATCH (c:Car) WHERE 1=1"
        params = {}

        if make:
            query += " AND toLower(c.make) CONTAINS toLower($make)"
            params['make'] = make
        if model:
            query += " AND toLower(c.model) CONTAINS toLower($model)"
            params['model'] = model
        if year:
            query += " AND c.year = $year"
            params['year'] = int(year)

        query += " RETURN c ORDER BY c.price"

        with driver.session() as session_db:
            result = session_db.run(query, params)
            cars = [record["c"] for record in result]

    return render_template('search.html', cars=cars)



# Assuming `driver` is your Neo4j connection driver
# Assuming `df` is your DataFrame containing car data with columns like 'Make', 'Model', 'Price', etc.

@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'email' not in session:
        return redirect(url_for('login'))

    recommended_cars = []

    if request.method == 'POST':
        income = int(request.form['income'])
        expenditure = int(request.form['expenditure'])
        down_payment = int(request.form['down_payment'])
        loan_tenure = int(request.form['loan_tenure'])
        buffer = int(request.form['buffer'])

        user_email = session['email']
        monthly_savings = income - expenditure
        available_emi = monthly_savings - buffer
        loan_months = loan_tenure * 12
        max_loan = available_emi * loan_months
        max_price = max_loan + down_payment

        # Step 1: Query all cars from Neo4j database
        with driver.session() as session_db:
            result = session_db.run("""
                MATCH (c:Car)
                RETURN c.Make AS Make, c.Model AS Model, c.Price AS Price, c.Year AS Year,
                       c.Fuel_Type AS Fuel_Type, c.Transmission AS Transmission, c.Owner AS Owner
                ORDER BY c.Price ASC
            """)

            # Step 2: Process the results and calculate EMI and comfort score for each car
            for record in result:
                car_data = record.data()
                price = car_data['Price']
                
                # Check if price is None or invalid
                if price is None or price <= 0:
                    continue  # Skip this car if the price is invalid

                emi = calculate_emi(price, down_payment, loan_months)

                if emi <= available_emi:
                    # Calculate comfort score (higher is better)
                    comfort_score = ((max_price - price) / price) if price <= max_price else 0
                    car_data['estimated_emi'] = round(emi, 2)
                    car_data['comfort_score'] = round(comfort_score, 2)

                    # Add to the recommended cars list
                    recommended_cars.append(car_data)

        # Step 3: Sort recommended cars by comfort score (higher score first)
        recommended_cars.sort(key=lambda x: x['comfort_score'], reverse=True)

        # Optional: Store user's latest financial preferences in the database
        with driver.session() as session_db:
            session_db.run("""
                MERGE (p:Person {email: $email})
                SET p.income = $income,
                    p.expenditure = $expenditure,
                    p.down_payment = $down_payment,
                    p.loan_tenure = $loan_tenure,
                    p.buffer = $buffer
            """, email=user_email, income=income, expenditure=expenditure,
                 down_payment=down_payment, loan_tenure=loan_tenure, buffer=buffer)

        # Return the recommended cars to the template
        return render_template('home.html', cars=recommended_cars)

    return render_template('home.html', cars=recommended_cars)



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





if __name__ == '__main__':
    app.run(debug=True)
