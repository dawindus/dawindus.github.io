import os

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Create portfolio
    portfolio = {}

    # Set total to 0
    total = 0

    # Query database for each owned stock
    stocks = db.execute("SELECT * FROM portfolios WHERE user_id=? ORDER BY symbol", session["user_id"])

    # Iterate through stocks
    for stock in stocks:
        symbol = stock["symbol"]
        info = lookup(symbol)

        # Save all relevant information to portfolio dictionary
        portfolio[symbol] = {
            "symbol" : symbol,
            "name" : info["name"],
            "quantity" : stock["quantity"],
            "price" : info["price"],
            "value" : int(stock["quantity"]) * float(info["price"])
        }

        # Update total
        total = total + portfolio[symbol]["value"]

    # Get cash value
    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    cash = float(user[0]["cash"])

    # Update total
    total = total + cash

    return render_template("index.html", portfolio=portfolio, total=total, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        quantity = request.form.get("shares")

        # Look up stock
        stock = lookup(symbol)

        # Stock not found
        if stock == None:
            return apology("stock not found", 400)

        # Ensure quantity is valid
        try:
            quantity = int(quantity)
            if quantity < 1:
                return apology("invalid quantity of shares", 400)
        except ValueError:
            return apology("invalid quantity of shares", 400)

        # Get user cash total
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        cash = float(user[0]["cash"])

        # User cannot afford
        if cash < float(stock["price"]) * int(quantity):
            return apology("cannot afford stock", 400)

        # Complete purchase
        cash -= float(stock["price"]) * int(quantity)
        db.execute("UPDATE users SET cash=? WHERE id=?", cash, session["user_id"])

        # Save transaction
        time = datetime.now()
        db.execute("INSERT INTO transactions (user_id, symbol, quantity, price, time) VALUES (?, ?, ?, ?, ?)", session["user_id"], symbol, quantity, stock["price"], time)

        # Update portfolio
        portfolio = db.execute("SELECT * FROM portfolios WHERE user_id=? AND symbol=?", session["user_id"], symbol)
        if len(portfolio) == 0:
            db.execute("INSERT INTO portfolios (user_id, symbol, quantity) VALUES (?, ?, ?)", session["user_id"], symbol, quantity)
        else:
            db.execute("UPDATE portfolios SET quantity=(quantity + ?) WHERE user_id=? AND symbol=?", int(quantity), session["user_id"], symbol)

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Query database for transaction history
    transactions = db.execute("SELECT * FROM transactions WHERE user_id=? ORDER BY time DESC", session["user_id"])

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        # Look up stock
        stock = lookup(symbol)

        # Stock not found
        if stock == None:
            return apology("stock not found", 400)

        # Found stock
        return render_template("quoted.html", name=stock["name"], symbol=stock["symbol"], price=stock["price"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached /register via POST
    if request.method == "POST":

    # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Ensure passwords match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Query database for username
        rows = db.execute("SELECT username FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username does not already exist
        if len(rows) != 0:
            return apology("username already exists", 400)

        # Hash password
        hash = generate_password_hash(request.form.get("password"))

        # Insert new user into db
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), hash)

        # Redirect user to login form
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    """Change Password"""

    if request.method == "POST":
        oldpassword = request.form.get("oldpassword")
        newpassword = request.form.get("newpassword")
        confirmation = request.form.get("confirmation")

        # Ensure old password was submitted
        if not oldpassword:
            return apology("must provide old password", 400)

        # Ensure old password was submitted
        elif not newpassword:
            return apology("must provide new password", 400)

        # Ensure old password was submitted
        elif not confirmation:
            return apology("must confirm new password", 400)

        # Ensure old password was submitted
        elif newpassword != confirmation:
            return apology("passwords do not match", 400)

        # Query database for old password
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Ensure old passwords match
        if not check_password_hash(rows[0]["hash"], oldpassword):
            return apology("incorrect password", 400)

        # Hash new password
        hash = generate_password_hash(newpassword)

        # Update password hash in database
        db.execute("UPDATE users SET hash=? WHERE id=?", hash, session["user_id"])

        return redirect("/")

    else:
        return render_template("changepassword.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        portfolio = db.execute("SELECT quantity FROM portfolios WHERE user_id=?", session["user_id"])
        current = portfolio[0]["quantity"]
        symbol = request.form.get("symbol")
        stock = lookup(symbol)
        quantity = request.form.get("shares")

        # Ensure valid quantity
        try:
            quantity = int(quantity)
            if quantity < 1 or quantity > current:
                return apology("invalid quantity of shares", 400)
        except ValueError:
            return apology("invalid quantity of shares", 400)

        sold = 0 - quantity

        # Update portfolio
        if current + sold == 0:
            db.execute("DELETE FROM portfolios WHERE user_id=? AND symbol=?", session["user_id"], symbol)
        else:
            db.execute("UPDATE portfolios SET quantity=quantity + ? WHERE user_id=? AND symbol=?", sold, session["user_id"], symbol)

        # Update cash
        profit = quantity * stock["price"]
        db.execute("UPDATE users SET cash=(cash + ?) WHERE id=?", profit, session["user_id"])

        # Save transaction
        time = datetime.now()
        sold = 0 - quantity
        db.execute("INSERT INTO transactions (user_id, symbol, quantity, price, time) VALUES (?, ?, ?, ?, ?)", session["user_id"], symbol, sold, stock["price"], time)

        return redirect("/")
    else:
        portfolio = db.execute("SELECT symbol FROM portfolios WHERE user_id=? ORDER BY symbol", session["user_id"])
        # Check user has stock to sell
        if len(portfolio) == 0:
            return apology("no stock to sell", 400)
        return render_template("sell.html", stocks=portfolio)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
