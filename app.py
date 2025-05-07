from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from sqlalchemy import func
import csv
from io import StringIO
from datetime import datetime
import json

app = Flask(__name__)
# Use absolute path for database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'pos.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure secret key
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    stock = db.Column(db.Float, nullable=False)
    price_tiers = db.Column(db.Text, nullable=False, default='{"1": 0}')  # JSON string of quantity-based prices

    def get_price(self, quantity):
        tiers = json.loads(self.price_tiers)
        # Sort tiers by quantity in descending order
        sorted_tiers = sorted([(int(q), float(p)) for q, p in tiers.items()], reverse=True)
        # Find the first tier where quantity is less than or equal to the requested quantity
        for tier_qty, tier_price in sorted_tiers:
            if quantity >= tier_qty:
                return tier_price
        return float(tiers['1'])  # Default to base price if no tier matches

    def set_price_tier(self, quantity, price):
        tiers = json.loads(self.price_tiers)
        tiers[str(quantity)] = float(price)
        self.price_tiers = json.dumps(tiers)

class Sale(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/items', methods=['GET', 'POST'])
@login_required
def items():
    if not current_user.is_admin:
        flash('You do not have permission to access this page')
        return redirect(url_for('home'))
    if request.method == 'POST':
        try:
            name = request.form['name']
            stock = float(request.form['stock'])
            base_price = float(request.form['base_price'])
            
            if stock < 0 or base_price < 0:
                flash('Stock and price must be positive numbers')
                return redirect(url_for('items'))
                
            new_item = Item(name=name, stock=stock)
            new_item.set_price_tier(1, base_price)
            db.session.add(new_item)
            db.session.commit()
            flash('Item added successfully')
        except ValueError as e:
            flash('Invalid input: Please enter valid numbers for stock and price')
            db.session.rollback()
        except Exception as e:
            flash(f'An error occurred: {str(e)}')
            db.session.rollback()
        return redirect(url_for('items'))
    all_items = Item.query.all()
    return render_template('items.html', items=all_items)

@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    if not current_user.is_admin:
        flash('You do not have permission to edit items')
        return redirect(url_for('home'))
    
    item = Item.query.get_or_404(item_id)
    if request.method == 'POST':
        try:
            if 'update_stock' in request.form:
                new_stock = float(request.form['new_stock'])
                if new_stock < 0:
                    flash('Stock cannot be negative')
                    return redirect(url_for('edit_item', item_id=item_id))
                item.stock = new_stock
                db.session.commit()
                flash('Stock updated successfully')
            else:
                quantity = int(request.form['quantity'])
                price = float(request.form['price'])
                if price < 0:
                    flash('Price cannot be negative')
                    return redirect(url_for('edit_item', item_id=item_id))
                item.set_price_tier(quantity, price)
                db.session.commit()
                flash('Price tier updated successfully')
        except ValueError as e:
            flash('Invalid input: Please enter valid numbers')
            db.session.rollback()
        except Exception as e:
            flash(f'An error occurred: {str(e)}')
            db.session.rollback()
        return redirect(url_for('items'))
    
    tiers = json.loads(item.price_tiers)
    return render_template('edit_item.html', item=item, tiers=tiers)

@app.route('/delete_item/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    if not current_user.is_admin:
        flash('You do not have permission to delete items')
        return redirect(url_for('home'))
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('items'))

@app.route('/sales', methods=['GET', 'POST'])
@login_required
def sales():
    items = Item.query.all()
    if request.method == 'POST':
        item_id = int(request.form['item_id'])
        quantity = float(request.form['quantity'])
        item = Item.query.get(item_id)
        if item and item.stock >= quantity:
            price = item.get_price(quantity)
            total_price = price * quantity
            sale = Sale(item_id=item_id, quantity=quantity, total_price=total_price)
            item.stock -= quantity
            db.session.add(sale)
            db.session.commit()
        return redirect(url_for('sales'))
    sales_list = Sale.query.order_by(Sale.timestamp.desc()).all()
    for sale in sales_list:
        sale.item = Item.query.get(sale.item_id)
    return render_template('sales.html', items=items, sales=sales_list)

@app.route('/report')
@login_required
def report():
    total_sales = db.session.query(func.sum(Sale.total_price)).scalar() or 0
    sales_data = db.session.query(Sale.item_id, func.sum(Sale.quantity)).group_by(Sale.item_id).all()
    most_sold = []
    for item_id, quantity_sold in sales_data:
        item = Item.query.get(item_id)
        if item:
            most_sold.append({'name': item.name, 'quantity_sold': quantity_sold})
    most_sold.sort(key=lambda x: x['quantity_sold'], reverse=True)
    daily_sales = db.session.query(func.date(Sale.timestamp), func.sum(Sale.total_price)).group_by(func.date(Sale.timestamp)).all()
    return render_template('report.html', total_sales=total_sales, most_sold=most_sold, daily_sales=daily_sales)

@app.route('/download_report')
@login_required
def download_report():
    if not current_user.is_admin:
        flash('You do not have permission to download reports')
        return redirect(url_for('home'))
    
    try:
        si = StringIO()
        cw = csv.writer(si)
        
        # Write headers
        cw.writerow(['Date', 'Item', 'Quantity', 'Total Price (KES)'])
        
        # Get all sales with their items
        sales = Sale.query.order_by(Sale.timestamp.desc()).all()
        
        # Write data rows
        for sale in sales:
            item = Item.query.get(sale.item_id)
            if item:  # Only write if item exists
                cw.writerow([
                    sale.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    item.name,
                    f"{sale.quantity:.2f}",
                    f"{sale.total_price:.2f}"
                ])
        
        output = si.getvalue()
        si.close()
        
        # Create response with proper headers
        response = send_file(
            StringIO(output),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'sales_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
        
        # Add headers to prevent caching
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        
        return response
        
    except Exception as e:
        flash(f'Error generating report: {str(e)}')
        return redirect(url_for('report'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect')
            return redirect(url_for('change_password'))
            
        if new_password != confirm_password:
            flash('New passwords do not match')
            return redirect(url_for('change_password'))
            
        current_user.set_password(new_password)
        db.session.commit()
        flash('Password changed successfully')
        return redirect(url_for('home'))
        
    return render_template('change_password.html')

@app.route('/users')
@login_required
def users():
    if not current_user.is_admin:
        flash('You do not have permission to access this page')
        return redirect(url_for('home'))
    all_users = User.query.all()
    return render_template('users.html', users=all_users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to edit users')
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        try:
            new_password = request.form.get('new_password')
            is_admin = 'is_admin' in request.form
            
            if new_password:
                user.set_password(new_password)
            
            user.is_admin = is_admin
            db.session.commit()
            flash('User updated successfully')
            return redirect(url_for('users'))
        except Exception as e:
            flash(f'Error updating user: {str(e)}')
            db.session.rollback()
    
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to delete users')
        return redirect(url_for('home'))
    
    if user_id == current_user.id:
        flash('You cannot delete your own account')
        return redirect(url_for('users'))
    
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}')
        db.session.rollback()
    
    return redirect(url_for('users'))

# Initialize the database and create admin user if not exists
with app.app_context():
    db.create_all()
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', is_admin=True)
        admin.set_password('admin123')  # Change this password in production
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)