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

class Shop(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    users = db.relationship('User', backref='shop', lazy=True)
    items = db.relationship('Item', backref='shop', lazy=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_shop_admin = db.Column(db.Boolean, default=False)  # Shop-specific admin
    shop_id = db.Column(db.Integer, db.ForeignKey('shop.id'))
    is_active = db.Column(db.Boolean, default=False)  # For user approval
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    stock = db.Column(db.Float, nullable=False)
    price_tiers = db.Column(db.Text, nullable=False, default='{"1": 0}')  # JSON string of quantity-based prices
    shop_id = db.Column(db.Integer, db.ForeignKey('shop.id'), nullable=False)

    def get_price(self, quantity):
        try:
            tiers = json.loads(self.price_tiers) if self.price_tiers else {"1": 0}
            # Sort tiers by quantity in descending order
            sorted_tiers = sorted([(int(q), float(p)) for q, p in tiers.items()], reverse=True)
            # Find the first tier where quantity is less than or equal to the requested quantity
            for tier_qty, tier_price in sorted_tiers:
                if quantity >= tier_qty:
                    return tier_price
            return float(tiers.get('1', 0))  # Default to base price if no tier matches
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            # If there's any error parsing JSON, return a default price
            return 0.0

    def set_price_tier(self, quantity, price):
        try:
            tiers = json.loads(self.price_tiers) if self.price_tiers else {"1": 0}
            tiers[str(quantity)] = float(price)
            self.price_tiers = json.dumps(tiers)
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            # If there's any error, set a default price tier
            self.price_tiers = json.dumps({"1": float(price)})

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
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        shop_id = request.form.get('shop_id', type=int)

        # Validate username
        if len(username) < 3:
            flash('Username must be at least 3 characters long')
            return redirect(url_for('signup'))

        # Validate password
        if len(password) < 8:
            flash('Password must be at least 8 characters long')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('signup'))

        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))

        # Validate shop
        if not shop_id or not Shop.query.get(shop_id):
            flash('Please select a valid shop')
            return redirect(url_for('signup'))

        try:
            user = User(
                username=username,
                shop_id=shop_id,
                is_active=False  # Requires admin approval
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully! Please wait for admin approval.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while creating your account. Please try again.')
            return redirect(url_for('signup'))

    shops = Shop.query.all()
    return render_template('signup.html', shops=shops)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Your account is pending approval. Please contact your administrator.')
                return redirect(url_for('login'))
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
    
    try:
        all_items = Item.query.all()
        # Ensure all items have valid price_tiers
        for item in all_items:
            if not item.price_tiers:
                item.price_tiers = '{"1": 0}'
                db.session.commit()
    except Exception as e:
        flash(f'Error loading items: {str(e)}')
        all_items = []
    
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
    
    try:
        tiers = json.loads(item.price_tiers) if item.price_tiers else {"1": 0}
    except (json.JSONDecodeError, TypeError, ValueError):
        tiers = {"1": 0}
        item.price_tiers = json.dumps(tiers)
        db.session.commit()
    
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

@app.route('/shops')
@login_required
def shops():
    if not current_user.is_admin:
        flash('You do not have permission to access this page')
        return redirect(url_for('home'))
    all_shops = Shop.query.all()
    return render_template('shops.html', shops=all_shops)

@app.route('/add_shop', methods=['GET', 'POST'])
@login_required
def add_shop():
    if not current_user.is_admin:
        flash('You do not have permission to access this page')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        name = request.form['name'].strip()
        location = request.form['location'].strip()
        
        if Shop.query.filter_by(name=name).first():
            flash('Shop name already exists')
            return redirect(url_for('add_shop'))
        
        try:
            shop = Shop(name=name, location=location)
            db.session.add(shop)
            db.session.commit()
            flash('Shop added successfully')
            return redirect(url_for('shops'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while adding the shop')
            return redirect(url_for('add_shop'))
    
    return render_template('add_shop.html')

@app.route('/shop_users/<int:shop_id>')
@login_required
def shop_users(shop_id):
    if not (current_user.is_admin or (current_user.is_shop_admin and current_user.shop_id == shop_id)):
        flash('You do not have permission to access this page')
        return redirect(url_for('home'))
    
    shop = Shop.query.get_or_404(shop_id)
    users = User.query.filter_by(shop_id=shop_id).all()
    return render_template('shop_users.html', shop=shop, users=users)

@app.route('/approve_user/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    if not (current_user.is_admin or (current_user.is_shop_admin and current_user.shop_id == user.shop_id)):
        flash('You do not have permission to approve users')
        return redirect(url_for('home'))
    
    user = User.query.get_or_404(user_id)
    try:
        user.is_active = True
        db.session.commit()
        flash('User approved successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error approving user')
    
    return redirect(url_for('shop_users', shop_id=user.shop_id))

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