from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import os
from sqlalchemy import func

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///pos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Float, nullable=False)

class Sale(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/items', methods=['GET', 'POST'])
def items():
    if request.method == 'POST':
        name = request.form['name']
        price = float(request.form['price'])
        stock = float(request.form['stock'])
        new_item = Item(name=name, price=price, stock=stock)
        db.session.add(new_item)
        db.session.commit()
        return redirect(url_for('items'))
    all_items = Item.query.all()
    return render_template('items.html', items=all_items)

@app.route('/delete_item/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('items'))

@app.route('/sales', methods=['GET', 'POST'])
def sales():
    items = Item.query.all()
    if request.method == 'POST':
        item_id = int(request.form['item_id'])
        quantity = float(request.form['quantity'])
        item = Item.query.get(item_id)
        if item and item.stock >= quantity:
            total_price = item.price * quantity
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
def report():
    total_sales = db.session.query(func.sum(Sale.total_price)).scalar() or 0
    sales_data = db.session.query(Sale.item_id, func.sum(Sale.quantity)).group_by(Sale.item_id).all()
    most_sold = []
    for item_id, quantity_sold in sales_data:
        item = Item.query.get(item_id)
        if item:
            most_sold.append({'name': item.name, 'quantity_sold': quantity_sold})
    most_sold.sort(key=lambda x: x['quantity_sold'], reverse=True)
    # Daily sales summary
    daily_sales = db.session.query(func.date(Sale.timestamp), func.sum(Sale.total_price)).group_by(func.date(Sale.timestamp)).all()
    return render_template('report.html', total_sales=total_sales, most_sold=most_sold, daily_sales=daily_sales)

# Initialize the database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)