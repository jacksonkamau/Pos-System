# POS System

A Point of Sale (POS) system built with Flask that helps manage inventory, process sales, and generate reports.

## Features

- User Authentication and Authorization
  - Admin and regular user roles
  - Password management
  - User management (admin only)

- Inventory Management
  - Add, edit, and delete items
  - Stock management
  - Price tier system for bulk purchases

- Sales Processing
  - Process sales with automatic stock updates
  - View sales history
  - Price calculation based on quantity tiers

- Reporting
  - Sales reports
  - Most sold items
  - Daily sales summary
  - Export reports to CSV

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd pos-system
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

5. Run the application:
```bash
python wsgi.py
```

## Default Admin Account

- Username: admin
- Password: admin123

**Important**: Change the default admin password after first login.

## Security Notes

- Change the `SECRET_KEY` in `app.py` before deploying to production
- Use strong passwords
- Regularly backup the database
- Keep dependencies updated

## License

This project is licensed under the MIT License - see the LICENSE file for details. 