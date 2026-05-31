from flask import Flask, render_template, request, redirect, url_for, session
import database

app = Flask(__name__)
app.secret_key = "your-secret-key-here"  # Nên đổi thành khóa bí mật thực tế

# Khởi tạo database nếu chưa có
database.init_database()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        success, message = database.register_user(username, password)
        if success:
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error=message)
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        success, message = database.login_user(username, password)
        if success:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error=message)
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    users = database.get_all_users()
    return render_template('dashboard.html', username=session['username'], users=users)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)