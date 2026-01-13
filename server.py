from flask import Flask, request, render_template
import sqlite3

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('main.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    conn = sqlite3.connect('mylab.db')
    cursor = conn.cursor()

    # secure, parameterized query:
    # query = "SELECT * FROM users WHERE username = ? AND password = ?"
    # cursor.execute(query, (username, password))

    # insecure, non-parameterized query:
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    
    # Fetch ALL results to show UNION attacks that extract multiple rows
    results = cursor.fetchall()
    conn.close()

    if results:
        return render_template('success.html', query=query, results=results)
    else:
        return render_template('failed.html', query=query)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)