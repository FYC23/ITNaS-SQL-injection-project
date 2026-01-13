# SQL Injection Lab

## 📌 What Is This Project?

This is an educational lab environment designed to teach students about **SQL injection vulnerabilities** in web applications. The project contains an intentionally vulnerable login system that allows students to practice identifying and exploiting SQL injection flaws in a safe, controlled environment.

**⚠️ WARNING:** This application is intentionally insecure. **NEVER** deploy this to a production environment or expose it to the internet.

---

## 🔓 What Is SQL Injection?

**SQL Injection (SQLi)** is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It occurs when user-supplied input is directly concatenated into SQL queries without proper sanitization or parameterization.

### Why It Works

SQL injection works because the application treats user input as part of the SQL command itself, rather than as data. When a developer uses string concatenation or formatting to build SQL queries, malicious users can inject their own SQL code that gets executed by the database.

**Example of vulnerable code:**
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

If a user enters special SQL characters (like single quotes, semicolons, or SQL keywords), they can break out of the intended query structure and execute their own commands.

**What makes it dangerous:**
- Bypass authentication
- Extract sensitive data
- Modify or delete database records
- Execute administrative operations on the database
- In some cases, execute operating system commands

---

## 🚀 Setup and Running the Project

### Prerequisites
- Python 3.x installed
- Basic understanding of SQL and web applications

### Installation Steps

1. **Navigate to the project directory:**
   ```bash
   cd /home/kali/Documents/sqli-lab
   ```

2. **Install Flask (the only dependency):**
   ```bash
   pip install flask
   ```
   or
   ```bash
   pip3 install flask
   ```

3. **Verify the database and users:**
   The `mylab.db` file is included with the project. To verify it has users:
   ```bash
   sqlite3 mylab.db
   ```
   Then in the SQLite prompt:
   ```sql
   SELECT * FROM users;
   .quit
   ```
   You should see the `admin` and `user` accounts listed.

4. **Run the server:**
   ```bash
   python3 server.py
   ```

5. **Access the application:**
   Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```

---

## 💡 Hint: How to Perform SQL Injection

Think about how SQL queries work. The login form checks if a username AND password match. What if you could make the query always return true, regardless of the password?

Consider these questions:
- What happens when you add a single quote `'` to your input?
- Can you use SQL logical operators like `OR` to change the query's logic?
- What would happen if the condition after `OR` is always true?
- How can you comment out the rest of a SQL query so the password check is ignored?

**Key SQL concepts to explore:**
- `OR` operator (logical OR)
- `--` (SQL comment syntax)
- `'1'='1'` (always true condition)

Try entering special characters in the username or password field and observe what happens!

---

## 🎯 Solution: Exploiting the SQL Injection

### The Attack

In the **password** field, enter:
```
password' OR '1'='1
```

(You can enter anything in the username field, like `admin` or even just `test`)

### Why This Works

Let's break down what happens step by step:

#### 1. **The Original Query**

The vulnerable code builds a SQL query like this:
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

With normal input (`admin` / `mypassword`), the query becomes:
```sql
SELECT * FROM users WHERE username='admin' AND password='mypassword'
```
This only succeeds if both username AND password match.

#### 2. **Injecting the Malicious Input**

When you enter `password' OR '1'='1` as the password, the query becomes:
```sql
SELECT * FROM users WHERE username='admin' AND password='password' OR '1'='1'
```

#### 3. **Breaking Down the Injection**

Let's analyze what happened:
- `password'` - The single quote **closes** the password string
- `OR` - Adds a logical OR condition
- `'1'='1'` - This is always TRUE (1 always equals 1)

#### 4. **SQL Logic Evaluation**

The SQL query now has three conditions combined:
```
(username='admin') AND (password='password') OR ('1'='1')
```

Due to SQL operator precedence:
- Even if the first part is false (wrong password)
- The `OR '1'='1'` part is **always true**
- SQL returns ANY row where the condition evaluates to true

**Result:** The database returns user records, and the application thinks you've successfully logged in!

### Alternative Payloads

Other SQL injection strings to try:

**Username field bypass:**
- `admin'--` - The `--` comments out everything after (including password check). Enter anything as password.

**Always true conditions:**
- `' OR 1=1--` - Uses numeric comparison instead of string. Works in both username or password field.
- `' OR 'a'='a` - Same concept - any comparison that's always true works!

**Combined attacks:**
- `admin' OR '1'='1'--` - Combines username injection with always-true condition.

**UNION attacks (advanced):**
- `' UNION SELECT 4, 'hacked', 'password'--` - Returns a fake user row. Shows how attackers can inject fabricated data.
- `' UNION SELECT id, username, password FROM users--` - Dumps ALL usernames and passwords from the database! This shows how SQL injection can lead to massive data breaches.

### The Root Cause

The vulnerability exists because the code uses **string concatenation** (f-strings) to build the query instead of **parameterized queries** (prepared statements).

**Vulnerable:**
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)
```

**Secure:**
```python
query = "SELECT * FROM users WHERE username=? AND password=?"
cursor.execute(query, (username, password))
```

With parameterized queries, the database treats user input as **data**, not as part of the SQL command structure, preventing injection attacks.

---

## 🛡️ How to Prevent SQL Injection

1. **Use Parameterized Queries (Prepared Statements):** Always use `?` placeholders with tuple parameters
2. **Input Validation:** Whitelist allowed characters, reject special SQL characters
3. **Least Privilege:** Database users should have minimal necessary permissions
4. **Web Application Firewall (WAF):** Detect and block common SQL injection patterns
5. **Error Handling:** Don't expose database errors to users
6. **ORMs:** Use Object-Relational Mappers that handle query building safely

---

## 📚 Learning Objectives

By completing this lab, students should understand:
- How SQL injection vulnerabilities occur
- Why string concatenation in SQL queries is dangerous
- How to identify potentially vulnerable code
- The importance of input validation and parameterized queries
- Real-world impact of SQL injection attacks