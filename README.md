# SQL Injection Lab

## 📌 What Is This Project?

This is an educational lab environment designed to teach students about **SQL injection vulnerabilities** in web applications. The project contains an intentionally vulnerable login system that allows students to practice identifying and exploiting SQL injection flaws in a safe, controlled environment.

**⚠️ WARNING:** This application is intentionally insecure. **NEVER** deploy this to a production environment or expose it to the internet.

---

## 🔓 What Is SQL Injection?

**SQL Injection (SQLi)** is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It occurs when user-supplied input is directly concatenated into SQL queries without proper sanitization or parameterization.

SQL injection is consistently ranked among the most critical web application security risks in the [OWASP Top 10](https://owasp.org/Top10/A03_2021-Injection/), appearing as **A03:2021 - Injection**. According to OWASP, injection vulnerabilities can lead to data loss, corruption, disclosure to unauthorized parties, loss of accountability, or denial of access.

### Why It Works

SQL injection works because the application treats user input as part of the SQL command itself, rather than as data. When a developer uses string concatenation or formatting to build SQL queries, malicious users can inject their own SQL code that gets executed by the database.

According to [OWASP](https://owasp.org/www-community/attacks/SQL_Injection), SQL injection occurs when:
1. Data enters a program from an untrusted source
2. The data is used to dynamically construct a SQL query

**Example of vulnerable code:**
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

If a user enters special SQL characters (like single quotes, semicolons, or SQL keywords), they can break out of the intended query structure and execute their own commands.

**What makes it dangerous:**
- **Bypass authentication** - Gain unauthorized access to accounts
- **Extract sensitive data** - Steal passwords, personal information, credit cards
- **Modify or delete database records** - Corrupt or destroy data integrity
- **Execute administrative operations** - Grant privileges, create backdoors
- **In some cases, execute operating system commands** - Completely compromise the server
- **Data exfiltration at scale** - Extract entire databases in a single attack

According to [OWASP Top 10](https://owasp.org/Top10/A03_2021-Injection/), injection attacks can result in data loss, corruption, disclosure to unauthorized parties, loss of accountability, or denial of access. In some cases, injection can lead to complete host takeover.

### Types of SQL Injection Attacks

Based on [OWASP SQL Injection documentation](https://owasp.org/www-community/attacks/SQL_Injection), SQL injection attacks can be classified into several types:

#### 1. **In-Band SQL Injection (Classic)**
The most common and easy-to-exploit type where the attacker uses the same communication channel to launch the attack and gather results.

- **Error-Based**: Forces the database to generate error messages that reveal information about the database structure
- **Union-Based**: Uses the UNION SQL operator to combine results of multiple SELECT queries (like the examples in this lab)

#### 2. **Blind SQL Injection**
Used when the application doesn't display database errors or data, but behaves differently based on the query result.

- **Boolean-Based Blind**: Sends queries that return different responses based on whether the query is TRUE or FALSE
- **Time-Based Blind**: Forces the database to wait (using commands like SLEEP) to infer information from response time

#### 3. **Out-of-Band SQL Injection**
Less common, relies on features enabled on the database server (like DNS or HTTP requests) to transfer data to the attacker.

**This lab focuses on In-Band (Classic) SQL Injection**, which is the most straightforward to understand and demonstrate for educational purposes.

---

## 🚀 Setup and Running the Project

### What You'll Need

**No programming experience required!** This guide will walk you through everything step by step.

You'll need:
- A computer (Windows, Mac, or Linux)
- About 15-20 minutes
- An internet connection (for downloading Python if needed)

### What is Python?

Python is a programming language. Think of it like Microsoft Word, but instead of writing documents, it runs programs. This project needs Python to work, just like you need Microsoft Word to open .docx files.

---

### Step 1: Check if Python is Already Installed

Python might already be on your computer. Let's check!

#### Opening the Terminal (Command Line)

The "terminal" or "command line" is a text-based way to give your computer instructions. Here's how to open it:

**On Windows:**
1. Click the Start menu (Windows icon in bottom-left corner)
2. Type `cmd` or `command prompt`
3. Click on "Command Prompt" when it appears
4. A black window with white text will open

**On Mac:**
1. Press `Command + Space` to open Spotlight Search
2. Type `terminal`
3. Press Enter
4. A white or black window will open

**On Linux:**
1. Press `Ctrl + Alt + T`
2. Or search for "Terminal" in your applications menu

#### Check Your Python Version

Once your terminal is open, type this command and press Enter:

```bash
python3 --version
```

**What you should see:**
- If Python is installed, you'll see something like `Python 3.9.7` or `Python 3.11.2` (the numbers may vary)
- If you see an error like `command not found` or `not recognized`, Python is not installed

**If Python is NOT installed:**
1. Go to [https://www.python.org/downloads/](https://www.python.org/downloads/)
2. Click the big yellow "Download Python" button
3. Run the downloaded file
4. **IMPORTANT for Windows users:** Check the box that says "Add Python to PATH" during installation
5. Follow the installation wizard (click "Next" through the steps)
6. After installation, close and reopen your terminal, then try `python3 --version` again

---

### Step 2: Download This Project

You need to get the project files onto your computer.

**If you downloaded a ZIP file:**
1. Find the ZIP file in your Downloads folder
2. Right-click it and choose "Extract All" (Windows) or double-click it (Mac)
3. Remember where you extracted it (like your Documents folder)

**If you used Git (advanced):**
- You already have the files in a folder somewhere on your computer

---

### Step 3: Navigate to the Project Folder

Now we need to tell the terminal where the project files are located.

#### Find Your Project Path

First, find the full path (address) of your project folder:

**On Windows:**
1. Open File Explorer
2. Navigate to where you extracted the project
3. Click on the address bar at the top (where it shows the folder path)
4. The full path will be highlighted (something like `C:\Users\YourName\Documents\ITNaS-SQL-injection-project`)
5. Copy this path (Ctrl+C)

**On Mac:**
1. Open Finder
2. Navigate to your project folder
3. Right-click on the folder
4. Hold down the Option key
5. Click "Copy [folder name] as Pathname"

#### Navigate in the Terminal

In your terminal, type `cd` (which means "change directory") followed by a space, then paste your path:

**Windows example:**
```bash
cd C:\Users\YourName\Documents\ITNaS-SQL-injection-project
```

**Mac/Linux example:**
```bash
cd /Users/YourName/Documents/ITNaS-SQL-injection-project
```

Press Enter. If successful, you won't see an error message.

**To verify you're in the right place**, type:
```bash
dir
```
(on Windows) or
```bash
ls
```
(on Mac/Linux)

You should see files listed including `server.py` and `mylab.db`.

---

### Step 4: Install Flask

Flask is a tool (called a "library") that helps Python create websites. We need to install it.

In your terminal (make sure you're still in the project folder), type:

```bash
pip3 install flask
```

Press Enter and wait. You'll see text scrolling by - this is normal!

**What success looks like:**
- You'll see messages about "Downloading" and "Installing"
- At the end, you'll see something like "Successfully installed flask"
- You'll get your command prompt back (the line where you can type)

**If you see an error:**
- Try `pip install flask` instead (without the "3")
- Or try `python3 -m pip install flask`

---

### Step 5: Run the Project

Now we're ready to start the web application!

In your terminal, type:

```bash
python3 server.py
```

Press Enter.

**What success looks like:**
- You'll see several lines of text appear
- One line will say something like `Running on http://127.0.0.1:5000` or `Running on http://localhost:5000`
- The cursor will NOT come back - this is normal! The program is running.
- **Do NOT close this terminal window** - the program needs to stay running

**If you see an error:**
- Try `python server.py` instead (without the "3")
- Make sure you're in the correct folder (go back to Step 3)
- Make sure Flask installed correctly (go back to Step 4)

---

### Step 6: Open the Application in Your Web Browser

Now let's see the application!

1. Open your web browser (Chrome, Firefox, Safari, Edge - any browser works)
2. In the address bar at the top (where you normally type google.com), type:
   ```
   http://localhost:5000
   ```
3. Press Enter

**What you should see:**
- A login page with fields for username and password
- This is the vulnerable application you'll be testing!

**Troubleshooting:**
- If the page doesn't load, make sure the terminal window from Step 5 is still open and running
- Try `http://127.0.0.1:5000` instead
- Make sure you typed the address exactly as shown (including the `http://` part)

---

### Step 7: When You're Done

To stop the application:

1. Go back to the terminal window where the program is running
2. Press `Ctrl + C` (hold Control and press C)
3. The program will stop and you'll get your command prompt back
4. You can now close the terminal window

---

### Quick Reference: Starting the Application Again

After the first time, starting the application is easier:

1. Open terminal
2. Navigate to project folder: `cd [your-project-path]`
3. Run the server: `python3 server.py`
4. Open browser to: `http://localhost:5000`

---

### Need Help?

**Common Issues:**

- **"Python not found"** - Go back to Step 1 and install Python
- **"Flask not found"** - Go back to Step 4 and install Flask
- **"No such file or directory"** - You're not in the right folder, go back to Step 3
- **"Address already in use"** - The program is already running in another terminal window, or another program is using port 5000. Close other terminals or restart your computer.
- **Page won't load in browser** - Make sure the terminal is still running the program (you should see the text from Step 5)

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

Other SQL injection strings to try (based on [OWASP SQL Injection examples](https://owasp.org/www-community/attacks/SQL_Injection)):

**Username field bypass:**
- `admin'--` - The `--` comments out everything after (including password check). Enter anything as password.
- `admin'#` - Alternative comment syntax (works in MySQL)
- `admin'/*` - Yet another comment syntax

**Always true conditions:**
- `' OR 1=1--` - Uses numeric comparison instead of string. Works in both username or password field.
- `' OR 'a'='a` - Same concept - any comparison that's always true works!
- `' OR 'x'='x'--` - Another variant of always-true condition

**Combined attacks:**
- `admin' OR '1'='1'--` - Combines username injection with always-true condition.
- `' OR 1=1 LIMIT 1--` - Returns first user (often admin)

**UNION attacks (advanced):**
- `' UNION SELECT 4, 'hacked', 'password'--` - Returns a fake user row. Shows how attackers can inject fabricated data.
- `' UNION SELECT id, username, password FROM users--` - Dumps ALL usernames and passwords from the database! This shows how SQL injection can lead to massive data breaches.
- `' UNION SELECT NULL, NULL, NULL--` - Used to determine number of columns in original query

**Stacked queries (dangerous):**
- `admin'; DROP TABLE users; --` - Attempts to execute multiple statements (works in some databases like MS SQL Server)

**Blind SQL injection (advanced):**
- `' AND SLEEP(5)--` - Time-based blind injection (MySQL)
- `' AND 1=1--` vs `' AND 1=2--` - Boolean-based blind injection to infer information

**Note:** Different databases (MySQL, PostgreSQL, SQLite, MS SQL Server, Oracle) may have slightly different syntax. The payloads above are generally compatible with SQLite (used in this lab) and MySQL.

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

Based on guidance from [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), here are the primary defenses against SQL injection:

### Primary Defenses

1. **Use Parameterized Queries (Prepared Statements)** ⭐ **MOST IMPORTANT**
   - Always use `?` placeholders or named parameters with tuple/dictionary parameters
   - This separates SQL logic from data, ensuring user input is treated as data only
   - Available in virtually all database libraries and ORMs
   - Example shown in the `server.py` comments (lines 18-20)
   - See [OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html) for language-specific examples

2. **Use Stored Procedures (Safely)**
   - Can provide protection IF they don't use dynamic SQL concatenation internally
   - Parameters must be properly bound, not concatenated into the procedure's SQL

3. **Allow-List Input Validation**
   - Validate all user inputs using whitelists (allow only known good values)
   - Especially critical for table names, column names, and sort order parameters that cannot be parameterized
   - Never rely solely on blacklists - attackers can often find ways around them

### Additional Defense Layers

4. **Escaping User Input (Last Resort)**
   - Only use when parameterization is not possible
   - Must use database-specific escaping functions
   - Error-prone and not recommended as primary defense

5. **Least Privilege Principle**
   - Database accounts used by applications should have minimal necessary permissions
   - Don't use admin/root accounts for web applications
   - Restrict permissions to only required operations (e.g., SELECT only if no writes needed)
   - See [OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)

6. **Web Application Firewall (WAF)**
   - Can detect and block common SQL injection patterns
   - Should be used as an additional layer, not as primary defense
   - Cannot replace proper secure coding practices

7. **Proper Error Handling**
   - Don't expose database errors or stack traces to end users
   - Log detailed errors securely for developers
   - Use generic error messages for users

8. **Use ORMs Carefully**
   - Object-Relational Mappers (ORMs) usually handle query building safely
   - However, be careful with raw query features that bypass ORM protections

**Further Reading:**
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

---

## 🌍 Real-World Impact

SQL injection is not just a theoretical vulnerability. According to OWASP, it has been used in many high-profile data breaches:

- **Authentication Bypass**: Attackers gain unauthorized access to admin panels and user accounts
- **Data Theft**: Millions of user records including passwords, credit cards, and personal information stolen
- **Website Defacement**: Attackers modify website content or inject malicious scripts
- **Data Destruction**: Entire databases deleted or corrupted
- **Privilege Escalation**: Normal users elevated to administrator status

**Why It's Still Common:**
Despite being well-understood for decades, SQL injection remains prevalent because:
- Legacy code that hasn't been updated
- Developers unfamiliar with secure coding practices  
- Third-party components and plugins with vulnerabilities
- Insufficient security testing and code review
- Time pressure leading to shortcuts in development

**Industry Statistics:**
- SQL injection consistently appears in the OWASP Top 10 vulnerabilities
- Ranked as **#3 in OWASP Top 10:2021** under "Injection"
- Can affect applications across all industries: healthcare, finance, e-commerce, government

This lab demonstrates why proper input handling and parameterized queries are absolutely critical for web application security.

---

## 📚 Learning Objectives

By completing this lab, students should understand:
- How SQL injection vulnerabilities occur
- Why string concatenation in SQL queries is dangerous
- How to identify potentially vulnerable code
- The importance of input validation and parameterized queries
- Real-world impact of SQL injection attacks

---

## 📖 References & Further Reading

This lab's content is based on industry-standard security guidance from the following authoritative sources:

### Primary Resources

- **[OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)**
  - Comprehensive overview of SQL injection attacks, types, and impacts
  - Examples of vulnerable code and attack scenarios

- **[OWASP Top 10:2021 - A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)**
  - Current ranking and assessment of injection vulnerabilities
  - Risk factors and prevention strategies

- **[OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)**
  - Detailed defense mechanisms: prepared statements, stored procedures, input validation
  - Code examples and best practices

- **[OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)**
  - Language-specific examples of parameterized queries
  - Covers Java, .NET, PHP, Python, Ruby, and more

- **[OWASP Database Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)**
  - Guidance on securing database configurations
  - Principle of least privilege and access controls

### Additional Learning Resources

- **[OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)**
  - Broader coverage of injection attacks beyond SQL
  - Testing techniques and secure development practices

- **[PortSwigger Web Security Academy - SQL Injection](https://portswigger.net/web-security/sql-injection)**
  - Interactive labs and detailed tutorials
  - Advanced techniques including blind SQL injection

- **[Snyk - SQL Injection Cheat Sheet](https://snyk.io/blog/sql-injection-cheat-sheet/)**
  - Practical security tips and common pitfalls
  - Modern framework-specific guidance

### Academic & Industry References

- **[CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)**
  - Common Weakness Enumeration entry for SQL injection
  - Technical details and mitigation strategies

- **Berkeley Information Security - [How to Protect Against SQL Injection](https://security.berkeley.edu/education-awareness/how-protect-against-sql-injection-attacks)**
  - Educational institution's perspective on prevention
  - Developer best practices

---

## 🤝 Contributing

This is an educational project. If you find issues or have suggestions for improvement, please feel free to contribute or provide feedback.

## 📄 License

This project is intended for educational purposes only. Use responsibly and ethically.