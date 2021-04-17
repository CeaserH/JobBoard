from flask import Flask, render_template, session, redirect, flash, request
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
app.secret_key = 'killingit'
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
PASSWORD_REGEX = re.compile(r'\d.*[A-Z]|[A-Z].*\d')

@app.route('/')
def index():
    return render_template('login_reg.html')

@app.route('/register', methods=['POST'])
def reg():
    is_valid = True

    if len(request.form['firstname']) < 2:
        is_valid = False
        flash("Please enter a valid first name")
    elif request.form['firstname'].isalpha() == False:
        is_valid = False
        flash("Please enter a valid first name")
    if len(request.form['lastname']) < 2:
        is_valid = False
        flash("Please enter a valid last name")
    elif request.form['lastname'].isalpha() == False:
        is_valid = False
        flash("Please enter a valid last name")   

    if len(request.form['email']) < 1:
        is_valid = False
        flash("Please enter a valid email address") 
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Please enter a valid email address")

    if len(request.form['password']) < 1:
        is_valid = False
        flash("Password cannot be blank")
    elif len(request.form['password']) < 8:
        is_valid = False
        flash("Password must be at least 8 characters")
    elif not PASSWORD_REGEX.match(request.form['password']):
        is_valid = False
        flash("Password much contain at least one uppercase and one number")
    
    if len(request.form['passwordconfirm']) < 1:
        is_valid = False
        flash("Confirm password cannot be blank")
    elif request.form['passwordconfirm'] != request.form['password']:
        is_valid = False
        flash("Passwords do not match")
    
    if is_valid == False:
        return redirect('/')

    if is_valid == True:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        query = 'INSERT INTO users (firstname, lastname, email, password, created_at, updated_at) VALUES(%(fn)s, %(ln)s, %(em)s, %(pw)s, NOW(), NOW());'
        data = {
            'fn': request.form['firstname'],
            'ln': request.form['lastname'],
            'em': request.form['email'],
            'pw': pw_hash,
        }
        mysql = connectToMySQL('Jobs')
        mysql.query_db(query, data)

        session['email'] = request.form['email']
        session['register_success'] = True
        session['login_success'] = False
        flash("You have successfully registered, please sign in!")
        return redirect('/dashboard')


@app.route('/login', methods=['POST'])
def login():
    is_valid = True

    query = 'SELECT * FROM users WHERE email = %(em)s'
    data = {
        'em': request.form['email']
    }
    mysql = connectToMySQL('Jobs')
    email = mysql.query_db(query, data)

    if len(email) > 0:
        if bcrypt.check_password_hash(email[0]['password'], request.form['password']):
            session['userid'] = email[0]['id']
            session['firstname'] = email[0]['firstname']
            return redirect('/dashboard')
    
    flash("You could not be logged in")
    return redirect('/')


@app.route('/dashboard')
def dashboard():
    if 'userid' in session:
        query = 'SELECT * FROM jobs'
        mysql = connectToMySQL('Jobs')
        jobs = mysql.query_db(query)
        return render_template('dashboard.html', all_jobs=jobs)
    else:
        return redirect('/')

@app.route('/jobs/new')
def newjob():
    return render_template('newjob.html')

@app.route('/addjob', methods=['POST'])
def addjob():
    is_valid = True

    if len(request.form['title']) < 3:
        is_valid = False
        flash("Please enter a valid job title")
    if len(request.form['description']) < 3:
        is_valid = False
        flash("Please enter a valid description")
    if len(request.form['location']) < 3:
        is_valid = False
        flash("Please enter a valid location")
    
    if is_valid == False:
        return redirect('/jobs/new')

    if is_valid == True:
        query = 'INSERT INTO jobs (title, description, location, created_at, updated_at, posted_by_id) VALUES(%(ti)s, %(desc)s, %(loc)s, NOW(), NOW(), %(pid)s);'
        data = {
            'ti': request.form['title'],
            'desc': request.form['description'],
            'loc': request.form['location'],
            'pid': session['userid']
        }
        mysql = connectToMySQL('Jobs')
        mysql.query_db(query, data)
        return redirect('/dashboard')

@app.route('/jobs/<id>', methods=['get'])
def viewjob(id):
    if 'userid' in session:

        query = 'SELECT jobs.id, jobs.title, jobs.description, jobs.location, jobs.created_at, jobs.posted_by_id, users.firstname, users.lastname FROM jobs JOIN users ON jobs.posted_by_id = users.id WHERE jobs.id = %(jid)s;'
        data = {
            'jid': id,
        }
        mysql = connectToMySQL('Jobs')
        job = mysql.query_db(query, data)

        return render_template('viewjob.html', job=job)
    else:
        return redirect('/')

@app.route('/jobs/edit/<id>')
def editjob(id):
    if 'userid' in session:

        query = 'SELECT jobs.id, jobs.title, jobs.description, jobs.location, jobs.created_at, jobs.posted_by_id, users.firstname, users.lastname FROM jobs JOIN users ON jobs.posted_by_id = users.id WHERE jobs.id = %(jid)s;'
        data = {
            'jid': id,
        }
        mysql = connectToMySQL('Jobs')
        job = mysql.query_db(query, data)

        return render_template('editjob.html', job=job)

    else:
        return redirect('/')

@app.route('/jobs/update/', methods=['POST'])
def updatejob():
    is_valid = True

    if len(request.form['title']) < 3:
        is_valid = False
        flash("Please enter a valid job title")
    if len(request.form['description']) < 3:
        is_valid = False
        flash("Please enter a valid description")
    if len(request.form['location']) < 3:
        is_valid = False
        flash("Please enter a valid location")
    
    if is_valid == False:
        return redirect('/jobs/edit/' + request.form['job_id'])

    if is_valid == True:
        query = 'UPDATE jobs SET title = %(ti)s, description = %(desc)s, location = %(loc)s, updated_at = NOW() WHERE jobs.id = %(jid)s'
        data = {
            'ti': request.form['title'],
            'desc': request.form['description'],
            'loc': request.form['location'],
            'jid': request.form['job_id'],
        }
        mysql = connectToMySQL('Jobs')
        mysql.query_db(query, data)
        return redirect('/dashboard')


@app.route('/jobs/delete/<id>')
def deletejob(id):
    query = 'DELETE FROM jobs WHERE jobs.id = %(jid)s'
    data = {
        'jid': id,
    }
    mysql = connectToMySQL('Jobs')
    mysql.query_db(query, data)
    return redirect('/dashboard')


@app.route('/logout')
def logout():
    if session.get('userid'):
        session.pop('userid')
    if session.get('firstname'):
        session.pop('firstname')
    return redirect('/')

if __name__=='__main__':
    app.run(debug=True)