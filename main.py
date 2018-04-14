import bcrypt
from flask import Flask, render_template, flash, request, redirect


app = Flask(__name__)

@app.route('/', methods=['GET','POST'])
def index():
    if request.method == 'GET':
        return render_template('index.html')


@app.route('/generate')
def generate():
    password = request.args.get('password', '')
    hashed_pass = hash_password(password)
    return render_template('index.html', password=password, hashed_pass=hashed_pass)

@app.route('/verify')
def verify():
    password = request.args.get('pass', '')
    hash = request.args.get('hash', '')
    try:
        is_same = verify_password(password, hash)
    except ValueError:
        flash('Invalid hash')
        return redirect('/')
    if is_same:
        flash("It's a match!")
        return render_template('index.html', background='green')
    else:
        flash("Doesn't match!")
        return render_template('index.html', background='red')

def hash_password(plain_text_password):
    # By using bcrypt, the salt is saved into the hash itself
    hashed_bytes = bcrypt.hashpw(plain_text_password.encode('utf-8'), bcrypt.gensalt())
    return hashed_bytes.decode('utf-8')


def verify_password(plain_text_password, hashed_password):
    hashed_bytes_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(plain_text_password.encode('utf-8'), hashed_bytes_password)


if __name__ == '__main__':
    app.secret_key = 'qwertzui5544'
    app.run(
        debug=True
    )