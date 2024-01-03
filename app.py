from flask import Flask, render_template, request, session, url_for, redirect, flash
from flask_socketio import SocketIO, send
import string
import secrets
from flask_mail import Mail, Message
import rsa
import os
import re

# ----------------App----------------
app = Flask(__name__, template_folder="templates", static_folder="static") 

# ----------------Flask-Mail-Configuration----------------
app.config["MAIL_SERVER"] = "smtp.gmail.com" 
app.config["MAIL_PORT"] = 587
app.config["MAIL_USERNAME"] = os.environ.get("email_for_ChatOn")
app.config["MAIL_PASSWORD"] = os.environ.get("password_for_ChatOn")
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_DEBUG"] = True
mail = Mail(app)

# ----------------Secure-App---------------- 
num = string.digits
char_num = string.ascii_letters + string.digits
secret_key = "".join(secrets.choice(char_num)for i in range(50))

app.config["SECRET_KEY"] = secret_key

socket = SocketIO(app, cors_allowed_origins="*")

# ----------------Getting-RSA-Keys----------------
with open("public.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open("private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

# ----------------DataBase----------------
file = "DataBase_for_ChatOn.txt"

# ----------------Deleting-Duplicates----------------
with open(file, "r") as f:
    fl = f.readlines()

dup_dict = []
dict = []

for l in fl:
    if l in dict:
        dup_dict.append(l)
    else:
        dict.append(l)

with open(file, "w") as f:
    for l in dict:
        f.write(l)

# ----------------Routes----------------
@app.route("/", methods=['GET', 'POST'])
def index():
    session.pop("username", None)
    # ----------------Home-Page----------------
    return render_template("index.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    session.pop("username", None)
    # ----------------Deleting-Duplicates----------------
    with open(file, "r") as f:
        fl = f.readlines()

    dup_dict = []
    dict = []

    for l in fl:
        if l in dict:
            dup_dict.append(l)
        else:
            dict.append(l)

    with open(file, "w") as f:
        for l in dict:
            f.write(l)
    if request.method == "POST":
        user = request.form.get("username")
        pw = request.form.get("password")
        session['username'] = user

        # ----------------Encryption----------------
        encrypted_message = rsa.encrypt(pw.encode(), public_key)
        decrypted_message = rsa.decrypt(encrypted_message, private_key)

        clear_message = decrypted_message.decode()

        # ----------------Logic-for-logging-in----------------
        save_dict = {}

        with open(file, "r") as f:
            for i in f:
                username, password = i.strip().split(":")
                save_dict[username] = password

        if user in save_dict and save_dict[user] == clear_message:
            return redirect(url_for("main"))
        else:
            flash("Incorrect Username or Password!")

    return render_template("login.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    session.pop("username", None)
    if request.method == "POST":
        # ----------------Receiving-User-Data---------------- 
        email = request.form.get("email")
        user = request.form.get("username")
        pw = request.form.get("password")

        # ----------------Encrypting----------------
        encrypted_message = rsa.encrypt(pw.encode(), public_key)
        decrypted_message = rsa.decrypt(encrypted_message, private_key)
        clear_message = decrypted_message.decode()
        
        # ----------------Checking-User-Data----------------
        save_dict = {}

        with open(file, "r") as f:
            for i in f:
                username, password = i.strip().split(":")
                save_dict[username] = password

        # ----------------Generating-Email-Verification-Code----------------
        session['ver_code'] = "".join(secrets.choice(num) for i in range(5))

        # ----------------Generating-Email----------------
        msg_title = "Verification Code"
        sender = "noreply@app.com"
        msg = Message(msg_title, recipients=[email], sender=sender)

        # ----------------Email-Content----------------
        msg.html = f"""
        <!DOCTYPE html>
        <html>
            <head>
                <style>
                    body {{
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        font-family: Arial, sans-serif;
                        background-color: #ffffff;
                        text-align: center;
                    }}
                    .container {{
                        gap: 2px;
                        display: grid;
                        background-color: #ffffff;
                        border: 4px solid rgb(54, 144, 246);
                        border-radius: 10px;
                        width: 400px;
                        text-align: center;
                    }}
                    .h {{
                        grid-column: 1;
                        grid-row: 3;
                        color: #333;
                        grid-column: 1;
                    }}
                    .code {{
                        grid-column: 1;
                        grid-row: 4;
                        color: #333;
                        font-size: 20px;
                    }}
                    h1 {{
                        grid-column: 1;
                        grid-row: 1;
                        color: rgba(250, 198, 27, 0.948);
                        font-size: 40px;
                    }}
                    span {{
                        color: #333;
                        padding-bottom: 13px;
                        text-decoration: none;
                        color: rgb(54, 144, 246);
                    }}
                    p {{
                        grid-column: 1;
                        grid-row: 2;
                        font-size: 13px;
                    }}
                    .start {{
                        border-bottom: 3px solid rgb(54, 144, 246);
                    }}
                    .orange {{
                        font-size: 20px;
                        color: rgba(250, 198, 27, 0.948);
                    }}
                </style>
            </head>
            <body>
                <center>
                    <div class="container">
                        <div class="start">
                            <h1>Chat<span>On</span></h1>
                            <p>Email sent to <span>{email}</span></p>
                        </div>
                        <div class="h">
                            <h3>Your <span class="orange">Verification Code:</span></h3>
                        </div>
                        <div class="code">
                            <h3>{session.get('ver_code')}</h3>
                        </div>
                    </div>
                </center>
            </body>
        </html>
        """
        # ----------------Checking-For-Duplicates----------------
        if user in save_dict:
            flash("The username is already taken by another user!")
        else:
            # ----------------Email-Validation----------------
            pat = r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$"
            if re.match(pat, email):
                print("Valid Email")
                # ----------------Sending-Email-And-Handeling-Error----------------
                try:
                    mail.send(msg)
                    session['user'] = user
                    session['encrypted_password'] = clear_message
                    return redirect(url_for("ver"))
                except Exception as e:
                    # ----------------Error-Handling----------------
                    flash("Incorrect email address. Please double-check and try again.")
                    print("Error sending email", str(e))
            else: 
                # ----------------Error-Handling----------------
                flash("Incorrect email address. Please double-check and try again.")
    return render_template("register.html")

@app.route("/verification", methods=['GET', 'POST'])
def ver():
    session.pop("username", None)
    # ----------------Verification----------------
    if request.method == "POST":
        code = request.form.get("code")
        user = session.get('user')
        clear_message = session.get("encrypted_password")

        if code == session.get('ver_code'):
            with open(file, "a") as f:
                f.write(f"{user}:{clear_message}\n")
            return redirect(url_for("login"))
        else:
            flash("Verification failed; please re-enter the code or register again!")
    return render_template("email_verification.html", email=mail)

@app.route("/about", methods=['GET', 'POST'])
def about():
    session.pop("username", None)
    # ----------------About-Page----------------
    return render_template("about.html")

@app.route("/feedback", methods=['GET', 'POST'])
def feedback():
    session.pop("username", None)
    # ----------------Feedback-Page----------------
    if request.method == "POST":
        email = request.form.get("email")
        name = request.form.get("name")
        feedback = request.form.get("feedback")

        file = "feedback_from_ChatOn.txt"

        if email == 0 and feedback == 0:
            print("No feedback recieved")
        else:
            with open(file, "a") as f:
                f.write(f"{email}: {feedback}\n")
            print("Feedback received!")

            msg_to_send_title = "Thank You!"
            sender = "noreply@app.com"
            msg_to_send = Message(msg_to_send_title, recipients=[email], sender=sender)

            msg_to_send.html = f"""
                <!DOCTYPE html>
                <html>
                    <head>
                        <style>
                            body {{
                                font-family: Arial, sans-serif;
                                background-color: #ffffff;
                                color: #000000;
                            }}
                            .container {{
                                padding: 15px;
                                border-radius: 25px;
                                border: 3px solid rgb(54, 144, 246);
                            }}
                            h1 {{
                                font-size: 32px;
                            }}
                            h2 {{
                                font-size: 25px;
                            }}
                            h3 {{
                                font-size: 28px;
                            }}
                            p {{
                                font-size: 20px;
                            }}
                            .Chat, .dear, span {{
                                font-weight: bold;
                                color: rgb(54, 144, 246);
                            }}
                            .On, .name, .other {{
                                font-weight: bold;
                                color: rgba(251, 196, 16, 0.948);
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <h1><span class="dear">Dear</span> <span class="name">{name},</span></h1>
                            <h2><span>Thank you</span> for your feedback!</h2>
                            <p>We truly <span>appreciate</span> you sharing your feedback with us.
                                Your feedback provides us with <span class="other">valuable information</span> that helps us understand your needs better and allows us to make the necessary adjustments to create a more enjoyable and seamless chatting experience for you. 
                                We are <span>truly grateful</span> for your input, as it enables us to <span class="other">grow and evolve.</span> <br><br>
                                We <span>appreciate</span> your support and the trust you've placed in us. 
                                If you ever have more feedback or suggestions, please don't hesitate to reach out. We're always here to listen and improve based on your needs.
                                <span class="other">Thank you</span> once again for <span>helping</span> us make our chatting platform even <span class="other">better.</span></p>
                            <h3 class="bold">Best regards,<br>
                            <span class="Chat">Chat<span class="On">On</span></span>
                            </h3>
                        </div>
                    </body>
                </html>
            """
            pat = r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$"
            if re.match(pat, email):
                print("Valid Email")
                try:
                    mail.send(msg_to_send)
                    email = 0
                    feedback = 0
                    flash("Thank you for the feedback!")
                except Exception as error:
                    flash("Incorrect email address. Please double-check and try again.")
                    print(f"Unable to send an email, reason: {error}")
            else: 
                flash("Incorrect email address. Please double-check and try again.")
                print("Invalid Email")
    return render_template("feedback.html")

@app.route("/main")
def main():
    user = session.get("username")
    if user == None:
        return redirect(url_for('login'))
    else:
        # ----------------Chatting-Area----------------
        host = f"http://{ip_host}:5000"
        return render_template("main.html", user=user, host=host)
    
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html")

# ----------------Sockets----------------
@socket.on("message")
def handle_message(message):
    encrypted_message = rsa.encrypt(message.encode(), public_key)
    decrypted_message = rsa.decrypt(encrypted_message, private_key)
    message_clear = decrypted_message.decode()
    print(f"Received message: {message_clear}")
    send(message_clear, broadcast=True)

# ----------------Runing----------------
ip_host = "0.0.0.0"
if __name__ == "__main__":
    socket.run(app, debug=False, host=ip_host)
    