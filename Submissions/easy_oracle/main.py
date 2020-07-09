from flask import Flask, request
from Crypto.Util.number import bytes_to_long
from config import flag, render_source, e, n, d

app = Flask(__name__)

def encrypt(m):
    return pow(m, e, n)

def decrypt(c):
    return pow(c, d, n)

@app.route("/flag")
def getflag():
    return str(encrypt(bytes_to_long(flag)))

@app.route("/key")
def getkey():
    return str(e) + "," + str(n)

@app.route("/")
def main():
    if "decrypt" in request.args:
        cleartext = decrypt(int(request.args["decrypt"]))
        return str(cleartext % 2)
    else:
        return render_source(__file__)

if __name__ == "__main__":
    app.run()