
from flask import Flask, render_template, request
from aes import encrypt_result, decrypt_result

# from sha512hash import hash_it

app = Flask(__name__)


@app.route("/")
@app.route("/home")
def home():
    return render_template("index.html")


@app.route("/encrypt", methods=['POST', 'GET'])
def encrypt():
    output = request.form.to_dict()

    plaintext = output["plaintext"]

    key_size = int(output.get("key_size", 128))

    # key = hash_it(output["key"])
    key = output["key"]

    ans = encrypt_result(plaintext, key, key_size)
    no_of_rounds = ans["no_of_rounds"]

    cipher_raw = ""
    for i in range(len(ans["blocks"])):
        cipher_raw = cipher_raw + ans[i]["cipher"]

    # Convert the encrypted raw bytes into a hexadecimal string.
    cipher_hex = "".join("{:02x}".format(ord(c)) for c in cipher_raw)

    return render_template("result.html", ans=ans, blocks=len(ans["blocks"]), cipher=cipher_hex,
                           no_of_rounds=no_of_rounds)


@app.route("/decrypt", methods=['POST', 'GET'])
def decrypt():
    output = request.form.to_dict()

    ciphertext_hex = output["ciphertext"]

    key_size = int(output.get("key_size", 128))

    # key = hash_it(output["key"])
    key = output["key"]

    try:
        ciphertext_hex = ciphertext_hex.strip()
        ciphertext_raw = "".join(chr(int(ciphertext_hex[i:i + 2], 16)) for i in range(0, len(ciphertext_hex), 2))
    except Exception as e:
        return f"Error: Input is not a valid Hex string. Details: {str(e)}"

    ans = decrypt_result(ciphertext_raw, key, key_size)
    no_of_rounds = ans["no_of_rounds"]

    plaintext = ""
    for i in range(len(ans["blocks"])):
        plaintext = plaintext + ans[i]["plaintext"]

    return render_template("result.html", ans=ans, blocks=len(ans["blocks"]), plaintext=plaintext,
                           no_of_rounds=no_of_rounds)


if __name__ == '__main__':
    app.run(debug=True, port=5001)