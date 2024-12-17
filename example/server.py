from flask import Flask, request, make_response, abort, Response
import ssl
from config import HOSTNAME, USER

URI = f"https://{HOSTNAME}"

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    f"/etc/letsencrypt/live/{HOSTNAME}/fullchain.pem",
    f"/etc/letsencrypt/live/{HOSTNAME}/privkey.pem",
)

app = Flask(__name__)


@app.route("/users/<username>")
def user(username):
    print(f"Received GET request for /users/{username}")
    print(request.headers)

    if username != USER:
        abort(404)

    public_key = open("public.pem", "r").read()

    response = make_response(
        {
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/v1",
            ],
            "id": f"{URI}/users/{USER}",
            "inbox": f"{URI}/users/{USER}/inbox",
            "outbox": f"{URI}/users/{USER}/outbox",
            "type": "Person",
            "name": USER.title(),
            "preferredUsername": USER,
            "publicKey": {
                "id": f"{URI}/users/{USER}#main-key",
                "owner": f"{URI}/users/{USER}",
                "publicKeyPem": public_key,
            },
        }
    )

    # Servers may discard the result if you do not set the appropriate content type
    response.headers["Content-Type"] = "application/activity+json"

    return response


@app.route("/users/<username>/inbox", methods=["POST"])
def user_inbox(username):
    print(f"Received POST request for /users/{username}/inbox")
    print(request.headers)
    print(request.data)

    if username != USER:
        abort(404)

    # Accept any message sent to our inbox while testing
    return Response("", status=202)


@app.route("/.well-known/webfinger")
def webfinger():
    resource = request.args.get("resource")

    if resource != f"acct:{USER}@{HOSTNAME}":
        abort(404)

    response = make_response(
        {
            "subject": f"acct:{USER}@{HOSTNAME}",
            "links": [
                {
                    "rel": "self",
                    "type": "application/activity+json",
                    "href": f"{URI}/users/{USER}",
                }
            ],
        }
    )

    # Servers may discard the result if you do not set the appropriate content type
    response.headers["Content-Type"] = "application/jrd+json"

    return response


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    print(path)
    print(request.headers)
    print(request.data)

    return ""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443, ssl_context=context)
