from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from urllib.parse import urlparse
import base64
import datetime
import requests
import json
import hashlib
import sys
from config import HOSTNAME, USER, TEST_HOSTNAME, TEST_USER


OWNED_URI = f"https://{HOSTNAME}"
OWNED_USER = USER

sender_url = f"{OWNED_URI}/users/{OWNED_USER}"
sender_key = f"{OWNED_URI}/users/{OWNED_USER}#main-key"
# NOTE: This id should be unique for each action
activity_id = f"{OWNED_URI}/users/{OWNED_USER}/follows/test"

TEST_URI = f"https://{TEST_HOSTNAME}"


def get_resource_from_webfinger(uri, resource):
    print("Getting recipient url from .well-known/webfinger")
    webfinger = requests.get(
        f"{uri}/.well-known/webfinger?resource={resource}",
        headers={"Accept": "application/jrd+json, application/json"},
    )
    return json.loads(webfinger.content)


def get_canonical_from_webfinger(uri, resource):
    webfinger_json = get_resource_from_webfinger(uri, resource)

    if "links" not in webfinger_json:
        print("No links in webfinger")
        return None

    self_uri = [
        link["href"] for link in webfinger_json["links"] if link["rel"] == "self"
    ]
    if len(self_uri) == 0:
        print("No self uri")
        return None

    return self_uri[0]


def get_inbox_from_canonical_user(uri, resource):
    recipient_url = get_canonical_from_webfinger(uri, resource)

    user = requests.get(
        recipient_url, headers={"Accept": "application/activity+json, application/json"}
    )
    user_json = json.loads(user.content)

    if "inbox" not in user_json:
        print("No inbox")
        return None

    return user_json["inbox"]


def sign(text):
    # The following is to sign the HTTP request as defined in HTTP Signatures.
    private_key_text = open("private.pem", "rb").read()  # load from file

    private_key = crypto_serialization.load_pem_private_key(
        private_key_text, password=None, backend=crypto_default_backend()
    )
    return private_key.sign(text, padding.PKCS1v15(), hashes.SHA256())


def follow():
    recipient_url = get_canonical_from_webfinger(
        TEST_URI, f"acct:{TEST_USER}@{TEST_HOSTNAME}"
    )
    recipient_inbox = get_inbox_from_canonical_user(
        TEST_URI, f"acct:{TEST_USER}@{TEST_HOSTNAME}"
    )

    print(f"Sending follow request from {sender_url} to {recipient_inbox}")

    recipient_parsed = urlparse(recipient_inbox)
    recipient_host = recipient_parsed.netloc
    recipient_path = recipient_parsed.path

    follow_request_message = {
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": activity_id,
        "type": "Follow",
        "actor": sender_url,
        "object": recipient_url,
    }

    digest = base64.b64encode(
        hashlib.sha256(json.dumps(follow_request_message).encode("utf-8")).digest()
    )

    current_date = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )

    # signature_text = generate_signing_text
    signature_text: bytes = b"(request-target): post " + recipient_path.encode("utf-8")
    signature_text += b"\nhost: " + recipient_host.encode("utf-8")
    signature_text += b"\ndate: " + current_date.encode("utf-8")
    signature_text += b"\ndigest: SHA-256=" + digest

    raw_signature = sign(signature_text)

    signature_text_b64 = base64.b64encode(raw_signature).decode("utf-8")
    signature_header = (
        'keyId="'
        + sender_key
        + '",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="'
        + signature_text_b64
        + '"'
    )

    headers = {
        "Date": current_date,
        "Content-Type": "application/activity+json",
        "Host": recipient_host,
        "Digest": "SHA-256=" + digest.decode("utf-8"),
        "Signature": signature_header,
    }
    print(headers)

    # Now that the header is set up, we will construct the message
    r = requests.post(recipient_inbox, headers=headers, json=follow_request_message)
    print(r)
    print(r.content)


def unfollow():
    recipient_url = get_canonical_from_webfinger(
        TEST_URI, f"acct:{TEST_USER}@{TEST_HOSTNAME}"
    )
    recipient_inbox = get_inbox_from_canonical_user(
        TEST_URI, f"acct:{TEST_USER}@{TEST_HOSTNAME}"
    )

    print(f"Sending unfollow request from {sender_url} to {recipient_inbox}")

    recipient_parsed = urlparse(recipient_inbox)
    recipient_host = recipient_parsed.netloc
    recipient_path = recipient_parsed.path

    follow_request_message = {
        "id": activity_id,
        "type": "Follow",
        "actor": sender_url,
        "object": recipient_url,
    }

    unfollow_request_message = {
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": f"{activity_id}/undo",
        "type": "Undo",
        "actor": sender_url,
        "object": follow_request_message,
    }

    digest = base64.b64encode(
        hashlib.sha256(json.dumps(unfollow_request_message).encode("utf-8")).digest()
    )

    current_date = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%a, %d %b %Y %H:%M:%S GMT"
    )

    # signature_text = generate_signing_text
    signature_text: bytes = b"(request-target): post " + recipient_path.encode("utf-8")
    signature_text += b"\nhost: " + recipient_host.encode("utf-8")
    signature_text += b"\ndate: " + current_date.encode("utf-8")
    signature_text += b"\ndigest: SHA-256=" + digest

    raw_signature = sign(signature_text)

    signature_text_b64 = base64.b64encode(raw_signature).decode("utf-8")
    signature_header = (
        'keyId="'
        + sender_key
        + '",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="'
        + signature_text_b64
        + '"'
    )

    headers = {
        "Date": current_date,
        "Content-Type": "application/activity+json",
        "Host": recipient_host,
        "Digest": "SHA-256=" + digest.decode("utf-8"),
        "Signature": signature_header,
    }
    print(headers)

    # Now that the header is set up, we will construct the message
    r = requests.post(recipient_inbox, headers=headers, json=unfollow_request_message)
    print(r)
    print(r.content)


if __name__ == "__main__":
    command = "follow"
    if len(sys.argv) > 1:
        if sys.argv[1] == "--unfollow":
            command = "unfollow"

    if command == "follow":
        follow()
    elif command == "unfollow":
        unfollow()
    else:
        print("Command not handled")
