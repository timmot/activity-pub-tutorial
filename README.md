<p align="center">
  <img style="max-height: 250px;" src="https://raw.githubusercontent.com/timmot/activity-pub-tutorial/master/title.png" alt="ActivityPub"/>
</p>

# ActivityPub Tutorial

## Requirements
* You need a domain name
* You need an HTTPS certificate for this domain name
* Python3
* Python3 packages: flask, cryptography, requests

## Short method
1. [Read the ActivityPub overview](#1-read-the-activitypub-overview)
2. [Create an endpoint for yourself](#2-create-an-endpoint-for-yourself)
3. [Extend this endpoint for real servers](#3-extend-this-endpoint-for-real-servers)
4. [Create a Webfinger endpoint for yourself](#4-create-a-webfinger-endpoint-for-yourself)
5. [Create an inbox endpoint for yourself](#5-create-an-inbox-endpoint-for-yourself)
6. [Follow a user from an instance to start receiving activities on your instance](#6-follow-a-user-from-an-instance-to-start-receiving-activities-on-your-instance)

## Long method
We'll run with some assumptions. Your domain name is `example.com`, your user name will be `zampano`.

### 1. Read the ActivityPub overview
[https://www.w3.org/TR/activitypub/#Overview](https://www.w3.org/TR/activitypub/#Overview)

### 2. Create an endpoint for yourself
[https://www.w3.org/TR/activitypub/#actors](https://www.w3.org/TR/activitypub/#actors)

ActivityStreams expects that we define a @context, id, type, and name property.
ActivityPub expects that we define an inbox and outbox property.

```python
@app.route('/users/<username>')
def user(username):
    if username != "zampano":
        abort(404)

    response = make_response({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": "https://example.com/users/zampano",
        "inbox": "https://example.com/users/zampano/inbox",
        "outbox": "https://example.com/users/zampano/outbox",
        "type": "Person",
        "name": "Zampano",
    })

    # Servers may discard the result if you do not set the appropriate content type
    response.headers['Content-Type'] = 'application/activity+json'

    return response
```

### 3. Extend this endpoint for real servers

This would be okay and meets the core specification, but to interact with Mastodon we need to add the preferredUsername attribute (from ActivityPub) and we need to add the publicKey property (from Linked Data Proofs).

#### Generate public and private keys
```sh
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

or in Python
```python
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

key = rsa.generate_private_key(
    backend=crypto_default_backend(),
    public_exponent=65537,
    key_size=2048
)

private_key = key.private_bytes(
    crypto_serialization.Encoding.PEM,
    crypto_serialization.PrivateFormat.PKCS8,
    crypto_serialization.NoEncryption())

public_key = key.public_key().public_bytes(
    crypto_serialization.Encoding.PEM,
    crypto_serialization.PublicFormat.SubjectPublicKeyInfo
)
```

#### Modify user endpoint

```python
@app.route('/users/<username>')
def user(username):
    if username != "zampano":
        abort(404)

    public_key = b'' # retrieve from file/database

    response = make_response({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
        ],
        "id": "https://example.com/users/zampano",
        "inbox": "https://example.com/users/zampano/inbox",
        "outbox": "https://example.com/users/zampano/outbox",
        "type": "Person",
        "name": "Zampano",
        "preferredUsername": "zampano",
        "publicKey": {
            "id": "https://example.com/users/zampano#main-key",
            "id": "https://example.com/users/zampano",
            "publicKeyPem": public_key
        }
    })

    # Servers may discard the result if you do not set the appropriate content type
    response.headers['Content-Type'] = 'application/activity+json'

    return response
```


### 4. Create a Webfinger endpoint for yourself

"Web finger is used to discover information about people or other entities on the Internet that are identified by a URI."
Some ActivityPub servers, like Mastodon, will use Webfinger to find the location of the Actor record we've been creating. 

```python
from flask import request, make_response

# ...

@app.route('/.well-known/webfinger')
def webfinger():
    resource = request.args.get('resource')

    if resource != "acct:zampano@example.com":
        abort(404)

    response = make_response({
        "subject": "acct:zampano@example.com",
        "links": [
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": "https://example.com/users/zampano"
            }
        ]
    })

    # Servers may discard the result if you do not set the appropriate content type
    response.headers['Content-Type'] = 'application/jrd+json'
    
    return response
```

### 5. Create an inbox endpoint for yourself 

We've defined an inbox and outbox property in our Person record.
```
...
"inbox": "https://example.com/users/zampano/inbox",
"outbox": "https://example.com/users/zampano/outbox",
...
```

We will want to define the outbox later for the client-to-server interactions, but for now we can get away with just the inbox.

```python
@app.route('/users/<username>/inbox', methods=['POST'])
def user_inbox(username):
    if username != "zampano":
        abort(404)

    app.logger.info(request.headers)
    app.logger.info(request.data)
    
    return Response("", status=202)
```

### 6. Follow a user from an instance to start receiving activities on your instance
You could feasibly follow any ActivityPub Actor now but I recommend testing with an account you control on a Mastodon instance, or with a bot account.

Let's assume you're sending a follow request to the user 'truant' at the Mastodon instance 'exampletwo.com'.

```python
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from urllib.parse import urlparse
import base64
import datetime
import requests


recipient_url = "https://exampletwo.com/users/truant"
recipient_inbox = "https://exampletwo.com/users/truant/inbox"

sender_url = "https://example.com/users/zampano"
sender_key = "https://example.com/users/zampano#main-key"

activity_id = "https://example.com/users/zampano/follows/test"


# The following is to sign the HTTP request as defined in HTTP Signatures.
private_key_text = b'' # load from file

private_key = crypto_serialization.load_pem_private_key(
    private_key_text,
    password=None,
    backend=crypto_default_backend()
)

current_date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

recipient_parsed = urlparse(recipient_inbox)
recipient_host = recipient_parsed.netloc
recipient_path = recipient_parsed.path

signature_text = b'(request-target): post %s\nhost: %s\ndate: %s' % recipient_path.encode('utf-8'), recipient_host.encode('utf-8'), date.encode('utf-8')

raw_signature = private_key.sign(
    signature_text,
    padding.PKCS1v15(),
    hashes.SHA256()
)

signature_header = 'keyId="%s",algorithm="rsa-sha256",headers="(request-target) host date",signature="%s"' % sender_key, base64.b64encode(raw_signature).decode('utf-8')

headers = {
    'Date': date,
    'Content-Type': 'application/activity+json',
    'Host': recipient_host,
    'Signature': signature_header
}

# Now that the header is set up, we will construct the message
follow_request_message = {
    "@context": "https://www.w3.org/ns/activitystreams",
    "id": activity_id,
    "type": "Follow",
    "actor": sender_url,
    "object": recipient_url
}

r = requests.post(recipient_inbox, headers=headers, json=follow_request_message)
```


## Standards
* [ActivityPub](https://www.w3.org/TR/activitypub/)
* [ActivityStreams 2.0](https://www.w3.org/TR/activitystreams-core/)
    * [JSON-LD](https://www.w3.org/TR/json-ld/)
* [HTTP signatures (draft 12)](https://tools.ietf.org/id/draft-cavage-http-signatures-12.html)
* [Linked Data Proofs](https://w3c-ccg.github.io/ld-proofs/) (previously Linked Data Signatures)
* [Webfinger](https://tools.ietf.org/html/rfc7033)


## Resources
* [How to implement a basic ActivityPub server](https://blog.joinmastodon.org/2018/06/how-to-implement-a-basic-activitypub-server/)
* [How to make friends and verify requests](https://blog.joinmastodon.org/2018/07/how-to-make-friends-and-verify-requests/)
