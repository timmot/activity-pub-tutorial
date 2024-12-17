# ActivityPub Example

Here is a less wordy example which will let you see some results immediately.

1. Set up a server using Let's Encrypt to get your HTTPS certificates.
2. Turn off any web servers you may have used, e.g. nginx/apache/caddy
3. Generate a public/private key pair for your user
    ```sh
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -outform PEM -pubout -out public.pem
    ```
4. Set up Python environment
    ```sh
    python3 -m venv env
    source env/bin/activate
    pip install -r requirements.txt
    ```
5. Enter your own details in config.py
6. Run the server in one shell `python server.py`
    a. This may need to run as root as it binds port 443
    b. Confirm by searching your user on Mastodon, e.g. `@user@host.com` and note what response you receive
7. Run `python follow_user.py` and `python follow_user.py --unfollow`
    a. The server must be running for Mastodon to send an accept message.
