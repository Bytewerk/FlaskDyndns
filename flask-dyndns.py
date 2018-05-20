from functools import wraps
from flask import Flask, request, Response

import dns.query
import dns.tsigkeyring
import dns.update

import socket

from config import Config

app = Flask(__name__)

def check_auth(username, password):
    return username in Config.users and Config.users[username]["password"] == password

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="dyndns"'}
    )

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route('/nic/update')
@requires_auth
def update():
    user_config = Config.users[request.authorization.username]

    hostname = request.args.get('hostname')
    if hostname not in user_config["hostnames"]:
        raise Exception("hostname %s not defined for user %s" % (hostname, request.authorization.username))

    myip = request.args.get('myip')
    if myip is None:
        raise Exception("parameter 'myip' is required.")
    try:
        ip = socket.inet_ntoa(socket.inet_aton(myip))
    except:
        raise Exception("invalid ip '" + myip + "' in get parameter 'myip'")

    keyring = dns.tsigkeyring.from_text(Config.keyring_data)
    dnsupdate = dns.update.Update(user_config["domain"], keyring=keyring, keyname=Config.key_name, keyalgorithm=Config.key_algo)
    dnsupdate.replace(str(hostname), 10, 'A', ip)
    response = dns.query.tcp(dnsupdate, Config.nameserver)
    error = dns.rcode.from_flags(response.flags, response.ednsflags)
    if error != dns.rcode.NOERROR:
        raise Exception("dns update returned error: " + str(error))
    return "ok"


if __name__ == '__main__':
    app.debug = True
    app.run()
