# ssssh

ssssh.py is a simple script to login to a remote server using SSHv2 after obtaining the required credentials (password) from StoredSafe.

- User do not have to copy and paste password from StoredSafe
- Every retrieval of logon credentials will be recorded in the StoredSafe audit log

The script is written in Python v3 and has been tested on macOS Catalina (10.15.5) and on Linux (any fairly recent version of Ubuntu or Red Hat should work fine).

Support for previous versions of StoredSafe (pre v2.1.0) can be found in the legacy branch.

ssssh.py uses Paramiko (A Python implementation of SSHv2) for all of it's SSH needs. Mad shouts to the Paramiko team for their excellent code.

## Installation instructions

This script requires Python v3 and some libraries.

It has been developed and tested using Python v3.7.7, on macOS Catalina 10.15.5.

Most of the required libraries are installed by default, but requests and paramiko might require manual installation.

```bash
sudo pip install -r requirements.txt
```

or

**requests:**

```bash
sudo -H pip install requests
```

**paramiko:**

```bash
sudo -H pip install paramiko
```

## Syntax

```bash
# ssssh.py --help
Usage: ssssh.py [-vdsuat] user@host.domain.cc[:port]
 --verbose (or -v)              (Boolean) Enable verbose output.
 --debug (or -d)                (Boolean) Enable debug output.
 --rc <rc file>                 Use this file to obtain a valid token and a server address.
 --storedsafe (or -s) <Server>  Use this StoredSafe server.
 --user (or -u) <user>          Authenticate as this user to the StoredSafe server.
 --apikey (or -a) <API Key>     Use this unique API key when communicating with the StoredSafe server.
 --token (or -t) <Auth Token>   Use pre-authenticated token instead of --user and --apikey.

Obtain password for the user from StoredSafe and connect on port 1234:
$ ssssh.py user@server.domain.cc:1234
```

```bash
--verbose
```

> Add verbose output.

```bash
--debug
```

> Add debug output.

```bash
--rc <RC file>
```

> Obtain credentials (token) and server information from this file. (Enabled by default to ```~/.storedsafe-client.rc```)

```bash
--storedsafe|-s <server>
```

> Upload certificates to this StoredSafe server.

```bash
--user|-u <user>
```

> Authenticate as this StoredSafe user.

```bash
--apikey|-a <apikey>
```

> Use this unique API key when communicating with StoredSafe. (Unique per application and installation)

```bash
--token <token>
```

> Use pre-authenticated token instead of ```--user``` and ```--apikey```, also removes requirement to login with passphrase and OTP.

```bash
user@host.domain.cc[:port]
```

> Login as user on host.domain.cc. Specify port number for SSH, unless it's 22.

## Usage

ssssh.py utilizes StoredSafe's REST API to lookup credentials and will require either that pre-authentication has been performed by the StoredSafe token handler CLI module ([storedsafe-tokenhandler.py](https://github.com/storedsafe/tokenhandler)) and stored in an init file which location can be specified with the ```--rc``` option. (By default ~/.storedsafe-client.rc)

Other authentication options includes specifying a valid token (```--token```) or perform an on-line, one-shot authentication (```--user```, ```--storedsafe``` and ```--apikey```)

Using pre-authenticated REST API to the StoredSafe appliance, the user *sven* obtains the password for the user *andreas* (credentials which sven has been granted access to by an appropriate information owner in StoredSafe) and *sven* can silently use these credentials to login via SSHv2 to the host domain.cc.

```bash
[sven@client ~]$ ssssh.py --verbose andreas@domain.cc
Found credentials for "andreas@domain.cc" (Object-ID 744 in Vault-ID 182)
Connecting to "domain.cc" on port 22
Last login: Sun Oct 15 19:55:20 2017 from clients.domain.cc
[andreas@domain.cc ~]$
```

It's also possible to authenticate in one-shot mode to StoredSafe to obtain the required credentials to log on to the remote server. Below, the StoredSafe user *sven* will use his StoredSafe account to obtain the password for the user *andreas@domain.cc* which will be used to open up an SSH connection to *domain.cc* and logon as the user *andreas* using the password obtained from StoredSafe.

```bash
[sven@client ~]$ ssssh.py -v --storedsafe safe.stored.safe --user sven --apikey myAPIKey andreas@10.44.44.203
Enter sven's passphrase:
Press sven's Yubikey:
Found credentials for "andreas@domain.cc" (Object-ID 744 in Vault-ID 182)
Connecting to "domain.cc" on port 22
Last login: Sun Oct 15 20:18:19 2017 from clients.domain.cc
[andreas@domain.cc ~]$
```

## Limitations / Known issues

- ssssh.py can only handle tunneled passwords.
- If multiple identical credentials are available in StoredSafe, ssssh.py will use the last one found.

## License

GPL
