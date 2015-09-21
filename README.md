# Golang PhotoBackup server

Browsing through F-Droid one day, I came across
[PhotoBackup](https://photobackup.github.io/) - ever since I stopped using
[Owncloud](https://www.owncloud.org), the lack of automatic photo uploads from
my phone to my server has been bugging me, so I installed the client and started
looking at the server. The concept is reasonable, the API is simple, but the
implementations are a bit terrifying, so here's my attempt.

It's written in Go to avoid runtime dependencies; some glaring errors in the
Python implementation have been corrected. To build from source (assuming
you already have a Go runtime):

		$ go get github.com/lupine/photobackup-server-go
		$ cd $GOPATH/src/github.com/lupine/photobackup-server-go
		$ go build
		$ cp config.example ~/.photobackup
		$ vi ~/.photobackup # Add a Password= or PasswordBcrypt= line
		$ ./photobackup-server-go

There's now a HTTP server running on 127.0.0.1:8420 that will upload to 
./incoming with the given password. 

If there's demand, I'll put up some precompiled blobs. I wouldn't generally
recommend *using* precompiled blobs you find on the Internet, though.

Generating bcrypt hashes to stick into PasswordBcrypt is a bit of a pain, so
here's a oneliner to do it in Ruby:

	
## Deployment strategy

I'd say stick it under runit or systemd, bound to
localhost, behind a HTTPS reverse proxy (nginx, say). For bonus points, run it
as an unprivileged user in a jail. This is made much easier by the lack of
runtime dependencies, of course.

Here's an nginx reverse proxy directive:

		location /photobackup {
		    proxy_pass http://127.0.0.1:8420;
		}

Here's a systemd unit file:

		[Unit]
		Description=HTTP server for PhotoBackup
		After=network.target

		[Service]
		ExecStart=/home/lupine/bin/photobackup-server-go
		User=lupine
		WorkingDirectory=/home/lupine
		Restart=always


## Features

### Improvements on photobackup-python
* Stores the secret on disc in a different format to on the wire (bcrypt(sha512(secret))
* Constant-time comparison of the secret, to avoid timing attacks
* Doesn't have to bind to the IPv4 wildcard
* Supports HTTP prefixes
* Uses 405 Method Not Allowed where appropriate
* Uses 409 Conflict where an upload would overwrite an existing file
* Doesn't read POST data beyond the filesize parameter


### To add
* Direct HTTPS support
* Sensible multi-user support (support for, say, POST /:username[/test])
* Config file management like the python version's "init" stuff.

