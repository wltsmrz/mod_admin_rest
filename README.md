#mod_admin_rest

A RESTful admin interface to [Prosody](http://prosody.im/) XMPP server.

###Why

There are a few ways to administer Prosody; by using either the `mod_admin_telnet`, `mod_admin_adhoc`, or via `prosodyctl`. Each has an independent purpose but there is considerable functional overlap. `mod_admin_rest` seeks to enable a more programmatic interface to Prosody commands that exist in the stock admin modules, and some commands that don't.

###Note

Compatible with `v0.9`. Not tested and likely incompatible with previous versions.

###Installation

1. Place `mod_admin_rest.lua` in your `plugins` directory.
2. Add `admin_rest` to `modules_enabled` list of your `prosody.cfg.lua`
3. Start or restart Prosody

Your admin_rest HTTP server is now listening on Prosody's HTTP service port (Default `5280`)

##Issuing commands

All requests must contain Basic authentication for a user who has administrative privileges. Requests must contain `Content-Type` and `Content-Length` headers. Additionally, some `admin_rest` commands may require request bodies. Request paths have the following general structure:

> /admin_rest/`route`/`hostname`/`resource`/`attribute`

Responses are JSON-encoded objects and have the form:

> ```{ success: boolean, message: { ... } }``

`mod_admin_rest` makes appropriate use of HTTP status codes and request methods.

##Commands

A handful of useful commands are supported. More will come in the future.

###get user

If the user does not exist, response status code is `404`. Otherwise `200`. If a user is offline, response will contain user session data and roster. Otherwise the user's roster alone will be sent, along with `offline=true`.

> **GET** /admin_rest/user/`hostname`/`username`

```
{
  user: {
    sessions: { ... },
    roster: { ... }
  }
}
```

###get connected users

If command complete successfully, an array of user objects is returned, with status code `2001`. If no users are connected, an empty object is returned.

> **GET** /admin_rest/users/`hostname`/

```
{
  users: {
    [ { hostname, username, resource }, ... ]
  }
}
```

###add user

Add a user. If the user exists, response status code is `409`. If a user is successfully created, `201`.

> **POST** /admin_rest/user/`hostname`/`username`

Include `password` in the request body

```
{
  password: "mypassword"
}
```

###remove user

Removes a user. If the user does not exist, response status code is `404`. If a user is successfully removed, `200`.

> **DELETE** /admin_rest/user/`hostname`/`username`

###change user attributes

The only implemented attribute for now is `password`. Ultimately roster modifications may be implemented. Supply values for attributes in the request body as encoded JSON:

> **PATCH** /admin_rest/user/`hostname`/`username`/`attribute`

```
{
  attribute: value
}
```

Example: For changing a user's password. Assuming user's name is `testuser` and using host `localhost`:

> **PATCH** /admin_rest/user/localhost/testuser/password

With request body:

```
{
 password: "mypassword" 
}
```

If a user was updated successfully, response status code is `200`. If a user does not exist, response status code is `404`.

###send message

Send a message to a particular user on a particular host. Broadcasts are not yet supported. Messages are sent from the hostname. Include the content of your message in a JSON-encoded request body.

> **POST** /admin_rest/message/`hostname`/`username`

```
{
  message: "My message"
}
```

If message was sent successfully, response status code is `200`. If message was sent to offline queue (to be re-sent when the user becomes online), response status code is `201`. If the message cannot be delivered, response status code is `501`.

##Options

Add any of the following options to your `prosody.cfg.lua`.  You may forward additional HTTP options to Prosody's `http` module.

* `admin_rest_secure` **boolean** [false]

Whether incoming connections must be secure.

* `admin_rest_base` **string** [/admin_rest]

Base path. Default paths begin with `/admin_rest`.

* `admin_rest_whitelist` **array** [nil]

List of IP addresses to whitelist. Only these IP addresses will be allowed to issue commands over HTTP. If you modify the whitelist while Prosody is running, you will need to reload `admin_rest` module. One way you can do this is by connecting to `admin_telnet` service which runs by default on port `5582`. Then issue the command:

```
module:reload("admin_rest", <host>)
```

##TODO

* Proper module logging
* More commands. Roster management perhaps, broadcast announcement
