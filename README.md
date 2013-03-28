#mod_admin_rest

A RESTful admin interface to [Prosody](http://prosody.im/) XMPP server.

###Why

There are a few ways to administer Prosody; by using either the `mod_admin_telnet`, `mod_admin_adhoc`, or via `prosodyctl`. mod_admin_rest seeks to enable a more programmatic interface to Prosody commands that exist in the stock admin modules, and some commands that don't.

###Note

Compatible with `v0.9`. Not tested and likely incompatible with previous versions.

###Installation

1. Place `mod_admin_rest.lua` in your `plugins` directory.
2. Add `admin_rest` to `modules_enabled` list of your `prosody.cfg.lua`
3. Start or restart Prosody

##Issuing commands

This module depends on Prosody's `http` module, so it inherits the `http` module's configuration. By default, http server listens on port `5280`. All requests must contain Basic authentication for a user who has administrative privileges. Requests must contain `Content-Type` and `Content-Length` headers. Additionally, some `admin_rest` commands may require request bodies. `mod_admin_rest` attempts to make appropriate use of HTTP status codes and request methods. Request paths have the following general structure:

> /admin_rest/`operation`/`resource`/`attribute`

Responses are JSON-encoded objects with a `result` property. They have the form:

> `{ result: { ... } }`

##Commands

A handful of useful commands are supported. More will come in the future.

---------------------------------------

###get user

If the user does not exist, response status code is `404`. Otherwise `200`. If a user is offline, response will contain user session data and roster. Otherwise the user's roster alone will be sent, along with `offline=true`.

> **GET** /admin_rest/user/`username`

```
{
  user: {
    sessions: { ... },
    roster: { ... }
  }
}
```

---------------------------------------

###get connected users

If command complete successfully, an array of user objects is returned, with status code `2001`. If no users are connected, an empty object is returned.

> **GET** /admin_rest/users

```
{
  count: count,
  users: {
    [ { hostname, username, resource }, ... ]
  }
}
```

---------------------------------------

###add user

Add a user. If the user exists, response status code is `409`. If a user is successfully created, `201`.

> **POST** /admin_rest/user/`username`

Include `password` in the request body

```
{
  password: "mypassword"
}
```

---------------------------------------

###remove user

Removes a user. If the user does not exist, response status code is `404`. If a user is successfully removed, `200`.

> **DELETE** /admin_rest/user/`username`

---------------------------------------

###change user attributes

The only implemented attribute for now is `password`. Ultimately roster modifications may be implemented. Supply values for attributes in the request body as encoded JSON:

> **PATCH** /admin_rest/user/`username`/`attribute`

```
{
  attribute: value
}
```

Example: For changing a user's password. Assuming user's name is `testuser`

> **PATCH** /admin_rest/user/testuser/password

With request body:

```
{
 password: "mypassword" 
}
```

If a user was updated successfully, response status code is `200`. If a user does not exist, response status code is `404`.

---------------------------------------

###send message

Send a message to a particular user on a particular host. Messages are sent from the hostname. Include the content of your message in a JSON-encoded request body.

> **POST** /admin_rest/message/`username`

```
//request body
{
  message: "My message"
}
```

If message was sent successfully, response status code is `200`. If message was sent to offline queue (to be re-sent when the user becomes online), response status code is `201`. If the message cannot be delivered, response status code is `501`.

---------------------------------------

###broadcast message

Send a message to every connected user using a particular host. Messages are sent from the hostname. Include the content of your message in a JSON-encoded request body. 

> **POST** /admin_rest/broadcast

```
//request body
{
  message: "My message"
}
```

Successful response has status code `200`. In the response body is a count of the number of users who were sent the message. Example response:

```
//response body
{
  count: 100
}
```

---------------------------------------

###get module

Returns the name and loaded state of provided module. Successful response status code is `200`.

> **GET** /admin_rest/module/`modulename`

```
//Response body
{
  module: "mymodule",
  loaded: true
}
```

---------------------------------------

###list modules

List loaded modules for a particular host. Successful response status code is `200`.

> **GET** /admin_rest/modules

Sample response:

```
{
  count: 5,
  modules: [
    "ping",
    "dialback",
    "presence",
    "s2s",
    "message"
  ]
}
```

---------------------------------------

###load module

Load or reload a module. Successful response status code is `200`.

> **PUT** /admin_rest/module/`modulename`

---------------------------------------

###unload module

Unload a module. Successful response status code is `200`. If a module is not loaded, `404`.

> **DELETE** /admin_rest/module/`modulename`

---------------------------------------

###get whitelist

Returns array of whitelisted as per `admin_rest_whitelist` [configuration](https://github.com/Weltschmerz/mod_admin_rest#options). Returns an empty object if no whitelist configuration exists.

> **GET** /admin_rest/whitelist

```
//response body
{
  whitelist: [ "127.0.0.1", ... ],
  count: 1
}
```

---------------------------------------

###add to whitelist

Add a provided IP to whitelist.

> **PUT** /admin_rest/whitelist/`ip`

---------------------------------------

###remove from whitelist

Remove a provided IP from whitelist.

> **DELETE** /admin_rest/whitelist/`ip`

---------------------------------------

##Options

Add any of the following options to your `prosody.cfg.lua`.  You may forward additional HTTP options to Prosody's `http` module.

* `admin_rest_secure` **boolean** [false]

Whether incoming connections must be secure.

* `admin_rest_base` **string** [/admin_rest]

Base path. Default paths begin with `/admin_rest`.

* `admin_rest_whitelist` **array** [nil]

List of IP addresses to whitelist. Only these IP addresses will be allowed to issue commands over HTTP. If you modify the whitelist while Prosody is running, you will need to reload `admin_rest` module. One way you can do this is by connecting to `admin_telnet` service which runs by default on port `5582`.

```
$ echo "module:reload('admin_rest', <host>)" | nc localhost 5582
```

Alternatively, you may use `admin_rest` to reload itself by issuing a [load](https://github.com/Weltschmerz/mod_admin_rest#load-module) request to itself. Example:

> **PUT** /admin_rest/module/admin_rest

Better still, you may use `admin_rest` itself to [add](https://github.com/Weltschmerz/mod_admin_rest#add-to-whitelist) or [remove](https://github.com/Weltschmerz/mod_admin_rest#remove-from-whitelist) IPs from whitelist while in operation.

##TODO
