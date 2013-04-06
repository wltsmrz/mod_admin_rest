local url    = require "socket.url";
local jid    = require "util.jid";
local stanza = require "util.stanza";
local b64    = require "util.encodings".base64;
local sp     = require "util.encodings".stringprep;

local JSON = { };

-- Use lua-cjson if it is available
local ok, error = pcall(function() JSON = require "cjson.safe" end);

-- Fall back to util.json
if not ok or error then JSON = require "util.json" end

local um = usermanager;
local rm = rostermanager;
local mm = modulemanager;
local hm = hostmanager;

local secure    = module:get_option_boolean("admin_rest_secure", false);
local base_path = module:get_option_string("admin_rest_base", "/admin_rest");
local whitelist = module:get_option_array("admin_rest_whitelist", nil);

local function to_set(list)
  local l = #list;
  if l == 0 then return nil end
  local set = { };
  for i=1, l do set[list[i]] = true end
  return set;
end

-- Convert whitelist into a whiteset for efficient lookup
if whitelist then whitelist = to_set(whitelist) end

local function split_path(path)
  local result = {}; 
  local pattern = "(.-)/";
  local last_end = 1;
  local s, e, cap = path:find(pattern, 1); 

  while s do
    if s ~= 1 or cap ~= "" then
      table.insert(result, cap);
    end 
    last_end = e + 1;
    s, e, cap = path:find(pattern, last_end);
  end 

  if last_end <= #path then
    cap = path:sub(last_end);
    table.insert(result, cap);
  end 

  return result;
end

local function parse_path(hostname, path) 
  local split = split_path(url.unescape(path));
  return {
    hostname  = hostname;
    route     = split[2];
    resource  = split[3];
    attribute = split[4];
  };
end

-- Parse request Authentication headers. Return username, password
local function parse_auth(auth)
  return b64.decode(auth:match("[^ ]*$") or ""):match("([^:]*):(.*)");
end

local function Response(status_code, message, array)
  local response = { };

  local ok, error = pcall(function()
    message = JSON.encode({ result = message });
  end);

  if not ok or error then
    response.status_code = 500
    response.body = "Failed to encode JSON response";
  else
    response.status_code = status_code;
    response.body = message;
  end

  return response;
end

-- Build static responses
local RESPONSES = {
  missing_auth    = Response(400, "Missing authorization header");
  invalid_auth    = Response(400, "Invalid authentication details");
  auth_failure    = Response(401, "Authentication failure");
  unauthorized    = Response(401, "User must be an administrator");
  decode_failure  = Response(400, "Request body is not valid JSON");
  invalid_path    = Response(404, "Invalid request path");
  invalid_method  = Response(405, "Invalid request method");
  invalid_body    = Response(400, "Body does not exist or is malformed");
  invalid_host    = Response(404, "Host does not exist or is malformed");
  invalid_user    = Response(404, "User does not exist or is malformed");
  offline_message = Response(202, "Message sent to offline queue");
  drop_message    = Response(501, "Message dropped per configuration");
  internal_error  = Response(500, "Internal server error");
  pong            = Response(200, "PONG");
};

local function respond(event, res, headers)
	local response = event.response;

  if headers then
    for header, data in pairs(headers) do 
      response.headers[header] = data;
    end
  end

  response.headers.content_type = "application/json";
  response.status_code = res.status_code;
  response:send(res.body);
end

local function get_host(hostname)
  return hosts[hostname];
end

local function get_sessions(hostname)
  local host = get_host(hostname);
  return host and host.sessions;
end

local function get_session(hostname, username)
  local sessions = get_sessions(hostname);
  return sessions and sessions[username];
end

local function get_connected_users(hostname) 
  local sessions = get_sessions(hostname);
  local users = { };

  for username, user in pairs(sessions or {}) do
    for resource, session in pairs(user.sessions or {}) do
      table.insert(users, { 
        username = username,
        resource = resource 
      });
    end
  end

  return users;
end

local function get_recipient(hostname, username)
  local session = get_session(hostname, username)
  local offline = not session and um.user_exists(username, hostname);
  return session, offline;
end

local function get_user_connected(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local username = sp.nodeprep(path.resource);

  if not hostname or not username then
    return respond(event, RESPONSES.invalid_path);
  end

  local jid = jid.join(username, hostname);
  local connected = get_session(hostname, username);
  local response;

  if connected then
    response = Response(200, "User is connected: " .. jid);
  else
    response = Response(404, "User is not connected: " .. jid);
  end

  respond(event, response);
end

local function normalize_user(user)
  local cleaned = { };
  cleaned.connected = user.connected or false;
  cleaned.sessions  = { };
  cleaned.roster    = { };

  for resource, session in pairs(user.sessions or {}) do
    local c_session = { 
      resource = resource;
      id       = session.conn.id;
      ip       = session.conn._ip;
      port     = session.conn._port;
      secure   = session.secure;
    }
    table.insert(cleaned.sessions, c_session);
  end

  if user.roster and #user.roster > 0 then
    cleaned.roster = user.roster;
  end

  return cleaned;
end

local function get_user(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local username = sp.nodeprep(path.resource);

  if not hostname or not username then
    return respond(event, RESPONSES.invalid_path);
  end

  if not um.user_exists(username, hostname) then
    local joined = jid.join(username, hostname)
    return respond(event, Response(404, "User does not exist: " .. joined));
  end

  local user = { hostname = hostname, username = username };
  local session = get_session(hostname, username);

  if session then
    user.connected = true;
    user.roster = session.roster;
    user.sessions = session.sessions;
  else
    user.roster = rm.load_roster(username, hostname);
  end

  local response = { user = normalize_user(user) };
  respond(event, Response(200, response));
end

local function get_users(event, path, body)
  local hostname = sp.nameprep(path.hostname);

  if not hostname then
    return respond(event, RESPONSES.invalid_path);
  end

  local users = get_connected_users(hostname);

  respond(event, Response(200, { users = users, count = #users }));
end

local function add_user(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local username = sp.nodeprep(path.resource);
  local password = body["password"];

  if not username then
    return respond(event, RESPONSES.invalid_path);
  end

  if not password then
    return respond(event, RESPONSES.invalid_body);
  end

  local jid = jid.join(username, hostname);

  if um.user_exists(username, hostname) then
    return respond(event, Response(409, "User already exists: " .. jid));
  end

  if not um.create_user(username, password, hostname) then
    return respond(event, RESPONSES.internal_error);
  end

  local result = "User registered: " .. jid;

  respond(event, Response(201, result));

  module:fire_event("user-registered", {
    username = username;
    hostname = hostname;
    source   = "mod_admin_rest";
  })

  module:log("info", result);
end

local function remove_user(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local username = sp.nodeprep(path.resource);

  if not hostname or not username then
    return respond(event, RESPONSES.invalid_path);
  end

  local jid = jid.join(username, hostname);

  if not um.user_exists(username, hostname) then
    return respond(event, Response(404, "User does not exist: " .. jid));
  end

  if not um.delete_user(username, hostname) then
    return respond(event, RESPONSES.internal_error);
  end

  respond(event, Response(200, "User deleted: " .. jid));

  module:fire_event("user-deleted", {
    username = username;
    hostname = hostname;
    source = "mod_admin_rest";
  });

  module:log("info", "Deregistered user: " .. jid);
end

local function patch_user(event, path, body) 
  local hostname = sp.nameprep(path.hostname);
  local username = sp.nodeprep(path.resource);
  local attribute = path.attribute;

  if not (hostname and username and attribute)  then
    return respond(event, RESPONSES.invalid_path);
  end

  local jid = jid.join(username, hostname);

  if not um.user_exists(username, hostname) then
    return respond(event, Response(404, "User does not exist: " .. jid));
  end

  if attribute == "password" then
    local password = body.password;
    if not password then
      return respond(event, RESPONSES.invalid_body);
    end
    if not um.set_password(username, password, hostname) then
      return respond(event, RESPONSES.internal_error);
    end
  end

  local result = "User modified: " .. jid;

  respond(event, Response(200, result));

  module:log("info", result);
end

local function offline_enabled()
  local host = module:get_host();
  return mm.is_loaded(host, "offline")
  or mm.is_loaded(host, "offline_authed")
  or false;
end

local function send_multicast(event, path, body, hostname)
  local recipients = body.recipients;
  local sent = 0;
  local delayed = 0;

  for i=1, #recipients do
    repeat
      local recipient = recipients[i];
      local msg = recipient.message;
      local node = recipient.to;

      if not node or not msg then break end

      local session, offline = get_recipient(hostname, node);

      if not session and not offline then break end

      local attrs = { from = hostname, to = jid.join(node, hostname) };

      local message = stanza.message(attrs, msg);

      if offline and offline_enabled() then
        module:fire_event("message/offline/handle", {
          stanza = stanza.deserialize(message);
        });
        delayed = delayed + 1;
      elseif session then
        for _, session in pairs(session.sessions or {}) do
          session.send(message);
        end
        sent = sent + 1;
      end

    until true
  end

  local result;

  if sent > 0 then
    result = "Message multicasted to users: " .. sent .. "/" .. delayed;
    respond(event, Response(200, result));
  else
    result = "No multicast recipients";
    respond(event, Response(404, result));
  end

  module:log("info", result);
end

local function send_message(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local username = sp.nodeprep(path.resource);

  if not username and body.recipients then
    return send_multicast(event, path, body, hostname);
  end

  local session, offline = get_recipient(hostname, username);

  if not session and not offline then
    return respond(event, RESPONSES.invalid_user);
  end

  local jid = jid.join(username, hostname);
  local message = stanza.message({ to = jid, from = hostname}, body.message);

  if offline then
    if not offline_enabled() then
      respond(event, RESPONSES.drop_message);
      return
    else
      respond(event, RESPONSES.offline_message);
      module:fire_event("message/offline/handle", {
        stanza = stanza.deserialize(message)
      });
      return
    end
  end

  for resource, session in pairs(session.sessions or {}) do
    session.send(message)
  end

  local result = "Message sent to user: " .. jid;

  respond(event, Response(200, result));

  module:log("info", result);
end

local function broadcast_message(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local attrs = { from = hostname };
  local count = 0;

  for username, session in pairs(get_sessions(hostname) or {}) do
    attrs.to = jid.join(username, hostname);
    local message = stanza.message(attrs, body.message);
    for _, session in pairs(session.sessions or {}) do
      session.send(message);
    end
    count = count + 1;
  end

  respond(event, Response(200, { count = count }));

  if count > 0 then
    module:log("info", "Message broadcasted to users: " .. count);
  end
end

function get_module(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local modulename = path.resource;

  if not modulename then
    return respond(event, RESPONSES.invalid_path);
  end

  local result = { module = modulename };
  local status;

  if not mm.is_loaded(hostname, modulename) then
    result.loaded = false;
    status = 404;
  else
    result.loaded = true;
    status = 200;
  end

  respond(event, Response(status, result))
end

function get_modules(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local list = { }
  for name in pairs(mm.get_modules(hostname) or {}) do
    table.insert(list, name);
  end
  respond(event, Response(200, { modules = list, count = #list }));
end

function load_module(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local modulename = path.resource;
  local fn = "load";

  if mm.is_loaded(hostname, modulename) then fn = "reload" end

  if not mm[fn](hostname, modulename) then
    return respond(event, RESPONSES.internal_error);
  end

  local result = "Module loaded: " .. modulename;

  respond(event, Response(200, result));

  module:log("info", result);
end

function unload_module(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local modulename = path.resource;

  if not mm.is_loaded(hostname, modulename) then
    return respond(event, Response(404, "Module is not loaded:" .. modulename));
  end

  mm.unload(hostname, modulename);

  local result = "Module unloaded: " .. modulname;

  respond(event, Response(200, result));

  module:log("info", result);
end

local function get_whitelist(event, path, body)
  local list = { };

  if whitelist then
    for ip, _ in pairs(whitelist) do
      table.insert(list, ip);
    end
  end

  respond(event, Response(200, { whitelist = list, count = #list }));
end

local function add_whitelisted(event, path, body)
  local ip = path.resource;
  if not whitelist then whitelist = { } end

  whitelist[ip] = true;

  local result = "IP added to whitelist: " .. ip;

  respond(event, Response(200, result));

  module:log("warn", result);
end

local function remove_whitelisted(event, path, body)
  local ip = path.resource;

  if not whitelist or not whitelist[ip] then
    return respond(event, Response(404, "IP is not whitelisted: " .. ip));
  end

  local new_list = { };
  for whitelisted, _ in pairs(whitelist) do
    if whitelisted ~= ip then
      new_list[whitelisted] = true;
    end
  end
  whitelist = new_list;

  local result = "IP removed from whtielist: " .. ip;

  respond(event, Response(200, result));

  module:log("warn", result);
end

local function ping(event, path, body)
  return respond(event, RESPONSES.pong);
end

--Routes and suitable request methods
local ROUTES = {
  ping = {
    GET = ping;
  };

  user = {
    GET    = get_user;
    POST   = add_user;
    DELETE = remove_user;
    PATCH  = patch_user;
  };

  user_connected = {
    GET = get_user_connected;
  };

  users = {
    GET = get_users;
  };

  message = {
    POST = send_message;
  };

  broadcast = {
    POST = broadcast_message;
  };

  modules = {
    GET = get_modules;
  };

  module = {
    GET    = get_module;
    PUT    = load_module;
    DELETE = unload_module;
  };

  whitelist = {
    GET    = get_whitelist;
    PUT    = add_whitelisted;
    DELETE = remove_whitelisted;
  }
};

--Reserved top-level request routes
local RESERVED = to_set({ "admin" });

--Entry point for incoming requests. 
--Authenticate admin and route request.
local function handle_request(event)
  local request = event.request;

  -- Check whitelist for IP
  if whitelist and not whitelist[request.conn._ip] then 
    return respond(event, { status_code = 401, message = nil });
  end

  -- ********** Authenticate ********** --

  -- Prevent insecure requests
  if secure and not request.secure then return end

  -- Request must have authorization header
  if not request.headers["authorization"] then
    return respond(event, RESPONSES.missing_auth);
  end

  local auth = request.headers.authorization;
  local username, password = parse_auth(auth);

  username = jid.prep(username);

  -- Validate authentication details
  if not username or not password then 
    return respond(event, RESPONSES.invalid_auth);
  end

  local user_node, user_host = jid.split(username);

  -- Validate host
  if not hosts[user_host] then 
    return respond(event, RESPONSES.invalid_host);
  end

  -- Authenticate user
  if not um.test_password(user_node, user_host, password) then
    return respond(event, RESPONSES.auth_failure);
  end

  -- ********** Route ********** --

  local path = parse_path(user_host, request.path);
  local route, hostname = path.route, path.hostname;

  -- Restrict to admin
  if not um.is_admin(username, hostname) then
    return respond(event, RESPONSES.unauthorized);
  end

  local handlers = ROUTES[route];

  -- Confirm that route exists
  if not route or not handlers then
    return respond(event, RESPONSES.invalid_path);
  end

  -- Confirm that the host exists
  if not RESERVED[route] then
    if not hostname or not hosts[hostname] then
      return respond(event, RESPONSES.invalid_host);
    end
  end

  local handler = handlers[request.method];

  -- Confirm that handler exists for method
  if not handler then
    return respond(event, RESPONSES.invalid_method);
  end

  local body = { };

  -- Parse JSON request body
  if request.body and #request.body > 0 then
    if not pcall(function() body = JSON.decode(request.body) end) then
      return respond(event, RESPONSES.decode_failure);
    end
  end

  return handler(event, path, body);
end

module:depends("http");

module:provides("http", {
  name = base_path:gsub("^/", "");
  route = {
    ["GET /*"]    = handle_request;
    ["POST /*"]   = handle_request;
    ["PUT /*"]    = handle_request;
    ["DELETE /*"] = handle_request;
    ["PATCH /*"]  = handle_request;
  };
})
