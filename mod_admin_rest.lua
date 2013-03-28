local url    = require "socket.url";
local jid    = require "util.jid";
local JSON   = require "util.json";
local stanza = require "util.stanza";
local b64    = require "util.encodings".base64;
local sp     = require "util.encodings".stringprep;

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

-- Convenience function for emitting events
local function emit(host, event, data) 
  local host = hosts[host];
  if host and host.events then
    host.events.fire_event(event, data);
  end
end

-- Generate a Response object of the form:
--
-- {
--  {number} status_code:  <HTTP status code>
--  {string} message:      <JSON response message>
-- }
--
local function Response(status_code, message)
  local response = { };
  local ok, error = pcall(function()
    message = JSON.encode({ result = message });
  end);
  if not ok or error then
    response.status_code = 500
  else
    response.status_code = status_code;
    response.message = message;
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
  sent_message    = Response(200, "Sent message");
  offline_message = Response(202, "Message sent to offline queue");
  drop_message    = Response(501, "Message dropped per configuration");
  internal_error  = Response(500, "Internal server error");
  pong            = Response(200, "pong");
};

local function respond(event, message, headers)
	local response = event.response;

  if headers then
    for header, data in pairs(headers) do 
      response.headers[header] = data;
    end
  end;

	response.headers.content_type = "application/json";
	response.status_code = message.status_code;
	response:send(message.message);
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
  local sessions = get_sessions(hostname) or { };
  local users = { };

  for username, user in pairs(sessions) do
    for resource, session in pairs(user.sessions or {}) do
      table.insert(users, { 
        username = username,
        hostname = hostname,
        resource = resource 
      });
    end
  end

  return users;
end

local function get_recipient(hostname, username)
  local jid = jid.join(username, hostname);
  local session = get_session(hostname, username);
  local offline = not session and user_exists(username, hostname);
  return jid, offline;
end

-- Return a user's roster & session data if connected.
-- If not connected, return the roster alone.
-- If the user does not exist, 404.
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

  local response = { };
  local user = { };
  local session = get_session(hostname, username);
  if session then
    user.connected = true;
    user.roster = session.roster;
    user.sessions = session.sessions;
  else
    user.connected = false;
    user.roster = rm.load_roster(username, hostname);
  end

  response.user = user;
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

  if not hostname or not username then
    return respond(event, RESPONSES.invalid_path);
  end

  if not password then
    return respond(event, RESPONSES.invalid_body);
  end

  local joined = jid.join(username, hostname);

  if um.user_exists(username, hostname) then
    return respond(event, Response(409, "User already exists: " .. joined));
  end

  if not um.create_user(username, password, hostname) then
    return respond(event, RESPONSES.internal_error);
  end

  respond(event, Response(201, "User created: " .. joined));

  emit(hostname, "user-registered", {
    username = username;
    hostname = hostname;
    source   = "mod_admin_rest";
  })

  module:log("info", "Registered user: " .. joined);
end

local function remove_user(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local username = sp.nodeprep(path.resource);

  if not hostname or not username then
    return respond(event, RESPONSES.invalid_path);
  end

  local joined = jid.join(username, hostname);

  if not um.user_exists(username, hostname) then
    return respond(event, Response(404, "User does not exist: " .. joined));
  end

  if not um.delete_user(username, hostname) then
    return respond(event, RESPONSES.internal_error);
  end

  respond(event, Response(200, "User deleted: " .. joined));

  emit(hostname, "user-deregistered", {
    username = username;
    hostname = hostname;
    source = "mod_admin_rest";
  });

  module:log("info", "Deregistered user: " .. jioned);
end

local function patch_user(event, path, body) 
  local hostname = sp.nameprep(path.hostname);
  local username = sp.nodeprep(path.resource);
  local attribute = path.attribute;

  if not (hostname and username and attribute)  then
    return respond(event, RESPONSES.invalid_path);
  end

  local joined = jid.join(username, hostname);

  if not um.user_exists(username, hostname) then
    return respond(event, Response(404, "User does not exist: " .. joined));
  end

  if attribute == "password" then
    local password = body.password;
    if not password then
      return respond(event, RESPONSES.invalid_body);
    end
    if not set_password(username, password, hostname) then
      return respond(event, RESPONSES.internal_error);
    end
  end

  respond(event, Response(200, "User updated: " .. joined));

  module:log("info", "User modified: " .. jioned);
end

local function send_message(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local username = sp.nodeprep(path.resource);
  local to, offline = get_recipient(hostname, username);

  if not to and not offline then
    return respond(event, RESPONSES.invalid_user);
  end

  local attrs = { to = to, from = hostname };
  local message = stanza.message(attrs):tag("body"):text(body.message);

  if offline then
    if not mm.get_module(hostname, "offline") then
      return respond(event, RESPONSES.drop_message);
    else
      emit(hostname, "message/offline/handle", {
        origin = { host = hostname, username = username },
        stanza = stanza.deserialize(message)
      });
      return respond(event, RESPONSES.offline_message);
    end
  end

  if not pcall(function() module:send(message); end) then
    return respond(event, RESPONSES.internal_ERROR);
  end

  respond(event, Response(200, "Sent message to user: " .. to));

  module:log("info", "Message sent to user: " .. to);
end

local function broadcast_message(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local sessions = get_sessions(hostname);
  local count = 0;

  local text = body.message or "";

  for username, user in pairs(sessions or {}) do
    local jid = jid.join(username, hostname);
    local attrs = { to = jid, from = hostname };
    local message = stanza.message(attrs):tag("body"):text(text);
    module:send(message);
    count = count + 1;
  end

  respond(event, Response(200, { count = count }));

  module:log("info", "Message broadcasted to users: " .. count);
end

function get_module(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local modulename = path.resource;

  if not modulename then
    return respond(event, RESPONSES.invalid_path);
  end

  local loaded = (mm.get_module(hostname, modulename) and true) or false;
  local result = { module = modulename, loaded = loaded };
  respond(event, Response(200, result));
end

function get_modules(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local modules = mm.get_modules(hostname);
  local list = { }
  for name, _ in pairs(modules or {}) do
    table.insert(list, name);
  end
  respond(event, Response(200, { modules = list, count = #list }));
end

function load_module(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local modulename = path.resource;
  local fn = "load";

  if mm.get_module(hostname, modulename) then fn = "reload" end

  if not mm[fn](hostname, modulename) then
    return respond(event, RESPONSES.internal_error);
  end

  respond(event, Response(200, "Loaded module: " .. modulename));

  module:log("info", "Module loaded: " .. modulename);
end

function unload_module(event, path, body)
  local hostname = sp.nameprep(path.hostname);
  local modulename = path.resource;

  if not mm.get_module(hostname, modulename) then
    return respond(event, Response(404, "Module is not loaded:" .. modulename));
  end

  mm.unload(hostname, modulename);
  respond(event, Response(200, "Module unloaded: " .. modulename));

  module:log("info", "Module unloaded: " .. modulename)
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

  respond(event, Response(200, "Added IP to whitelist: " .. ip));

  module:log("warn", "IP added to whitelist: " .. ip);
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

  respond(event, Response(200, "Removed IP '" .. ip .. "' from whitelist"));

  module:log("warn", "IP removed from whitelist: " .. ip)
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
