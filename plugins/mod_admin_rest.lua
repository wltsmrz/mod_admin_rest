module:depends("http");

local url        = require "socket.url";
local jid        = require "util.jid";
local JSON       = require "util.json";
local stanza     = require "util.stanza";
local b64_decode = require "util.encodings".base64.decode;
local stringprep = require "util.encodings".stringprep;

local escape, unescape = url.escape, url.unescape;
local jid_join, jid_prep, jid_split = jid.join, jid.prep, jid.split;
local nodeprep, nameprep  = stringprep.nodeprep, stringprep.nameprep;

local secure    = module:get_option_boolean("admin_rest_secure", false);
local base_path = module:get_option_string("admin_rest_base", "/admin_rest");
local whitelist = module:get_option_array("admin_rest_whitelist", nil);

-- Convert whitelist into a whiteset for efficient lookup
if whitelist then
  local length = #whitelist;
  if length == 0 then
    whitelist = nil 
  else
    local whiteset = {};
    for i=1, #whitelist do whiteset[whitelist[i]] = true end
    whitelist = whiteset;
  end
end

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

-- Paths adhere to the following structure:
-- (/admin_rest/) <route> / <hostname> / <resource> / <attribute>
-- 
-- Example: to get a user's available data, assuming he or she
-- exists, has the name `testuser` and is using the host 
-- `localhost` we use:
--
-- GET /admin_rest/localhost/testuser
--
-- To modify a user's password, we send a PATCH request, and this
-- time we specify the `attribute` path:
--
-- PATCH /admin_rest/localhost/testuser/password
--
-- With the password supplied in a JSON request body under the
-- property `password`
local function parse_path(path) 
  local split = split_path(unescape(path));
  return {
    route     = split[2];
    hostname  = split[3];
    resource  = split[4];
    attribute = split[5];
  };
end

-- Parse request Authentication headers. Return username, password
local function parse_auth(auth)
  return b64_decode(auth:match("[^ ]*$") or ""):match("([^:]*):(.*)");
end

-- Convenience function for emitting events
local function emit(host, event, data) 
  local host = hosts[host];
  if not host or not host.events then return nil; end
  return host.events.fire_event(event, data);
end

-- Generate a Response object of the form:
--
-- {
--  {number} status_code:  <HTTP status code>
--  {string} message:      <JSON response message>
-- }
--
local function Response(status_code, message)
  local response = {};
  local success = status_code < 400;
  local ok, error = pcall(function()
    message = JSON.encode({ success = success, message = message });
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
  nonexist_user   = Response(404, "User does not exist");
  invalid_path    = Response(404, "Invalid request path");
  invalid_method  = Response(405, "Invalid request method");
  invalid_body    = Response(400, "Body does not exist or is malformed");
  invalid_host    = Response(404, "Host does not exist or is malformed");
  invalid_user    = Response(404, "User does not exist or is malformed");
  user_unconnect  = Response(406, "User is not connected");
  user_exists     = Response(409, "User already exists");
  user_created    = Response(201, "User created");
  user_updated    = Response(200, "User updated");
  user_deleted    = Response(200, "User deleted");
  sent_message    = Response(200, "Sent message");
  offline_message = Response(202, "Message sent to offline queue");
  drop_message    = Response(501, "Message dropped per configuration");
  internal_error  = Response(500, "Internal server error");
  pong            = Response(200, "pong");
};

-- Convenience function for responding to HTTP requests
local function respond(event, message, headers)
	local response = event.response;

  if headers then
    for header, data in pairs(headers) do 
      response.headers[header] = data;
    end
  end

	response.headers.content_type = "application/json";
	response.status_code = message.status_code;
	response:send(message.message);
end

-- Return a user's roster & session data if he or she
-- is online. Otherwise return the roster along with
-- offline=true. If the user does not exist, 404.
local function get_user(event, path, body)
  local hostname = nameprep(path.hostname);
  local username = nodeprep(path.resource);

  if not username or not hostname then
    return respond(event, RESPONSES.invalid_path);
  end

  if not usermanager.user_exists(username, hostname) then
    return respond(event, RESPONSES.nonexist_user);
  end

  local user;

  local ok, error = pcall(function()
    user = hosts[hostname].sessions[username];
  end);

  if not ok or error then
    respond(event, RESPONSES.internal_error);
  else if user then
    respond(event, Response(200, { user = user }))
  else 
    local roster = rostermanager.load_roster(username, hostname);
    if not roster then 
      respond(event, RESPONSES.internal_error);
    else
      local response = Response(200, { 
        user = { offline = true, roster = roster } 
      });
      respond(event, response);
    end
  end
end
end

local function add_user(event, path, body)
  local hostname = nameprep(path.hostname);
  local username = nodeprep(path.resource);
  local password = body["password"];

  if not hostname or not username then
    return respond(event, RESPONSES.invalid_path);
  end

  if not password then
    return respond(event, RESPONSES.invalid_body);
  end

  if usermanager.user_exists(username, hostname) then
    return respond(event, RESPONSES.user_exists);
  end

  if not usermanager.create_user(username, password, hostname) then
    return respond(event, RESPONSES.internal_error);
  end

  respond(event, RESPONSES.user_created);

  emit(hostname, "user-registered", {
    username = username;
    hostname = hostname;
    source   = "mod_admin_rest";
  })
end

local function remove_user(event, path, body)
  local hostname = nameprep(path.hostname);
  local username = nodeprep(path.resource);

  local valid_body = hostname and username;

  if not valid_body then
    return respond(event, RESPONSES.invalid_path);
  end

  if not username or not usermanager.user_exists(username, hostname) then
    return respond(event, RESPONSES.invalid_username);
  end

  if not usermanager.delete_user(username, hostname) then
    respond(event, RESPONSES.internal_error);
  else
    respond(event, RESPONSES.user_deleted);
  end

  emit(hostname, "user-deregistered", {
    username = username;
    hostname = hostname;
    source = "mod_admin_rest";
  });
end

local function patch_user(event, path, body) 
  local hostname = nameprep(path.hostname);
  local username = nodeprep(path.resource);
  local attribute = path.attribute;

  if not hostname or not username or not attribute then
    return respond(event, RESPONSES.invalid_path);
  end

  if not username or not usermanager.user_exists(username, hostname) then
    return respond(event, RESPONSES.invalid_username);
  end

  if attribute == "password" then
    local password = body.password;
    if not password then
      return respond(event, RESPONSES.invalid_body);
    end
    if not usermanager.set_password(username, password, hostname) then
      return respond(event, RESPONSES.internal_error);
    end
  end

  respond(event, RESPONSES.user_updated);
end

local function ping(event, path, body)
  return respond(event, RESPONSES.pong);
end

local function get_jid(hostname, username)
  if not usermanager.user_exists(username, hostname) then 
    return nil; 
  end

  local session = nil;
  local ok, error = pcall(function()
    session = hosts[hostname].sessions[username];
  end);

  if not ok or error then return nil; end

  -- User is offline
  if not session then return nil, true; end

  -- User is online, grab a session
  for resource, _ in pairs(session.sessions) do 
    return jid_join(username, hostname, resource), false;
  end
end

local function send_message(event, path, body)
  local hostname = nameprep(path.hostname);
  local username = nodeprep(path.resource);
  local to, offline = get_jid(hostname, username);

  if not to and not offline then
    return respond(event, RESPONSES.invalid_user);
  end

  local attrs = { to = to or jid_join(username, hostname), from = hostname };
  local message = stanza.message(attrs):tag("body"):text(body.message or "");

  if offline then
    if not modulemanager.get_module(hostname, "offline") then
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

  respond(event, RESPONSES.sent_message);
end

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
  message = {
    POST = send_message;
  };
};

local RESERVED = { 
  ping = true;
};

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

  username = jid_prep(username);

  -- Validate authentication details
  if not username or not password then 
    return respond(event, RESPONSES.invalid_auth);
  end

  local user_node, user_host = jid_split(username);

  -- Validate host
  if not hosts[user_host] then 
    return respond(event, RESPONSES.invalid_host);
  end

  -- Authenticate user
  if not usermanager.test_password(user_node, user_host, password) then
    return respond(event, RESPONSES.auth_failure);
  end

  -- ********** Route ********** --

  local path = parse_path(request.path);
  local route, hostname = path.route, path.hostname;

  -- Restrict to admin
  if not usermanager.is_admin(username, hostname) then
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

  local body = {};

  -- Parse JSON request body
  if request.body then
    if not pcall(function() body = JSON.decode(request.body) end) then
      return respond(event, RESPONSES.decode_failure);
    end
  end

  return handler(event, path, body);
end

module:provides("http", {
  name = base_path:gsub("^/", "");
  route = {
    ["GET /*"]    = handle_request;
    ["POST /*"]   = handle_request;
    ["DELETE /*"] = handle_request;
    ["PATCH /*"]  = handle_request;
  };
})
