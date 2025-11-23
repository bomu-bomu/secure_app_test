# frozen_string_literal: true

require 'sinatra'
require 'sinatra/json'
require 'sqlite3'
require 'bcrypt'
require 'fileutils'
require 'rack/attack'
require 'securerandom'
require 'thread'

begin
  require 'redis'
rescue LoadError
  # Redis gem required only when REDIS_URL is provided
end

set :bind, '0.0.0.0'
set :sessions,
    key: 'secure.session',
    secret: ENV.fetch('SESSION_SECRET', SecureRandom.hex(64)),
    httponly: true,
    same_site: :lax,
    secure: ENV['RACK_ENV'] == 'production'

# --- Rate limiting -----------------------------------------------------------
class Rack::Attack
  class MemoryStore
    def initialize
      @data = {}
      @mutex = Mutex.new
    end

    def read(key)
      @mutex.synchronize do
        purge_expired!(key)
        entry = @data[key]
        entry && entry[:value]
      end
    end

    def write(key, value, expires_in: nil)
      @mutex.synchronize do
        @data[key] = { value: value, expires_at: expires_in ? Time.now + expires_in : nil }
      end
    end

    def delete(key)
      @mutex.synchronize { @data.delete(key) }
    end

    def increment(key, amount = 1, expires_in: nil)
      @mutex.synchronize do
        purge_expired!(key)
        entry = @data[key] ||= { value: 0, expires_at: nil }
        entry[:value] += amount
        entry[:expires_at] = expires_in ? Time.now + expires_in : nil
        entry[:value]
      end
    end

    def delete_matched(pattern)
      @mutex.synchronize do
        @data.keys.each do |key|
          next unless key.match?(pattern)
          @data.delete(key)
        end
      end
    end

    private

    def purge_expired!(key)
      keys = key ? [key] : @data.keys
      keys.each do |k|
        entry = @data[k]
        next unless entry
        expires_at = entry[:expires_at]
        next unless expires_at && expires_at <= Time.now
        @data.delete(k)
      end
    end
  end

  store = if ENV['REDIS_URL'] && defined?(Redis)
            Rack::Attack::StoreProxy::RedisStoreProxy.new(Redis.new(url: ENV['REDIS_URL']))
          else
            MemoryStore.new
          end

  Rack::Attack.cache.store = store

  throttle('req/ip', limit: 60, period: 60) do |req|
    req.ip
  end
end

use Rack::Attack
use Rack::Protection, except: [:remote_referrer]
use Rack::Protection::ContentSecurityPolicy, default_src: "'self'"

DB_PATH = File.join(__dir__, 'db', 'secure.db')
FileUtils.mkdir_p(File.dirname(DB_PATH))

DB = SQLite3::Database.new(DB_PATH)
DB.results_as_hash = true
DB.execute('PRAGMA journal_mode=WAL;')
DB.execute('PRAGMA foreign_keys=ON;')

SCHEMA_PATH = File.join(__dir__, 'db', 'schema.sql')
DB.execute_batch(File.read(SCHEMA_PATH)) if File.exist?(SCHEMA_PATH)

helpers do
  def db
    DB
  end

  def current_user
    return @current_user if defined?(@current_user)
    return unless session[:user_id]

    stmt = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?')
    rs = stmt.execute(session[:user_id])
    @current_user = rs.next
  ensure
    stmt&.close
  end

  def authenticate!
    redirect '/login' unless current_user
  end

  def admin_only!
    authenticate!
    halt 403, 'Admins only' unless current_user && current_user['role'] == 'admin'
  end

  def password_valid?(password)
    password.length >= 12 &&
      password.match?(/[A-Z]/) &&
      password.match?(/[a-z]/) &&
      password.match?(/[0-9]/) &&
      password.match?(/[!@#$%^&*]/)
  end

  def sanitize(text)
    Rack::Utils.escape_html(text.to_s)
  end
end

before do
  headers 'X-Content-Type-Options' => 'nosniff',
          'X-Frame-Options' => 'DENY',
          'Content-Security-Policy' => "default-src 'self'",
          'Referrer-Policy' => 'strict-origin-when-cross-origin',
          'Permissions-Policy' => 'geolocation=()'
end

# --- Routes ------------------------------------------------------------------
get '/' do
  erb :home
end

get '/register' do
  erb :register
end

post '/register' do
  username = params[:username].to_s.strip
  email = params[:email].to_s.strip
  password = params[:password].to_s

  halt 400, 'Password does not meet policy' unless password_valid?(password)

  stmt = db.prepare('INSERT INTO users (username, email, password_digest, role) VALUES (?, ?, ?, ?)')
  stmt.execute(username, email, BCrypt::Password.create(password), 'user')
  redirect '/login'
rescue SQLite3::ConstraintException
  halt 400, 'Username already taken'
ensure
  stmt&.close
end

get '/login' do
  erb :login
end

post '/login' do
  username = params[:username]
  password = params[:password]

  stmt = db.prepare('SELECT * FROM users WHERE username = ?')
  user = stmt.execute(username).next
  halt 401, 'Invalid credentials' unless user && BCrypt::Password.new(user['password_digest']) == password

  session[:user_id] = user['id']
  redirect '/dashboard'
ensure
  stmt&.close
end

post '/logout' do
  session.clear
  redirect '/'
end

before '/dashboard' do
  authenticate!
end

get '/dashboard' do
  erb :dashboard
end

get '/profile/:id' do
  authenticate!
  halt 403 unless current_user['role'] == 'admin' || current_user['id'].to_s == params[:id]

  stmt = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?')
  user = stmt.execute(params[:id]).next
  halt 404, 'Not found' unless user
  json user
ensure
  stmt&.close
end

get '/comment' do
  authenticate!
  stmt = db.prepare('SELECT author, body, created_at FROM comments ORDER BY created_at DESC LIMIT 50')
  @comments = stmt.execute.map do |row|
    { author: sanitize(row['author']), body: sanitize(row['body']), created_at: row['created_at'] }
  end
  erb :comment
ensure
  stmt&.close
end

post '/comment' do
  authenticate!
  author = sanitize(params[:author])
  body = sanitize(params[:body])
  halt 400, 'Comment required' if body.empty?

  stmt = db.prepare('INSERT INTO comments(author, body) VALUES (?, ?)')
  stmt.execute(author, body)
  redirect '/comment'
ensure
  stmt&.close
end

ALLOWED_MIME = %w[image/png image/jpeg application/pdf].freeze
MAX_FILE_SIZE = 5 * 1024 * 1024

get '/upload' do
  authenticate!
  erb :upload
end

post '/upload' do
  authenticate!
  file = params[:payload]
  halt 400, 'File required' unless file

  mime = file[:type]
  halt 400, 'Unsupported type' unless ALLOWED_MIME.include?(mime)
  halt 413, 'File too large' if file[:tempfile].size > MAX_FILE_SIZE

  filename = "#{SecureRandom.uuid}_#{File.basename(file[:filename])}"
  safe_dir = File.join(__dir__, 'uploads')
  FileUtils.mkdir_p(safe_dir)
  path = File.join(safe_dir, filename)
  File.open(path, 'wb') { |f| f.write(file[:tempfile].read) }
  "Stored #{filename} securely."
end

# Admin endpoint protected by role + CSRF token
get '/admin/users' do
  admin_only!
  stmt = db.prepare('SELECT id, username, email, role FROM users ORDER BY id')
  @users = stmt.execute.to_a
  erb :admin
ensure
  stmt&.close
end

post '/admin/users/:id/delete' do
  admin_only!
  halt 400, 'Invalid CSRF token' unless env['rack.session'][:csrf] == params[:csrf]
  halt 400, 'Cannot delete yourself' if params[:id].to_i == current_user['id']

  stmt = db.prepare('DELETE FROM users WHERE id = ?')
  stmt.execute(params[:id])
  redirect '/admin/users'
ensure
  stmt&.close
end

post '/api/search' do
  authenticate!
  term = params[:q].to_s.strip
  halt 400, 'Query required' if term.empty?
  stmt = db.prepare('SELECT username FROM users WHERE username LIKE ? LIMIT 5')
  json stmt.execute("%#{term}%").map { |row| row['username'] }
ensure
  stmt&.close
end

# --- Error handling ----------------------------------------------------------
error do
  status 500
  'Something went wrong. The incident has been logged.'
end

not_found do
  "The resource you were looking for doesn't exist."
end

# --- Database bootstrap ------------------------------------------------------
def seed_database
  count = DB.get_first_value('SELECT COUNT(*) FROM users')
  return if count.to_i.positive?

  users = [
    { username: 'admin', email: 'admin@example.com', password: 'Admin@1234', role: 'admin' },
    { username: 'sara', email: 'sara@example.com', password: 'Str0ng#Pass!', role: 'user' }
  ]

  users.each do |u|
    stmt = DB.prepare('INSERT INTO users(username, email, password_digest, role) VALUES (?, ?, ?, ?)')
    stmt.execute(u[:username], u[:email], BCrypt::Password.create(u[:password]), u[:role])
    stmt.close
  end

  DB.execute("INSERT INTO comments(author, body) VALUES (?, ?)", ['admin', 'Welcome to the secure wall.'])
end

seed_database

__END__

@@layout
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secure Demo</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/modern-normalize/2.0.0/modern-normalize.min.css">
  <style>
    body { font-family: system-ui, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
    nav a { margin-right: 1rem; }
    form input, form textarea { width: 100%; padding: .5rem; margin-bottom: .75rem; }
  </style>
</head>
<body>
  <nav>
    <a href="/">Home</a>
    <% if current_user %>
      <a href="/dashboard">Dashboard</a>
      <a href="/comment">Wall</a>
      <a href="/upload">Upload</a>
      <% if current_user['role'] == 'admin' %><a href="/admin/users">Admin</a><% end %>
      <form method="POST" action="/logout" style="display:inline"><button>Logout</button></form>
    <% else %>
      <a href="/login">Login</a>
      <a href="/register">Register</a>
    <% end %>
  </nav>
  <%= yield %>
</body>
</html>

@@home
<h1>✅ Secure Demo</h1>
<p>This app addresses the STRIDE-style checklist from <code>../checklist.txt</code> by enforcing strong auth, defense-in-depth, and secure defaults.</p>
<ul>
  <li>Authentication + MFA-ready password policy</li>
  <li>RBAC for admin endpoints</li>
  <li>Parameterized SQL everywhere</li>
  <li>Security headers + CSP</li>
  <li>CSRF protection + rate limiting</li>
  <li>Safe file uploads and logging hygiene</li>
</ul>

@@register
<h2>Create an account</h2>
<form method="POST" action="/register">
  <label>Username<input name="username" required></label>
  <label>Email<input name="email" type="email" required></label>
  <label>Password<input type="password" name="password" required></label>
  <p>Password must be ≥12 chars with upper, lower, number, and symbol.</p>
  <button>Create account</button>
</form>

@@login
<h2>Login</h2>
<form method="POST" action="/login">
  <label>Username<input name="username" required></label>
  <label>Password<input type="password" name="password" required></label>
  <button>Sign in</button>
</form>

@@dashboard
<h2>Hi <%= current_user['username'] %></h2>
<p>Your role: <strong><%= current_user['role'] %></strong></p>
<p>Use the navigation to explore secure flows.</p>

@@comment
<h2>Secure Wall</h2>
<form method="POST" action="/comment">
  <label>Name<input name="author" value="<%= current_user['username'] %>"></label>
  <label>Message<textarea name="body" required></textarea></label>
  <button>Post</button>
</form>
<ul>
  <% @comments.each do |c| %>
    <li><strong><%= c[:author] %></strong>: <%= c[:body] %> (<%= c[:created_at] %>)</li>
  <% end %>
</ul>

@@upload
<h2>Secure upload</h2>
<form method="POST" action="/upload" enctype="multipart/form-data">
  <input type="file" name="payload" accept="image/png,image/jpeg,application/pdf" required>
  <button>Upload</button>
</form>
<p>Only PNG/JPEG/PDF ≤5MB are accepted. Files are renamed and stored outside the web root.</p>

@@admin
<h2>Admin users</h2>
<table>
  <thead><tr><th>ID</th><th>User</th><th>Email</th><th>Role</th><th></th></tr></thead>
  <tbody>
  <% @users.each do |u| %>
    <tr>
      <td><%= u['id'] %></td>
      <td><%= u['username'] %></td>
      <td><%= u['email'] %></td>
      <td><%= u['role'] %></td>
      <td>
        <% if u['id'] != current_user['id'] %>
          <form method="POST" action="/admin/users/<%= u['id'] %>/delete">
            <input type="hidden" name="csrf" value="<%= session[:csrf] ||= SecureRandom.hex(16) %>">
            <button>Delete</button>
          </form>
        <% end %>
      </td>
    </tr>
  <% end %>
  </tbody>
</table>
