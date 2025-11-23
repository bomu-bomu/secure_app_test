# frozen_string_literal: true

require 'sinatra'
require 'sqlite3'
require 'json'
require 'fileutils'

set :bind, '0.0.0.0'
set :sessions, secret: 'super-insecure-secret' * 4, expire_after: 604800

DB_PATH = File.join(__dir__, 'db', 'insecure.db')
FileUtils.mkdir_p(File.dirname(DB_PATH))
DB = SQLite3::Database.new(DB_PATH)
DB.results_as_hash = true

helpers do
  def db
    DB
  end

  def current_user
    return unless session[:user_id]

    db.execute("SELECT * FROM users WHERE id = #{session[:user_id]}").first
  end
end

# Homepage summarizing vulnerable behavior
get '/' do
  <<~HTML
    <h1>⚠️ Insecure Demo</h1>
    <p>This Sinatra app intentionally violates the checklist in <code>../checklist.txt</code>.</p>
    <ul>
      <li><a href="/login">Weak authentication & SQL injection</a></li>
      <li><a href="/profile/1">IDOR profile leak</a></li>
      <li><a href="/comment">Stored XSS</a></li>
      <li><a href="/admin/deleteUser?id=2">Forced browsing to admin endpoint</a></li>
      <li><a href="/upload">Unrestricted file upload</a></li>
      <li><a href="/logs">Sensitive log disclosure</a></li>
    </ul>
    <p>Try things like <code>' OR '1'='1</code> during login to bypass checks.</p>
  HTML
end

# --- Authentication issues ---------------------------------------------------
get '/login' do
  <<~HTML
    <h2>Login</h2>
    <form method="POST" action="/login">
      <label>Username <input name="username"></label><br>
      <label>Password <input type="password" name="password"></label><br>
      <button>Login</button>
    </form>
    <p><a href="/forgot-password?username=admin">Forgot password</a> leaks user existence.</p>
  HTML
end

post '/login' do
  # Vulnerable: string interpolation enables SQL injection (AUTH-001, INPUT-001)
  query = "SELECT * FROM users WHERE username='#{params[:username]}' AND password='#{params[:password]}'"
  user = db.execute(query).first

  if user
    session[:user_id] = user['id']
    "Logged in as #{user['username']} (password stored in plaintext)."
  else
    status 401
    "Invalid credentials"
  end
end

# Username enumeration - reveals if account exists (Spoofing)
get '/forgot-password' do
  username = params[:username]
  user = db.execute("SELECT * FROM users WHERE username='#{username}'").first
  if user
    "We emailed #{user['email']} a reset link (but not really)."
  else
    status 404
    "User not found"
  end
end

# Forced browsing / missing auth for dashboard
get '/dashboard' do
  "Anyone can see this dashboard. Session: #{session.inspect}"
end

# --- IDOR / Data exposure ----------------------------------------------------
get '/profile/:id' do
  user = db.execute("SELECT * FROM users WHERE id = #{params[:id]}").first
  content_type :json
  user.to_json # No access control, leaks PII
end

# --- Stored XSS ---------------------------------------------------------------
get '/comment' do
  comments = db.execute('SELECT * FROM comments ORDER BY created_at DESC')
  list = comments.map { |c| "<li><strong>#{c['author']}</strong>: #{c['body']}</li>" }.join
  <<~HTML
    <h2>Public Wall (Stored XSS)</h2>
    <form method="POST" action="/comment">
      <input name="author" placeholder="Name">
      <textarea name="body" placeholder="Say anything"></textarea>
      <button>Post</button>
    </form>
    <ul>#{list}</ul>
  HTML
end

post '/comment' do
  db.execute("INSERT INTO comments(author, body) VALUES('#{params[:author]}', '#{params[:body]}')")
  redirect '/comment'
end

# --- File upload without validation -----------------------------------------
get '/upload' do
  <<~HTML
    <h2>Upload anything</h2>
    <form method="POST" action="/upload" enctype="multipart/form-data">
      <input type="file" name="payload">
      <button>Upload</button>
    </form>
  HTML
end

post '/upload' do
  halt 400, 'No file' unless params[:payload]

  file = params[:payload][:tempfile]
  filename = params[:payload][:filename]
  dest = File.join(__dir__, 'uploads', filename)
  FileUtils.mkdir_p(File.dirname(dest))
  File.write(dest, file.read)
  "Stored #{filename} with no validation (FILE-001, FILE-002)."
end

# --- Admin endpoints without authorization ----------------------------------
get '/admin/deleteUser' do
  db.execute("DELETE FROM users WHERE id = #{params[:id]}")
  "Deleted user ##{params[:id]} without any authorization checks (EoP)."
end

# --- Logging of sensitive data ----------------------------------------------
post '/api/search' do
  term = params[:q]
  File.open(File.join(__dir__, 'logs.txt'), 'a') do |f|
    f.puts "[#{Time.now}] search=#{term} session=#{session.inspect}"
  end
  "Logged everything!"
end

get '/logs' do
  content_type 'text/plain'
  File.read(File.join(__dir__, 'logs.txt')) rescue "No logs yet"
end

# --- Missing TLS / security headers simulated by exposing config ------------
get '/config' do
  content_type 'text/plain'
  File.read(__FILE__)
end

# Initialize database if empty
begin
  DB.execute('SELECT 1 FROM users LIMIT 1')
rescue SQLite3::SQLException
  schema_path = File.join(__dir__, 'db', 'schema.sql')
  seeds_path = File.join(__dir__, 'db', 'seeds.sql')
  DB.execute_batch(File.read(schema_path)) if File.exist?(schema_path)
  DB.execute_batch(File.read(seeds_path)) if File.exist?(seeds_path)
end
