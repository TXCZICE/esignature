import multiprocessing

# Server socket
bind = "0.0.0.0:5000"
backlog = 2048

# Worker processes - reduced for Render's limited resources
workers = 2  # Conservative for memory-limited environments
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 120  # Increased timeout to prevent worker timeouts
keepalive = 2

# Process naming
proc_name = "esignature"

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Logging
loglevel = "info"
accesslog = "-"
errorlog = "-"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = "esignature"

# SSL
keyfile = None
certfile = None
