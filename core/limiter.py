from slowapi import Limiter
from slowapi.util import get_remote_address

# Initialize the limiter
# key_func=get_remote_address means we limit based on the client's IP address
limiter = Limiter(key_func=get_remote_address)