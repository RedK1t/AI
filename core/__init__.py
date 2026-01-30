# Import main classes to make them accessible directly from 'core'
from .parser import parse_endpoint
from .request_builder import RequestBuilder

# Now you can use: from core import RequestBuilder 
# instead of: from core.request_builder import RequestBuilder