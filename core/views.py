from django.shortcuts import render
from django.http import HttpResponse, HttpRequest

### Utility
def get_remote_addr(request: HttpRequest):
    x_forward = request.META.get('HTTP_X_FORWARDED_FOR', None)

    if x_forward:
        remote_addr = x_forward.split(',')[0]
    else:
        remote_addr = request.META.get('REMOTE_ADDR', 'Unknown IP')
    
    return remote_addr

### Views
def index(request: HttpRequest):
    return HttpResponse(f'Hello {get_remote_addr(request)}')

