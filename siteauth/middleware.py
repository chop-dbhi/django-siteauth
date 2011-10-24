import re
from django.conf import settings
from django.utils import simplejson
from django.http import HttpResponse, HttpResponseRedirect

# dumb regex to extract the referer's path
extract_path = re.compile(r'^https?:\/\/[^\/]*(.*)$')

LOGIN_URL = getattr(settings, 'LOGIN_URL')
ACCESS_ORDER = getattr(settings, 'SITEAUTH_ACCESS_ORDER', 'deny/allow').lower()
DENY_URLS = map(lambda x: re.compile(x), getattr(settings, 'SITEAUTH_DENY_URLS', ()))
ALLOW_URLS = map(lambda x: re.compile(x), getattr(settings, 'SITEAUTH_ALLOW_URLS', ()))

ALWAYS_DENY = ACCESS_ORDER.endswith('deny') and True or False

class SiteAuthenticationMiddleware(object):
    "Applies Apache-like access control using the 'Allow,Deny' order."
    def _process_ajax_request(self, request):
        try:
            # extract path of referrer URL of the AJAX request as a better
            # next URL
            path = extract_path.match(request.META['HTTP_REFERER']).groups()[0]
            redirect = '%s?next=%s' % (LOGIN_URL, path)
        except (AttributeError, IndexError):
            redirect = LOGIN_URL

        # return JSON payload which can be caught during response parsing
        # by the client that will redirect the user to the `redirect` URL
        return HttpResponse(simplejson.dumps({'redirect': redirect}),
            mimetype='application/json', status=302)

    def _process_request(self, request):
        redirect = '%s?next=%s' % (LOGIN_URL, request.path)
        return HttpResponseRedirect(redirect)

    def process_request(self, request):
        if request.user.is_authenticated():
            return

        path = request.path_info.lstrip('/')
        denied, allowed = False, False

        for url in DENY_URLS:
            if url.match(path):
                denied = True
                break

        for url in ALLOW_URLS:
            if url.match(path):
                allowed = True
                break

        if not allowed and (denied or ALWAYS_DENY):
            if request.is_ajax():
                return self._process_ajax_request(request)
            return self._process_request(request)

