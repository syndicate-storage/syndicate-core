#!/usr/bin/env python

"""
   Copyright 2017 The Trustees of Princeton University

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

import webapp2
import logging
import re
import hashlib
import json
import time
import os
import base64 
import urllib

from google.appengine.ext import ndb

EMAILS_AUTH_SECRET = "ac5c015e354bf68a81df8177858064a296b3377d7da7828b71a393c7eee01a60ec840c2013485608c1732abe65927d87adfa159f36ec604638c147ccff777c80"

SIGNUP_PAGE = """
<html>
<head></head>
<style>
.code {
    font-family: "Courier New", Courier, "Lucida Sans Typewriter", "Lucida Typewriter", monospace;
    font-size: 12px;
    font-style: normal;
    font-variant: normal;
    font-weight: 400;
    line-height: 30px;
    background-color: #f0f0f0;
}
</style>
<body>
<h1>Syndicate Demo Signup</h1>
<div>
    Please enter your email below, and we will create an demo Syndicate user account for you.<br>
    Using this account, you will be able to<br>
    <ul>
        <li>Mount the <a href="https://imicrobe.us">iMicrobe</a> dataset in a Docker image at <span class="code">/opt/dataset</span>,</li>
        <li>Read the iMicrobe dataset via the image's filesystem,</li>
        <li>Run local computations over the data,</li>
        <li>Store temporary results to S3 by writing them to <span class="code">/opt/results</span> in the image.</li>
    </ul>
    Your user account and any data you save to S3 will be cleared out every 12 hours, at 00:00 GMT and 12:00 GMT.
</div>
<br>
<div>
    <form action="/register" method="post">
        Email address: <input type="text" name="email"> <input type="submit" value="Register">
    </form>
</div>
</body>
</html>
"""

SIGNUP_FINISH_PAGE_TEMPLATE = """
<html>
<head></head>
<style>
.code {{
    font-family: "Courier New", Courier, "Lucida Sans Typewriter", "Lucida Typewriter", monospace;
    font-size: 12px;
    font-style: normal;
    font-variant: normal;
    font-weight: 400;
    line-height: 30px;
    background-color: #f0f0f0
}}
</style>
<body>
<h1>Syndicate Demo Signup</h1>
Thank you for signing up.  Your user account will be created in a few minutes.<br>
<br>
You will be prompted for password when you start your Syndicate demo software.  That password is <span class="code">{}</span><br>
</body>
</html>
"""

EMAIL_REGEX = r"^(?=^.{1,256}$)(?=.{1,64}@)(?:[^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|\x22(?:[^\x0d\x22\x5c\x80-\xff]|\x5c[\x00-\x7f])*\x22)(?:\x2e(?:[^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|\x22(?:[^\x0d\x22\x5c\x80-\xff]|\x5c[\x00-\x7f])*\x22))*\x40(?:[^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|[\x5b](?:[^\x0d\x5b-\x5d\x80-\xff]|\x5c[\x00-\x7f])*[\x5d])(?:\x2e(?:[^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|[\x5b](?:[^\x0d\x5b-\x5d\x80-\xff]|\x5c[\x00-\x7f])*[\x5d]))*$"

BASE64_REGEX = r'^((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4}))$'

def send_response( request_handler, status, data, content_type=None ):
   """
   Helper to send a response
   """
   
   if content_type == None:
      content_type = "text/plain"

   request_handler.response.headers['Content-Type'] = content_type
   request_handler.response.status = status
   request_handler.response.write( data )
   return


def streq_constant(s1, s2):
    """
    constant-time string comparison.
    Return True if equal
    Return False if not equal
    """
    res = 0
    s1h = hashlib.sha256(s1).digest()
    s2h = hashlib.sha256(s2).digest()
    for s1c, s2c in zip(s1h, s2h):
        # will xor to 0 for each char if equal
        res |= ord(s1c) ^ ord(s2c)

    return res == 0


def check_auth(request_handler, secret):
    """
    Verify that a request handler passed in the right secret
    """
    auth_header = request_handler.request.headers.get('Authorization')
    if auth_header is None:
        return False

    if not auth_header.startswith("bearer "):
        return False

    auth_secret = auth_header.split(" ")[1]
    if not streq_constant(auth_secret, secret):
        return False
    
    return True


class EmailEntry(ndb.Model):
    """
    Email queue
    """
    email_addr = ndb.StringProperty()
    date = ndb.DateTimeProperty(auto_now_add=True)
    password = ndb.TextProperty()
    demo_payload = ndb.TextProperty()

    @classmethod
    def list_emails(cls):
        return cls.query().order(cls.date)


class RegisterHandler(webapp2.RequestHandler):
    
    def post(self):
        """
        Queue a name up for registration
        """
        email_addr = self.request.get("email")
        if email_addr is None or len(email_addr) == 0:
            return send_response(self, 401, "Invalid email address")

        if not re.match(EMAIL_REGEX, email_addr):
            return send_response(self, 401, "Invalid email address")

        password = base64.b64encode(os.urandom(32))

        email_entry = EmailEntry(key=ndb.Key(EmailEntry, email_addr), email_addr=email_addr, password=password)
        email_entry.put()

        signup_page = SIGNUP_FINISH_PAGE_TEMPLATE.format(password)
        return send_response(self, 200, signup_page, content_type="text/html")


    def get(self):
        """
        Get the list of email addresses pending.
        Return [{'email': email address, 'date': UTC time of creation, 'password': password to use to encrypt the private key}]
        """
        if not check_auth(self, EMAILS_AUTH_SECRET):
            return send_response(self, 403, "Access denied")

        count = 20
        offset = 0
        if self.request.get("count") is not None and len(self.request.get('count')) > 0:
            try:
                count = int(self.request.get("count"))
            except ValueError:
                return send_response(self, 401, "Invalid count")
        
        if count <= 0:
            return send_response(self, 401, "Invalid count")

        if self.request.get("offset") is not None and len(self.request.get("offset")) > 0:
            try:
                offset = int(self.request.get("offset"))
            except ValueError:
                return send_response(self, 401, "Invalid offset")

        if offset < 0:
            return send_response(self, 401, "Invalid offset")

        email_objects = EmailEntry.list_emails().fetch(count, offset=offset)
        emails = [{'email': email.email_addr, 'date': int(time.mktime(email.date.timetuple())), 'password': email.password} for email in email_objects]
        txt = json.dumps(emails)
        return send_response(self, 200, txt, content_type="application/json")

        
    def delete(self):
        """
        Delete an email address from the queue
        """
        if not check_auth(self, EMAILS_AUTH_SECRET):
            return send_response(self, 403, "Access denied")
       
        email_addr = self.request.get('email')
        if email_addr is None or len(email_addr) == 0:
            return send_response(self, 401, "Invalid request")

        if not re.match(EMAIL_REGEX, email_addr):
            return send_response(self, 401, "Invalid request")

        email_entry_key = ndb.Key(EmailEntry, email_addr)
        email_entry_key.delete()
        return send_response(self, 200, "OK")

        
class ProvisionHandler(webapp2.RequestHandler):

    def post(self, email):
        """
        Store a private key for a user.
        Takes a string under 'private_key' (encrypted with the user's password),
        stores it as base64, and deletes the password.
        """
        if not check_auth(self, EMAILS_AUTH_SECRET):
            return send_response(self, 403, "Access denied")

        email_addr = urllib.unquote(email)
        if not re.match(EMAIL_REGEX, email_addr):
            return send_response(self, 401, 'Invalid request: invalid email')

        email_key = ndb.Key(EmailEntry, email_addr)
        email_entry = email_key.get()
        if email_entry is None:
            return send_response(self, 404, 'Email not found')

        if email_entry.demo_payload is not None:
            # already set 
            return send_response(self, 202, 'key already set')

        # read demo payload 
        demo_payload = self.request.POST.get('demo_payload')
        if demo_payload is None:
            return send_response(self, 401, 'Invalid request: no payload given')
    
        # must be JSON
        try:
            json.loads(demo_payload)
        except:
            return send_response(self, 401, 'Invalid request: not JSON')

        email_entry.demo_payload = demo_payload
        
        # clear password 
        email_entry.password = ""
        email_entry.put()

        return send_response(self, 200, 'OK')


    def get(self, email):
        """
        Get back the encrypted private key for the user.
        Return base64-encoded data.
        """
        email = urllib.unquote(email)
        if not re.match(EMAIL_REGEX, email):
            return send_response(self, 401, "Invalid argument")

        email_key = ndb.Key(EmailEntry, email)
        email_entry = email_key.get()
        if email_entry is None:
            return send_response(self, 401, 'Invalid request')

        return send_response(self, 200, email_entry.demo_payload, content_type='application/json')


class GreetingsHandler(webapp2.RequestHandler):

    def get(self):
        """
        Give back some sign-up instructions
        """
        return send_response(self, 200, SIGNUP_PAGE, content_type="text/html")


handlers = [
    (r'[/]+', GreetingsHandler),
    (r'[/]+register', RegisterHandler),
    (r'[/]+provision[/]+(.+)', ProvisionHandler),
]

app = webapp2.WSGIApplication(routes=handlers, debug=True)

