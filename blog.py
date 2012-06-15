import os
import re
import random
import hashlib
import hmac
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db
import logging  # Call logging.error() to print messages to console
import urllib2
from xml.dom import minidom

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.set_cookie(name, cookie_val) # Setting secure=True causes problems for local testing
        # self.response.headers.add_header(
        #     'Set-Cookie',
        #     '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
       self.response.delete_cookie('user_id')
#        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

    def getPost(self, post_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        if not post:
            self.abort(404)
        return post

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

# http://forums.udacity.com/cs253-april2012/questions/19776/how-to-make-bcrypt-work-with-gae
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.render('index.html')

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class Coords(db.Model):
    coords=db.GeoPtProperty(required=True)

IP_URL="http://api.hostip.info/?ip="
def get_coords(ip):
    url=IP_URL+ip
    content = None
    try:
        content=urllib2.urlopen(url).read()
    except URLError:
        return
    if content:
        d=minidom.parseString(content)
        coords= d.getElementsByTagName("gml:coordinates")
        if coords and coords[0].childNodes[0].nodeValue:
            lon,lat= coords[0].childNodes[0].nodeValue.split(',')
            return db.GeoPt(lat,lon)

GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"

def gmaps_img(points):
    markers= '&'.join('markers=%s,%s'%(p.coords.lat,p.coords.lon) for p in points)
    return GMAPS_URL +markers

class BlogFront(BlogHandler):
    def get(self):
        # Store each unique visitor on front page
        coords = get_coords(self.request.remote_addr)
        if coords:
           q = db.Query(Coords)
           q.filter('coords =', coords)
           if not q.count():
              c = Coords(coords=coords)
              c.put()

        # Map all visitors
        img_url = None
        points = db.GqlQuery("select * from Coords")
        if points:
           img_url = gmaps_img(points)

        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts = posts, img_url = img_url)

class PostPage(BlogHandler):
    def get(self, post_id):
        post = self.getPost(post_id)
        self.render("permalink.html", post = post)

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')
        post = self.getPost(post_id)
        is_edit = self.request.get('edit')
        is_delete = self.request.get('delete')
        if is_delete:
           db.delete(post.key())
           self.redirect('/blog')
        elif is_edit:
           self.redirect(self.uri_for('edit', post_id = post_id))
        else:
           self.error(404)

class EditPostPage(BlogHandler):
    def get(self, post_id):
        if self.user:
           post = self.getPost(post_id)
           self.render("newpost.html", subject=post.subject, content=post.content)
        else:
           self.redirect("/login")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')
        post = self.getPost(post_id)
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect(self.uri_for('post', post_id = post_id))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect(self.uri_for('post', post_id = str(p.key().id())))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
           #make sure the user doesn't already exist
           u = User.by_name(username)
           if u:
              msg = 'That user already exists.'
              self.render('signup-form.html', error_username = msg)
           else:
              u = User.register(username, password, email)
              u.put()

              self.login(u)
              self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/?', BlogFront),
#                               ('/blog/(\d+)/?', PostPage),
                               webapp2.Route('/blog/<post_id:\d+>', handler=PostPage, name='post'),
                               webapp2.Route('/blog/<post_id:\d+>/edit', handler=EditPostPage, name='edit'),
                               ('/blog/newpost', NewPost),
                               ],
                              debug=True)
