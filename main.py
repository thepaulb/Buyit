#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import cgi
import hmac
import json
import jinja2
import random
import string
import logging
import webapp2
import hashlib
import datetime

from string import letters
from datetime import datetime

from google.appengine.ext import ndb
from google.appengine.api import memcache

templates = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(templates), autoescape = True)


#### utils functions

def get_entity(key_string): # by key string
	key = ndb.Key(urlsafe = key_string)
	# logging.info("get_entity()")
	# logging.info(key)
	# logging.info(key.get())
	return key.get()

def get_entity2(key_string): # rework of the above
	key = ndb.Key(urlsafe = key_string)
	# logging.info("get_entity()")
	# logging.info(key)
	# logging.info(key.get())
	return key.get(), key

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

def get_items(key_string):
	key = ndb.Key(urlsafe = key_string)
	return Item.all(key)

def add_item(key_string, title):
	ent = get_entity(key_string)
	item = Item(parent = ent.key, title = title, purchased = False, deleted = False)
	return item.put()

def check_item(key_string, toggle = False):
	item = get_entity(key_string)
	if toggle and item.purchased:
		item.purchased = False
	else:
		item.purchased = True
	return item.put()

def check_all(list_key):
	items = get_items(list_key)
	if not len(list(items)): return
	for item in items:
		if not item.deleted and not item.purchased:
			item.purchased = True
			item.put()

def delete_item(key_string):
	# item being an Entity, rather than list item
	item = get_entity(key_string)
	item.deleted = True # soft delete
	item.deleted_date = datetime.now()
	return item.put()

def get_lists(owner):
	return List.all(owner.key).filter(List.deleted == False).order(-List.created)

def add_list(title, owner):
	l = List(parent = owner, title = title, deleted = False)
	return l.put()

def delete_list(key_string):
	return delete_item(key_string)

def accept_invite(invite_key):
	invite, key = get_entity2(invite_key)
	invite.status = "accepted"
	return invite.put()


#### Base handler class

class Handler(webapp2.RequestHandler):
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_user_cookie('user_id')
		self.user = uid and User.get_by_id(int(uid))

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		return render_str(template, **params)
	
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_user_cookie(self, name, value):
		cookie_val = make_secure_value(value)
		self.response.headers.add_header('Set-Cookie', str('%s=%s; Path=/' % (name, cookie_val)))

	def set_shw_purchased_cookie(self, value = 0):
		self.response.headers.add_header('Set-Cookie', str('shoppr_shw_purchased=%s; Path=/' % (value)))

	def read_user_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_user_cookie(cookie_val)

	def read_shw_purchased_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and int(cookie_val) 

	def login(self, user):
		self.set_user_cookie('user_id', str(user.key.id()))  

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')  


#### Entities
class Base(ndb.Model):
	deleted_date = ndb.DateTimeProperty()
	created = ndb.DateTimeProperty(auto_now_add = True)
	deleted = ndb.BooleanProperty(required = True)
	title = ndb.StringProperty(required = True)


class Item(Base):
	purchased = ndb.BooleanProperty(required = True)

	@classmethod
	def all(cls, ancestor_key):
		q = cls.query(ancestor = ancestor_key).order(-cls.created)
		return q.filter(Item.deleted == False)

	@classmethod
	def clear(cls, ancestor_key):
		for item in cls.all(ancestor_key):
			item.purchased = False
			item.put()


class List(Base):
	@classmethod
	def all(cls, ancestor_key):
		return cls.query(ancestor = ancestor_key).order(-cls.created)


class Guest(ndb.Model):
	created = ndb.DateTimeProperty(auto_now_add = True)
	# status values invited, member
	status = ndb.StringProperty(required = True)
	guest = ndb.StringProperty(required = True)
	title = ndb.StringProperty(required = True)
	host = ndb.StringProperty(required = True) # list owner



	def get_owner_name(self):
		# double messy, however ..
		return self.key.parent().get().key.parent().get().name


#### App

class HomePage(Handler):
	def get(self):
		msg = None
		if self.user:
			q = Guest.query()
			if q:
				invites = []
				for invite in q:
					if invite.guest == self.user.key.urlsafe():
						invites.append(invite)
						logging.info(invite)
			self.render("index.html", lists = get_lists(self.user), invites = invites, msg = msg)
		else:
			self.redirect("/login")

	def post(self):
		msg = None
		method = cgi.escape(self.request.get("_method"))
		# replicate HTTP(S) methods
		if method == "delete":
			key = cgi.escape(self.request.get("list_key"))
			self.deleteList(key)
		if method == "put":
			key = cgi.escape(self.request.get("invite_key"))
			msg = "Invitation excepted!"
			self.acceptInvite(key)

		self.render("index.html", lists = get_lists(self.user), msg = msg)

	def deleteList(self, list_key):
		delete_list(list_key)

	def acceptInvite(self, invite_key):
		accept_invite(invite_key)


class ListPage(Handler):
	def get(self, list_string, *args):
		if self.user:
			self._render(list_string)
		else:
			self.redirect("/login")

	def post(self, list_key):
		item_key = cgi.escape(self.request.get("item_key"))
		method = cgi.escape(self.request.get("_method"))
		title = cgi.escape(self.request.get("title"))
        
		logging.info(["title:", title.split("\r")])

		# replicate HTTP(S) methods
		if method == "put":
			self.checkItem(item_key)
		elif method == "post":
			multi = title.split("\r")
			if multi:
			    multi.reverse()
			    for title in multi:
					if title != "\n":
					    self.addItem(list_key, title)
			else:
			    self.addItem(list_key, title)
		elif method == "delete":
			self.deleteItem(item_key)
		elif method == "check_all":
			self.checkAll(list_key)

		self._render(list_key)

	def addItem(self, list_key, title):
		add_item(list_key, title)

	def deleteItem(self, item_key):
		delete_item(item_key)

	def checkItem(self, item_key):
		check_item(item_key, True)

	def checkAll(self, list_key):
		check_all(list_key)


	def _render(self, list_key):
		enable_purchase_all = True
		shw_purchased = self.read_shw_purchased_cookie("shoppr_shw_purchased")
		items = get_items(list_key)

		if not shw_purchased:
			items = items.filter(Item.purchased == False)
		
		list = get_entity(list_key)
		self.render("list.html", items = items, list = list, list_key = list_key, shw_purchased = shw_purchased)


class Hide(Handler):
	def post(self, list_key):
		shw_purchased = self.read_shw_purchased_cookie("shoppr_shw_purchased")

		if shw_purchased is not None:
			shw_purchased = 1 - shw_purchased
		else:
			shw_purchased = 0

		self.set_shw_purchased_cookie(shw_purchased)
		self.redirect("/list/"+list_key)	


class Share(Handler):
	def get(self, list_key):
		users = []
		listing, listing_key = get_entity2(list_key)
		# get all guests for this list
		guests = Guest.query(ancestor = listing_key)
		for user in User.query():
			# exclude current user from list ..
			if user.key.urlsafe() != self.user.key.urlsafe():
				# check if user has been invited
				invited = False
				for guest in guests:
					u, k = get_entity2(guest.guest)
					if user.name == u.name:
						invited = True	
						break
				if not invited:
					users.append(user)
		self.render("share.html", users = users, list_key = list_key)

	def post(self, list_key):
		user_key = cgi.escape(self.request.get("user_key"))
		listing = get_entity(list_key) 
		user = get_entity(user_key) 
		guest = Guest(parent = listing.key, guest = user_key, status = "invited", host = self.user.key.urlsafe(), title = listing.title)
		guest.put()
		self.render("invited.html", name = user.name)


class AddList(Handler): 
	def get(self):
		self.render("addlist.html")

	def post(self):
		title = cgi.escape(self.request.get("title"))
		add_list(title, self.user.key)
		self.redirect("/")


#### User management 

RE_USER = "^[a-zA-Z0-9_-]{3,20}$"
RE_PASS = "^.{3,20}$"
RE_MAIL = "[\S]+@[\S]+.[\S]+$"

secret = "qwdc456&d^"


def make_secure_value(val):
	return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_user_cookie(value):
	val = value.split("|")[0]
	if value == make_secure_value(val): 
		return val

def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)


class User(ndb.Model):
	pw_hash = ndb.StringProperty(required = True)
	email = ndb.StringProperty()
	name = ndb.StringProperty(required = True)

	@classmethod
	def by_name(cls, name):
		u = User.query(User.name == name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(name = name, pw_hash = pw_hash, email = email)


class Signup(Handler):
	def get(self):
		return self.render("signup.html")

	def post(self):
		has_errors = False
		self.username = cgi.escape(self.request.get('username'))
		self.password = cgi.escape(self.request.get('password'))
		self.verify = cgi.escape(self.request.get('verify'))
		self.email = cgi.escape(self.request.get('email'))
		params = dict(username = self.username, email = self.email)

		if not re.match(RE_USER, self.username):
			params['err_user'] = 'Invalid username'
			has_errors = True
		if not re.match(RE_PASS, self.password):
			params['err_pass'] = 'Invalid password'
			has_errors = True
		if self.verify != self.password:
			params['err_verify'] = 'Passwords must match'
			has_errors = True
		if self.email and not re.match(RE_MAIL, self.email):
			params['err_email'] = 'Invalid email'
			has_errors = True

		if has_errors:
			self.render("signup.html", **params)
		else:
			self.success()

	def success(self):
		u = User.by_name(self.username)
		if u:
			self.render('signup.html', err_user = "Username already exists")
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()
			self.login(u)
			self.redirect('/')


class Login(Handler):
	def get(self):
		return self.render("login.html")

	def post(self):
		username = cgi.escape(self.request.get('username'))
		password = cgi.escape(self.request.get('password'))

		u = User.by_name(username)
		if u and valid_pw(username, password, u.pw_hash):
			self.login(u)
			self.redirect("/")
		else:
			self.render("login.html", error = "Invalid login")


class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect("/")


#### Cache management

def age_set(key, val):
	# add item AND time to cache
	memcache.delete(key) # explicitly delete key;
	memcache.set(key,(val, time.time()))

def age_get(key):
	# get item and time from cache
	r = memcache.get(key)

	if r:
		val, save_time = r
		age = time.time() - int(save_time)
	else:
		val, age = None, 0

	return val, age


#### Lets go!

RE_URL = '([a-zA-Z0-9_\-\s]+)'

app = webapp2.WSGIApplication([ ('/', HomePage), 
								("/create", AddList),
								("/list/"+RE_URL, ListPage),
								("/list/"+RE_URL+"/hide", Hide),
								("/list/"+RE_URL+"/share", Share),
								('/signup', Signup), 
								('/login', Login), 
								('/logout', Logout)], debug=True)