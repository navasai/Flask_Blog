import os
import secrets
from PIL import Image
from flaskblog import app, db, bcrypt, mail
from flask import render_template, url_for, flash, redirect, request, abort
from flaskblog.forms import (RegistrationForm, LoginForm, 
							UpdateAccountForm, PostForm, ResetRequestForm, ResetPasswordForm)
from flaskblog.models import User,Post
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message

@app.route('/')
def home():
	posts = Post.query.all()
	return render_template('home.html',posts=posts)

@app.route('/about')
def about():
	return render_template('about.html',title='About')

@app.route('/login',methods=['POST','GET'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user and bcrypt.check_password_hash(user.password,form.password.data):
			login_user(user,remember=form.remember.data)
			next_page = request.args.get('next')
			return redirect(next_page) if next_page else redirect(url_for('home'))
		else:
			flash('Login is Unsuccessfull. Please enter valid email and password','danger')
	return render_template('login.html',title='Login',form=form)

@app.route('/register',methods=['POST','GET'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = RegistrationForm()
	if form.validate_on_submit():
		hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user=User(username=form.username.data,email=form.email.data,password=hashed_password)
		db.session.add(user)
		db.session.commit()
		flash('Your account is created successfully! Now You can Log In','success')
		return redirect(url_for('login'))
	return render_template('register.html',title='Register',form=form)

@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('home'))

def save_picture(form_picutre):
	random_hex = secrets.token_hex(8)
	_, f_ext = os.path.splitext(form_picutre.filename)

	picture_fn = random_hex + f_ext
	picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

	output_size = (125,125)
	i = Image.open(form_picutre)

	i.thumbnail(output_size)

	i.save(picture_path)

	return picture_fn

@app.route('/account',methods=['POST','GET'])
@login_required
def account():
	form = UpdateAccountForm()
	if form.validate_on_submit():
		if form.picture.data:
			picture_file = save_picture(form.picture.data)
			current_user.image_file = picture_file
		current_user.username = form.username.data
		current_user.email = form.email.data
		db.session.commit()
		logout()
		flash('Your account info is updated successfully! Now You can Log In','success')
		return redirect(url_for('login'))
	image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
	return render_template('account.html',title='Account', image_file=image_file,form=form)
	
@app.route('/post/new',methods=['GET','POST'])
@login_required
def new_post():
	form = PostForm()
	if form.validate_on_submit():
		post = Post(title = form.title.data, content = form.content.data, author = current_user)
		db.session.add(post)
		db.session.commit()
		flash('Your post is created successfully!','success')
		return redirect(url_for('home'))
	return render_template('create_post.html',title='New Post', form=form,legend='Create New Post')

@app.route('/post/<int:post_id>')
def post(post_id):
	post = Post.query.get_or_404(post_id)
	return render_template('post.html',title = post.title, post=post)

@app.route('/post/<int:post_id>/update', methods=['GET','POST'])
@login_required
def update_post(post_id):
	post = Post.query.get_or_404(post_id)
	if post.author != current_user:
		abort(403)
	form = PostForm()
	if form.validate_on_submit():
		post.title = form.title.data
		post.content = form.content.data
		db.session.commit()
		flash('Your post is updated successfully!','success')
		return redirect(url_for('post', post_id=post.id))
	elif request.method=='GET':
		form.title.data = post.title
		form.content.data = post.content
	return render_template('create_post.html',title='New Post', form=form, legend='Update This Post')

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
	post = Post.query.get_or_404(post_id)
	if post.author != current_user:
		abort(403)
	db.session.delete(post)
	db.session.commit()
	flash('Your post is deleted!','success')
	return redirect(url_for('home'))

def send_reset_email(user):
	token = user.get_reset_token()

	msg = Message('Password Reset Request', 
					sender='noreply@demo.com',
					recipients=[user.email])
	msg.body = f''' To reset password go through with below link:
				{ url_for('reset_password', token=token, _external=True) } 

				If you did not make any request. Please ignore this email.'''

	mail.send(msg)

@app.route('/reset_request',methods=['POST','GET'])
def reset_request():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = ResetRequestForm()
	if form.validate_on_submit():

		user = User.query.filter_by(email = form.email.data).first()
		send_reset_email(user)

		flash('An reset password link is sent to your mail.','info')
		return redirect(url_for('login'))
	return render_template('reset_request.html',title='Reset Password', form=form)

@app.route('/reset_password/<token>',methods=['POST','GET'])
def reset_password(token):
	if current_user.is_authenticated:
		return redirect(url_for('home'))

	user = User.verify_reset_token(token)

	if user is None:
		flash('Invalid or Expired Link','warning')
		return redirect(url_for('reset_request'))

	form = ResetPasswordForm()
	if form.validate_on_submit():
		hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user.password = hashed_password
		db.session.commit()
		flash('Your password is updated!','success')
		return redirect(url_for('login'))
	return render_template('reset_password.html',title='Reset Password', form=form)