from models import Admin,Project,User,ParaphraseEntry
import logging
from flask import Flask, render_template, redirect, url_for, flash, request,session,jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from flask_ckeditor import CKEditor
from flask_migrate import Migrate
from extensions import login_manager,db
from functools import wraps




import os

from groq import Groq

GROQ_APIKEY="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"
app = Flask(__name__)

app.secret_key = 'seoscriberFlask'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///seoscriber.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db.init_app(app)
csrf = CSRFProtect(app)
login_manager.init_app(app)

migrate = Migrate(app, db)




class ProjectForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Save')



class ParaphraseForm(FlaskForm):
    text = TextAreaField('Text', validators=[DataRequired()], render_kw={"placeholder": "Enter text to paraphrase..."})
    submit = SubmitField('Suggestions')




@login_manager.user_loader
def load_user(user_id):
    # Check if the user_id belongs to User or Admin
    user = User.query.get(user_id)
    if user:
        return user

    admin = Admin.query.get(user_id)
    if admin:
        return admin

    return None
login_manager.login_view = "login"


@app.route("/")
def home():
    logged_in = current_user.is_authenticated
    name = current_user.username if logged_in else None
    return render_template("index.html", logged_in=logged_in, name=name)

@app.route("/login", methods=['GET', 'POST'])
def login():
    login_errors = {}
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            flash('Login successful!', 'success')
            login_user(user)
            return redirect(url_for('home'))
        else:
            login_errors['email'] = ['Invalid email or password.']
    return render_template('login_signup.html', login_errors=login_errors, signup_errors={})

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    signup_errors = {}
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm')

        if password != confirm:
            signup_errors['confirm'] = ['Passwords must match.']
        else:
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                signup_errors['email'] = ['Email already exists. Please log in.']
            else:
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                new_user = User(username=username, email=email, password=hashed_password)
                try:
                    db.session.add(new_user)
                    db.session.commit()
                    flash('Account created successfully!', 'success')
                    login_user(new_user)
                    return redirect(url_for('login'))
                except Exception as e:
                    db.session.rollback()
                    signup_errors['general'] = [f'Error creating account: {e}']
    return render_template('login_signup.html', login_errors={}, signup_errors=signup_errors)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))



def signup_requireds(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('signup'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/projects")
@signup_requireds  # Use the custom decorator
def projects():
    user_projects = Project.query.filter_by(user_id=current_user.id).all()
    form = ProjectForm()
    return render_template("projects.html", projects=user_projects, form=form)

@app.route("/projects/new", methods=['GET', 'POST'])
@login_required
def new_project():
    form = ProjectForm()
    if form.validate_on_submit():
        new_project = Project(title=form.title.data, description=form.description.data, user_id=current_user.id)
        db.session.add(new_project)
        db.session.commit()
        flash('Project created successfully!', 'success')
        return redirect(url_for('keyword_generation', project_id=new_project.id))

    return render_template('project_form.html', form=form)



@app.route("/projects/<int:project_id>/delete", methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        flash('You are not authorized to delete this project.', 'danger')
        return redirect(url_for('projects'))

    db.session.delete(project)
    db.session.commit()
    flash('Project deleted successfully!', 'success')
    return redirect(url_for('projects'))


class KeywordForm(FlaskForm):
    keyword = StringField('Keyword', validators=[DataRequired()])
@app.route('/project/<int:project_id>/keyword_generation', methods=['GET', 'POST'])
@login_required
def keyword_generation(project_id):
    form = KeywordForm()
    long_tail_keywords = []
    lsi_keywords = []
    keyword = ''

    if request.method == 'POST' and form.validate_on_submit():
        keyword = request.form.get('keyword')

        client = Groq(api_key=GROQ_APIKEY)  # Replace with your actual API key
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": f"Generate long tail keywords and LSI keywords for: {keyword}, dont use inverted commas and any other thing just generate keywords as mentioned and dont even give number mentioned of keyword just only word, dont use astericks at the start of word even"
                }
            ],
            model="llama3-8b-8192",
        )

        response = chat_completion.choices[0].message.content
        long_tail_keywords_section = False
        lsi_keywords_section = False

        for line in response.splitlines():
            line = line.strip()
            if "Long Tail Keywords" in line:
                long_tail_keywords_section = True
                lsi_keywords_section = False
                continue
            elif "LSI Keywords" in line:
                long_tail_keywords_section = False
                lsi_keywords_section = True
                continue

            if long_tail_keywords_section and line:
                long_tail_keywords.append(line)
            elif lsi_keywords_section and line:
                lsi_keywords.append(line)

        session[f'project_{project_id}_long_tail_keywords'] = long_tail_keywords
        session[f'project_{project_id}_lsi_keywords'] = lsi_keywords

    return render_template('keywordtoolhml.html', form=form, long_tail_keywords=long_tail_keywords, lsi_keywords=lsi_keywords, keyword=keyword, project_id=project_id)




@app.route('/project/<int:project_id>/paraphrase', methods=['GET', 'POST'])
@login_required
def paraphrase(project_id):
    suggestions = None
    if request.method == 'POST':
        data = request.json
        original_text = data.get('editor_content', '')

        # Generate prompt for Groq API
        prompt = (
            f"Analyze the following text and provide suggestions for improvement:\n\n"
            f"Text: {original_text}\n\n"
            "Suggestions:\n"
            "- Rewrite hard to read sentences.\n"
            "- Consider using active voices.\n"
            "- Replace too complex words.\n"
            "Dont use any asterick and inverted commas in the answer be straight forward and just give me the suggestions and dont even say here are the suggesions , Dont mention any other line except the suggestions"
        )

        # Initialize Groq client
        client = Groq(api_key=GROQ_APIKEY)

        # Call Groq API for suggestions
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model="llama3-8b-8192",
        )

        # Retrieve suggestions from Groq API response
        response = chat_completion.choices[0].message.content
        suggestions = response

        # Save entry with suggestions to database (optional)
        new_entry = ParaphraseEntry(
            user_id=current_user.id,
            project_id=project_id,
            original_text=original_text,
            suggestions=suggestions,
            long_tail_keywords=session.get(f'project_{project_id}_long_tail_keywords', []),
            lsi_keywords=session.get(f'project_{project_id}_lsi_keywords', [])
        )
        db.session.add(new_entry)
        db.session.commit()

        # Return suggestions as JSON response for AJAX handling
        return jsonify({'suggestions': suggestions})

    # Fetch existing keywords and latest entry for rendering paraphrase.html
    long_tail_keywords = session.get(f'project_{project_id}_long_tail_keywords', [])
    lsi_keywords = session.get(f'project_{project_id}_lsi_keywords', [])

    latest_entry = ParaphraseEntry.query.filter_by(user_id=current_user.id, project_id=project_id).order_by(
        ParaphraseEntry.id.desc()).first()

    # Render the HTML template for GET request
    return render_template('paraphrase.html',
                           long_tail_keywords=long_tail_keywords,
                           lsi_keywords=lsi_keywords,
                           form=ParaphraseForm(),
                           latest_entry=latest_entry,
                           project_id=project_id,
                           suggestions=suggestions)
@app.route('/projects/<int:project_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project.user_id != current_user.id:
        flash('You are not authorized to edit this project.', 'danger')
        return redirect(url_for('projects'))

    if request.method == 'POST':
        data = request.json
        original_text = data.get('editor_content', '')

        # Create the prompt for the Groq API
        prompt = (
            f"Analyze the following text and provide suggestions for improvement:\n\n"
            f"Text: {original_text}\n\n"
            "Suggestions:\n"
            "- Rewrite hard to read sentences.\n"
            "- Consider using active voices.\n"
            "- Replace too complex words.\n"
        )

        client = Groq(api_key=GROQ_APIKEY)  # Replace with your actual API key
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model="llama3-8b-8192",
        )

        response = chat_completion.choices[0].message.content
        suggestions = response

        # Save the paraphrased text, keywords, and suggestions to the database
        new_entry = ParaphraseEntry(
            user_id=current_user.id,
            project_id=project.id,
            original_text=original_text,
            suggestions=suggestions,
            long_tail_keywords=session.get('long_tail_keywords', []),
            lsi_keywords=session.get('lsi_keywords', [])
        )
        db.session.add(new_entry)
        db.session.commit()

        return jsonify({'suggestions': suggestions})

    # Fetch existing entries for the project
    latest_entry = ParaphraseEntry.query.filter_by(user_id=current_user.id, project_id=project.id).order_by(ParaphraseEntry.id.desc()).first()

    long_tail_keywords = latest_entry.long_tail_keywords if latest_entry else []
    lsi_keywords = latest_entry.lsi_keywords if latest_entry else []

    return render_template('paraphrase.html',
                           long_tail_keywords=long_tail_keywords,
                           lsi_keywords=lsi_keywords,
                           form=ParaphraseForm(),
                           latest_entry=latest_entry,
                           project_id=project.id)

@app.route('/project/<int:project_id>/save_content', methods=['POST'])
@login_required
def save_content(project_id):
    data = request.json
    editor_content = data.get('editor_content', '')
    long_tail_keywords = data.get('long_tail_keywords', [])
    lsi_keywords = data.get('lsi_keywords', [])

    new_entry = ParaphraseEntry(
        user_id=current_user.id,
        project_id=project_id,
        original_text=editor_content,
        long_tail_keywords=long_tail_keywords,
        lsi_keywords=lsi_keywords
    )
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({'message': 'Content saved successfully!'})



@app.route('/adminsignin', methods=['GET', 'POST'])
def admin_signin():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Query Admin table for the provided username and password
        admin = Admin.query.filter_by(admin=username, password=password).first()

        if admin:
            # Successful login
            login_user(admin)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))  # Replace 'dashboard' with your actual dashboard route

        else:
            # Login failed
            flash('Incorrect username or password. Please try again.', 'danger')

    return render_template('admin_signin.html')



@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # Fetch all users
    users = User.query.all()

    if request.method == 'POST':
        # Handle form submission for creating a new user
        if request.form['action'] == 'create':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']

            # Example: Create new user
            new_user = User(username=username, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('User created successfully!', 'success')
            return redirect(url_for('dashboard'))

        # Handle form submission for updating a user
        elif request.form['action'] == 'update':
            user_id = request.form['user_id']
            username = request.form['username']
            email = request.form['email']

            # Example: Update user
            user = User.query.get(user_id)
            if user:
                user.username = username
                user.email = email
                db.session.commit()
                flash('User updated successfully!', 'success')
            else:
                flash('User not found.', 'danger')
            return redirect(url_for('dashboard'))

        # Handle form submission for deleting a user
        elif request.form['action'] == 'delete':
            user_id = request.form['user_id']

            # Example: Delete user
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                flash('User deleted successfully!', 'success')
            else:
                flash('User not found.', 'danger')
            return redirect(url_for('dashboard'))

    return render_template('dashboard.html', users=users)


# Example routes for CRUD operations
@app.route('/update_user', methods=['POST'])
@login_required
def update_user():


    user_id = request.form.get('user_id')
    username = request.form.get('username')
    email = request.form.get('email')

    user = User.query.get(user_id)
    if user:
        user.username = username
        user.email = email
        db.session.commit()
        flash('User updated successfully!', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('dashboard'))  # Redirect to the dashboard endpoint

@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():

    user_id = request.form.get('user_id')

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('dashboard'))  # Redirect to the dashboard endpoint



@app.route('/create_user', methods=['POST'])
@login_required
def create_user():


    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    # Example: Create new user
    new_user = User(username=username, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()
    flash('User created successfully!', 'success')

    return redirect(url_for('dashboard'))  # Redirect to the dashboard endpoint

@app.route('/logout_admin')
@login_required
def logout_admin():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))
#
#
# def get_synonyms(word):
#     synonyms = set()
#     for syn in wordnet.synsets(word):
#         for lemma in syn.lemmas():
#             synonym = lemma.name().replace('_', ' ').lower()
#             if synonym != word:
#                 synonyms.add(synonym)
#     return list(synonyms)
#
#
# def paraphrase_sentence(sentence):
#     words = word_tokenize(sentence)
#     tagged_words = pos_tag(words)
#
#     new_sentence = []
#     for word, tag in tagged_words:
#         if tag.startswith('NN') or tag.startswith('VB') or tag.startswith('JJ'):
#             synonyms = get_synonyms(word)
#             if synonyms:
#                 new_word = random.choice(synonyms)
#                 new_sentence.append(new_word)
#             else:
#                 new_sentence.append(word)
#         else:
#             new_sentence.append(word)
#
#     return ' '.join(new_sentence)
#
#
# def paraphrase_text(text, variation=3):
#     blob = TextBlob(text)
#     sentences = blob.sentences
#     paraphrased_sentences = [paraphrase_sentence(str(sentence)) for sentence in sentences]
#
#     for _ in range(variation - 1):
#         additional_sentences = [paraphrase_sentence(str(sentence)) for sentence in sentences]
#         paraphrased_sentences.extend(additional_sentences)
#
#     return ' '.join(paraphrased_sentences)

@app.route('/paraphrasetool', methods=['GET', 'POST'])
def paraphrasetool():
    original_text = ""
    paraphrased_text = None

    if request.method == 'POST':
        original_text = request.form.get('text', '')

        # Initialize Groq client
        client = Groq(api_key=GROQ_APIKEY)

        # Create prompt for Groq API
        prompt = f"Paraphrase the following text but not include anything else init be straight forward just give me the paraphrased text:\n\n{original_text}"

        # Send prompt to Groq API
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model="llama3-8b-8192",
        )

        # Extract response from Groq API
        response = chat_completion.choices[0].message.content

        paraphrased_text = response
        print(paraphrased_text)
        # Return paraphrased text as JSON response
        return jsonify({'paraphrased_text': paraphrased_text})

    return render_template('paraphrasingtool.html', original_text=original_text, paraphrased_text=paraphrased_text)

@app.route("/keyword_gen", methods=['GET', 'POST'])
def keyword_gen():
    form = KeywordForm()
    long_tail_keywords = []
    lsi_keywords = []
    keyword = ''

    if request.method == 'POST' :
        keyword = request.form.get('keyword')

        client = Groq(api_key=GROQ_APIKEY)  # Replace with your actual API key
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": f"Generate long tail keywords and LSI keywords for: {keyword}, dont use inverted commas and any other thing just generate keywords as mentioned and dont even give number mentioned of keyword just only word, dont use astericks at the start of word even"
                }
            ],
            model="llama3-8b-8192",
        )

        response = chat_completion.choices[0].message.content
        long_tail_keywords_section = False
        lsi_keywords_section = False

        for line in response.splitlines():
            line = line.strip()
            if "Long Tail Keywords" in line:
                long_tail_keywords_section = True
                lsi_keywords_section = False
                continue
            elif "LSI Keywords" in line:
                long_tail_keywords_section = False
                lsi_keywords_section = True
                continue

            if long_tail_keywords_section and line:
                long_tail_keywords.append(line)
            elif lsi_keywords_section and line:
                lsi_keywords.append(line)

    return render_template("keyword_gen.html", form=form, long_tail_keywords=long_tail_keywords, lsi_keywords=lsi_keywords)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    with app.app_context():
        db.create_all()
    app.run(debug=True)


# keyboard and paraphrase no restrictiion
# writing assisstant restriction


