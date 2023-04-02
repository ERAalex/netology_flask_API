from datetime import datetime, timedelta
from flask import Flask
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask import request
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_swagger_ui import get_swaggerui_blueprint
import json

app = Flask('app')


app.config['SECRET_KEY'] = 'assdfweff3f24fvvmfl2330bfv2313kmfwemfweDDSDM243mdDAD56gg'
app.config["JWT_SECRET_KEY"] = "sadsad6323djda223"

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1221@localhost:5432/task1_flask'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# Configure Swagger UI
SWAGGER_URL = '/swagger'
API_URL = 'http://127.0.0.1:5000/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "DESCRIPTION of my API"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

@app.route('/swagger.json')
def swagger():
    with open('swagger.json', 'r') as f:
        return jsonify(json.load(f))



class User(db.Model):
    """ User Model for storing user related details """
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    login = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, default=datetime.utcnow)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    articles = db.relationship('Article', backref='user', cascade='all, delete, delete-orphan')


class Article(db.Model):
    __tablename__ = "articles"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    text = db.Column(db.String(500))
    show_article = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# create tables User + Article on DB
# with app.app_context():
#     db.create_all()
#     db.session.commit()    # <- Here commit changes to database
#     print('tables created')


# decorator for verifying the JWT
def token_required(f):
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])

            current_user = User.query \
                .filter_by(login=data['login']) \
                .first()
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        resul_user = data['id']
        return f(*((resul_user,)+args), **kwargs)
    # внимание! тут мы берем с собой из декоратора данные по пользователю (result_user), его 'id', поэтому в
    # функции роутера мы должны прописать параметр. нам это надо например, чтобы посмотреть может ли этот юзер
    # удалить сатью (его ли статья) ниже конструкция позволяет не перезаписывать аргумент декоратора,
    # тем который прописан в роутере.
    decorated.__name__ = f.__name__
    return decorated


# route for recive token
@app.route('/api/create_token', methods=['POST'])
def token_create():
    data = request.get_json()

    login_user = data['login']
    user = User.query.filter_by(login=login_user).first()

    if user is None:
        return jsonify({'message': 'пользователь не найден'})

    if check_password_hash(user.password, data['password']):
        token = jwt.encode({
            'id': user.id,
            'login': user.login,
            'exp': datetime.utcnow() + timedelta(minutes=60)
        }, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    else:
        return jsonify({'message': 'Вы ввели не корректный пароль'})


# GET information about all users - ONLY if you have token
@app.route('/api/users', methods=['GET'])
@token_required
def get_all_users(user_id):
    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['email'] = user.email
        user_data['login'] = user.login
        user_data['registered_on'] = user.registered_on
        output.append(user_data)

    return jsonify({'пользователи': output})


# Find some user by his id
@app.route('/api/user/<id>', methods=['GET'])
def get_one_user(id):
    user = User.query.filter_by(id=id).first()

    if user is None:
        return jsonify({'message': 'пользователь не найден'})

    user_data = {}
    user_data['id'] = user.id
    user_data['email'] = user.email
    user_data['login'] = user.login
    user_data['registered_on'] = user.registered_on

    return jsonify({'Данные по пользователю': user_data})


# Create new user
@app.route('/api/user', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(login=data['login'], email=data['email'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': f'New user created! name - {data["login"]}'})


# Give to some user admin status
@app.route('/api/user/admin_rights/<id>', methods=['PUT'])
def promote_user(id):
    user = User.query.filter_by(id=id).first()

    if user is None:
        return jsonify({'message': 'пользователь - не найден'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': f'user -{user.login} have admin rights now'})


# Delete some user
@app.route('/api/user/<id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.filter_by(id=id).first()

    if user is None:
        return jsonify({'message': 'пользователь - не найден'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': f'user -{user.login} was deleted'})


####### CREATE ARTICLES #######

# Create new  article associated with some user_id
@app.route('/api/article', methods=['POST'])
def create_article():
    data = request.get_json()

    user = User.query.filter_by(id=data['user_id']).first()
    if user is None:
        return jsonify({'message': 'пользователь - не найден, перепроверьте поле user_id'})

    new_article = Article(
        text=data['text'],
        show_article=True,
        user_id=data['user_id'])

    db.session.add(new_article)
    db.session.commit()
    return jsonify({'message': f'New Article created! text:  {data["text"]}'})


# Get all articles
@app.route('/api/article', methods=['GET'])
def get_all_articles():
    articles = Article.query.all()
    output = []

    for article in articles:
        article_data = {}
        article_data['id'] = article.id
        article_data['text'] = article.text
        user = User.query.filter_by(id=article.id).first()
        article_data['user_id'] = str(article.user_id) + ' - ' + user.login

        output.append(article_data)

    return jsonify({'все статьи': output})


# Change text in our article
@app.route('/api/article/<id>', methods=['PUT'])
@token_required
def change_article(result_user, id):
    print(f'user_id - {result_user}')
    data = request.get_json()
    article = Article.query.filter_by(id=id).first()

    if article is None:
        return jsonify({'message': 'статья не найдена'})

    if result_user != article.user_id:
        return jsonify({'message': 'Это не Ваша статья и не Вам ее редактировать!'})

    article.text = data['text']
    db.session.commit()

    return jsonify({'message': 'Статья успешно изменена'})


# Delete article can only user who created
@app.route('/api/article/<id>', methods=['DELETE'])
@token_required
def delete_article(result_user, id):
    print(f'user_id - {result_user}')
    article = Article.query.filter_by(id=id).first()

    if article is None:
        return jsonify({'message': 'статья не найдена'})

    if result_user != article.user_id:
        return jsonify({'message': 'Это не Ваша статья и не Вам ее удалять!'})

    db.session.delete(article)
    db.session.commit()

    return jsonify({'message': 'Статья успешно удалена'})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)