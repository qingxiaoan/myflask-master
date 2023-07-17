import numpy as np
import pymysql
from flask import Flask, render_template, redirect, request, session, flash, jsonify, abort, make_response, json
from flask_bootstrap import Bootstrap
from model.DataResponse import DataResponse
import sqlite3
from flask_cors import *

from werkzeug.security import check_password_hash

from function import hash_code

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nemo'
bootstrap = Bootstrap(app)
app.config['MYSQL_HOST'] = '101.43.129.9'  # 数据库地址
app.config['MYSQL_PORT'] = 3306  # 数据库端口
app.config['MYSQL_USER'] = 'root'  # 数据库用户名
app.config['MYSQL_PASSWORD'] = 'asdfghjkl'  # 数据库密码
app.config['MYSQL_DB'] = 'demo'  # 数据库名称


@app.route('/')
@cross_origin()
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET'])
@cross_origin()
def login2():
    return render_template('login.html')


@app.route('/login3', methods=['POST'])
@cross_origin()
def login3():
    print(request.form.get('username'))
    response = DataResponse(False, {'message': 'ssy登录失败'})
    return render_template('login_bk.html')


@app.route('/login2', methods=['POST'])
@cross_origin()
def login():
    data = json.loads(request.data)
    username = data['username']
    password = data['password']
    print("松鼠鱼测试", username, password)
    conn = pymysql.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        db=app.config['MYSQL_DB']
    )
    db_password = ''
    cur = conn.cursor()
    try:
        # sqlite3支持?占位符，通过绑定变量的查询方式杜绝sql注入
        cur.execute("SELECT password FROM userinfo WHERE username=%s", (username,))
        result = cur.fetchone()
        cur.close()

        if result:
            db_password = result[0]
    except:
        flash("error")
        # return render_template('login.html')
    finally:
        conn.close()

    if db_password == password:
        # 登录成功后存储session信息
        session['is_login'] = True
        session['name'] = username
        response = DataResponse(True, {'message': '登录成功'})
    else:
        flash('用户名或密码错误！')
        response = DataResponse(False, {'message': 'ssy登录失败'})
    return jsonify(response.to_dict())


@app.route('/register', methods=['GET', 'POST'])
@cross_origin()
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm')
        # 判断所有输入都不为空
        if username and password and confirm_password:
            if password != confirm_password:
                flash('两次输入的密码不一致！')
                return render_template('register.html', username=username)
            # 连接数据库
            # conn = sqlite3.connect('db.db')
            # cur = conn.cursor()
            conn = pymysql.connect(
                host=app.config['MYSQL_HOST'],
                user=app.config['MYSQL_USER'],
                password=app.config['MYSQL_PASSWORD'],
                db=app.config['MYSQL_DB']
            )
            cur = conn.cursor()
            # 查询输入的用户名是否已经存在
            # sql_same_user = 'SELECT 1 FROM userinfo WHERE USERNAME=%s'
            # same_user = cur.execute(sql_same_user, (username,)).fetchone()
            cur.execute("SELECT * FROM userinfo WHERE username=%s", (username,))
            same_user = cur.fetchone()
            if same_user:
                flash('用户名已存在！')
                return render_template('register.html', username=username)
            # 通过检查的数据，插入数据库表中
            sql_insert_user = 'INSERT INTO userinfo (username, password) VALUES (%s, %s)'
            cur.execute(sql_insert_user, (username, password))
            conn.commit()
            conn.close()
            # 重定向到登录页面
            return redirect('/')
        else:
            flash('所有字段都必须输入！')
            if username:
                return render_template('register.html', username=username)
            return render_template('register.html')
    return render_template('register.html')


@app.route('/logout')
def logout():
    # 退出登录，清空session
    if session.get('is_login'):
        session.clear()
        return redirect('/')
    return redirect('/')


@app.route('/api/adduser', methods=['GET', 'POST'])
def add_user():
    if request.json:
        username = request.json.get('username', '').strip()
        password = request.json.get('password')
        confirm_password = request.json.get('confirm')
        # 判断所有输入都不为空
        if username and password and confirm_password:
            if password != confirm_password:
                return jsonify({'code': '400', 'msg': '两次密码不匹配！'}), 400
            # 连接数据  库
            conn = sqlite3.connect('db.db')
            cur = conn.cursor()
            # 查询输入的用户名是否已经存在
            sql_same_user = 'SELECT 1 FROM USER WHERE USERNAME=?'
            same_user = cur.execute(sql_same_user, (username,)).fetchone()
            if same_user:
                return jsonify({'code': '400', 'msg': '用户名已存在'}), 400
            # 通过检查的数据，插入数据库表中
            sql_insert_user = 'INSERT INTO USER(USERNAME, PASSWORD) VALUES (?,?)'
            cur.execute(sql_insert_user, (username, hash_code(password)))
            conn.commit()
            sql_new_user = 'SELECT id,username FROM USER WHERE USERNAME=?'
            user_id, user = cur.execute(sql_new_user, (username,)).fetchone()
            conn.close()
            return jsonify({'code': '200', 'msg': '账号生成成功！', 'newUser': {'id': user_id, 'user': user}})
        else:

            return jsonify({'code': '404', 'msg': '请求参数不全!'})
    else:
        abort(400)


@app.route('/api/testjson', methods=['GET', 'POST'])
def test_json():
    if 'x' in request.json:
        print(request.json)
        return jsonify(request.json)
    else:
        abort(400)


@app.route('/api/infoget', methods=['GET'])
def mock1():
    """
    简单的mock，客户端发送什么请求，直接以json格式返回请求数据
    :return:
    """
    conn = pymysql.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        db=app.config['MYSQL_DB']
    )
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM INFO")
    data = cursor.fetchall()
    cursor.close()
    return jsonify(data)


@app.route('/api/infopost', methods=['POST'])
def infopost():
    """
    简单的mock，客户端发送什么请求，直接以json格式返回请求数据
    :return:
    """
    conn = pymysql.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        db=app.config['MYSQL_DB']
    )
    cur = conn.cursor()
    smog = request.json['smog']
    CO = request.json['CO']
    CH4 = request.json['CH4']
    tem = request.json['tem']
    sql_insert_user = 'INSERT INTO INFO (smog, CO,CH4,tem) VALUES (%s, %s,%s, %s)'
    cur.execute(sql_insert_user, (smog, CO, CH4, tem))
    query = "SELECT MIN(id) FROM INFO"
    cur.execute(query)
    result = cur.fetchone()
    min_id = int(result[0])
    print(min_id)
    cur.execute('DELETE FROM INFO WHERE id = %s', (min_id))
    conn.commit()
    conn.close()
    return jsonify(request.json)


@app.route('/api/mock', methods=['GET'])
def mock():
    conn = pymysql.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        db=app.config['MYSQL_DB']
    )
    cur = conn.cursor()
    query = "SELECT MAX(id) FROM INFO"
    cur.execute(query)
    result = cur.fetchone()
    max_id = int(result[0])
    # data_last = "SELECT * FROM INFO WHERE id = %s"
    # # fin = cur.execute(data_last, (max_id,)).fetchone()
    # sql_new_user = 'SELECT smog,CH4,CO,tem FROM INFO WHERE id = %s'
    # smog, CH4, CO, tem = cur.execute(sql_new_user, max_id).fetchone()
    # jg_list = [smog, CH4, CO, tem]
    query = "SELECT * FROM INFO WHERE id = (SELECT MAX(id) FROM INFO)"
    cur.execute(query)
    result = cur.fetchone()
    conn.commit()
    conn.close()
    return jsonify(result)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port='5000')
