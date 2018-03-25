import bcrypt
import logging
import os
import os.path
import sqlite3
import tornado.httpserver
import tornado.ioloop
import tornado.web


logging.basicConfig(level=logging.DEBUG,
                    format='%(process)d|%(threadName)s %(asctime)s %(levelname)s %(message)s')

# todo xsrf
class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', HomeHandler),
            (r'/sign_up', SignUpHandler),
            (r'/uploads/(.+)/(.+)/(.+)', UploadHandler),
        ]
        www_path = os.path.dirname(__file__)
        settings = {
            'template_path': os.path.join(www_path, 'templates'),
            'upload_path': os.path.join(www_path, 'uploads'),
            'db_scheme_path': os.path.join(www_path, 'scheme.sql'),
            'debug': True,
            'cookie_secret': 'my_super_secret_key',
            'login_url': '/sign_in',
            # 'xsrf_cookies': True,
            'auth_cookie_name': 'sid'
        }
        super(Application, self).__init__(handlers, **settings)

        db_path = os.path.join(www_path, 'data.db')
        self.conn = sqlite3.connect(db_path)    # autocommit=True
        self.cursor = self.conn.cursor()
        self._create_db_scheme()

    def _create_db_scheme(self):
        with open(self.settings['db_scheme_path'], 'r') as scheme_file:
            self.cursor.execute(scheme_file.read())


class User:
    def __init__(self, user_id=None, username=None, hashed_password=None):
        self.id = user_id
        self.username = username
        self.hashed_password = hashed_password


class BaseHandler(tornado.web.RequestHandler):
    @property
    def cursor(self):
        return self.application.cursor

    @property
    def auth_cookie_name(self):
        return self.application.settings['auth_cookie_name']

    def get_current_user(self):
        user_id = self.get_secure_cookie(self.auth_cookie_name)
        if not user_id:
            return None
        try:
            user_id = int(user_id)
        except ValueError:
            user_id = 0
        self.cursor.execute("""
          SELECT id, username, hashed_password FROM user WHERE id = ?
        """, (user_id,))
        return self._make_user_from_row(self.cursor.fetchone())

    def get_user_by_username(self, username):
        self.cursor.execute("""
          SELECT id, username, hashed_password 
          FROM user WHERE username = ?
        """, (username,))
        return self._make_user_from_row(self.cursor.fetchone())

    @staticmethod
    def _make_user_from_row(row):
        if row is None:
            return None
        return User(*row)


class SignUpHandler(BaseHandler):
    def get(self):
        self.render('sign_up.html', error='')

    def post(self):
        username = self.get_argument('username', None)
        if not username:
            self.render('sign_up.html', error='Username is required')
            return
        password = self.get_argument('password', None)
        if not password:
            self.render('sign_up.html', error='Password is required')
            return
        user = self.get_user_by_username(username)
        if user:
            self.render('sign_up.html', error='Please, change username')
            return

        # todo async hash
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        self.cursor.execute("""
            INSERT INTO user (username, hashed_password)
            VALUES (?, ?)
        """, (username, hashed_password))
        user_id = self.cursor.lastrowid
        self.set_secure_cookie(self.auth_cookie_name, str(user_id))
        self.redirect('/')


class HomeHandler(BaseHandler):
    def get(self):
        pdf_list = [
            {
                'username': 'Vasya',
                'pdf_name': 'pdf-sample.pdf',
                'pdf_url': '/uploads/test_user/pdf-sample/pdf-sample.pdf'
            },
            {
                'username': 'Kolya',
                'pdf_name': 'pdf-sample.pdf',
                'pdf_url': '/uploads/test_user/pdf-sample/pdf-sample.pdf'
            },
        ]
        self.render('home.html', pdf_list=pdf_list, secure_cookie=self.get_secure_cookie(self.auth_cookie_name))

    def post(self):
        for _, files in self.request.files.items():
            for file_dict in files:
                filename = file_dict['filename']
                content_type = file_dict['content_type']
                data = file_dict['body']
                logging.info('POST %s %s %d' % (filename, content_type, len(data)))

                upload_path = self.settings['upload_path']
                if not os.path.exists(upload_path):
                    os.makedirs(upload_path)
                username = 'test_user'
                user_folder_path = os.path.join(upload_path, username)
                if not os.path.exists(user_folder_path):
                    os.makedirs(user_folder_path)
                file_dir_name = filename.rstrip('.pdf')
                file_dir_path = os.path.join(user_folder_path, file_dir_name)
                if not os.path.exists(file_dir_path):
                    os.makedirs(file_dir_path)
                file_path = os.path.join(file_dir_path, filename)
                with open(file_path, 'wb') as f:
                    f.write(data)
                    # todo pdf to png

                self.write('POST %s %s %d' % (filename, content_type, len(data)))


class UploadHandler(BaseHandler):
    def get(self, username, folder_name, file_name):
        file_path = os.path.join(self.settings['upload_path'],
                                 username, folder_name, file_name)
        if os.path.exists(file_path):
            fo = open(file_path, 'rb')
            data = fo.read()
            self.set_header('Content-Type', 'application/pdf')
            self.set_header('Content-Disposition', 'attachment; filename="%s"' % file_name)
            self.set_header('Content-Length', len(data))
            self.write(data)
            fo.close()
        else:
            self.send_error(404)


def main():
    app = Application()
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(8080)
    tornado.ioloop.IOLoop.current().start()


if __name__ == '__main__':
    main()
