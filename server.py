import bcrypt
import concurrent.futures
import logging
import os
import os.path
import sqlite3
import tornado.concurrent
import tornado.httpserver
import tornado.ioloop
import tornado.web
from wand.image import Image


logging.basicConfig(level=logging.DEBUG,
                    format='%(process)d|%(threadName)s %(asctime)s %(levelname)s %(message)s')


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', HomeHandler),
            (r'/sign_up', SignUpHandler),
            (r'/sign_in', SignInHandler),
            (r'/sign_out', SignOutHandler),
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
            # 'xsrf_cookies': True,   todo xsrf
            'auth_cookie_name': 'sid',
            'www_path': www_path
        }
        super(Application, self).__init__(handlers, **settings)

        db_path = os.path.join(www_path, 'data.db')
        self.conn = sqlite3.connect(db_path, isolation_level=None)    # autocommit=True
        self.cursor = self.conn.cursor()
        self._create_db_scheme()

    def _create_db_scheme(self):
        with open(self.settings['db_scheme_path'], 'r') as scheme_file:
            sql_commands = scheme_file.read().split(';')
            for sql in sql_commands:
                self.cursor.execute(sql)


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
    template = 'sign_up.html'

    def get(self):
        self.render(self.template, error='')

    def post(self):
        username = self.get_argument('username', None)
        if not username:
            self.render(self.template, error='Username is required')
            return
        password = self.get_argument('password', None)
        if not password:
            self.render(self.template, error='Password is required')
            return
        user = self.get_user_by_username(username)
        if user:
            self.render(self.template, error='Please, change username')
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


class SignInHandler(BaseHandler):
    template = 'sign_in.html'

    def get(self):
        self.clear_cookie(self.auth_cookie_name)
        self.render(self.template, error='')

    def post(self):
        username = self.get_argument('username', None)
        if not username:
            self.render(self.template, error='Username is required')
            return
        password = self.get_argument('password', None)
        if not password:
            self.render(self.template, error='Password is required')
            return

        user = self.get_user_by_username(username)
        if not user:
            self.render(self.template, error='User with this username is not registered')
            return

        # todo async
        hashed_password = bcrypt.hashpw(password.encode(), user.hashed_password)
        if hashed_password == user.hashed_password:
            self.set_secure_cookie(self.auth_cookie_name, str(user.id))
            self.redirect(self.get_argument('next', '/'))
        else:
            self.render(self.template, error='Password is incorrect')
            return


class SignOutHandler(BaseHandler):
    def get(self):
        self.clear_cookie(self.auth_cookie_name)
        self.redirect('/sign_in')


class HomeHandler(BaseHandler):
    executor = concurrent.futures.ThreadPoolExecutor(4)

    def _get_file_url(self, path):
        return path.lstrip(self.settings['www_path'])

    def _get_file_name(self, path):
        return os.path.split(path)[1]

    def get(self):
        if self.current_user:
            self.cursor.execute("""
                WITH tPDF AS (
                    SELECT
                      upl.id,
                      us.username,
                      upl.path,
                      upl.date_created
                    FROM upload AS upl
                      JOIN user AS us ON upl.user_id = us.id
                    WHERE upl.parent_id IS NULL
                ),
                  tPNG AS (
                    SELECT
                      parent_id,
                      group_concat(path) AS paths
                    FROM upload
                    WHERE parent_id IS NOT NULL
                    GROUP BY parent_id
                  )
                SELECT
                  tPDF.username,
                  tPDF.path,
                  tPDF.date_created,
                  tPNG.paths
                FROM tPDF
                  JOIN tPNG ON tPDF.id = tPNG.parent_id
                ORDER BY date_created
            """)
            pdf_list = [
                {
                    'username': username,
                    'pdf_name': self._get_file_name(path),
                    'pdf_url': self._get_file_url(path),
                    'date_created': str(date_created),
                    'png_names': [self._get_file_name(p) for p in png_paths.split(',')] if png_paths else [],
                    'png_urls': [self._get_file_url(p) for p in png_paths.split(',')] if png_paths else [],
                }
                for username, path, date_created, png_paths in self.cursor
            ]
        else:
            pdf_list = []
        self.render('home.html', pdf_list=pdf_list)

    def _pdf_to_png(self, pdf_path, png_path, user_id):
        logging.info('Convert PDF TO PNG ' + pdf_path)

        folder_path, pdf_name = os.path.split(pdf_path)

        # todo process chunk, suspend and resume!
        with Image(filename=pdf_path) as pdf:
            pdf.save(filename=png_path)
            basename = pdf_name.rstrip('.pdf')
            if len(pdf.sequence) > 1:
                images = ['{0}-{1.index}.png'.format(basename, x) for x in pdf.sequence]
            else:
                images = ['{}.png'.format(basename)]

        self.cursor.execute("SELECT id FROM upload WHERE path = ?", (pdf_path,))
        pdf_row = self.cursor.fetchone()
        pdf_row_id = pdf_row[0] if pdf_row else 0

        if pdf_row_id:
            for img_name in images:
                img_path = os.path.join(folder_path, img_name)
                self.cursor.execute("""
                    INSERT INTO upload (path, user_id, parent_id)
                      VALUES (?, ?, ?)
                """, (img_path, user_id, pdf_row_id))

    @tornado.web.gen.coroutine
    @tornado.web.authenticated
    def post(self):
        for _, files in self.request.files.items():
            for file_dict in files:
                filename = file_dict['filename']
                content_type = file_dict['content_type']
                data = file_dict['body']
                logging.info('POST %s %s %d' % (filename, content_type, len(data)))

                user = self.current_user

                upload_path = self.settings['upload_path']
                if not os.path.exists(upload_path):
                    os.makedirs(upload_path)
                user_folder_path = os.path.join(upload_path, user.username)
                if not os.path.exists(user_folder_path):
                    os.makedirs(user_folder_path)
                file_dir_name = filename.rstrip('.pdf')
                file_dir_path = os.path.join(user_folder_path, file_dir_name)
                if not os.path.exists(file_dir_path):
                    os.makedirs(file_dir_path)
                file_path = os.path.join(file_dir_path, filename)
                res = yield self._write_file(data, file_path)

                logging.info('writing file...done' + str(res))

                self.cursor.execute("""
                    INSERT INTO upload (path, user_id)
                      VALUES (?, ?)
                """, (file_path, user.id))

                # background task pdf to png
                png_path = file_path.rstrip('.pdf') + '.png'
                tornado.ioloop.IOLoop.current().spawn_callback(self._pdf_to_png,
                                                               file_path, png_path,
                                                               user.id)

                self.redirect('/')

    @tornado.concurrent.run_on_executor
    def _write_file(self, content, file_path):
        logging.info('writing file...')
        with open(file_path, 'wb') as f:
            # todo write chunk
            f.write(content)
        logging.info('writing file...done')
        return True


class UploadHandler(BaseHandler):
    executor = concurrent.futures.ThreadPoolExecutor(4)

    @tornado.web.gen.coroutine
    @tornado.web.authenticated
    def get(self, username, folder_name, file_name):
        file_path = os.path.join(self.settings['upload_path'],
                                 username, folder_name, file_name)
        if os.path.exists(file_path):
            content = yield self._read_file(file_path)
            self.set_header('Content-Type', 'application/pdf')
            self.set_header('Content-Disposition', 'attachment; filename="%s"' % file_name)
            self.set_header('Content-Length', len(content))
            self.write(content)
        else:
            self.send_error(404)

    @tornado.concurrent.run_on_executor
    def _read_file(self, file_path):
        with open(file_path, 'rb') as fo:
            # todo read chunk
            return fo.read()


def main():
    app = Application()
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(8080)
    tornado.ioloop.IOLoop.current().start()


if __name__ == '__main__':
    main()
