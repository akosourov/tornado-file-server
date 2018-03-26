# tornado-file-server
Файловый http сервер построенный на tornado, позволяющий зайти под пользователем, загрузить
pdf-файл. Загруженный pdf-файл в фоне сконвертируется в изображения png. Сервер позволяет скачивать
загруженные и сконфертированные файлы.

todo
Поделить конвертацию pdf в png на части (обработку по частям)

Для запуска (Linux Ubuntu, Python 3):
```
apt-get install libmagickwand-dev
git clone https://github.com/akosourov/tornado-file-server
cd tornado-file-server
pip install -r requirements.txt
python server.py
```