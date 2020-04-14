import sys
import time
import logging
from flask_table import Table, Col
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from json import loads
from json.decoder import JSONDecodeError
from Crypto.Util.number import bytes_to_long

class ItemTable(Table):
    a = Col('a')
    m = Col('m',column_html_attrs = {"style" : "word-break:break-all;"})
    c = Col("c",column_html_attrs = {"style" : "word-break:break-all;"})
    s = Col("s",column_html_attrs = {"style" : "word-break:break-all;"})

def generate_html():
    items = []
    try:
        lines = open("{}/provider2/service_data/votes".format(sys.argv[1]), "r").readlines()
        for line in lines:
            try:
                item = loads(line)
                items.append(item)
            except JSONDecodeError:
                print(line)
    except FileNotFoundError:
        pass
    try:
        lines = open("{}/provider1/service_data/votes".format(sys.argv[1]), "r").readlines()
        for line in lines:
            try:
                item = loads(line)
                items.append(item)
            except JSONDecodeError:
                print(line)
    except FileNotFoundError:
        pass

    table = ItemTable(items)
    with open("static/index.html", "w") as f:
        f.write(table.__html__())

def handler(event):
    if "votes" in event.src_path :
        generate_html()

if __name__ == "__main__":
    path = sys.argv[1]
    generate_html()
    event_handler = FileSystemEventHandler()
    event_handler.on_any_event = handler
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()