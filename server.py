from socketserver import ThreadingUnixStreamServer, StreamRequestHandler
import os

class socket_listen_server(StreamRequestHandler):
    def handle(self):
        username = self.rfile.readline(512).strip().lower()
        print("Username {}".format(username))
        password = self.rfile.readline(512).strip()
        print("Password {}".format(password))
        response = b"0"
        self.wfile.write(response)

if __name__ == '__main__':
    socket = "/tmp/sock"
    os.unlink(socket)
    print("Starting Listening on {}".format(socket))
    ThreadingUnixStreamServer(socket,socket_listen_server).serve_forever()
