from socketserver import ThreadingUnixStreamServer, StreamRequestHandler
import os

class socket_listen_server(StreamRequestHandler):
    def handle(self):
        username = self.rfile.readline(512).strip()
        print("Username {}".format(username))
        otp_code = self.rfile.readline(512).strip()
        print("Otp code {}".format(otp_code))

        if username.decode("utf-8").startswith("TeSt"):
            if username!=otp_code: response = b"1"
            else: response = b"0"
            print([response])
            self.wfile.write(response)

if __name__ == '__main__':
    socket = "/tmp/sock"
    os.unlink(socket)
    print("Starting Listening on {}".format(socket))
    ThreadingUnixStreamServer(socket,socket_listen_server).serve_forever()
