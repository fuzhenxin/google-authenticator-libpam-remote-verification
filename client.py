from socketserver import ThreadingUnixStreamServer, StreamRequestHandler
import os, time, random
import socket
import multiprocessing


def send_request(sock_file_name, q):
    sock = socket.socket(socket.AF_UNIX , socket.SOCK_STREAM)
    sock.connect(sock_file_name)
    send_str = bytes(("TeSt"+str(int(random.random()*10))+"\n").encode('utf-8'))
    print(send_str)
    sock.send(send_str)
    print("Send 1 finished {}".format(send_str))
    time.sleep(random.random()*10)
    sock.send(send_str)
    print("Send 2 finished {}".format(send_str))
    res = sock.recv(1024)
    print(res)
    sock.close()
    q.put(res)


if __name__ == '__main__':

    sock_file_name = "/tmp/sock"

    q = multiprocessing.Queue()
    jobs = []
    for i in range(10):
        p = multiprocessing.Process(target=send_request, args=(sock_file_name, q))
        jobs.append(p)
        p.start()
    
    for p in jobs:
        p.join()
    
    results = [int(q.get()) for j in jobs]
    print(results)
    if sum(results)==0:
        print("Check Success")
    else:
        print("Check Failed")


