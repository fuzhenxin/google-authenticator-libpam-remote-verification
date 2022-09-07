import os, sys, time, json
from socketserver import ThreadingUnixStreamServer, StreamRequestHandler, ThreadingTCPServer
import qrcode, socket, pyotp
import mysql.connector
import config as config
import logging
import threading
logging.basicConfig(filename=config.LOGGING_PATH, format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)
# logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', level=logging.INFO)


class OTPDB:
    def __init__(self):
        self.mydb = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWD,
            database=config.DB_DATABASE,
            #auth_plugin='mysql_native_password'
        )
        self.table_name_secret = "otp_record"
        self.table_name_login = "otp_login"

        self.db_columns_secret = [
            ["user_id", "VARCHAR", 30, "PRIMARY KEY"],
            ["secret", "VARCHAR", 30],
            ["update_time", "DATETIME"]
        ]

        self.db_columns_login = [
            ["id", "INT", 4, "PRIMARY KEY AUTO_INCREMENT"],
            ["user_id", "VARCHAR", 30],
            ["remote_ip", "VARCHAR", 30],
            ["status", "VARCHAR", 30],
            ["request_time", "DOUBLE", "40,2"],
            ["update_time", "DATETIME"]
        ]

        self.mycursor = self.mydb.cursor()
        self.create_table(self.table_name_secret, self.db_columns_secret)
        self.create_table(self.table_name_login, self.db_columns_login)
        self.lock = threading.Lock()

    def create_table(self, table_name, db_columns):
        columns = []
        for i in db_columns:
            if len(i)==2:
                columns.append("{} {}".format(i[0], i[1]))
            elif len(i)==3:
                columns.append("{} {}({})".format(i[0],i[1],i[2]))
            elif len(i)==4:
                columns.append("{} {}({}) {}".format(i[0], i[1], i[2], i[3]))
        columns = ", ".join(columns)
        run_cmd = "CREATE TABLE IF NOT EXISTS {} ({})".format(table_name, columns)
        print(run_cmd)
        self.mycursor.execute(run_cmd)

    def get_secret(self, user_id, table_name):
        try:
            sql = 'select secret from {} where user_id="{}"'.format(table_name, user_id)
            self.mycursor.execute(sql)
            myresult = self.mycursor.fetchall()
            self.mydb.commit()
            return {"code": 0, "data": myresult}
        except Exception as inst:
            return {"code": -1, "reason": str(inst)}

    def get_loginstatus(self, login_id, table_name):
        try:
            sql = 'select status from {} where id="{}"'.format(table_name, login_id)
            self.mycursor.execute(sql)
            myresult = self.mycursor.fetchall()
            self.mydb.commit()
            return {"code": 0, "data": myresult}
        except Exception as inst:
            return {"code": -1, "reason": str(inst)}
    
    def get_loginqueue(self, user_id, thre_time, table_name):
        try:
            sql = 'select id,remote_ip,request_time from {} where status="request" and user_id="{}" and request_time>{}'.format(table_name, user_id, thre_time)
            self.mycursor.execute(sql)
            print(sql)
            myresult = self.mycursor.fetchall()
            self.mydb.commit()
            return {"code": 0, "data": myresult}
        except Exception as inst:
            return {"code": -1, "reason": str(inst)}

    def get_all_user(self, table_name):
        try:
            sql = "select user_id,secret from {}".format(table_name)
            self.mycursor.execute(sql)
            myresult = self.mycursor.fetchall()
            self.mydb.commit()
            return {"code": 0, "data": myresult}
        except Exception as inst:
            return {"code": -1, "reason": str(inst)}

    def insert_one_line(self, insert_dict, table_name):
        with self.lock:
            keys = []
            values = []
            for key,value in insert_dict.items():
                keys.append(key)
                values.append(value)
            keys = ", ".join(keys)
            sql = "REPLACE INTO {} ({}) VALUES ({})".format(table_name, keys,
                                                        ", ".join(["%s" for i in range(len(values))]))
            try:
                self.mycursor.execute(sql, values)
                self.mydb.commit()
                return {"code": 0, "data": self.mycursor.lastrowid}
            except mysql.connector.Error as inst:
                if inst.errno==1062:
                    return {"code": -2, "reason": str(inst)}
                return {"code": -1, "reason": str(inst)}
            except Exception as inst:
                return {"code": -1, "reason": str(inst)}

    def update_element(self, login_id, user_id, update_key, update_value, table_name):
        sql = "update {} set {}=%s where id=%s and user_id=%s".format(table_name, update_key)
        try:
            ret = self.mycursor.execute(sql, (update_value, login_id, user_id))
            ret = self.mydb.commit()
            return {"code": 0}
        except Exception as inst:
            return {"code": -1, "reason": ret_str}

class OTPUtils:
    def __init__(self):
        logging.info("OTPUTIL init!")
        self.datadb=OTPDB()

    def get_new_secret(self,user_id):
        scret_line = pyotp.random_base32()
        return {"code":0, "data": scret_line}

    def secret_to_url(self, user_id, secret):
        url_line = pyotp.totp.TOTP(secret).provisioning_uri(name='{}@{}'.format(user_id, config.OTP_ISSUER), issuer_name=config.OTP_ISSUER)
        return url_line

    def get_otp(self, user_id):
        ret = self.datadb.get_secret(user_id, self.datadb.table_name_secret)
        if ret["code"]<0:
            logging.error(str(user_id)+str(ret))
            return ret
        if len(ret["data"])==0:
            # return self.get_new_otp(user_id)
            return {"code": 0, "msg":"User not exist!", "userexist": False}
        else:
            return {"code": 0, "msg": ret["data"][0][0], "userexist": True}

    def get_new_otp(self, user_id):
        ret = self.get_new_secret(user_id)
        if ret["code"]<0:
            logging.error(str(user_id)+str(ret))
            return ret
        new_secret = ret["data"]

        insert_dict = {
            "user_id": user_id,
            "secret": new_secret,
            "update_time": time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        ret = self.datadb.insert_one_line(insert_dict, self.datadb.table_name_secret)
        if ret["code"]<0:
            logging.error(str(user_id)+str(ret))
            return ret
        return {"code": 0, "data": self.secret_to_url(user_id, new_secret)}
    
    def verify_code(self, userid, input_code):
        ret = self.get_otp(userid)
        if ret["code"]<0:
            logging.error(str(user_id)+str(ret))
            return ret
        if ret["code"]==0 and ret["userexist"] is False: return {"code": 0, "data": 2}
        secret = ret["msg"]
        totp = pyotp.TOTP(secret)
        code1 = totp.at(time.time())
        code2 = totp.at(time.time()-30)
        if input_code == code1 or input_code == code2: return {"code": 0, "data": 0}
        return {"code": 0, "data": 1}
    
    def new_verification_request(self, user_id, remote_ip):
        cur_time = time.time()
        insert_dict = {
            "user_id": user_id,
            "remote_ip": remote_ip,
            "status": "request",
            "request_time": cur_time,
            "update_time": time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        ret = self.datadb.insert_one_line(insert_dict, self.datadb.table_name_login)
        if ret["code"]<0:
            logging.error(str(user_id)+str(ret))
            return ret
        login_id = ret["data"]

        while True:
            cur_time1 = time.time()
            if cur_time1-cur_time>20: return {"code":0, "data":0} # Judge whether the user exists
            ret = self.datadb.get_loginstatus(login_id, self.datadb.table_name_login)["data"][0][0]
            if ret == "succ":
                print("SUCC")
                return {"code": 0, "data": b"0"}
            elif ret == "fail":
                return {"code": 0, "data": b"1"}
            else:
                pass            
            time.sleep(1)

    def get_login_request(self, user_id):
        ret = self.datadb.get_loginqueue(user_id, time.time()-10000, self.datadb.table_name_login)
        print(ret)
        if len(ret["data"])==0: return None
        return ret["data"][0]

    def login_verify(self, login_id, user_id, verify_msg):
        assert verify_msg in ["succ", "fail"]
        ret = self.datadb.update_element(login_id, user_id, "status", verify_msg, self.datadb.table_name_login)
        return ret


class OTPServer_scoket(StreamRequestHandler):
    def handle(self):
        try:
            verify_json = self.rfile.readline(512).strip()
            verify_dict = json.loads(verify_json)
            username = verify_dict["Username"]
            otpcode = verify_dict["OTPCode"]    
            ipaddr = verify_dict["IPAddr"]  
            connection_key = verify_dict["ConnectionKey"]

            ret_code = self.check_block(username, ipaddr)
            if ret_code!=b"0":
                self.wfile.write(ret_code) # 0 6 7
                return 

            if connection_key!=config.CONNECTION_KEY:
                self.wfile.write(b"9")
                return
            if otpcode=="UserExist":
                ret = self.server.otputil.get_otp(username)
                if ret["code"]<0:
                    logging.error(str(verify_dict)+str(ret))
                    response = b"9"
                elif ret["code"]==0 and ret["userexist"] is True: response = b"0"
                else: response = b"1"
            else:
                if otpcode=="111111":
                    print("Coming Here")
                    response = self.server.otputil.new_verification_request(username, ipaddr)["data"]
                else:
                    logging.info("Verification_"+ipaddr)
                    ret = self.server.otputil.verify_code(username, otpcode)
                    if ret["code"]<0:
                        logging.error(str(verify_dict)+str(ret))
                        response = b"9"
                    else: response = str(ret["data"]).encode()
            logging.info("User {} send code {} with response {}".format(username, otpcode, response))
            
            self.wfile.write(response)
        except Exception as inst:
            self.wfile.write(b"9")
            logging.error(str(inst))
        # verification code
        # 0 otp right
        # 1 otp wrong
        # 2 user not exist
        # 9 system wrong
        # 6 7 block

        # user exist code
        # 0 user not exist
        # 1 user exist
        # 9 system wrong


    def check_block(self, username, ipaddr):
        with self.server.lock_dup:
            if time.time()-self.server.ipblocking["time"] > 60*60:
                self.server.ipblocking = {"time": time.time()}
            dup_key = username+" "+ipaddr
            if dup_key in self.server.ipblocking and self.server.ipblocking[dup_key]>600:
                return b"7"
            if dup_key not in self.server.ipblocking:
                self.server.ipblocking[dup_key] = 1
            self.server.ipblocking[dup_key] += 1

            dup_key = username
            if dup_key in self.server.ipblocking and self.server.ipblocking[dup_key]>600:
                return b"6"
            if dup_key not in self.server.ipblocking:
                self.server.ipblocking[dup_key] = 1
            self.server.ipblocking[dup_key] += 1
            return b"0"

class OTPServerClient_scoket(StreamRequestHandler):
    def handle(self):
        try:
            username = self.rfile.readline(512).strip()
            otp_code = self.rfile.readline(512).strip()
            ip_addr = self.rfile.readline(512).strip()

            sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
            sock.connect((config.OTP_SERVER_ADDR, config.OTP_SERVER_PORT))

            send_str = (json.dumps({
                "Username": username.decode("utf-8"), 
                "OTPCode": otp_code.decode("utf-8"),
                "IPAddr": ip_addr.decode("utf-8"),
                "ConnectionKey": config.CONNECTION_KEY
                })+"\n").encode('utf-8')
            sock.send(send_str)
            res = sock.recv(1024)
            logging.info("Request {} with response {}".format(send_str, res))
            sock.close()
            self.wfile.write(res)
        except Exception as inst:
            self.wfile.write(b"9")
            logging.error(str(inst))

if __name__=="__main__":
    if sys.argv[1]=="server":
        server = ThreadingTCPServer((config.OTP_SERVER_ADDR, config.OTP_SERVER_PORT), OTPServer_scoket)
        server.otputil = OTPUtils()
        server.ipblocking = {"time": time.time()}
        server.lock_dup = threading.Lock()
        sys.stderr.write = logging.error
        sys.stdout.write = logging.info
        server.serve_forever()
    elif sys.argv[1]=="client":
        try:
            os.unlink(config.SOCK_ADDR)
        except Exception as inst:
            logging.error("Error {}".format(inst))
        logging.info("Listening on {}".format(config.SOCK_ADDR))
        sys.stderr.write = logging.error
        sys.stdout.write = logging.info
        ThreadingUnixStreamServer(config.SOCK_ADDR, OTPServerClient_scoket).serve_forever()
    elif sys.argv[1]=="util":
        otputil = OTPUtils()
        if sys.argv[2]=="new":
            ret = otputil.get_new_otp(sys.argv[3])
            qr = qrcode.QRCode()
            qr.add_data(ret["data"])
            qr.print_ascii()
        elif sys.argv[2]=="get":
            syswrite(otputil.get_otp(sys.argv[3]))
        elif sys.argv[2]=="verify":
            print(otputil.verify_code(sys.argv[3], sys.argv[4]))
        else:
            pass
    elif sys.argv[1]=="test":
        otputil = OTPUtils()
        otputil.new_verification_request("2106195055", "115.26.161.1")
        #otputil.get_login_request("2106195055")
    else:
        print("Please run with python OTPServer.py server|client|util")
