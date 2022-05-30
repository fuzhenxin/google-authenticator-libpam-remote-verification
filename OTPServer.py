import os, sys, time, json
from socketserver import ThreadingUnixStreamServer, StreamRequestHandler, ThreadingTCPServer
import qrcode, socket, pyotp
import mysql.connector
import config

class OTPDB:
    def __init__(self):
        self.mydb = mysql.connector.connect(
            host=config.DB_HOST,
            user=config.DB_USER,
            password=config.DB_PASSWD,
            database=config.DB_DATABASE,
            #auth_plugin='mysql_native_password'
        )
        self.table_name = "otp_record"

        self.db_columns = [
            ["user_id", "VARCHAR", 30, "PRIMARY KEY"],
            ["secret", "VARCHAR", 30],
            ["update_time", "DATETIME"]
        ]

        self.mycursor = self.mydb.cursor()
        self.create_table()

    def create_table(self):
        columns = []
        for i in self.db_columns:
            if len(i)==2:
                columns.append("{} {}".format(i[0], i[1]))
            elif len(i)==3:
                columns.append("{} {}({})".format(i[0],i[1],i[2]))
            elif len(i)==4:
                columns.append("{} {}({}) {}".format(i[0], i[1], i[2], i[3]))
        columns = ", ".join(columns)
        run_cmd = "CREATE TABLE IF NOT EXISTS {} ({})".format(self.table_name, columns)
        self.mycursor.execute(run_cmd)

    def get_element(self, user_id):
        try:
            sql = 'select secret from {} where user_id="{}"'.format(self.table_name, user_id)
            print(sql)
            self.mycursor.execute(sql)
            myresult = self.mycursor.fetchall()
            self.mydb.commit()
            return {"code": 0, "data": myresult}
        except Exception as inst:
            return {"code": -1, "reason": str(inst)}

    def get_all_user(self):
        try:
            sql = "select user_id,secret from {}".format(self.table_name)
            self.mycursor.execute(sql)
            myresult = self.mycursor.fetchall()
            self.mydb.commit()
            return {"code": 0, "data": myresult}
        except Exception as inst:
            return {"code": -1, "reason": str(inst)}

    def insert_one_line(self, insert_dict):
        keys = []
        values = []
        for key,value in insert_dict.items():
            keys.append(key)
            values.append(value)
        keys = ", ".join(keys)
        sql = "REPLACE INTO {} ({}) VALUES ({})".format(self.table_name, keys,
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

class OTPUtils:
    def __init__(self):
        print("INIT OTPUTIL")
        self.datadb=OTPDB()

    def get_new_secret(self,user_id):
        scret_line = pyotp.random_base32()
        return {"code":0, "data": scret_line}

    def secret_to_url(self, user_id, secret):
        url_line = pyotp.totp.TOTP(secret).provisioning_uri(name='{}@{}'.format(user_id, config.OTP_ISSUER), issuer_name=config.OTP_ISSUER)
        return url_line

    def get_otp(self, user_id):
        ret = self.datadb.get_element(user_id)
        if ret["code"]<0: return ret
        if len(ret["data"])==0:
            # return self.get_new_otp(user_id)
            return {"code": 0, "msg":"User not exist!", "userexist": False}
        else:
            return {"code": 0, "msg": ret["data"][0][0], "userexist": True}

    def get_new_otp(self, user_id):
        ret = self.get_new_secret(user_id)
        if ret["code"] < 0: return ret
        new_secret = ret["data"]

        insert_dict = {
            "user_id": user_id,
            "secret": new_secret,
            "update_time": time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        ret = self.datadb.insert_one_line(insert_dict)
        if ret["code"]<0: return ret
        return {"code": 0, "data": self.secret_to_url(user_id, new_secret)}
    
    def verify_code(self, userid, input_code):
        ret = self.get_otp(userid)
        if ret["code"]<0: return ret
        if ret["code"]==0 and ret["userexist"] is False: return {"code": 0, "data": 2}
        secret = ret["msg"]
        print([secret])
        totp = pyotp.TOTP(secret)
        code1 = totp.at(time.time())
        code2 = totp.at(time.time()-30)
        if input_code == code1 or input_code == code2: return {"code": 0, "data": 0}
        return {"code": 0, "data": 1}

class OTPServer_scoket(StreamRequestHandler):
    otputil = None
    def handle(self):
        print("Listen new!")
        verify_json = self.rfile.readline(512).strip()
        verify_dict = json.loads(verify_json)
        username = verify_dict["Username"]
        otpcode = verify_dict["OTPCode"]       
        connection_key = verify_dict["ConnectionKey"]
        if connection_key!=config.CONNECTION_KEY:
            self.wfile.write("-4")
            return
        print([username, otpcode])
        if self.otputil is None: self.otputil = OTPUtils()
        if otpcode=="UserExist":
            ret = self.otputil.get_otp(username)
            if ret["code"]==0 and ret["userexist"] is True:
                ret = {"code":0, "data":0}
            else:
                ret = {"code":0, "data":1}
        else:
            ret = self.otputil.verify_code(username, otpcode)
        if ret["code"]<0:
            response="-1"
        else:
            response = str(ret["data"]).encode()
        print([response])
        self.wfile.write(response)
        # 0 otp right
        # 1 otp wrong
        # 2 user not exist

class OTPServerClient_scoket(StreamRequestHandler):
    def handle(self):
        username = self.rfile.readline(512).strip()
        print("Username {}".format(username))
        otp_code = self.rfile.readline(512).strip()
        print("Otp code {}".format(otp_code))

        sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
        print("Socket Connected")
        sock.connect((config.OTP_SERVER_ADDR, config.OTP_SERVER_PORT))

        send_str = (json.dumps({
            "Username": username.decode("utf-8"), 
            "OTPCode": otp_code.decode("utf-8"),
            "ConnectionKey": config.CONNECTION_KEY
            })+"\n").encode('utf-8')
        print([send_str])
        sock.send(send_str)
        print("Send finished {}".format(send_str))
        res = sock.recv(1024)
        print(res)
        sock.close()
        self.wfile.write(res)

if __name__=="__main__":
    if sys.argv[1]=="server":
        otputil = OTPUtils()
        ThreadingTCPServer((config.OTP_SERVER_ADDR, config.OTP_SERVER_PORT), OTPServer_scoket).serve_forever()
    elif sys.argv[1]=="client":
        try:
            os.unlink(config.SOCK_ADDR)
        except Exception as inst:
            print(inst)
        print("Listening on {}".format(config.SOCK_ADDR))
        ThreadingUnixStreamServer(config.SOCK_ADDR, OTPServerClient_scoket).serve_forever()
    elif sys.argv[1]=="util":
        otputil = OTPUtils()
        if sys.argv[2]=="new":
            ret = otputil.get_new_otp(sys.argv[3])
            qr = qrcode.QRCode()
            qr.add_data(ret["data"])
            qr.print_ascii()
        elif sys.argv[2]=="get":
            print(otputil.get_otp(sys.argv[3]))
        elif sys.argv[2]=="verify":
            print(otputil.verify_code(sys.argv[3], sys.argv[4]))
        else:
            pass
