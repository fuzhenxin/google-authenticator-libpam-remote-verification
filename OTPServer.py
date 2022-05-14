from socketserver import ThreadingUnixStreamServer, StreamRequestHandler, ThreadingTCPServer
import random
import mysql.connector
import time
import os
import requests
import hmac, base64, struct, hashlib, time, platform
import config
import json
import sys
import socket
import qrcode
import pyotp

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

    # def get_all_elements(self):
    #     try:
    #         sql = "select user_id,secret from {}".format(self.table_name)
    #         # print(sql, select_value)
    #         self.mycursor.execute(sql)
    #         myresult = self.mycursor.fetchall()
    #         self.mydb.commit()
    #         return {"code": 0, "data": myresult}
    #     except Exception as inst:
    #         return {"code": -1, "reason": str(inst)}
    # def update_synced(self, user_id):
    #     try:
    #         sql = "update {} set is_synced=1 where user_id={}".format(self.table_name, user_id)
    #         # print(sql, select_value)
    #         self.mycursor.execute(sql)
    #         myresult = self.mycursor.fetchall()
    #         self.mydb.commit()
    #         return {"code": 0, "data": myresult}
    #     except Exception as inst:
    #         return {"code": -1, "reason": str(inst)}

    def get_all_user(self):
        try:
            sql = "select user_id,secret from {}".format(self.table_name)
            # print(sql, select_value)
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
        try:
            # tmp_file_name = "/tmp/otp_{}.txt".format(str(int(random.random()*10000)))
            # os.system("google-authenticator -q -t --allow-reuse -f -r 10 -R 15 -W --issuer={} --label={}@{} --secret={}".format(
            #     config.OTP_ISSUER, user_id, config.OTP_ISSUER, tmp_file_name))
            # with open(tmp_file_name) as f:
            #     lines = f.readlines()
            # os.popen("rm {} -f".format(tmp_file_name))
            # scret_line = lines[0].strip()
            scret_line = pyotp.random_base32()
        except Exception as inst:
            return {"code":-1, "reason": str(inst)}
        return {"code":0, "data": scret_line}

    def secret_to_url(self, user_id, secret):
        url_line = pyotp.totp.TOTP(secret).provisioning_uri(name='{}@{}'.format(user_id, config.OTP_ISSUER), issuer_name=config.OTP_ISSUER)
        url_line1 = "otpauth://totp/{}@pkuhpc?secret={}&issuer=pkuhpc".format(user_id, secret)
        print(url_line, url_line1)
        return url_line

    def get_otp(self, user_id):
        ret = self.datadb.get_element(user_id)
        if ret["code"]<0: return ret
        if len(ret["data"])==0:
            # return self.get_new_otp(user_id)
            return {"code": 0, "msg":"User not exist!", "userexist": False}
        else:
            return {"code": 0, "msg": ret["data"][0][0], "userexist": True}
    # def get_hpcuid(self, user_id):
    #     all_user_uid = requests.get("http://162.105.133.132/all/user").json()
    #     for i,j,k in zip(all_user_uid["userList"], all_user_uid["uidNumberList"], all_user_uid["gidNumberList"]):
    #         if i==user_id:
    #             return {"code":0, "data": {"uid":j,"gid":k}}
    #     return {"code":-1, "reason": "getuid error"}

    def get_new_otp(self, user_id):
        ret = self.get_new_secret(user_id)
        if ret["code"] < 0: return ret
        new_secret = ret["data"]

        #ret = self.get_hpcuid(user_id)
        #if ret["code"] < 0: return ret
        #hpc_uid = ret["data"]["uid"]
        #hpc_gid = ret["data"]["gid"]
        hpc_uid = 0
        hpc_gid = 0

        insert_dict = {
            "user_id": user_id,
            "secret": new_secret,
            "update_time": time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        ret = self.datadb.insert_one_line(insert_dict)
        if ret["code"]<0: return ret
        return {"code": 0, "data": self.secret_to_url(user_id, new_secret)}
    
    # def get_otp_code(self, secret, bias):
    #     if len(secret)%8!=0: secret = secret + "="*(8-len(secret)%8)
    #     intervals_no=int(time.time()+bias)//30
    #     key = base64.b32decode(secret, True)
    #     msg = struct.pack(">Q", intervals_no)
    #     h = hmac.new(key, msg, hashlib.sha1).digest()
    #     o = ord(chr(h[19])) & 15
    #     h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    #     return '%06d' % h

    def verify_code(self, userid, input_code):
        ret = self.get_otp(userid)
        if ret["code"]<0: return ret
        if ret["code"]==0 and ret["userexist"] is False: return {"code": 0, "data": 2}
        secret = ret["msg"]
        print([secret])
        # if secret=="empty": return {"code":-1}
        # code1 = self.get_otp_code(secret, 0)
        # code2 = self.get_otp_code(secret, -30)
        totp = pyotp.TOTP(secret)
        code1 = totp.at(time.time())
        code2 = totp.at(time.time()-30)
        if input_code == code1 or input_code == code2: return {"code": 0, "data": 0}
        return {"code": 0, "data": 1}

class OTPServer_scoket(StreamRequestHandler):
    otputil = OTPUtils()
    def handle(self):
        print("Listen new!")
        verify_json = self.rfile.readline(512).strip()
        verify_dict = json.loads(verify_json)
        username = verify_dict["Username"]
        otpcode = verify_dict["OTPCode"]
        print([username, otpcode])
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

        send_str = (json.dumps({"Username": username.decode("utf-8"), "OTPCode": otp_code.decode("utf-8") })+"\n").encode('utf-8')
        print([send_str])
        sock.send(send_str)
        print("Send finished {}".format(send_str))
        res = sock.recv(1024)
        print(res)
        sock.close()
        self.wfile.write(res)

if __name__=="__main__":
    if sys.argv[1]=="server":
        ThreadingTCPServer(("127.0.0.1", config.OTP_SERVER_PORT), OTPServer_scoket).serve_forever()
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
    elif sys.argv[1]=="client":
        try:
            os.unlink(config.SCOK_ADDR)
        except Exception as inst:
            print(inst)
        print("Listening on {}".format(socket_file_name))
        ThreadingUnixStreamServer(socket_file_name, OTPServerClient_scoket).serve_forever()

    
    # print(otpserver.verify_code(sys.argv[1], sys.argv[2]))
    # print(res)

# sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
# sudo yum install google-authenticator
