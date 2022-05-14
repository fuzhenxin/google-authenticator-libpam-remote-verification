# google-authenticator-libpam-remote-verification

The original google-authenticator-libpam verifies the code in the login server. If the server is hacked, all the secret will be lost. To improve the security for the system, the code is modified to verify the code in remote server. The code is sent to another python socket server called ClientServer through unix file. The the code then is sent to Server to verify. The Server connects with mysql to get the otp secret to verify.


## Install google-authenticator-libpam
```bash
cd google-authenticator-libpam
./bootstrap.sh
./configure
make
mkdir 
cp .libs/pam_google_authenticator.so /usr/lib64/security
```

## Config google-authenticator-libpam
1. The user parameter must be set in ``/etc/pam.d/sshd``
2. Other setting is the same in original google-authenticator-libpam
3. The following parameters do not work any more: secret, noskewadj, grace_period

## Run Servers
1. Server: ``python3 OTPServer.py server`` in a verification server which can connect to mysql.
2. ClientServer: ``sudo -u username python3 OTPServer.py client`` in the login server. ``username`` should be the same with user in ``/etc/pam.d/sshd``

## OTP Utils
1. ``python3 OTPServer.py util new username`` set new otp secret the speficy user.
2. ``python3 OTPServer.py util get username`` get otp secret the speficy user.
1. ``python3 OTPServer.py util verify username otpcode`` verify the otpcode for a specific user.