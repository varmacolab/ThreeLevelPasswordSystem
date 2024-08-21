import getpass  
import hashlib  
import os  
import binascii  
import secrets  
import pyotp  
import time  
import smtplib  
from email.mime.text import MIMEText  
  
class ThreeLevelPasswordSystem:  
   def __init__(self, username, password, security_question, security_answer, email):  
      self.username = username  
      self.salted_password = self._hash_password(password)  
      self.security_question = security_question  
      self.security_answer = security_answer  
      self.email = email  
      self.otp_secret = self._generate_otp_secret()  
      self.lockout_count = 0  
      self.lockout_time = 0  
  
   def _hash_password(self, password):  
      salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')  
      pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)  
      pwdhash = binascii.hexlify(pwdhash)  
      return (salt + pwdhash).decode('ascii')  
  
   def _verify_password(self, stored_password, provided_password):  
      salt = stored_password[:64]  
      stored_password = stored_password[64:]  
      pwdhash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt.encode('ascii'), 100000)  
      pwdhash = binascii.hexlify(pwdhash).decode('ascii')  
      return pwdhash == stored_password  
  
   def _generate_otp_secret(self):  
      return secrets.token_urlsafe(16)  
  
   def _generate_otp(self):  
      return pyotp.TOTP(self.otp_secret).now()  
  
   def _send_otp_email(self, otp):  
      msg = MIMEText(f"Your OTP is: {otp}")  
      msg['Subject'] = "OTP for Three Level Password System"  
      msg['From'] = "your_email@example.com"  
      msg['To'] = self.email  
      server = smtplib.SMTP('smtp.example.com', 587)  
      server.starttls()  
      server.login("your_email@example.com", "your_password")  
      server.sendmail("your_email@example.com", self.email, msg.as_string())  
      server.quit()  
  
   def authenticate(self, username, password, security_answer):  
      if self.lockout_count >= 3:  
        if time.time() - self.lockout_time < 300:  
           print("Account locked out due to excessive failed attempts. Try again in 5 minutes.")  
           return  
        else:  
           self.lockout_count = 0  
           self.lockout_time = 0  
      if username == self.username:  
        if self._verify_password(self.salted_password, password):  
           print("Level 1 Authentication Successful!")  
           if security_answer == self.security_answer:  
              print("Level 2 Authentication Successful!")  
              otp = self._generate_otp()  
              self._send_otp_email(otp)  
              print("OTP sent to your registered email. Enter the OTP:")  
              user_otp = input("Enter OTP: ")  
              if user_otp == otp:  
                print("Level 3 Authentication Successful! Access Granted.")  
              else:  
                print("Level 3 Authentication Failed. Access Denied.")  
                self.lockout_count += 1  
                self.lockout_time = time.time()  
           else:  
              print("Level 2 Authentication Failed. Access Denied.")  
              self.lockout_count += 1  
              self.lockout_time = time.time()  
        else:  
           print("Level 1 Authentication Failed. Access Denied.")  
           self.lockout_count += 1  
           self.lockout_time = time.time()  
      else:  
        print("Invalid username. Access Denied.")  
        self.lockout_count += 1  
        self.lockout_time = time.time()  
  
   def change_password(self, old_password, new_password):  
      if self._verify_password(self.salted_password, old_password):  
        self.salted_password = self._hash_password(new_password)  
        print("Password changed successfully!")  
      else:  
        print("Invalid old password. Password not changed.")  
  
   def reset_password(self, security_answer, new_password):  
      if security_answer == self.security_answer:  
        self.salted_password = self._hash_password(new_password)  
        print("Password reset successfully!")  
      else:  
        print("Invalid security answer. Password not reset.")  
  
# Example usage:  
username = input("Enter username: ")  
password = getpass.getpass("Enter password: ")  
security_question = "What is your favorite color?"  
security_answer = "blue"  
email = "user@example.com"  
system = ThreeLevelPasswordSystem(username, password, security_question, security_answer, email)  
system.authenticate(username, password, security_answer)  
  
# Change password example:  
# system.change_password("old_password", "new_password")  
  
# Reset password example:  
# system.reset_password("blue", "new_password")
