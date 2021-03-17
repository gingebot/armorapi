#!/bin/python3
import os, logging, sys
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/../../src")
from armorapi import *

def set_creds():
    global password
    global username
    password = os.environ.get('armor_password')
    username = os.environ.get('armor_username')

def test_basic_invocation():

    print('\n----------------- TEST START --------------------\n')
    print('*** TESTING BASIC INVOCATION :\n')
    armorapi = ArmorApi(username, password)

    print('\n----------------- TEST COMPLETE -----------------\n')

def test_accountid_sanitisation():

    print('\n----------------- TEST START --------------------\n')
    print('*** TESTING INVOCATION WITH INVLAID ACCOUNT ID:\n')
    try:
        armorapi = ArmorApi(username, password, accountid='007')
        print('\n********************* TEST FAILED **************************\n')
    except:
        print('\n********************* TEST PASS ****************************\n')

    print('\n----------------- TEST COMPLETE -----------------\n')
   


def test_explicit_v1_auth_invocation():
    print('\n----------------- TEST START --------------------\n')
    print('*** TESTING EXPLICIT V1 AUTH INVOCATION :\n')
    armorapi = ArmorApi(username, password, auth=1)

    print('\n----------------- TEST COMPLETE -----------------\n')


def test_explicit_v2_auth_invocation():
    print('\n----------------- TEST START --------------------\n')
    print('*** TESTING EXPLICIT V2 AUTH INVOCATION :\n')
    armorapi = ArmorApi(username, password, auth=2)

    print('\n----------------- TEST COMPLETE -----------------\n')


def test_401_timer():
    print('\n----------------- TEST START --------------------\n')
    print('*** TESTING 401 TIMER :\n')
    armorapi = ArmorApi(username, password, retries401=2)
    assert armorapi._count401 == 2, 'initial 401 count doesn\'t match retries401 provided'
    armorapi._authorisation_token = 'NOTAVALIDTOKEN'
    armorapi._new_token = True
    try:
        armorapi._test_request_and_accountid()
    except requests.exceptions.HTTPError:
        assert armorapi._count401 < 0, '401 count has decremented below 0 before exception, value is: %s' % armorapi.count401

    print('\n----------------- TEST COMPLETE -----------------\n')

def test_retries401_sanitisation():
    print('\n----------------- TEST START --------------------\n')
    print('*** TESTING RETRIES401 SANITISATOIN :\n')
    try:
        armorapi = ArmorApi(username, password, retries401=101)
        print('\n********************* TEST FAILED **************************\n')
    except:
        print('\n********************* TEST PASS ****************************\n')

    print('\n----------------- TEST COMPLETE -----------------\n')

def test_v1_token_reissue():
    print('\n----------------- TEST START --------------------\n')
    print('*** TESTING v1 AUTH TOKEN REISSUE :\n')
    
    armorapi = ArmorApi(username, password, auth=1)
    auth_token = armorapi.session.headers['Authorization']
    armorapi.v1_reissue_authorisation_token()
    armorapi._test_request_and_accountid()
    auth_token_new = armorapi.session.headers['Authorization']   
    assert armorapi != auth_token_new, 'Auth token has not been udpated'

    print('\n----------------- TEST COMPLETE -----------------\n')

def test_make_request_sanitisation():
    print('\n----------------- TEST START --------------------\n')
    print('*** TESTING MAKE REQUEST SANITISATION :\n')
    try: 
        armorapi = ArmorApi(username, password, auth=1)
        armorapi.make_request('https://google.com')
        print('\n********************* TEST FAILED **************************\n')
    except:
        print('\n********************* TEST PASS ****************************\n')

    print('\n----------------- TEST COMPLETE -----------------\n')

if __name__ == '__main__':
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    set_creds()
    test_basic_invocation()
    test_explicit_v1_auth_invocation()
    test_explicit_v2_auth_invocation()
    test_401_timer()
    test_v1_token_reissue()
    test_retries401_sanitisation()
    test_make_request_sanitisation()
    test_accountid_sanitisation()
