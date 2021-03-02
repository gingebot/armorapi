#!/bin/python3
import os
import time
import logging
import threading
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class ArmorApi:
    """
    Rest API client for the Armor API, manages 0auth2 authentication.
    """

    def __init__(self, username, password, accountid=None, retries401=4, auth='v1'):
        self.username = username
        self.password = password
        self.accountid = accountid
        self.auth = auth
        self.session = requests.session()
        self.session.headers.update({ 'Accept' : 'application/json'})
        self.retries401 = retries401
        self.count401 = self.retries401
        self.timer = time.time()
        self._authorisation_token = ''
        self._new_token = False
        self._token_lock = threading.Lock()
        logger.debug('initialising armor api')

        self._authenticate()

    def _authenticate(self):
        """
        Executes authentication depending on authentication version selected
        """
        if self.auth == 'v1':
            self._v1_authentication()
        elif self.auth == 'v2':
            self._v2_authentication()
        else:
            logger.critical('Invalid auth version provided: %s' % self.auth)
            raise ValueError('Invalid auth version provided: %s' % self.auth)

    def _v1_authentication(self):
        self._token_prefix = "FH-AUTH"
        self._v1_get_authentication_token()
        self._v1_get_authorisation_token()
        self._test_request_and_accountid()
        self._v1_reissue_thread()

    def _v1_get_authentication_token(self):
        """
        1st stage v1, Perform initial authentication, to recieve authentication token
        """
        logger.debug('Performing initial v1 authentication to get authentication token')
        payload = {'userName' : self.username, 'password' : self.password}
        json_response = self.make_request('https://api.armor.com/auth/authorize',method="post", data=payload)
        logger.debug('API returned the following: %s' % json_response)
        self.v1_authcode = json_response.get('code')
        
    def _v1_get_authorisation_token(self):
        """
        2nd stage v1, use authentication token to get authorisation token to use on subsequent API requests
        """
        logger.debug('Performing 2nd stage v1 authentication, use authentication token to get authorisation token')
        payload = { "code":self.v1_authcode, "grant_type":"authorization_code"}
        json_response = self.make_request('https://api.armor.com/auth/token', method="post", data=payload)
        logger.debug('API returned the following: %s' % json_response)
        with self._token_lock:
            logger.debug('lock acquired to update _authorisation_token')
            self._authorisation_token = json_response.get('access_token')
            self._new_token = True
        logger.debug('Authorisation token set to: %s ' % self._authorisation_token)

    def _v1_reissue_authorisation_token(self):
        """
        v1 authorisation renew authorisation token
        """
        logger.debug('Renewing authorisation token (v1 auth)')
        logger.debug('Authorisation token currently set to: %s ' % self._authorisation_token)
        payload = { 'token' : self._authorisation_token }
        json_response = self.make_request('https://api.armor.com/auth/token/reissue', method="post", data=payload)
        logger.debug('API returned the following: %s' % json_response)
        with self._token_lock:
            logger.debug('lock acquired to update _authorisation_token')
            self._authorisation_token = json_response.get('access_token')
            self._new_token = True
        logger.debug('Authorisation token renewed to %s' % self._authorisation_token) 

    def _v1_reissue_thread(self):
        """
        Creates a thread to reissue token every n seconds
        """
        self.reissue_thread = threading.Timer(600, self._v1_reissue_authorisation_token)
        self.reissue_thread.start()

    def _v2_authentication(self):
        self._token_prefix = "Bearer"
        self._v2_set_bearer_request_url()
        self._v2_get_authentication_token()
        self._v2_get_authorisation_token()
        self._test_request_and_accountid()

    def _v2_set_bearer_request_url(self):
        """
        Sets the request url, including parameters for the bearer token request cycles
        """
        response_type = 'id_token'
        response_mode = 'form_post'
        client_id = 'b2264823-30a3-4706-bf48-4cf80dad76d3'
        redirect_uri = 'https://amp.armor.com/'
        client_request_id = 'f85529a0-7f20-4212-073c-0080000000a3'
        self.bearer_request_url = 'https://sts.armor.com/adfs/oauth2/authorize?response_type=%s&response_mode=%s&client_id=%s&redirect_uri=%s' % (response_type, response_mode, client_id, redirect_uri)
        
    def _v2_get_authentication_token(self):
        """
        Completes the initial username/password auth and retrieves authentication token.
        """
        
        logger.debug('Performing initial v2 authentication to get authentication token')
        payload = { 'UserName' : self.username, 'Password' : self.password, 'AuthMethod' : 'FormsAuthentication' }
        sso_auth_response = self.make_request(self.bearer_request_url,"post",data=payload,json=False)
        soup = BeautifulSoup(sso_auth_response, 'html.parser')
        self.context_token = soup.find('input', {'id' : 'context'})['value']

    def _v2_get_authorisation_token(self):
        """
        2nd stage v2, use authentication token to get authorisation token to use on subsequent API requests
        """
        logger.debug('performing final v2 authentication request to get authorisation token')
        payload = { 'AuthMethod' : 'AzureMfaServerAuthentication', 'Context' : self.context_token }
        bearer_response = self.make_request(self.bearer_request_url,"post",data=payload,json=False)
        soup = BeautifulSoup(bearer_response, 'html.parser')
        bearer = soup.find('input')['value']
        with self._token_lock:
            logger.debug('lock acquired to update _authorisation_token')
            self._authorisation_token = bearer
            self._new_token = True
        logger.debug('Authorisation token set to: %s ' % self._authorisation_token)

    def _401_timer(self):
        """
        counter method that allows n executions every 10 mintes
        """
        time_now = time.time()
        if time_now - self.timer > 60:
            #reset timer and retries if more than 10 minutes has passed since last execution 
            self.timer = time_now
            self.count401 = self.retries401

        interval = time_now - self.timer
        self.count401 -= 1
        if self.count401 >= 0:
            return True
        else:
            return False
    def _update_authorisation_header(self):
        """
        updates authorisation header in a thread safe manner if you auth token is acquired
        """
        if self._new_token:
            with self._token_lock:
                logger.debug('lock acquired to update session header with new token value')
                self.session.headers.update({ 'Authorization' : '%s %s' % (self._token_prefix, self._authorisation_token)})
                self._new_token = False
            logger.debug('New auth token headers updated to: %s' % self.session.headers)

    def make_request(self,uri,method="get",data={},json=True):
        """
        Makes a request and returns response, catches exceptions 
        """

        self._update_authorisation_header()

        try:
            if method == "get":
                response = self.session.get(uri,data=data)
            elif method == "post":
                response = self.session.post(uri,data=data)
            elif method == "put":
                response = self.session.put(uri,data=data)
            response.raise_for_status()
            if json == False:
                return response.text
            else:
                return response.json()

        except requests.exceptions.HTTPError as error:
            if response.status_code == 401 and self._401_timer():
                logger.warning(error)
                logger.warning('Attempting reauthentication')
                self._authenticate()
            else:    
                logger.critical(error)
                raise
        except requests.exceptions.ConnectionError as error:
            logger.critical(error)
            raise
        except requests.exceptions.RequestException as error:
            logger.critical(error)
            raise


    def _test_request_and_accountid(self):
        """
        performs an API request to confirm Authentication has worked, also sets the header for account ID, either as provide ID or First account ID from request
        """
        logger.debug('performing API request to test authentication and get/set account ID')
        json_response = self.make_request('https://api.armor.com/me')
        
        accountid = json_response['accounts'][0]['id'] 
        if not self.accountid and accountid:
            logger.debug('API request successful, setting account ID to: %s' % accountid)
            self.session.headers.update({'X-Account-Context' : '%s' % accountid})
        elif self.accountid:
            logger.debug('API request successful, however account ID already set to: %s' % self.accountid)
            self.session.headers.update({'X-Account-Context' : '%s' % self.accountid})

    def _simulate_fail(self):
        """
        For testing purpoases only, creates a 401 error
        """
        print(self.count401)
        self.session = requests.session()
        response = self.make_request('https://api.armor.com/me')
        print(response)

if __name__ == "__main__":

    #set console logging for debug
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    username = os.environ.get('armor_username')
    password = os.environ.get('armor_password')
    armorapi = ArmorApi(username,password)
    armorapi.reissue_thread.cancel()
