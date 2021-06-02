#!/bin/python3
import os
import time
import logging
import threading
import re
import json
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
logger.setLevel(logging.DEBUG)


class ArmorApi:
    """
    Rest API client for the Armor API, manages 0auth2 authentication.
    """

    def __init__(self,username,password,
                 accountid=None, retries401=4, auth=1):
        self.accountid = accountid
        self._auth = auth
        self.session = requests.session()
        self.session.headers.update({'Accept': 'application/json', 'Content-Type': 'application/json'})
        self._timer = time.time()
        self._authorisation_token = ''
        self._new_token = False
        self._token_lock = threading.Lock()
        self._domain_whitelist = ['amp.armor.com', 'sts.armor.com', 'api.armor.com', 'api.accounts.armor.com', 'agent-management.api.armor.com', 'security-detections.api.secure-prod.services', 'compliance.api.secure-prod.services', 'api.logs.armor.com', 'api.notifications.armor.com', 'webhooks.api.secure-prod.services', 'logs.api.secure-prod.services']
        logger.debug('initialising armor api')
        
        self._sanitise_creds(username,password)
        self._sanitise_retries401(retries401)
        self._authenticate()

    def _sanitise_creds(self,username,password):
        """
        sanitises credentials before making them members
        """
        if len(password) > 512 or len(username) > 512:
            logger.critical('username and/or password greater than 512 characters')
            raise ValueError('username and/or password greater than 512 characters')
        else:
            self._username = username
            self._password = password

    def _sanitise_retries401(self,retries401):
        """
        sanitises retires401 input before making it a member
        """
        if isinstance(retries401, int) and 1 <= retries401 <=100:
            self._retries401 = retries401
            self._count401 = self._retries401
        else:
            logger.critical('retries401 must be an integer between 1 and 100, the following was provided: %s' % retries401)
            raise ValueError('retries401 must be an integer between 1 and 100, the following was provided: %s' % retries401)

    def _authenticate(self):
        """
        Executes authentication depending on authentication version selected
        """
        if self._auth == 1:
            self._v1_authentication()
        elif self._auth == 2:
            self._v2_authentication()
        else:
            logger.critical('Invalid auth version provided: %s' % self._auth)
            raise ValueError('Invalid auth version provided: %s' % self._auth)

    def _v1_authentication(self):
        self._token_prefix = 'FH-AUTH'
        self._v1_get_authentication_token()
        self._v1_get_authorisation_token()
        self._test_request_and_accountid()

    def _v1_get_authentication_token(self):
        """
        1st stage v1, Perform initial authentication, 
        to recieve authentication token
        """
        logger.debug('Performing initial v1 authentication to get authentication token')
        payload = {'userName': self._username, 'password': self._password}
        response = self.make_request('https://api.armor.com/auth/authorize', method="post", data=payload)
        logger.debug('API returned the following: %s' % response.json())
        self.v1_authcode = response.json().get('code')

    def _v1_get_authorisation_token(self):
        """
        2nd stage v1, use authentication token to get authorisation token to use on subsequent API requests
        """
        logger.debug('Performing 2nd stage v1 authentication, use authentication token to get authorisation token')
        payload = {'code': self.v1_authcode, 'grant_type': 'authorization_code'}
        response = self.make_request('https://api.armor.com/auth/token', method='post', data=payload)
        logger.debug('API returned the following: %s' % response.json())
        with self._token_lock:
            logger.debug('lock acquired to update _authorisation_token')
            self._authorisation_token = response.json().get('access_token')
            self._new_token = True
        logger.debug('Authorisation token set to: %s ' % self._authorisation_token)

    def v1_reissue_authorisation_token(self):
        """
        v1 authorisation renew authorisation token
        """
        logger.debug('Renewing authorisation token (v1 auth)')
        logger.debug('Authorisation token currently set to: %s ' % self._authorisation_token)
        payload = {'token': self._authorisation_token}
        response = self.make_request('https://api.armor.com/auth/token/reissue', method='post', data=payload)
        logger.debug('API returned the following: %s' % response.json())
        with self._token_lock:
            logger.debug('lock acquired to update _authorisation_token')
            self._authorisation_token = response.json().get('access_token')
            self._new_token = True
        logger.debug('Authorisation token renewed to %s' % self._authorisation_token)

    def _v2_authentication(self):
        self._token_prefix = 'Bearer'
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
        self.bearer_request_url = 'https://sts.armor.com/adfs/oauth2/authorize?response_type=%s&response_mode=%s&client_id=%s&redirect_uri=%s' % (response_type, response_mode, client_id, redirect_uri)

    def _v2_get_authentication_token(self):
        """
        Completes the initial username/password auth and retrieves authentication token.
        """

        logger.debug('Performing initial v2 authentication to get authentication token')
        payload = {'UserName': self._username, 'Password': self._password, 'AuthMethod': 'FormsAuthentication'}
        sso_auth_response = self.session.post(self.bearer_request_url, data=payload)
        soup = BeautifulSoup(sso_auth_response.text, 'html.parser')
        self.context_token = soup.find('input', {'id': 'context'})['value']

    def _v2_get_authorisation_token(self):
        """
        2nd stage v2, use authentication token to get authorisation token to use on subsequent API requests
        """
        logger.debug('performing final v2 authentication request to get authorisation token')
        payload = {'AuthMethod': 'AzureMfaServerAuthentication', 'Context': self.context_token}
        bearer_response = self.session.post(self.bearer_request_url, data=payload)
        soup = BeautifulSoup(bearer_response.text, 'html.parser')
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
        if time_now - self._timer > 600:
            self._timer = time_now
            self._count401 = self._retries401

        self._count401 -= 1
        if self._count401 >= 0:
            return True
        else:
            return False

    def _update_authorisation_header(self):
        """
        updates authorisation header in a thread safe manner if an auth token is acquired
        """
        if self._new_token:
            with self._token_lock:
                logger.debug('lock acquired to update session header with new token value')
                self.session.headers.update({'Authorization': '%s %s' % (self._token_prefix, self._authorisation_token)})
                self._new_token = False
            logger.debug('New auth token headers updated to: %s' % self.session.headers)

    def _validate_url(self,url):
        """
        performs validation on a url to config domain is in the API whitelist
        """
        fqdn = re.findall('^(?:http.+?/+)*(.+?)(?:/.*)*$', url)[0]
        if fqdn not in self._domain_whitelist:
            logger.critical('domain: %s not on api whitelist' % fqdn)
            raise ValueError('domain: %s not on api whitelist' % fqdn)

    def make_request(self, url, method='get', data={}, headers={}):
        """
        Makes a request and returns response, catches exceptions
        """

        self._validate_url(url)
        self._update_authorisation_header()
        method = method.upper()
        try:
            if method == 'GET':
                response = self.session.get(url, data=json.dumps(data), headers=headers)
            elif method == 'POST':
                response = self.session.post(url, data=json.dumps(data), headers=headers)
            elif method == 'PUT':
                response = self.session.put(url, data=json.dumps(data), headers=headers)
            else:
                logger.critical('Only GET, POST and PUT are valid make_request methods. %s was provided' % method)        
                raise ValueError('Only GET, POST and PUT are valid make_request methods. %s was provided' % method)        

            response.raise_for_status()

            return response

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
        response = self.make_request('https://api.armor.com/me')
        json_response = response.json()
        
        accountids = [x['id'] for x in json_response['accounts']]
        accountid = json_response['accounts'][0]['id']
        if not self.accountid and accountid:
            logger.debug('API request successful, setting account ID to: %s' % accountid)
            self.session.headers.update({'X-Account-Context': '%s' % accountid})
        elif self.accountid:
            self.accountid = int(self.accountid)
            if self.accountid not in accountids:
                 logger.critical('Provided account ID %s, it not a valid account ID for this account. Valid account IDs: %s' % (self.accountid, accountids))
                 raise ValueError('Provided account ID %s, it not a valid account ID for this account. Valid account IDs: %s' % (self.accountid, accountids))
            logger.debug('API request successful, however account ID already set to: %s' % self.accountid)
            self.session.headers.update({'X-Account-Context': '%s' % self.accountid})
