import datetime
import time
import logging

import requests
from requests.auth import HTTPDigestAuth
from zeep.wsse.username import UsernameToken
from lxml import etree

import pytest

logger = logging.getLogger()
logger.setLevel(logging.INFO)


@pytest.mark.authentication
class TestAuthentication:
    GetUsers = """<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsdl="http://www.onvif.org/ver10/device/wsdl">
       <soap:Header/>
       <soap:Body>
          <wsdl:GetUsers/>
       </soap:Body>
    </soap:Envelope>"""

    GetSystemDateAndTime = """<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsdl="http://www.onvif.org/ver10/device/wsdl">
           <soap:Header/>
           <soap:Body>
              <wsdl:GetSystemDateAndTime/>
           </soap:Body>
        </soap:Envelope>"""

    SetUser = """<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsdl="http://www.onvif.org/ver10/device/wsdl" xmlns:sch="http://www.onvif.org/ver10/schema">
       <soap:Header/>
       <soap:Body>
          <wsdl:SetUser>
             <wsdl:User>
                <sch:Username>{username}</sch:Username>
                <sch:Password>{password}</sch:Password>
                <sch:UserLevel>{level}</sch:UserLevel>
             </wsdl:User>
          </wsdl:SetUser>
       </soap:Body>
    </soap:Envelope>"""
    
    base_headers = {'Connection': 'close',
                    'Content-Type': 'application/soap+xml; charset=utf-8'}

    headers_date = {'SOAPAction': '"http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime"',
                    'Content-Type': 'application/soap+xml; charset=utf-8; '
                                    'action="http://www.onvif.org/ver10/device/wsdl/GetSystemDateAndTime"'}

    headers_getUsers = {'SOAPAction': '"http://www.onvif.org/ver10/device/wsdl/GetUsers"',
                        'Content-Type': 'application/soap+xml; charset=utf-8; '
                                        'action="http://www.onvif.org/ver10/device/wsdl/GetUsers"'}

    sql_injections = ['or 1=1', 'or 1=1--', 'or 1=1#', 'or 1=1/*', "' --", "' #", "'/*", "' or '1'='1",
                      "' or '1'='1'--", "' or '1'='1'#", "' or '1'='1'/*", "'or 1=1 or ''='", "' or 1=1", "' or 1=1--",
                      "' or 1=1#", "' or 1=1/*", "') or ('1'='1", "') or ('1'='1'--", "') or ('1'='1'#",
                      "') or ('1'='1'/*", "') or '1'='1", "') or '1'='1'--", "') or '1'='1'#", "') or '1'='1'/*",
                      '" --', '" #', '"/*', '" or "1"="1', '" or "1"="1"--', '" or "1"="1"#', '" or "1"="1"/*',
                      '"or 1=1 or ""="', '" or 1=1', '" or 1=1--', '" or 1=1#', '" or 1=1/*', '") or ("1"="1',
                      '") or ("1"="1"--', '") or ("1"="1"#', '") or ("1"="1"/*', '") or "1"="1', '") or "1"="1"--',
                      '") or "1"="1"#', '") or "1"="1"/']

    ldap_injections = ['*', '*)(&', '*))%00', "*()|%26'", "*()|&'", '*(|(mail=*))', '*(|(objectclass=*))',
                       '*)(uid=*))(|(uid=*', '*/*', '*|', '/', '//', '//*', '@*', '|', '*)((|userpassword=*)',
                       '*)((|userPassword=*)', '*)((|password=*)']

    def _find_next_http_auth(self, buffer, offset):
        basic = buffer.find('Basic realm', offset)
        digest = buffer.find('Digest', offset)

        if basic == -1:
            return digest
        elif digest == -1:
            return basic
        else:
            return min(digest, basic)

    def _get_next_http_auth(self, buffer, offset):
        start = self._find_next_http_auth(buffer, offset)
        if start == -1:
            return ''
        end = self._find_next_http_auth(buffer, offset + start + 1) - 2
        if end < 0:
            end = len(buffer)

        return buffer[start:end]

    def test_weak_authentication_methods_no_auth(self, target, port, uri):
        try:
            rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                self.GetUsers, headers=self.base_headers, timeout=30)
        except Exception as e:
            if e.args[0].args[0] == 'Connection aborted.':
                logger.info('Exception during request: Connection aborted')
            else:
                logger.error('Exception during request:\n{}'.format(e))
                assert False
        else:
            if rsp.status_code != 401 and rsp.status_code != 400:
                logger.critical('No authentication: Receive status code {}'.format(rsp.status_code))
                assert False

    @pytest.mark.OTG_AUTHN_001
    def test_weak_authentication_methods_http_basic_auth(self, target, port, uri):
        try:
            rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                self.GetUsers, headers=self.base_headers, timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            assert False
        else:
            headers = rsp.headers

        if 'WWW-Authenticate' in headers:
            if headers['WWW-Authenticate'].find('Basic realm') != -1:
                logger.critical('Basic HTTP authentication proposed')
                assert False
            else:
                logger.info('No Basic HTTP authentication proposed')
        else:
            logger.info('No WWW-Authenticate header returned')

    def test_weak_authentication_methods_http_digest_variations_auth(self, target, port, uri):
        try:
            rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                self.GetUsers, headers=self.base_headers, timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            assert False
        else:
            headers = rsp.headers

        if 'WWW-Authenticate' in headers:
            auth_list = []
            offset = 0
            auth = self._get_next_http_auth(headers['WWW-Authenticate'], offset)
            while auth != '':
                auth_list.append(auth)
                offset += len(auth)
                auth = self._get_next_http_auth(headers['WWW-Authenticate'], offset)

            digest_proposed = False

            for auth in auth_list:
                if auth.find('Digest ') != -1:
                    digest_proposed = True
                    digest_params = auth[7:]

                    digest_params_list = [(p.split('=')[0], p.split('=')[1].replace('"', ''))
                                          for p in digest_params.split(', ')]
                    qop = ''
                    algo = ''

                    for key, value in digest_params_list:
                        if key == 'qop':
                            qop = value
                        elif key == 'algorithm':
                            algo = value

                    if qop == '' and (algo == '' or algo.lower() == 'md5'):
                        logger.critical('No client nonce required by the server')
                        assert False
                    elif qop.lower() == 'auth':
                        logger.info('Quality of protection is set to "auth" (minimal security)')
                    elif qop.lower() == 'auth-int':
                        logger.info('Quality of protection is set to "auth-int" (HTTP body integrity)')
                else:
                    logger.error('Unknown HTTP authentication method proposed')
                    assert False

            if not digest_proposed:
                logger.error('No Digest HTTP authentication proposed')
                assert False

    @pytest.mark.OTG_AUTHN_001
    def test_weak_authentication_methods_soap_passwordtext_auth(self, target, port, uri, adm_user, adm_password):
        token = UsernameToken(username=adm_user, password=adm_password, use_digest=False)
        message = etree.fromstring(self.GetUsers)
        token.apply(message, message[0])

        try:
            rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                etree.tostring(message).decode('utf-8'), headers=self.base_headers, timeout=30)
        except Exception as e:
            if e.args[0].args[0] == 'Connection aborted.':
                logger.info('Exception during request: Connection aborted')
            else:
                logger.error('Exception during request:\n{}'.format(e))
                assert False
        else:
            if rsp.status_code == 400 or rsp.status_code == 401:
                logger.info('SOAP PasswordText authentication rejected')
            elif rsp.status_code == 200:
                logger.critical('SOAP PasswordText authentication accepted')
                assert False

    @pytest.mark.OTG_AUTHN_002
    def test_default_credentials(self, target, port, uri, default_creds):
        for user, password in default_creds:
            try:
                rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                    self.GetUsers, headers=self.base_headers, auth=HTTPDigestAuth(user, password),
                                    timeout=30)
            except Exception as e:
                if e.args[0].args[0] != 'Connection aborted.':
                    logger.error('Exception during request:\n{}'.format(e))
                    assert False
            else:
                if rsp.status_code == 200:
                    logger.critical('Default credentials "{}" "{}" are in use'.format(user, password))
                    assert False

        logger.info('No default credentials in use')

    @pytest.mark.OTG_AUTHN_002
    def test_common_credentials(self, target, port, uri, common_creds):
        for user, password in common_creds:
            try:
                rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                    self.GetUsers, headers=self.base_headers, auth=HTTPDigestAuth(user, password),
                                    timeout=30)
            except Exception as e:
                if e.args[0].args[0] != 'Connection aborted.':
                    logger.error('Exception during request:\n{}'.format(e))
                    assert False
            else:
                if rsp.status_code == 200:
                    logger.critical('Weak credential "{}" "{}" is in use'.format(user, password))
                    assert False

        logger.info('No common credentials in use')

    @pytest.mark.OTG_AUTHN_003
    def test_weak_lockout_mechanism_http_level(self, target, port, uri, adm_user, adm_password):
        def try_login_http(n):
            i = 1
            while i <= n:
                try:
                    rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                        self.GetUsers, headers=self.base_headers,
                                        auth=HTTPDigestAuth(adm_user, adm_password + 'bad'), timeout=30)
                except Exception as e:
                    if e.args[0].args[0] != 'Connection aborted.':
                        logger.error('Exception during request:\n{}'.format(e))
                        assert False
                else:
                    if rsp.status_code != 401 and rsp.status_code != 400:
                        logger.error('Receive unexpected {} status code (HTTP auth)'.format(rsp.status_code))
                        assert False

                i += 1

            try:
                rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                    self.GetUsers, headers=self.base_headers,
                                    auth=HTTPDigestAuth(adm_user, adm_password), timeout=30)
            except Exception as e:
                if e.args[0].args[0] == 'Connection aborted.':
                    logger.critical('Account locked out after {} HTTP login attempt (Connection aborted)'.format(i))
                    assert False
                else:
                    logger.error('Exception during request:\n{}'.format(e))
                    assert False
            else:
                if rsp.status_code != 200:
                    logger.critical('Account locked out after {} HTTP login attempt (code {})'.format(i, rsp.status_code))
                    assert False

        for i in [3, 5, 10, 15, 30]:
            try_login_http(i)

        logger.info('Account not locked out after up to 30 HTTP login attempt')

    @pytest.mark.OTG_AUTHN_003
    def test_weak_lockout_mechanism_soap_level(self, target, port, uri, adm_user, adm_password):
        def try_login_soap(n):
            i = 1
            while i <= n:
                token = UsernameToken(username=adm_user, password=adm_password + 'bad', use_digest=True)
                message = etree.fromstring(self.GetUsers)
                token.apply(message, message[0])

                try:
                    rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                        etree.tostring(message).decode('utf-8'), headers=self.base_headers, timeout=30)
                except Exception as e:
                    if e.args[0].args[0] != 'Connection aborted.':
                        logger.error('Exception during request:\n{}'.format(e))
                        assert False
                else:
                    if rsp.status_code != 400:
                        logger.error('Receive unexpected {} status code (SOAP auth)'.format(rsp.status_code))
                        assert False

                i += 1

            token = UsernameToken(username=adm_user, password=adm_password, use_digest=True)
            message = etree.fromstring(self.GetUsers)
            token.apply(message, message[0])

            try:
                rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                    etree.tostring(message).decode('utf-8'), headers=self.base_headers, timeout=30)
            except Exception as e:
                if e.args[0].args[0] == 'Connection aborted.':
                    logger.critical('Account locked out after {} SOAP login attempt (Connection aborted)'.format(i))
                    assert False
                else:
                    logger.error('Exception during request:\n{}'.format(e))
                    assert False
            else:
                if rsp.status_code != 200:
                    logger.critical('Account locked out after {} SOAP login attempt (code {})'.format(i, rsp.status_code))

        for i in [3, 5, 10, 15, 30]:
            try_login_soap(i)

        logger.info('Account not locked out after up to 30 SOAP login attempt')

    @pytest.mark.OTG_AUTHN_004
    @pytest.mark.parametrize('delay', [0, 2])
    def test_replay_attack_soap_level(self, target, port, uri, adm_user, adm_password, delay):
        token = UsernameToken(username=adm_user, password=adm_password, use_digest=True)
        message = etree.fromstring(self.GetUsers)
        token.apply(message, message[0])

        try:
            rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                etree.tostring(message).decode('utf-8'), headers=self.base_headers, timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            assert False
        else:
            if rsp.status_code != 200:
                logger.error('Unexpected return code {} during first request (SOAP auth)'.format(rsp.status_code))
                assert False
            else:
                try:
                    time.sleep(delay)
                    rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                        etree.tostring(message).decode('utf-8'), headers=self.base_headers, timeout=30)
                except Exception as e:
                    if e.args[0].args[0] == 'Connection aborted.':
                        logger.info('Replay attack stopped at SOAP level (Connection aborted)')
                    else:
                        logger.error('Exception during request:\n{}'.format(e))
                        assert False
                else:
                    if rsp.status_code == 200:
                        logger.critical('Replay attack successful at SOAP level (delay={}s)'.format(delay))
                        assert False
                    elif rsp.status_code == 400 or rsp.status_code == 401:
                        logger.info('Replay attack stopped at SOAP level (delay={}s)'.format(delay))
                    else:
                        logger.error('Unexpected return code {} when replay at SOAP level'.format(rsp.status_code))
                        assert False

    @pytest.mark.OTG_AUTHN_004
    @pytest.mark.parametrize('delay', [0, 2])
    def test_replay_attack_http_level(self, target, port, uri, adm_user, adm_password, delay):
        try:
            rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                self.GetUsers, headers=self.base_headers, auth=HTTPDigestAuth(adm_user, adm_password),
                                timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            assert False
        else:
            if rsp.status_code != 200:
                logger.error('Unexpected return code {} during first request (HTTP auth)'.format(rsp.status_code))
                assert False
            else:
                try:
                    time.sleep(delay)
                    rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                        self.GetUsers, headers=rsp.request.headers, timeout=30)
                except Exception as e:
                    if e.args[0].args[0] == 'Connection aborted.':
                        logger.info('Replay attack stopped at HTTP level (Connection aborted)')
                    else:
                        logger.error('Exception during request:\n{}'.format(e))
                        assert False
                else:
                    if rsp.status_code == 200:
                        logger.critical('Replay attack successful at HTTP level (delay={}s)'.format(delay))
                        assert False
                    elif rsp.status_code == 401 or rsp.status_code == 400:
                        logger.info('Replay attack stopped at HTTP level (delay={}s)'.format(delay))
                    else:
                        logger.error('Unexpected return code {} when replay at HTTP level'.format(rsp.status_code))
                        assert False

    @pytest.mark.OTG_AUTHN_004
    @pytest.mark.parametrize('minutes', [1, 2, 5, 15, 30])
    def test_soap_authentication_with_past_created_value(self, target, port, uri, adm_user, adm_password, minutes):
        token = UsernameToken(username=adm_user, password=adm_password, use_digest=True,
                              created=datetime.datetime.utcnow() - datetime.timedelta(minutes=minutes))
        message = etree.fromstring(self.GetUsers)
        token.apply(message, message[0])

        try:
            rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                etree.tostring(message).decode('utf-8'), headers=self.base_headers, timeout=30)
        except Exception as e:
            if e.args[0].args[0] == 'Connection aborted.':
                logger.info('Request from the past is rejected (Connection aborted)')
            else:
                logger.error('Exception during request:\n{}'.format(e))
                assert False
        else:
            if rsp.status_code == 400 or rsp.status_code == 401:
                logger.info('Request from the past is rejected ({} minutes delay)'.format(minutes))
            else:
                logger.critical('Request from the past is accepted ({} minutes delay)'.format(minutes))
                assert False

    def test_mutual_authentication_for_http_digest(self, target, port, uri, adm_user, adm_password):
        try:
            rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                self.GetUsers, auth=HTTPDigestAuth(adm_user, adm_password),
                                headers=self.base_headers, timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            assert False
        else:
            if rsp.status_code == 401 or rsp.status_code == 400:
                logger.error('Authentication error')
                assert False
            else:
                headers = rsp.headers

        if 'AuthenticationInfo' not in headers:
            logger.critical('No AuthenticationInfo header found')
            assert False

        if headers['AuthenticationInfo'].find('rspauth') != -1:
            logger.info('Mutual authentication found (rspauth)')
        else:
            logger.critical('No mutual authentication found (rspauth)')
            assert False

    @pytest.mark.OTG_AUTHN_004
    def test_SOAPAction_authentication_bypass(self, target, port, uri):
        try:
            rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                self.GetSystemDateAndTime, timeout=30, headers=self.headers_getUsers)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            assert False

        if rsp.status_code == 200:
            if rsp.content.decode('utf-8').find('Users') != -1:
                logger.critical('Authentication bypassed with SOAPAction header tampering')
                assert False
            elif rsp.content.decode('utf-8').find('SystemDateAndTime'):
                logger.info("Receive status code 200 with SystemDateAndTime response. The device seems to ignore "
                            "SOAPAction header.")
            else:
                logger.error('Receive status code 200 with unexpected response:\n{}'.format(rsp.content.decode('utf-8')))
                assert False
        elif rsp.status_code == 401:
            logger.info('Receive status code 401. So potentially vulnerable to action bypass !')
        else:
            logger.error('Receive status code {}:\n{}'.format(rsp.status_code, rsp.content.decode('utf-8')))
            assert False

    @pytest.mark.OTG_AUTHN_004
    def test_SOAPAction_authentication_bypass_2(self, target, port, uri):
        try:
            rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                self.GetUsers, timeout=30, headers=self.headers_date)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            assert False

        if rsp.status_code == 200:
            if rsp.content.decode('utf-8').find('Users') != -1:
                logger.critical('Authentication bypassed with SOAPAction header tampering')
                assert False
            elif rsp.content.decode('utf-8').find('SystemDateAndTime'):
                logger.info("Receive status code 200 with SystemDateAndTime response. The device seems "
                            "to be vulnerable to action bypass.")
            else:
                logger.error('Receive status code 200 with unexpected response:\n{}'.format(rsp.content.decode('utf-8')))
                assert False
        elif rsp.status_code == 401:
            logger.info('Receive status code 401. The device seems to ignore SOAPAction header')
        else:
            logger.error('Receive status code {}:\n{}'.format(rsp.status_code, rsp.content.decode('utf-8')))
            assert False

    @pytest.mark.OTG_AUTHN_004
    def test_authentication_bypass_sql_injection_http(self, target, port, uri, adm_user):
        for i in self.sql_injections:
            user = adm_user + i
            try:
                rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                    self.GetUsers, auth=HTTPDigestAuth(user, ''),
                                    headers=self.base_headers, timeout=30)
            except Exception as e:
                logger.error('Exception during request:\n{}'.format(e))
                assert False
            else:
                if rsp.status_code == 200:
                    logger.critical('Authentication bypass by SQL injection at HTTP level: {}'.format(user))
                    assert False

        logger.info('No authentication bypass by SQL injection at HTTP level found')

    @pytest.mark.OTG_AUTHN_004
    def test_authentication_bypass_sql_injection_soap(self, target, port, uri, adm_user):
        for i in self.sql_injections:
            user = adm_user + i
            token = UsernameToken(username=user, password='', use_digest=True)
            message = etree.fromstring(self.GetUsers)
            token.apply(message, message[0])

            try:
                rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                    etree.tostring(message).decode('utf-8'), headers=self.base_headers, timeout=30)
            except Exception as e:
                logger.error('Exception during request:\n{}'.format(e))
                assert False
            else:
                if rsp.status_code == 200:
                    logger.critical('Authentication bypass by SQL injection at SOAP level: {}'.format(user))
                    assert False

        logger.info('No authentication bypass by SQL injection at SOAP level found')

    @pytest.mark.OTG_AUTHN_004
    def test_authentication_bypass_ldap_injection_http(self, target, port, uri, adm_user):
        for i in self.ldap_injections:
            user = adm_user + i
            try:
                rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                    self.GetUsers, auth=HTTPDigestAuth(user, ''),
                                    headers=self.base_headers, timeout=30)
            except Exception as e:
                logger.error('Exception during request:\n{}'.format(e))
                assert False
            else:
                if rsp.status_code == 200:
                    logger.critical('Authentication bypass by LDAP injection at HTTP level: {}'.format(user))
                    assert False

        logger.info('No authentication bypass by LDAP injection at HTTP level found')

    @pytest.mark.OTG_AUTHN_004
    def test_authentication_bypass_ldap_injection_soap(self, target, port, uri, adm_user):
        for i in self.ldap_injections:
            user = adm_user + i
            token = UsernameToken(username=user, password='', use_digest=True)
            message = etree.fromstring(self.GetUsers)
            token.apply(message, message[0])

            try:
                rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                    etree.tostring(message).decode('utf-8'), headers=self.base_headers, timeout=30)
            except Exception as e:
                logger.error('Exception during request:\n{}'.format(e))
                assert False
            else:
                if rsp.status_code == 200:
                    logger.critical('Authentication bypass by LDAP injection at SOAP level: {}'.format(user))
                    assert False

        logger.info('No authentication bypass by LDAP injection at SOAP level found')
