import datetime
import logging
import requests
from requests.auth import HTTPDigestAuth
from zeep.wsse.username import UsernameToken
from lxml import etree
import pytest

logger = logging.getLogger()
logger.setLevel(logging.INFO)


@pytest.mark.identity_management
class TestIdentityManagement:
    GetUsers = """<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsdl="http://www.onvif.org/ver10/device/wsdl">
       <soap:Header/>
       <soap:Body>
          <wsdl:GetUsers/>
       </soap:Body>
    </soap:Envelope>"""

    base_headers = {'Connection': 'close',
                    'Content-Type': 'application/soap+xml; charset=utf-8'}

    @pytest.mark.OTG_IDENT_004
    def test_username_enumeration_response_content(self, target, port, uri, adm_user, adm_password):
        token = UsernameToken(username=adm_user, password=adm_password + 'bad', use_digest=True)
        message = etree.fromstring(self.GetUsers)
        token.apply(message, message[0])

        try:
            rsp_bad_password = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                             etree.tostring(message).decode('utf-8'), headers=self.base_headers,
                                             timeout=30)
        except Exception as e:
            if e.args[0].args[0] == 'Connection aborted.':
                logger.info('Exception during request: Connection aborted')
                rsp_bad_password = None
            else:
                logger.error('Exception during request:\n{}'.format(e))
                assert False

        token = UsernameToken(username=adm_user + 'bad', password=adm_password, use_digest=True)
        message = etree.fromstring(self.GetUsers)
        token.apply(message, message[0])

        try:
            rsp_bad_username = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                             etree.tostring(message).decode('utf-8'), headers=self.base_headers,
                                             timeout=30)
        except Exception as e:
            if e.args[0].args[0] == 'Connection aborted.':
                logger.info('Exception during request: Connection aborted')
                rsp_bad_username = None
            else:
                logger.error('Exception during request:\n{}'.format(e))
                assert False

        if (rsp_bad_password is None and rsp_bad_username is not None) or \
                (rsp_bad_password is not None and rsp_bad_username is None):
            logger.critical('Username enumeration possible: differences found between responses to a bad password and '
                            'a bad username')
            assert False

        if rsp_bad_username.status_code != rsp_bad_password.status_code:
            logger.critical('Username enumeration possible: differences found between responses status code to a bad '
                            'password and a bad username')
            assert False

        if rsp_bad_password.content != rsp_bad_username.content:
            logger.critical('Username enumeration possible: differences found between responses content to a bad '
                            'password and a bad username')
            assert False

        logger.info('Username enumeration not possible regarding responses')

    def _send_requests(self, target, port, uri, user, password, n):
        """
        Send a n POST requests to http://target:port/uri with SOAP authentication and calculate the average of
        response time
        :param target: IP address
        :param port: Port number
        :param uri: URI
        :param user: User for the SOAP authentication
        :param password: Password for the SOAP authentication
        :param n: Number of requests to send
        :return: Average of response time
        """
        token = UsernameToken(username=user, password=password, use_digest=True)
        message = etree.fromstring(self.GetUsers)
        token.apply(message, message[0])

        average = datetime.timedelta()

        for i in range(n):
            try:
                rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                    etree.tostring(message).decode('utf-8'), headers=self.base_headers, timeout=30)
            except Exception as e:
                logger.error('Exception during request:\n{}'.format(e))
                assert False
            else:
                average += rsp.elapsed

        return average / n

    @pytest.mark.OTG_IDENT_004
    def test_username_enumeration_response_timing(self, target, port, uri, adm_user, adm_password):
        # Dummy requests to make sure that the DNS and ARP caches are filled and up to date
        self._send_requests(target, port, uri, adm_user, adm_password, 1)

        average_bad_password = self._send_requests(target, port, uri, adm_user, adm_password + 'bad', 50)
        average_bad_username = self._send_requests(target, port, uri, adm_user + 'bad', adm_password, 50)

        if average_bad_password > average_bad_username:
            logger.critical("""Username enumeration possible by timing attack (side channel):
Average time of valid username requests: {} time unit
Average time of invalid username requests: {} time unit""".format(average_bad_password, average_bad_username))
            assert False

        logger.info('Username enumeration not possible by timing attack')
