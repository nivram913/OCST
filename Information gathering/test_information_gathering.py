import socket
import logging
import requests
import pytest
import xml.etree.ElementTree as etree
import urllib.parse

logger = logging.getLogger()
logger.setLevel(logging.INFO)


@pytest.mark.information_gathering
class TestInformationGathering:
    GetSystemDateAndTime = """<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsdl="http://www.onvif.org/ver10/device/wsdl">
           <soap:Header/>
           <soap:Body>
              <wsdl:GetSystemDateAndTime/>
           </soap:Body>
        </soap:Envelope>"""

    discovery = """<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
                       xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                       xmlns:tns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
            <soap:Header>
                <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
                <wsa:MessageID>urn:uuid:c032cfdd-c3ca-49dc-820e-ee6696ad63e2</wsa:MessageID>
                <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
            </soap:Header>
            <soap:Body>
                <tns:Probe/>
            </soap:Body>
        </soap:Envelope>"""

    base_headers = {'Connection': 'close',
                    'Content-Type': 'application/soap+xml; charset=utf-8'}

    @pytest.mark.OTG_INFO_001
    def test_discovery_for_information_leakage(self, target):
        """
        Look for the presence of onvif://www.onvif.org/{hardware, name} scopes in discovery response
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.sendto(self.discovery.encode('ascii'), ('239.255.255.250', 3702))

        sock.settimeout(2)

        discovery_response = ''

        while True:
            try:
                data, addr = sock.recvfrom(8000)
                if addr[0] == target:
                    discovery_response = data
                    break
            except socket.timeout:
                break

        if discovery_response == '':
            logger.info('Device in non-discovery mode')
            return

        root = etree.fromstring(discovery_response)
        scopes = root.find('{http://www.w3.org/2003/05/soap-envelope}Body'). \
            find('{http://schemas.xmlsoap.org/ws/2005/04/discovery}ProbeMatches'). \
            find('{http://schemas.xmlsoap.org/ws/2005/04/discovery}ProbeMatch'). \
            find('{http://schemas.xmlsoap.org/ws/2005/04/discovery}Scopes').text.split(' ')

        hardware_value = ''
        name_value = ''
        for s in scopes:
            hardware_index = s.find('www.onvif.org/hardware/')
            if hardware_index != -1:
                hardware_value = urllib.parse.unquote(s[hardware_index + 23:])

            name_index = s.find('www.onvif.org/name/')
            if name_index != -1:
                name_value = urllib.parse.unquote(s[name_index + 19:])

        if hardware_value != '' or name_value != '':
            logger.warning('Sensitive information may be present in discovery response: {} {}'.format(hardware_value,
                                                                                                      name_value))
            assert False

        logger.info('No sensitive information found in discovery response')

    @pytest.mark.OTG_INFO_002
    def test_fingerprint_webserver_server_header(self, target, port, uri):
        """
        Test the presence of 'Server' HTTP headers in the response
        """
        try:
            rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                self.GetSystemDateAndTime, headers=self.base_headers, timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            assert False
        else:
            if 'Server' in rsp.headers:
                logger.warning('Possible web server fingerprint found in Server HTTP header: {}'
                               .format(rsp.headers['Server']))
                assert False

            logger.info('No "Server" header found in response')

    @pytest.mark.OTG_INFO_002
    def test_fingerprint_webserver_server_header_404(self, target, port):
        """
        Test the presence of 'Server' HTTP headers in the response of a non existing page (404)
        """
        try:
            rsp = requests.get('http://{host}:{port}/bidon404'.format(host=target, port=port), timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            assert False
        else:
            if 'Server' in rsp.headers:
                logger.warning('Possible web server fingerprint found in Server HTTP header: {}'
                               .format(rsp.headers['Server']))
                assert False

            logger.info('No "Server" header found in response')

    @pytest.mark.OTG_INFO_002
    def test_fingerprint_webserver_response_404(self, target, port):
        """
        Look for known server in response body of a non existing page (404)
        """
        try:
            rsp = requests.get('http://{host}:{port}/bidon404'.format(host=target, port=port), timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            assert False
        else:
            known_server = ['Apache', 'IIS', 'Netscape', 'SunONE', 'Zeus', 'Lotus', 'Stronghold', 'AOLserver',
                            'Jana', 'Xerver_v3', 'RemotelyAnywhere', 'MiniServ', 'Cisco-HTTP', 'Linksys', 'NetWare',
                            'TightVNC', 'Orion', 'CompaqHTTPServer', 'WebLogic', '3Com', 'thttpd', 'EHTTP', 'EMWHTTPD',
                            'dwhttpd', 'ServletExec', 'Microsoft ISA Server', 'Zope', 'ZServer', 'MikroTik', 'TUX',
                            'Tomcat', 'Jetty', 'Ubicom', 'Resin', 'WebSitePro', 'squid']
            found = ''
            for s in known_server:
                if rsp.content.decode('utf-8').find(s) != -1:
                    found = s
                    break

            if found != '':
                logger.warning('Server string found in response: {}'.format(found))
                assert False
            logging.info('No server string found in response')

    @pytest.mark.OTG_INFO_003
    def test_webserver_metafile_leakage(self, target, port):
        """
        Test the presence of robots.txt in web interface of the camera (if there is one)
        """
        try:
            rsp = requests.get('http://{host}:{port}/robots.txt'.format(host=target, port=port), timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            return
        else:
            if rsp.status_code == 200:
                logger.warning('robots.txt file found, maybe there are no sensitive information in it')
                assert False
            logger.info('No robots.txt found in web interface')

    @pytest.mark.OTG_INFO_008
    def test_fingerprint_framework_poweredby_header(self, target, port, uri):
        """
        Test the presence of 'X-Powered-By' HTTP headers in the response
        """
        try:
            rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                self.GetSystemDateAndTime, headers=self.base_headers, timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            assert False
        else:
            if 'X-Powered-By' in rsp.headers:
                logger.warning('Possible web application framework fingerprint found: X-Powered-By: {}'.
                               format(rsp.headers['X-Powered-By']))
                assert False

            logger.info('No "X-Powered-By" header found in response')

    @pytest.mark.OTG_INFO_008
    def test_fingerprint_framework_cookies(self, target, port):
        """
        Test the presence of framework specific cookies in the response
        """
        try:
            rsp = requests.get('http://{host}:{port}'.format(host=target, port=port), timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            return
        else:
            if rsp.status_code != 200:
                return
            known_cookies_name = ['zope3', 'cakephp', 'kohanasession', 'laravel_session', 'CFTOKEN',
                                  'CFID', 'fe_typo_user', 'phpbb3_', 'wp-settings', 'BITRIX_', 'AMP',
                                  'django', 'DotNetNukeAnonymous', 'e107_tz', 'EPiTrace', 'EPiServer',
                                  'graffitibot', 'hotaru_mobile', 'ICMSession', 'MAKACSESSION', 'Dynamicweb',
                                  'VivvoSessionId', 'ASPSESSION', 'JSESSIONID', 'PHPSESSID']
            found = ''
            for cookie_name in rsp.cookies:
                for known_cookie_name in known_cookies_name:
                    if cookie_name.find(known_cookie_name) != -1:
                        found += cookie_name + ' '

            if len(found) != 0:
                logger.warning('Framework specific cookie(s) found: {}'.format(found))
                assert False
            logger.info('No framework specific cookies found')

    @pytest.mark.OTG_INFO_008
    def test_fingerprint_framework_body_content(self, target, port):
        """
        Test the presence of framework specific string in the response body
        """
        try:
            rsp = requests.get('http://{host}:{port}'.format(host=target, port=port), timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            return
        else:
            if rsp.status_code != 200:
                return
            known_strings = ['WordPress', 'phpbb', 'MediaWiki', 'Joomla', 'Drupal']
            found = ''
            for string in known_strings:
                if rsp.content.decode('utf-8').find(string) != -1:
                    found += string + ' '

            if len(found) != 0:
                logger.warning('Framework specific string(s) found: {}'.format(found))
                assert False
            logger.info('No framework specific string found')

    @pytest.mark.OTG_INFO_008
    def test_fingerprint_framework_headers(self, target, port, uri):
        """
        Test the presence of framework specific headers in the response
        """
        try:
            rsp = requests.post('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                self.GetSystemDateAndTime, headers=self.base_headers, timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            return
        else:
            if rsp.status_code != 200:
                return
            known_headers = ['x-generator', 'x-cache-hits', 'x-timer', 'x-served-by', 'x-varnish',
                             'x-drupal-cache', 'x-dynatrace', 'x-server-name']
            found = ''
            for header in known_headers:
                if header in rsp.headers:
                    found += header + ' '

            if len(found) != 0:
                logger.warning('Framework specific header(s) found: {}'.format(found))
                assert False
            logger.info('No framework specific headers found')
