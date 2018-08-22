import logging
import requests
import pytest

logger = logging.getLogger()
logger.setLevel(logging.INFO)


@pytest.mark.configuration
class TestConfiguration:
    GetSystemDateAndTime = """<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsdl="http://www.onvif.org/ver10/device/wsdl">
               <soap:Header/>
               <soap:Body>
                  <wsdl:GetSystemDateAndTime/>
               </soap:Body>
            </soap:Envelope>"""

    base_headers = {'Connection': 'close',
                    'Content-Type': 'application/soap+xml; charset=utf-8'}

    @pytest.mark.OTG_CONFIG_002
    @pytest.mark.OTG_CONFIG_005
    def test_default_directory_and_admin_interfaces(self, target, port, dir_list):
        found = ''
        for d in dir_list:
            try:
                rsp = requests.get('http://{host}:{port}/{uri}'.format(host=target, port=port, uri=d), timeout=30)
            except Exception as e:
                logger.error('Exception during request:\n{}'.format(e))
                assert False
            else:
                if rsp.status_code in [200, 401, 403]:
                    found += d + ', '
        if found != '':
            logger.critical('Known directories found: {}'.format(found))
            assert False

        logger.info('No known directories found')

    @pytest.mark.OTG_CONFIG_006
    def test_http_methods(self, target, port, uri):
        try:
            rsp = requests.options('http://{host}:{port}{uri}'.format(host=target, port=port, uri=uri), timeout=30)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            assert False
        else:
            if rsp.status_code in [500, 501] or 'allow' not in rsp.headers:
                logger.error('Could not list available HTTP methods: status code {}'.format(rsp.status_code))
                assert False
            found = ''
            for m in ['PUT', 'DELETE', 'TRACE', 'CONNECT']:
                if rsp.headers['allow'].find(m) != -1:
                    found += m + ' '

            if found != '':
                logger.critical('Found these HTTP methods: {}'.format(found))
                assert False
            logger.info('No critical HTTP methods found')

    @pytest.mark.OTG_CONFIG_007
    def test_hsts(self, target, port, uri):
        try:
            rsp = requests.post('https://{host}:{port}{uri}'.format(host=target, port=port, uri=uri),
                                self.GetSystemDateAndTime, headers=self.base_headers, timeout=30, verify=False)
        except Exception as e:
            logger.error('Exception during request:\n{}'.format(e))
            assert False
        else:
            if 'Strict-Transport-Security' in rsp.headers:
                logger.info('HSTS header found')
            else:
                logger.critical('No HSTS header found')
                assert False
