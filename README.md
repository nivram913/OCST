# ONVIF IP Camera security testing (OCST)

## Description

This tool is a set of test suite for testing a set of attacks against ONVIF IP cameras.

It's based on `pytest` for the test framework and on OTGv4 (OWASP Testing Guide 4) for tests.

## Requirements

*Python 3.6*

- `pytest` >= 3.6.3
- `requests` >= 2.19.1
- `zeep` >= 3.0.0

## Usage

In the root directory of the tool, run:
```sh
Usage: pytest <options>...

  --target=TARGET       Target IP address
  --port=PORT           Target port number
  --adm-user=ADM_USER   ONVIF administrator account
  --adm-password=ADM_PASSWORD
                        ONVIF administrator password
  --op-user=OP_USER     ONVIF operator account
  --op-password=OP_PASSWORD
                        ONVIF operator password
  --usr-user=USR_USER   ONVIF user account
  --usr-password=USR_PASSWORD
                        ONVIF user password
  --default-creds=DEFAULT_CREDS
                        Default credentials file
  --common-creds=COMMON_CREDS
                        Common credentials file
  --dir-list=DIR_LIST   Known directories list file

```

You can use all pytest regular options. The following test markers have been defined according to OWASP Testing Guide v4:

- `authentication`
- `information_gathering`
- `configuration`
- `identity_management`
- `OTG_INFO_001`
- `OTG_INFO_002`
- `OTG_INFO_003`
- `OTG_INFO_008`
- `OTG_AUTHN_001`
- `OTG_AUTHN_002`
- `OTG_AUTHN_003`
- `OTG_AUTHN_004`
- `OTG_CONFIG_002`
- `OTG_CONFIG_005`
- `OTG_CONFIG_006`
- `OTG_CONFIG_007`
- `OTG_IDENT_004`

Use the `-m` switch of pytest to select only marked tests.

### Recommended usage

```sh
pytest --target <IP address> [--port <port>] --adm-user <user> --adm-password <password> -v --tb=short [-m ...]
```
