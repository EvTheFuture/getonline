Get Online
===========

_Keep you connected if your provider require you to login before accessing the Internet_

This [AppDaemon](https://appdaemon.readthedocs.io/en/latest/#) app for [Home Assistant](https://www.home-assistant.io/) will poll configured sites and if redirected it tries to login to the configured portal.

Currently only The Cloud in the EU has been tested.

[![buy-me-a-coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/EvTheFuture)

## Requirements

This app requires the python library icmplib.

In order to have AppDaemon install the requred python librares, add/change the folloging in your configuration for the AppDaemon 4 Add-on (in Lovelace)
```
python_packages:
  - icmplib
```
## Quick Examples

Here is an example configuration for the appdaemon configuration file apps.yaml.

**Please Note:** You need to change the configuration to match your setup.
```
keep_connected:
    module: getonline
    class: GetOnline
    DEBUG: no
    urls_to_check:
        - https://www.gp.se
        - http://www.dn.se/ekonomi
    detect_redirect_to: "service.thecloud.eu/service-platform"
    get_cookies_from: "https://service.thecloud.eu/service-platform/getonline"
    destination:
        send_to: "https://service.thecloud.eu/service-platform/macauthlogin/v1/registration"
        data: "terms=true"
        method: POST
```
