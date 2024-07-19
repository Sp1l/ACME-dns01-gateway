# Providers

DNS API implementation providers

```python
class MyDNSProvider():
    def acme_challenge(self, action: str, fqdn: str, token: str):
        """Add or remove the _acme-challenge dns-01 validation token

        Args:
            action (str): 'setup' or 'teardown' 
            fqdn (str): The Fully Qualified Domain Name, includes `_acme-challenge` prefix 
            token (str): Content for the `_acme-challenge` TXT RR
        """
```
