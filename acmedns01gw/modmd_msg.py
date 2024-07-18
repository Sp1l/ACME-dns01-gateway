"""Class representing a dns-01 message from mod_md"""

class ModMDMsg:
    """Class representing a dns-01 message from mod_md"""
    def __init__(self, payload: dict):
        try:
            self.action = payload["argument"]
            self.fqdn = payload["domain_name"]
            self.token = payload["challenge_content"]
        except KeyError as exc:
            raise exc

    def __str__(self):
        return str({"action": self.action,"fqdn": self.fqdn,"token": self.token})

    @property
    def action(self):
        """One of setup or teardown"""
        return self._verb

    @action.setter
    def action(self, value: str):
        if value not in ["setup", "add", "teardown", "remove"]:
            raise ValueError("action must be one of setup/add or teardown/remove")
        self._verb = value

    @property
    def fqdn(self):
        """The domain name"""
        return self._fqdn

    @fqdn.setter
    def fqdn(self, value: str):
        # The FQDN must ALWAYS have an _acme-challenge prefix
        self._fqdn = "_acme-challenge." + value.removeprefix("_acme-challenge.")

    @property
    def token(self):
        """The _acme-challenge content"""
        return self._token

    @token.setter
    def token(self, value: str):
        self._token = value
