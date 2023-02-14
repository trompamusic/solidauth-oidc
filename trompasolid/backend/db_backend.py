import sqlalchemy.exc

from trompasolid.backend import SolidBackend
from trompasolid import db


class DBBackend(SolidBackend):
    
    def __init__(self, session):
        self.session = session

    def is_ready(self):
        # ProgrammingError is raised if the tables don't exist. Use this as
        # a check that the database tables exist before running any code
        try:
            self.get_relying_party_keys()
            return True
        except sqlalchemy.exc.ProgrammingError:
            return False

    def get_relying_party_keys(self):
        rp = self.session.query(db.RelyingPartyKey).first()
        if rp:
            return rp.data
        else:
            return None

    def save_relying_party_keys(self, keys):
        rp = db.RelyingPartyKey(data=keys)
        self.session.add(rp)
        self.session.commit()

    def get_resource_server_configuration(self, provider):
        rsc = self.session.query(db.ResourceServerConfiguration).filter_by(provider=provider).first()
        if rsc:
            return rsc.data
        else:
            return None

    def save_resource_server_configuration(self, provider, configuration):
        rsc = db.ResourceServerConfiguration(
            provider=provider,
            data=configuration
        )
        self.session.add(rsc)
        self.session.commit()

    def get_resource_server_keys(self, provider):
        rsk = self.session.query(db.ResourceServerKeys).filter_by(provider=provider).first()
        if rsk:
            return rsk.data
        else:
            return None

    def save_resource_server_keys(self, provider, keys):
        rsk = db.ResourceServerKeys(
            provider=provider,
            data=keys
        )
        self.session.add(rsk)
        self.session.commit()

    def get_client_registration(self, provider):
        cr = self.session.query(db.ClientRegistration).filter_by(provider=provider).first()
        if cr:
            return cr.data
        else:
            return None

    def save_client_registration(self, provider, registration):
        cr = db.ClientRegistration(
            provider=provider,
            data=registration
        )
        self.session.add(cr)
        self.session.commit()

    def save_configuration_token(self, issuer, sub, token):
        ct = db.ConfigurationToken(
            issuer=issuer,
            sub=sub,
            data=token
        )
        self.session.add(ct)
        self.session.commit()

    def get_configuration_token(self, issuer, sub):
        ct = self.session.query(db.ConfigurationToken).filter_by(issuer=issuer, sub=sub).first()
        if ct:
            return ct.token
        else:
            return None

    def get_state_data(self, state):
        st = self.session.query(db.State).filter_by(state=state).first()
        if st:
            return st.code_verifier
        else:
            return None

    def delete_state_data(self, state):
        st = self.session.query(db.State).filter_by(state=state).first()
        if st:
            self.session.delete(st)
            self.session.commit()

    def set_state_data(self, state, code_verifier):
        st = db.State(
            state=state,
            code_verifier=code_verifier
        )
        self.session.add(st)
        self.session.commit()
