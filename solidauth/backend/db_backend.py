import datetime

import sqlalchemy.exc

from solidauth import db, model
from solidauth.backend import SolidBackend


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
        rsc = db.ResourceServerConfiguration(provider=provider, data=configuration)
        self.session.add(rsc)
        self.session.commit()

    def get_resource_server_keys(self, provider):
        rsk = self.session.query(db.ResourceServerKeys).filter_by(provider=provider).first()
        if rsk:
            return rsk.data
        else:
            return None

    def save_resource_server_keys(self, provider, keys):
        rsk = db.ResourceServerKeys(provider=provider, data=keys)
        self.session.add(rsk)
        self.session.commit()

    def get_client_registration(self, provider):
        cr = self.session.query(db.ClientRegistration).filter_by(provider=provider).first()
        if cr:
            return cr.data
        else:
            return None

    def save_client_registration(self, provider, registration):
        client_id = registration["client_id"]
        cr = db.ClientRegistration(provider=provider, client_id=client_id, data=registration)
        self.session.add(cr)
        self.session.commit()

    def save_configuration_token(self, issuer, profile, sub, client_id, token):
        # In the case that the token already exists, update it
        existing_token = self.get_configuration_token(issuer, profile, client_id)
        if existing_token:
            self.update_configuration_token(issuer, profile, client_id, token)
            return
        else:
            # Look up the client registration to set the foreign key
            client_registration = self.session.query(db.ClientRegistration).filter_by(client_id=client_id).first()

            ct = db.ConfigurationToken(
                issuer=issuer,
                profile=profile,
                sub=sub,
                client_id=client_id,
                data=token,
                client_registration_id=client_registration.id if client_registration else None,
            )
            self.session.merge(ct)
            self.session.commit()

    def update_configuration_token(self, issuer, profile, client_id, token):
        ct = (
            self.session.query(db.ConfigurationToken)
            .filter_by(issuer=issuer, profile=profile, client_id=client_id)
            .first()
        )
        if ct:
            ct.data = token
            ct.added = datetime.datetime.now(tz=datetime.timezone.utc)
            self.session.add(ct)
            self.session.commit()

    def get_configuration_token(self, issuer, profile, use_client_id_document):
        """Get the Configuration Token (auth token) for a given issuer and profile.
        There could be two Configuration Tokens for a single user:
          - One with the client id created by dynamic registration (linked in the client_registration_id FK)
          - One with the client id set to a client id document (a URL)
        It's only possible to have a maximum of two Configuration Tokens for a issuer/profile combination, either
        related to a single ClientRegistration, or a single client id.
        """
        ct = self.session.query(db.ConfigurationToken).where(
            db.ConfigurationToken.issuer == issuer, db.ConfigurationToken.profile == profile
        )
        if use_client_id_document:
            ct = ct.where(db.ConfigurationToken.client_registration_id.is_(None))
        ct = ct.first()

        if ct:
            return model.ConfigurationToken(
                issuer=ct.issuer, sub=ct.sub, profile=ct.profile, client_id=ct.client_id, added=ct.added, data=ct.data
            )
        else:
            return None

    def delete_configuration_token(self, issuer, profile, use_client_id_document):
        ct = self.session.query(db.ConfigurationToken).where(
            db.ConfigurationToken.issuer == issuer, db.ConfigurationToken.profile == profile
        )
        if use_client_id_document:
            ct = ct.where(db.ConfigurationToken.client_registration_id.is_(None))
        ct = ct.first()
        if ct:
            self.session.delete(ct)
            self.session.commit()

    def get_configuration_tokens(self):
        cts = self.session.query(db.ConfigurationToken).all()
        return [
            model.ConfigurationToken(
                issuer=ct.issuer, sub=ct.sub, profile=ct.profile, client_id=ct.client_id, added=ct.added, data=ct.data
            )
            for ct in cts
        ]

    def get_state_data(self, state):
        st = self.session.query(db.State).filter_by(state=state).first()
        if st:
            return {
                "code_verifier": st.code_verifier,
                "issuer": st.issuer,
            }
        else:
            return None

    def delete_state_data(self, state):
        st = self.session.query(db.State).filter_by(state=state).first()
        if st:
            self.session.delete(st)
            self.session.commit()

    def set_state_data(self, state, code_verifier, issuer=None):
        st = db.State(state=state, code_verifier=code_verifier, issuer=issuer)
        self.session.add(st)
        self.session.commit()
