"""db module"""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, LargeBinary
from sqlalchemy.orm import sessionmaker

engine = create_engine('sqlite:///passwords.db', echo=True)


Base = declarative_base()


class Password(Base):  # pylint: disable=R0903
    """password table"""
    __tablename__ = 'password'
    password_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), nullable=False)
    password_hash = Column(String(4096), nullable=False)
    link = Column(String(2000))
    email = Column(String(254))


class Configuration(Base):  # pylint: disable=R0903
    """configuration table"""
    __tablename__ = 'configuration'
    configuration_id = Column(Integer, primary_key=True, autoincrement=True)
    password_hash = Column(String(128))
    keyfile_hash = Column(String(128))
    keyfile_path = Column(String(4096))
    salt = Column(LargeBinary())


class Db:
    """db class to interact with db"""
    def __init__(self):
        mk_session = sessionmaker(bind=engine)
        mk_session = sessionmaker()
        Base.metadata.create_all(engine)
        mk_session.configure(bind=engine)
        self.session = mk_session()

    def search_passwords(self, fields_dict):
        """search for passwords by search fields
        results returned have to match every field/value given (and logic),
        non-existent fields will be ignored, if an empty dictionary or None is
        passed, a simple query without filters will be made.

        Args:
            fields_dict (dict): a dict containing table field name as keys and
                wanted values as their value

        Returns:
            dict : containing results
        """
        query_base = self.session.query(Password)
        current_query = query_base
        if fields_dict and fields_dict != {}:
            for fieldname in fields_dict:
                prevquery = current_query
                try:
                    current_query = current_query.filter(
                        getattr(Password, fieldname) == fields_dict[fieldname])
                except AttributeError:
                    current_query = prevquery
        result = current_query.all()
        result_dict = {}
        for item in result:
            result_dict[item.id] = item.__dict__
        return result_dict
    
    def delete_password(self, password_id):
        self.session.query(Password).filter(Password.password_id == password_id).delete()
        self.session.commit()

    def get_passwords(self, username=None, password_id=None):
        """gets passwords from db

        if both username and password_id are none, all passwords are returned,
        otherwise will filter for one or another parameter

        Args:
            username [optional](str): if given is used to filter passwords by
                username
            password_id [optional](int): if given is used to filter passwords
                by password_id
        """
        result = None
        if not username and not password_id:
            result = self.session.query(Password).all()
        elif username:
            result = self.session.query(Password).filter(
                Password.username == username).all()
        elif password_id:
            result = self.session.query(Password).filter(
                Password.password_id == password_id).all()
        result_dict = {}
        for item in result:
            result_dict[item.password_id] = item.__dict__
        return result_dict

    def insert_password(self, pass_dict):
        """inserts a new password

        Args:
            pass_dict (dict): dictionary containing password to insert
        """
        password = Password(**pass_dict)
        self.session.add(password)
        self.session.commit()

    def get_configuration(self):
        """gets configuration from configuration table

        Returns:
            dict : containing configuration
        """
        nrow = self.session.query(Configuration).count()
        if nrow == 0:
            return None
        result = self.session.query(Configuration).first()
        result_dict = result.__dict__
        return result_dict

    def set_configuration(self, conf_dict):
        """sets configuration (overwrites it if present)

        Args:
            conf_dict (dict): configuration to insert
        """
        nrow = self.session.query(Configuration).count()
        if nrow == 0:
            configuration = Configuration(**conf_dict)
            self.session.add(configuration)
        else:
            self.session.query(Configuration).update(conf_dict)
        self.session.commit()


def main():
    """main method for testing purposes"""
    database = Db()
    print(database.get_passwords())
    search_fields = {'url': 'www.google.com', 'username': 'couscous@gmail.com'}
    print(database.search_passwords(search_fields))


if __name__ == "__main__":
    main()
