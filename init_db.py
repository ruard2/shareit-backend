from database import engine, Base
import models  # dit registreert de tabellen

Base.metadata.create_all(bind=engine)
