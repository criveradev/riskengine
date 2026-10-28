from alembic import context
from sqlalchemy import engine_from_config, pool
from dotenv import load_dotenv
from riskengine.config import PROJECT_ROOT, database_url_from_env
from riskengine.models import Base

load_dotenv(PROJECT_ROOT / ".env")
config = context.config
config.set_main_option("sqlalchemy.url", database_url_from_env().replace("%", "%%"))
target_metadata = Base.metadata

if context.is_offline_mode():
    context.configure(url=config.get_main_option("sqlalchemy.url"), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = engine_from_config(config.get_section(config.config_ini_section), prefix="sqlalchemy.", poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
