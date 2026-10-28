from pathlib import Path
import os
from alembic import command
from alembic.config import Config
import uvicorn

if __name__ == '__main__':
    config = Config(str(Path(__file__).resolve().parents[1] / 'alembic.ini'))
    command.upgrade(config, 'head')
    uvicorn.run('riskengine.main:app', host='0.0.0.0', port=int(os.getenv('PORT', '8000')), workers=1)
