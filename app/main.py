from fastapi import FastAPI
from .routers import sql_app.account # you just need to add this line and line 4 to your main.py, this is just to show the file structure.
app = FastAPI()
app.include_router(account.router, prefix = "/account", tags=["account"])  #don't for get this one. 
