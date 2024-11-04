import os
from fastapi import FastAPI, Request, Depends
from starlette.responses import JSONResponse
import jwt
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

key = os.getenv("PUBLIC_KEY")

@app.middleware("http")
async def check_token(request: Request, call_next):
    if request.headers.get("Authorization"):
        token = request.headers["Authorization"].split(" ")[1]
        try:
            decoded = jwt.decode(token, key, algorithms=["RS256"])
            request.state.decoded_token = decoded
        except jwt.ExpiredSignatureError:
            return JSONResponse(content={"error": "token expired"}, status_code=401)
        except jwt.InvalidTokenError:
            return JSONResponse(content={"error": "invalid token"}, status_code=401)
    else:
        return JSONResponse(content={"error": "unauthorized"}, status_code=401)

    response = await call_next(request)
    return response

def get_decoded_token(request: Request):
    return request.state.decoded_token

@app.get("/")
async def root(decoded_token: dict = Depends(get_decoded_token)):
    return {"message": "Hello World", "decoded_token": decoded_token}

@app.get("/hello/{name}")
async def say_hello(name: str, decoded_token: dict = Depends(get_decoded_token)):
    return {"message": f"Hello {name}", "decoded_token": decoded_token}
