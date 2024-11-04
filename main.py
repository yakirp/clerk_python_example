import os
from fastapi import FastAPI, Request, Depends
import jwt
from starlette.responses import JSONResponse
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

public_key = os.getenv("PUBLIC_KEY")

@app.middleware("http")
async def check_token(request: Request, call_next):
    if request.headers.get("Authorization"):
        token = request.headers["Authorization"].split(" ")[1]
        try:
            header_data = jwt.get_unverified_header(token)
            payload_data = jwt.decode(jwt=token, key=public_key, algorithms=[header_data['alg'], ])
            request.state.decoded_token = payload_data
        except Exception as e:
            return JSONResponse(content={"error": "invalid token", "details": str(e)}, status_code=401)

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
