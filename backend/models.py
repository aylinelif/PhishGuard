from pydantic import BaseModel

class UserLogin(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    password: str
    email: str

class AnalysisRequest(BaseModel):
    text: str

class URLAnalysisRequest(BaseModel):
    url: str

class AnalysisResponse(BaseModel):
    score: int
    risk_level: str
