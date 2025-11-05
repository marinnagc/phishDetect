# app/main.py
from fastapi import FastAPI, HTTPException
from app.models import AnalyzeRequest, AnalyzeResult
from app.analysis import analyze_url
from app.db import init_db, save_result
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="PhishDetect - API (Conceito B)")

origins = ["*"]  # em produção restrinja isso
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()

# app/main.py  (substitua apenas a função analyze)
@app.post("/analyze", response_model=AnalyzeResult)
def analyze(req: AnalyzeRequest):
    try:
        # Garantir que passamos string para a função de análise
        url_str = str(req.url)
        res = analyze_url(url_str)
        save_result(res)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/health")
def health():
    return {"status":"ok"}
