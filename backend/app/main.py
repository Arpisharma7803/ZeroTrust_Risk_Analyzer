from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.analysis import router
from app.database import init_db

app = FastAPI()

# Initialize database on startup
@app.on_event("startup")
def startup():
    init_db()
    print("✅ Database initialized")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
