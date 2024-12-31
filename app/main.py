import os
from typing import Union
from fastapi import FastAPI, HTTPException, Depends, status, Response, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, String, Integer, Boolean, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import uuid
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer

# Database URL (replace with your actual PostgreSQL credentials)
DATABASE_URL = "postgresql://testuser:testpassword@localhost:5432/questiondb"

# Initialize the database connection and sessionmaker
engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create the base class for declarative models
Base = declarative_base()

# Initialize the password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# FastAPI app instance
app = FastAPI()

# SQLAlchemy User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)

# SQLAlchemy Form model
class Form(Base):
    __tablename__ = "forms"
    id = Column(String, primary_key=True, index=True, default=str(uuid.uuid4()))
    title = Column(String, index=True)
    description = Column(String)
    fields = relationship("Field", back_populates="form")

# SQLAlchemy Field model (each form has multiple fields)
class Field(Base):
    __tablename__ = "fields"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    field_id = Column(String, index=True)
    type = Column(String)  # Allowed values: "string", "number", "boolean"
    label = Column(String)
    required = Column(Boolean, default=True)
    form_id = Column(String, ForeignKey("forms.id"))

    form = relationship("Form", back_populates="fields")

# SQLAlchemy Submission model
class Submission(Base):
    __tablename__ = "submissions"
    submission_id = Column(String, primary_key=True, index=True, default=str(uuid.uuid4()))
    form_id = Column(String, ForeignKey("forms.id"))
    data = Column(Text)  # This can be a JSON or serialized string
    submitted_at = Column(String, default=str(uuid.uuid4()))  # Timestamp or use DateTime

    form = relationship("Form")

# Create the tables
Base.metadata.create_all(bind=engine)

# Pydantic models for user registration and login
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class UserInDB(UserCreate):
    hashed_password: str

class FieldSchema(BaseModel):
    field_id: str
    type: str  # Allowed values: "string", "number", "boolean"
    label: str
    required: bool

class FormCreateRequest(BaseModel):
    title: str
    description: str
    fields: list[FieldSchema]

class FormResponse(BaseModel):
    field_id: str
    value: Union[str, int, bool]   # Can be string, number, or boolean

class FormSubmissionRequest(BaseModel):
    responses: list[FormResponse]

# Dependency to get the DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Authentication Routes

# User Registration
@app.post("/auth/register")
async def register_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    # Generate a session token (this can be a UUID or any unique value)
    session_token = str(uuid.uuid4())
    response = JSONResponse(content={"message": "User registered successfully"})
    response.set_cookie(key="session_token", value=session_token, max_age=3600, httponly=True, secure=True)
    return response

# User Login
@app.post("/auth/login")
async def login_user(user: UserLogin, db: Session = Depends(get_db), response: Response = None):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate a session token
    session_token = str(uuid.uuid4())
    response = JSONResponse(content={"message": "Login successful"})
    response.set_cookie(key="session_token", value=session_token, max_age=3600, httponly=True, secure=True)
    return response

# User Logout
@app.post("/auth/logout")
async def logout_user(response: Response):
    response.delete_cookie(key="session_token")  # Delete the session token cookie
    return {"message": "Successfully logged out"}

# Form Management Routes

# Create a Form
@app.post("/forms/create")
async def create_form(form: FormCreateRequest, db: Session = Depends(get_db)):
    new_form = Form(title=form.title, description=form.description)
    db.add(new_form)
    db.commit()
    db.refresh(new_form)

    for field in form.fields:
        db.add(Field(
            field_id=field.field_id,
            type=field.type,
            label=field.label,
            required=field.required,
            form_id=new_form.id
        ))

    db.commit()

    return {"form_id": new_form.id}

# Get All Forms
@app.get("/forms/")
async def get_all_forms(db: Session = Depends(get_db)):
    return db.query(Form).all()

# Get Single Form
@app.get("/forms/{form_id}")
async def get_form(form_id: str, db: Session = Depends(get_db)):
    form = db.query(Form).filter(Form.id == form_id).first()
    if form:
        return form
    raise HTTPException(status_code=404, detail="Form not found")

# Delete a Form
@app.delete("/forms/delete/{form_id}")
async def delete_form(form_id: str, db: Session = Depends(get_db)):
    form = db.query(Form).filter(Form.id == form_id).first()
    if form:
        db.delete(form)
        db.commit()
        return {"message": f"Form {form_id} deleted"}
    raise HTTPException(status_code=404, detail="Form not found")

# Form Submission Routes

# Submit a Form
@app.post("/forms/submit/{form_id}")
async def submit_form(form_id: str, submission: FormSubmissionRequest, db: Session = Depends(get_db)):
    form = db.query(Form).filter(Form.id == form_id).first()
    if not form:
        raise HTTPException(status_code=404, detail="Form not found")

    # Convert form data to a dictionary or serialized JSON
    submission_data = {response.field_id: response.value for response in submission.responses}
    
    new_submission = Submission(form_id=form_id, data=str(submission_data))  # Store as a string or JSON
    db.add(new_submission)
    db.commit()

    return {"submission_id": new_submission.submission_id}

# Get Form Submissions
@app.get("/forms/submissions/{form_id}")
async def get_form_submissions(form_id: str, page: int = 1, limit: int = 10, db: Session = Depends(get_db)):
    submissions = db.query(Submission).filter(Submission.form_id == form_id).offset((page - 1) * limit).limit(limit).all()
    if submissions:
        for submission in submissions:
            del submission.form_id  
        return {
            "total_count": db.query(Submission).filter(Submission.form_id == form_id).count(),
            "page": page,
            "limit": limit,
            "submissions": submissions
        }
    raise HTTPException(status_code=404, detail="No submissions found for this form")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)