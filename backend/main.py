import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from fastapi import Body

from fastapi import FastAPI, Request, Depends, HTTPException, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Optional
from datetime import datetime
import shutil
from pathlib import Path
from passlib.hash import bcrypt
from database.models import User, Station, Review
from database.connector import DatabaseConnector
from backend.auth import get_db, get_current_user, get_current_user_required, create_access_token
from backend.config import settings
from backend.dependencies import require_admin

app = FastAPI(title=settings.app_name)
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")
templates = Jinja2Templates(directory="frontend/templates")

@app.on_event("startup")
async def startup_event():
    db_connector = DatabaseConnector()
    db_connector.create_tables()
    try:
        from database.stored_procedures import create_stored_procedures
        create_stored_procedures()
    except Exception as e:
        print(f"Ошибка при создании хранимых процедур: {e}")
    try:
        from database.import_data import import_data
        import_data()
    except Exception as e:
        print(f"Ошибка при автообновлении данных: {e}")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, db: Session = Depends(get_db), current_user: Optional[dict] = Depends(get_current_user)):
    total = db.execute(text("SELECT COUNT(*) FROM stations")).scalar()
    eco = db.execute(text("SELECT COUNT(*) FROM stations WHERE eco_status = true")).scalar()
    eco_percentage = round((eco / total * 100) if total > 0 else 0)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": current_user,
        "total_stations": total,
        "eco_stations": eco,
        "eco_percentage": eco_percentage,
        "last_update": datetime.now().strftime("%d.%m.%Y")
    })

@app.get("/map", response_class=HTMLResponse)
async def map_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    return templates.TemplateResponse("map.html", {"request": request, "user": current_user})

@app.get("/stats", response_class=HTMLResponse)
async def stats_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    return templates.TemplateResponse("stats.html", {"request": request, "user": current_user})

@app.get("/about", response_class=HTMLResponse)
async def about_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    return templates.TemplateResponse("about.html", {"request": request, "user": current_user})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    if current_user:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "user": None})

@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.execute(
        text("SELECT id, hashed_password, role FROM users WHERE email = :email"),
        {"email": email}
    ).mappings().first()

    if not user or not bcrypt.verify(password[:72], user.hashed_password):
        raise HTTPException(status_code=400, detail="Неверный email или пароль")

    access_token = create_access_token({
        "sub": str(user.id),
        "role": user.role
    })

    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response



@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    if current_user:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse("register.html", {"request": request, "user": None})

@app.post("/register")
async def register(username: str = Form(...), email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    exists = db.execute(text("SELECT id FROM users WHERE email = :email OR username = :username"), {"email": email, "username": username}).fetchone()
    if exists:
        raise HTTPException(status_code=400, detail="Email или имя пользователя уже существует")
    hashed = bcrypt.hash(password)
    db.execute(text("INSERT INTO users (username, email, hashed_password, created_at) VALUES (:u, :e, :p, NOW())"),
               {"u": username, "e": email, "p": hashed})
    db.commit()
    user = db.execute(text("SELECT id FROM users WHERE email = :email"), {"email": email}).fetchone()
    access_token = create_access_token(data={"sub": str(user.id)})
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(key="access_token", value=access_token, httponly=True)
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie(key="access_token")
    return response

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user_required)):
    reviews = db.execute(text("""
    SELECT 
        reviews.id AS id,
        reviews.rating AS rating,
        reviews.comment AS comment,
        reviews.created_at AS created_at,
        stations.name AS station_name
    FROM reviews
    JOIN stations ON reviews.station_id = stations.id
    WHERE reviews.user_id = :uid
    ORDER BY reviews.created_at DESC
    """), {"uid": current_user.id}).mappings().all()
    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "user": current_user,
            "reviews": reviews,
            "is_admin": getattr(current_user, "role", None) == "ADMIN"
        })

@app.get("/profile/edit", response_class=HTMLResponse)
async def edit_profile_page(request: Request, current_user: dict = Depends(get_current_user_required)):
    return templates.TemplateResponse("edit_profile.html", {"request": request, "user": current_user})

@app.post("/profile/edit")
async def update_profile(username: Optional[str] = Form(None), email: Optional[str] = Form(None), password: Optional[str] = Form(None), db: Session = Depends(get_db), current_user: dict = Depends(get_current_user_required)):
    if username:
        db.execute(text("UPDATE users SET username = :u WHERE id = :id"), {"u": username, "id": current_user.id})
    if email:
        db.execute(text("UPDATE users SET email = :e WHERE id = :id"), {"e": email, "id": current_user.id})
    if password:
        hashed = bcrypt.hash(password)
        db.execute(text("UPDATE users SET hashed_password = :p WHERE id = :id"), {"p": hashed, "id": current_user.id})
    db.commit()
    response = RedirectResponse(url="/profile", status_code=302)
    return response

@app.post("/station/{station_id}/review")
async def add_review(station_id: int, rating: int = Form(...), comment: str = Form(""), image: Optional[UploadFile] = File(None), db: Session = Depends(get_db), current_user: dict = Depends(get_current_user_required)):
    image_url = None
    if image and image.filename:
        upload_dir = Path("uploads")
        upload_dir.mkdir(exist_ok=True)
        ext = image.filename.split(".")[-1]
        filename = f"{current_user.id}_{station_id}_{int(datetime.now().timestamp())}.{ext}"
        file_path = upload_dir / filename
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        image_url = f"/uploads/{filename}"
    db.execute(text("INSERT INTO reviews (user_id, station_id, rating, comment, image_url, created_at) VALUES (:u, :s, :r, :c, :i, NOW())"),
               {"u": current_user.id, "s": station_id, "r": rating, "c": comment, "i": image_url})
    db.commit()
    return RedirectResponse(url=f"/station/{station_id}", status_code=302)

@app.get("/api/stations")
async def api_get_stations(db: Session = Depends(get_db)):
    stations = db.execute(text("SELECT id, name, address, district, admarea, owner, test_date, eco_status, latitude, longitude FROM stations")).fetchall()
    result = []
    for s in stations:
        avg = db.execute(text("SELECT COALESCE(AVG(rating),0) FROM reviews WHERE station_id = :id"), {"id": s.id}).scalar()
        result.append({
            "id": s.id,
            "name": s.name,
            "address": s.address,
            "district": s.district,
            "admarea": s.admarea,
            "owner": s.owner,
            "test_date": s.test_date.isoformat() if s.test_date else None,
            "eco_status": s.eco_status,
            "latitude": s.latitude,
            "longitude": s.longitude,
            "average_rating": round(avg, 1)
        })
    return result


@app.get("/station/{station_id}", response_class=HTMLResponse)
async def station_page(
    request: Request,
    station_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[dict] = Depends(get_current_user)
):
    station = db.execute(text("""
        SELECT id, name, address, district, admarea, owner, test_date, eco_status, latitude, longitude
        FROM stations
        WHERE id = :id
    """), {"id": station_id}).mappings().first()

    if not station:
        raise HTTPException(status_code=404, detail="Станция не найдена")

    reviews = db.execute(text("""
        SELECT 
            r.id,
            r.rating,
            r.comment,
            r.image_url,
            r.created_at,
            u.username
        FROM reviews r
        JOIN users u ON r.user_id = u.id
        WHERE r.station_id = :id
        ORDER BY r.created_at DESC
    """), {"id": station_id}).mappings().all()

    avg_rating = db.execute(text("""
        SELECT ROUND(AVG(rating), 1) FROM reviews WHERE station_id = :id
    """), {"id": station_id}).scalar() or 0

    return templates.TemplateResponse("station.html", {
        "request": request,
        "user": current_user,
        "station": station,
        "reviews": reviews,
        "avg_rating": avg_rating
    })




@app.get("/api/stats")
async def api_get_stats(db: Session = Depends(get_db)):
    total_stations = db.execute(text("SELECT COUNT(*) FROM stations")).scalar() or 0
    eco_stations = db.execute(text("SELECT COUNT(*) FROM stations WHERE eco_status = TRUE")).scalar() or 0
    non_eco_stations = total_stations - eco_stations

    eco_percentage = round((eco_stations / total_stations * 100) if total_stations > 0 else 0)

    by_district_rows = db.execute(text("""
        SELECT admarea, COUNT(*) 
        FROM stations 
        WHERE admarea IS NOT NULL 
        GROUP BY admarea
    """)).fetchall()
    by_district = {r[0]: r[1] for r in by_district_rows}


    eco_vs_non_eco = {
        "eco": eco_stations,
        "non_eco": non_eco_stations
    }

    avg_overall = db.execute(text("SELECT COALESCE(AVG(rating),0) FROM reviews")).scalar() or 0
    avg_eco = db.execute(text("""
        SELECT COALESCE(AVG(rating),0)
        FROM reviews r
        JOIN stations s ON r.station_id = s.id
        WHERE s.eco_status = TRUE
    """)).scalar() or 0
    avg_non_eco = db.execute(text("""
        SELECT COALESCE(AVG(rating),0)
        FROM reviews r
        JOIN stations s ON r.station_id = s.id
        WHERE s.eco_status = FALSE
    """)).scalar() or 0

    month_names = {
        1: "Янв",
        2: "Фев",
        3: "Март",
        4: "Апр",
        5: "Май",
        6: "Июнь",
        7: "Июль",
        8: "Авг",
        9: "Сен",
        10: "Окт",
        11: "Ноя",
        12: "Дек"
    }

    rows = db.execute(text("""
        SELECT EXTRACT(MONTH FROM created_at)::INT AS month, COUNT(*)
        FROM reviews
        GROUP BY month
        ORDER BY month
    """)).fetchall()

    reviews_by_month = {month_names[m]: count for m, count in rows}

    return {
        "total_stations": total_stations,
        "eco_stations": eco_stations,
        "non_eco_stations": non_eco_stations,
        "eco_percentage": eco_percentage,
        "by_district": by_district,
        "eco_vs_non_eco": eco_vs_non_eco,
        "average_ratings": {
            "overall": round(avg_overall, 1),
            "eco": round(avg_eco, 1),
            "non_eco": round(avg_non_eco, 1)
        },
        "reviews_by_month": reviews_by_month
    }



@app.get("/admin", response_class=HTMLResponse)
async def admin_panel(
    request: Request, 
    db: Session = Depends(get_db), 
    current_user: dict = Depends(require_admin)
):
    print(f"Admin access granted for user: {current_user.username}, role: {current_user.role}")
    
    users = db.execute(text("SELECT * FROM users ORDER BY created_at DESC")).mappings().all()
    stations = db.execute(text("SELECT * FROM stations ORDER BY id ASC")).mappings().all() 
    
    reviews = db.execute(text("""
        SELECT 
            r.id,
            r.rating,
            r.comment,
            r.image_url,
            r.created_at,
            u.username as user_username,
            u.id as user_id,
            s.name as station_name,
            s.id as station_id
        FROM reviews r
        LEFT JOIN users u ON r.user_id = u.id
        LEFT JOIN stations s ON r.station_id = s.id
        ORDER BY r.created_at DESC
    """)).mappings().all()
    
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "user": current_user,
        "users": users,
        "stations": stations,
        "reviews": reviews
    })
@app.on_event("startup")
async def startup_event():
    db_connector = DatabaseConnector()
    db_connector.create_tables()
    
 
    db = next(get_db())
    try:
        admin_exists = db.execute(
            text("SELECT id FROM users WHERE email = 'admin@example.com'")
        ).fetchone()
        
        if not admin_exists:
            hashed_password = bcrypt.hash("admin123")
            db.execute(
                text("INSERT INTO users (username, email, hashed_password, role, created_at) VALUES (:u, :e, :p, :r, NOW())"),
                {"u": "superadmin", "e": "admin@example.com", "p": hashed_password, "r": "ADMIN"}
            )
            db.commit()
            print("Администратор создан: admin@example.com / admin123")
    except Exception as e:
        print(f"Ошибка при создании администратора: {e}")
    
    try:
        from database.stored_procedures import create_stored_procedures
        create_stored_procedures()
    except Exception as e:
        print(f"Ошибка при создании хранимых процедур: {e}")
    try:
        from database.import_data import import_data
        import_data()
    except Exception as e:
        print(f"Ошибка при автообновлении данных: {e}")


@app.put("/admin/users/{user_id}")
async def admin_update_user(
    user_id: int,
    data: dict = Body(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    user = db.execute(
        text("SELECT * FROM users WHERE id = :id"),
        {"id": user_id}
    ).mappings().first()

    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    if "username" in data and data["username"].strip():
        db.execute(
            text("UPDATE users SET username = :u WHERE id = :id"),
            {"u": data["username"], "id": user_id}
        )

    if "email" in data and data["email"].strip():
        db.execute(
            text("UPDATE users SET email = :e WHERE id = :id"),
            {"e": data["email"], "id": user_id}
        )

    if "role" in data:
        db.execute(
            text("UPDATE users SET role = :r WHERE id = :id"),
            {"r": data["role"], "id": user_id}
        )
    if "password" in data and data["password"].strip():
        hashed = bcrypt.hash(data["password"])
        db.execute(
            text("UPDATE users SET hashed_password = :p WHERE id = :id"),
            {"p": hashed, "id": user_id}
        )

    db.commit()
    return {"success": True}

@app.put("/admin/stations/{station_id}")
async def admin_update_station(
    station_id: int,
    data: dict = Body(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    station = db.execute(
        text("SELECT * FROM stations WHERE id = :id"),
        {"id": station_id}
    ).mappings().first()

    if not station:
        raise HTTPException(status_code=404, detail="Станция не найдена")

    allowed_fields = [
        "name", "address", "district", "admarea",
        "owner", "eco_status", "latitude", "longitude", "test_date"
    ]

    for field, value in data.items():
        if field in allowed_fields:
            db.execute(
                text(f"UPDATE stations SET {field} = :v WHERE id = :id"),
                {"v": value, "id": station_id}
            )

    db.commit()
    return {"success": True}

@app.put("/admin/reviews/{review_id}")
async def admin_update_review(
    review_id: int,
    data: dict = Body(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_admin)
):
    review = db.execute(
        text("SELECT * FROM reviews WHERE id = :id"),
        {"id": review_id}
    ).mappings().first()

    if not review:
        raise HTTPException(status_code=404, detail="Отзыв не найден")

    if "rating" in data:
        db.execute(
            text("UPDATE reviews SET rating = :r WHERE id = :id"),
            {"r": int(data["rating"]), "id": review_id}
        )

    if "comment" in data:
        db.execute(
            text("UPDATE reviews SET comment = :c WHERE id = :id"),
            {"c": data["comment"], "id": review_id}
        )

    db.commit()
    return {"success": True}
