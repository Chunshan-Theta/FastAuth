# FastAPI Authentication API

This is a FastAPI-based authentication API with JWT token authentication, rate limiting using Redis, and MongoDB for user storage.

## 🚀 Features
- User registration and authentication
- JWT-based access tokens
- Rate limiting using Redis
- Docker and Docker Compose setup for easy deployment
- Interactive API documentation with Swagger UI

## 🛠 Technologies Used
- **FastAPI** for API framework
- **MongoDB** for user database
- **Redis** for rate limiting
- **Uvicorn** as the ASGI server
- **Docker & Docker Compose** for containerization

---

## 🐳 Running with Docker Compose
To run the API, MongoDB, and Redis using Docker Compose, execute:
```sh
docker-compose up -d --build
```
This will:
- Build and start the **FastAPI app**
- Start **MongoDB** for user storage
- Start **Redis** for rate limiting

### **Check Running Containers**
```sh
docker ps
```

To stop all containers:
```sh
docker-compose down
```

---

## 🔥 API Endpoints
### **1️⃣ User Registration**
```http
POST /register
```
**Request Body:**
```json
{
  "username": "testuser",
  "password": "testpass"
}
```
**Response:**
```json
{
  "message": "User registered successfully"
}
```

### **2️⃣ Generate Token**
```http
POST /token
```
**Request Form Data:**
```plaintext
username=testuser
password=testpass
```
**Response:**
```json
{
  "access_token": "your_jwt_token_here",
  "token_type": "bearer"
}
```

### **3️⃣ Access Protected Route**
```http
GET /protected
```
**Headers:**
```plaintext
Authorization: Bearer your_jwt_token_here
```
**Response:**
```json
{
  "message": "You have accessed a protected route",
  "user": "testuser"
}
```

---

## 🔎 API Documentation
After starting the server, you can access interactive API documentation:
- **Swagger UI** 👉 [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc UI** 👉 [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 🛑 Stopping & Cleaning Up
To stop and remove all containers:
```sh
docker-compose down -v
```
This will **remove all MongoDB & Redis data**.

---

## 📜 License
This project is licensed under the MIT License.

---

## 🤝 Contributing
Feel free to submit issues or pull requests to improve this API!

🚀 **Happy Coding!**

