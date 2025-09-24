# Procedimientos de uso común

## **Averiguar credenciales para acceder a la plataforma**

```bash
docker compose exec postgres psql -U user -d jwt_api -c "SELECT * FROM users;"
```

y la respuesta será:

![alt text](image.png)

## **Acceso con credenciales válidas obteniendo token**

Interactuando directamente con el backend, podemos usar el POST del login.

En el index del backend `services/backend/src/index.ts` se indica que la ruta de autenticación esta en `services/backend/src/routes/auth.routes.ts`

```tsx
import authRoutes from './routes/auth.routes';
app.use('/auth', authRoutes);
```

En `services/backend/src/routes/auth.routes.ts` se indica que el login esta en `services/backend/src/controllers/authController.ts`

```tsx
import routes from '../controllers/authController';
router.post('/login', routes.login);
```

Y en `services/backend/src/controllers/authController.ts` tenemos el método login que nos permitirá acceder, brindándonos el tocken que necesitamos

```tsx
const login = async (req: Request, res: Response, next: NextFunction) => {
  const { username, password } = req.body;
  try {
    const user = await AuthService.authenticate(username, password);
    const token = await AuthService.generateJwt(user.id);
    res.json({ token, user });
  } catch (err) {
    next(err);
  }
};
```

Siendo que el backend esta en `http://localhost:5000/` , podemos hacer una consulta mediante consola con el comando CURL al método de login, pasándole las credenciales:

```bash
curl -i -X POST http://localhost:5000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"test","password":"password"}' 
```

Y la respuesta será algo como:

![alt text](image-1.png)

Podemos guardar el TOKEN en una variable para no tener que recordarlo cada vez:

```bash
TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiaWF0IjoxNzU3Nzc1OTQwLCJleHAiOjE3NTc3Nzk1NDB9.axfQnI6yF-Bu41Dd4yXXcLZA_gpZwpgA23xO3wtQglc
```

Entonces ahora podemos usarle con `$TOKEN` en bash.

otra forma:

```bash
TOKEN=$(curl -s -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"password"}' \
  | sed -E 's/.*"token":"([^"]+)".*/\1/')
```

Verificar:

```bash
echo $TOKEN
```