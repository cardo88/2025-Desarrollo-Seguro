# Vulnerabilidades

## **Inyección SQL (SQLi)**

### Identificar

Código encontrado en el backend: `services/backend/src/services/invoiceService.ts`

```tsx
class InvoiceService {
  static async list( userId: string, status?: string, operator?: string): Promise<Invoice[]> {
    let q = db<InvoiceRow>('invoices').where({ userId: userId });
    if (status) q = q.andWhereRaw(" status "+ operator + " '"+ status +"'");
    const rows = await q.select();
    const invoices = rows.map(row => ({
      id: row.id,
      userId: row.userId,
      amount: row.amount,
      dueDate: row.dueDate,
      status: row.status} as Invoice
    ));
    return invoices;
  }
```

**Error:**

- Se están concatenando dos inputs en SQL crudo: operator y status

### Validar

El método  `list` es es usado en `services/backend/src/controllers/invoiceController.ts`  desde `listInvoices`

```tsx
const listInvoices = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const state = req.query.status as string | undefined;
    const operator = req.query.operator as string | undefined;
    const id   = (req as any).user!.id; 
    const invoices = await InvoiceService.list(id, state,operator);
    res.json(invoices);
  } catch (err) {
    next(err);
  }
};
```

`listInvoices` esta referenciado en `services/backend/src/routes/invoices.routes.ts` como parte de la raiz de `/invoices`

```tsx
import routes from '../controllers/invoiceController';
// GET /invoices
router.get('/', routes.listInvoices);
```

`/invoices` esta indicado ya desde el `services/backend/src/index.ts`

```bash
import invoiceRoutes from './routes/invoices.routes';
app.use('/invoices', invoiceRoutes);
```

Entonces podemos usar CURL con la URL de backend, más el path `/invoices`, más los parámetros, sin olvidarnos del TOKEN:

```bash

curl -i 
"http://localhost:5000/invoices?
userId=<userID>&
operator=<operador>&
status=<status>"\
-H "Authorization: Bearer $TOKEN"
```

Ejemplo que podemos ejecutar

```bash

curl -i "http://localhost:5000/invoices?userId=123&operator=%3D&status=paid'%20OR%20'1'%3D'1'--%20" \
  -H "Authorization: Bearer $TOKEN"

```

Donde el código vulnerable era:

```bash
.andWhereRaw(" status " + operator + " '" + status + "'");
```

Usamos los siguientes parámetros:

- `operator = =` para que no lo tome en cuenta
- `status = 'paid'` era la condición original.
- `OR '1'='1'` siempre es verdadero.
- `--`  en SQL es un comentario, por lo tanto ignora el resto de la línea.

Por consiguiente, ya que en SQL `AND` tiene mayor precedencia que `OR`, el WHERE sera algo como:

```bash
WHERE ( userId = '123' AND status = 'paid' ) OR ( '1'='1' )
```

Toda la condición es verdadera para todas las filas, brindando todas las facturas del sistema:

![alt text](/doc/vulnerabilidad-07/image.png)

Nota: podemos verificar esa información consultándola directamente a la base de datos:

![alt text](/doc/vulnerabilidad-07/image-1.png)

### Remediar

Sustituir el código:

```tsx
  static async list( userId: string, status?: string, operator?: string): Promise<Invoice[]> {
    let q = db<InvoiceRow>('invoices').where({ userId: userId });
    if (status) q = q.andWhereRaw(" status "+ operator + " '"+ status +"'");
    const rows = await q.select();
    const invoices = rows.map(row => ({
      id: row.id,
      userId: row.userId,
      amount: row.amount,
      dueDate: row.dueDate,
      status: row.status} as Invoice
    ));
    return invoices;
  }
```

por el siguiente:

```tsx
  // Modificado en PRACTICO 02
  static async list(userId: string, status?: string, operator?: string): Promise<Invoice[]> {
    let q = db<InvoiceRow>('invoices').where({ userId });

    if (status) {
      // Validar status contra un conjunto permitido (seria correcto validarlo con una tabla de estados en la BD)
      const allowedStatus = new Set(['paid', 'unpaid']);
      if (!allowedStatus.has(status)) {
        throw new Error('Invalid status');
      }

      // Whitelist de operadores (si realmente hace falta)
      // Para un campo de texto "status", típicamente solo "=" o "!=" tienen sentido.
      const op = operator ?? '=';
      switch (op) {
        case '=':
          q = q.andWhere('status', status);
          break;
        case '!=':
          q = q.andWhereNot('status', status);
          break;
        default:
          throw new Error('Invalid operator');
      }
    }
```

### Verificar

Volvemos a correr:

```bash

curl -i "http://localhost:5000/invoices?userId=123&operator=%3D&status=paid'%20OR%20'1'%3D'1'--%20" \
  -H "Authorization: Bearer $TOKEN"
```

y nos devuelve el error que agregamos para cuando el `status` no corresponde

```bash
{"message":"Invalid status"}
```

![alt text](/doc/vulnerabilidad-07/image-2.png)

## Almacenamiento inseguro (CWE-256)

### **Identificar**

En `services/backend/src/services/authService.ts` se encuentra el siguiente código, eso implica que en la Base de Datos la columna users.password guarda texto plano (o algo reversible).

```tsx
  static async authenticate(username: string, password: string) {
    const user = await db<UserRow>('users')
      .where({ username })
      .andWhere('activated', true)
      .first();
    if (!user) throw new Error('Invalid email or not activated');
    if (password != user.password) throw new Error('Invalid password');
    return user;
  }
```

1. Busca un usuario en la tabla users con ese username y activated = true.
2. Si no encuentra, devuelve error.
3. Si lo encuentra, compara directamente el password recibido con lo que está guardado en la base.
4. Si coincide, devuelve el usuario.

Problemas:

- Manejo de contraseñas en texto plano.
  - Se está guardando user.password tal cual en la base.
- Se compara con if (password != user.password) en lugar de usar un hash.
- O sea que permite que si alguien accede a la base, vea todas las contraseñas.

### Validar

Ver los datos insertados en la base de datos

```sql
SELECT username, password FROM users;
```

Podemos ejecutar directamente en la consola:

```bash
docker compose exec postgres psql -U user -d jwt_api -c "SELECT username, password FROM users;"
```

![alt text](/doc/vulnerabilidad-07/image-3.png)

### Remediar

Implementar el uso de `bcrypt` con un factor de `costo configurado en 12` para el almacenamiento de contraseñas. Esto permite que cada contraseña se guarde como un hash irreversible con una `sal` única generada automáticamente, impidiendo que dos usuarios con la misma contraseña tengan el mismo valor en la base de datos, así como dificultar los ataques de fuerza bruta.

También incorporar el uso de una variable `pepper`, otro valor secreto que se concatena con la contraseña antes de hashearla, que diferencia del salt, no se almacena en la base de datos, sino en un entorno seguro, como una variable de entorno.

En el proceso de autenticación se reemplaza la comparación directa de contraseñas por `bcrypt.compare`, garantizando verificaciones seguras y resistentes a ataques de temporización.

Por último, con fines de facilitar la conversión de contraseña desde texto plano a hasheada, se agrega funcionalidad `LEGACY_PW_MIGRATION` para verificar si la contraseña aun esta en texto plano, y conviertirla automáticamente.

Cambios aplicados en `services/backend/src/services/authService.ts`:

![alt text](/doc/vulnerabilidad-07/image-4.png)

![alt text](/doc/vulnerabilidad-07/image-5.png)

![alt text](/doc/vulnerabilidad-07/image-6.png)

![alt text](/doc/vulnerabilidad-07/image-7.png)

![alt text](/doc/vulnerabilidad-07/image-8.png)

![alt text](/doc/vulnerabilidad-07/image-9.png)

Si bien la funcionalidad `LEGACY_PW_MIGRATION`no introduce una nueva vulnerabilidad por sí misma (ya que si la base de datos contenía contraseñas en texto plano y si el atacante ya leyó la esta información, podrá autenticarse con o sin migración. De todas formas se agrega una bandera para desactivar esta funcionalidad.

![alt text](/doc/vulnerabilidad-07/image-10.png)

![alt text](/doc/vulnerabilidad-07/image-11.png)

### Verificar

Accedemos como lo haciamos desde el inicio

```bash
curl -s -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"password"}'
```

![alt text](/doc/vulnerabilidad-07/image-12.png)

Comprobamos si la contraseña de ese usuario se a convertido de texto plano a hash en la base de datos

```bash
docker compose exec postgres psql -U user -d jwt_api -c "SELECT username, password FROM users;"
```

![alt text](/doc/vulnerabilidad-07/image-13.png)

Volvemos a logueranos de la misma forma

![alt text](/doc/vulnerabilidad-07/image-14.png)
Y ya podemos confirmar que en este nuevo intento, la contraseña ya no es en texto plano tampoco la información devuelta por el backend (independiémente de si devolver ese valor es una buena práctica o no).


## Inyección de comandos en plantillas (Template Command Injection)

### **Identificar**

En `services/backend/src/services/authService.ts` se encuentra el siguiente código. Este crea la plantilla usando interpolación de JS y luego la procesa con EJS:

```tsx
import ejs from 'ejs';
  const template = `
    <html>
      <body>
        <h1>Hello ${user.first_name} ${user.last_name}</h1>
        <p>Click <a href="${ link }">here</a> to activate your account.</p>
      </body>
    </html>`;
  const htmlBody = ejs.render(template);
```

1. Primero la plantilla se forma con backticks (`...${...}...`).
2. Eso inserta los valores de user.first_name, user.last_name, link directamente en la cadena que se pasará a EJS.
3. Después EJS compila/ejecuta esa cadena como plantilla.

Si un valor de user.* contiene expresiones EJS (por ejemplo <% ... %> o <%= ... %>), esas expresiones llegan a EJS y se ejecutan en el servidor.
Ejemplo, si `user.first_name` fuese `<%= require('fs').readFileSync('/etc/passwd','utf8') %>` entonces EJS intentará ejecutar ese código y podría devolver el contenido de /etc/passwd en el htmlBody.

### Validar

Las pruebas de RCE pueden ejecutar comandos. Haremos pruebas no destructivas.

Obtener token y guardarlo en $TOKEN (referirse al documento de ProcedimiendoDeUsoComun).

El método `createUser` del service es usado en `services/backend/src/controllers/authController.ts` desde `createUser` del controlador

```tsx
const createUser = async (req: Request, res: Response, next: NextFunction) => {
  const { username, password, email, first_name, last_name } = req.body;
  try {
    const user: User = {
      username,
      password,
      email,
      first_name,
      last_name
    };
    const userDB = await AuthService.createUser(user);
    res.status(201).json(userDB);
  } catch (err) {
    next(err);
  }
};
```

El `createUser` del controlador esta referenciado en `services/backend/src/routes/user.routes.ts` como parte de la raiz `/`

```tsx
import routes from '../controllers/authController';
// POST /auth to create a new user
// This route is typically used for user registration
router.post('/', routes.createUser);
```

y este `/` esta indicado ya desde el `services/backend/src/index.ts`

```bash
import userRoutes from './routes/user.routes';
app.use('/users', userRoutes);
```

Entonces podemos usar CURL con la URL de backend, más el path `/users/`, más los parámetros, sin olvidarnos del TOKEN:

Antes de avanzar, como `mailhog` no esta funcionando nos mostrara un error respecto al intento de enviar un correo (errores relacionados a SMTP), por lo que podemos seguir verificando esta vulnerabildiad imprimiendo el resultado en consola agregando lo siguiente en el codigo:

```tsx
    console.log('--- HTML BODY START ---');
    console.log(htmlBody);
    console.log('--- HTML BODY END ---');
```

De esta forma, teniendo dos terminales abiertas, desde una terminal leeremos los logs del backend con el siguiente comando

```bash
docker compose logs -f backend
```

Y en la otra terminal ejecutaremos el comando CURL:

```bash
curl -i -X POST http://localhost:5000/users/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username":"pocuser5",
    "password":"pocpass",
    "email":"poc5@example.com",
    "first_name":"<%= 2 + 2 %>",
    "last_name":"Tester"
  }'
```

Enconrtando que en vez de tener el saludo al nuevo usaurio, haciendo uso del first_name, saluda al numero `4`, resultado de `2 + 2`.

![alt text](/doc/vulnerabilidad-06/image-15.png)

Otra prueba puede ser:

```bash
curl -i -X POST http://localhost:5000/users/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username":"pocuser10",
    "password":"pocpass",
    "email":"poc10@example.com",
    "first_name":"<%= process.env.PATH %>",
    "last_name":"Tester"
  }'
```

Donde obtendremos la siguiente respuesta:

![alt text](/doc/vulnerabilidad-06/image-16.png)

### Remediar

Se agrega una plantilla fija y se pasan los datos del usuario como variables. De esta forma se evita crear la plantilla  interpolación (${...}), pues esto permitía ejecutar código embebido. 
También se agregan validación/sanitización para los campos que el usuario completa (first_name, last_name, username y email), bloqueando tokens peligrosos (<%, require(, fs., etc.).
Se genera el link con encodeURIComponent para prevenir inyección vía URL. 
Con esto, EJS trata los valores como texto escapado (<%=) y se elimina la posibilidad de Template Command Injection.

Código viejo:

``` tsx
const link = `${process.env.FRONTEND_URL}/activate-user?token=${invite_token}&username=${user.username}`;

const template = `
  <html>
    <body>
      <h1>Hello ${user.first_name} ${user.last_name}</h1>
      <p>Click <a href="${ link }">here</a> to activate your account.</p>
    </body>
  </html>`;
const htmlBody = ejs.render(template);
```

Código nuevo:

```tsx
import validator from 'validator';

    const nameRegex = /^[A-Za-zÁÉÍÓÚáéíóúÑñ' \-]{1,80}$/;
    if (!nameRegex.test(user.first_name) || !nameRegex.test(user.last_name))
      throw new Error('Invalid name format');

    if (!validator.isEmail(user.email))
      throw new Error('Invalid email');

    const usernameRegex = /^[a-zA-Z0-9_.-]{3,32}$/;
    if (!usernameRegex.test(user.username))
      throw new Error('Invalid username');

    const dangerous = /<%|%>|require\(|child_process|fs\./i;
    if (dangerous.test(user.first_name) || dangerous.test(user.last_name) || dangerous.test(user.username))
      throw new Error('Invalid characters in input');

    const link = `${process.env.FRONTEND_URL || ''}/activate-user?token=${invite_token}&username=${encodeURIComponent(user.username)}`;

    const templateFile = `
  <html>
    <body>
      <h1>Hello <%= user.first_name %> <%= user.last_name %></h1>
      <p>Click <a href="<%= link %>">here</a> to activate your account.</p>
    </body>
  </html>`;

    const htmlBody = ejs.render(templateFile, {
      user: {
        first_name: user.first_name,
        last_name: user.last_name
      },
      link
    });
```

### Verificar

Volvemos a intentar pasar codigo en alguno de los campos rellenados por el usuario, obteniendo los siguientes resultados

Prueba 1

![alt text](/doc/vulnerabilidad-06/image-17.png)

![alt text](/doc/vulnerabilidad-06/image-18.png)

Prueba 2


![alt text](/doc/vulnerabilidad-06/image-19.png)

![alt text](/doc/vulnerabilidad-06/image-20.png)
