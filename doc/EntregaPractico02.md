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

![alt text](image.png)

Nota: podemos verificar esa información consultándola directamente a la base de datos:

![alt text](image-1.png)

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

![alt text](image-2.png)


## CREDENCIALES EMBEBIDAS (BELEN)

## FALSIFICACIÒN DE PETICIONES DEL LADO DEL SERVIDOR (BELEN)



## RECORRIDO DE DIRECTORIOS (CWE-22)

### Identificar

Còdigo encontrado en el backend: `services/backend/src/services/invoiceService.ts`

```tsx
  static async getReceipt(
    invoiceId: string,
    pdfName: string
  ) {
    // check if the invoice exists
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId}).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    try {
      const filePath = `/invoices/${pdfName}`;
      const content = await fs.readFile(filePath, 'utf-8');
      return content;
    } catch (error) {
      // send the error to the standard output
      console.error('Error reading receipt file:', error);
      throw new Error('Receipt not found');

    } 

  };
```

Este còdigo es vulnerable a Path traversal, ya que las lìneas:
```tsx
  const filePath = `/invoices/${pdfName}`;
  const content = await fs.readFile(filePath, 'utf-8');
  return content;
```

la variable `filePath` está armando la ruta de la `url` pegando direcramente lo que viene del usuario (`pdfName`) al directorio `/invoices`, y luego lo abre con `fs.readFile` sin verificar nada antes.
Esto significa que si alguien envía `pdfName` con rutas relativas como `../`, la ruta que se manda podría salir del directorio `/invoices` y apuntar a archivos que estén afuera que el proceso pueda leer, por lo que trataría de un Path Traversal.

---

### Validar

#### Introducción
Para reproducir la vulnerabilidad Path Traversal en `getReceipt`, crearemos un archivo `.txt` de prueba dentro del contenedor backend y luego intentaremos leerlo a través del endpoint de facturas usando el parámetro `pdfName` (`GET /invoices/{id}/invoice?pdfName=...`) usando un payload que salga del directorio `/invoices` .

Si la respuesta devuelve el contenido del archivo `.txt` de prueba creado, se podrá confirmar que la aplicación construye rutas a partir de datos controlados por el usuario sin normalizarlas ni validarlas, por lo que estaremos frente a un caso de Path Traversal.

#### Paso1: Creamos el archivo de prueba .txt
Creamos el archivo `archivoEncontrado.txt` dentro del contenedor backend:
```bash
  docker compose exec backend sh -c "mkdir -p /tmp/poc_test_dir && echo 'llegaste a la vulnerabilidad' > /tmp/poc_test_dir/archivoEncontrado.txt && cat /tmp/poc_test_dir/archivoEncontrado.txt"
```
![alt text](image-15.png)

#### Paso 2: Calculamos la ruta relativa del archivo
Calculamos la ruta relativa que hay desde `/invoices` hasta el archivo que tendremos como objetivo `/tmp/carpetaPOC/archivoEncontrado.txt`  usando  `path.relative`, para poder utilizar en el endpoint de consulta de facturas que se pasará como `pdfName`.

```bash
  docker compose exec backend node -e "const path=require('path'); console.log(path.relative(process.argv[1], process.argv[2]));" "/invoices" "/tmp/carpetaPOC/archivoEncontrado.tx
```
![alt text](image-16.png)

#### Paso 3: Listar usuarios
Listaremos los usuarios guardados en la base de datos para poder visualizar que factura le pertenece a que usuario, de esta manera podremos utilizar el `id` de factura que le corresponde al usuario que loguearemos para explotar esta vulnerabilidad.
```bash
  docker compose exec postgres psql -U user -d jwt_api -c "SELECT * FROM
users;"
```
![alt text](image-17.png)

#### Paso 4: Autenticaremos el usuario para saber el token de acceso
Mediante un `CURL`  con las credenciales del usuario de `id=1` nos autenticaremos para saber el `TOKEN` que utilizaremos para realizar el ataque.
```bash
  curl -i -X POST http://localhost:5000/auth/login \
 -H 'Content-Type: application/json' \
 -d '{"username":"test","password":"password"}'
```
![alt text](image-18.png)

#### Paso 5: Listaremos las facturas
Listaremos las facturas para tener un `invoiceId` válido para la `URL` de prueba `GET /invoices/{id}/invoice?pdfName=...`.
```bash
  docker compose exec -it postgres psql -U user -d jwt_api -c "SELECT id, \"userId\", amount, \"dueDate\", status FROM invoices ORDER BY id LIMIT 10;
```
![alt text](image-19.png)

#### Paso 6: Consulta al endpoint de la factura apuntando a la ruta relativa
Este paso es clave ya que acá se prueba la existencia del Path Traversal. Mediante `CURL` se realiza una petición al endpoint de la factura usando `invoiceId = 1` y `pdfName` igual a la ruta relativa calculada en el paso 2. Se incluye el `Authorization: Bearer <TOKEN>` obtenido en el paso 4 porque el endpoint está protegido. Si la respuesta contiene el contenido del archivo de prueba, se confirma la vulnerabilidad.
```bash
  curl -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiaWF0IjoxNzU4NzEwNjAwLCJleHAiOjE3NTg3MTQyMDB9.1XtLaZlnac0FjBuI3KXiydqGUnm51KIGLQ10xhxatuw" \
  "http://localhost:5000/invoices/1/invoice?pdfName=../tmp/carpetaPOC/archivoEncontrado.txt"
```
![alt text](image-20.png)

El servidor respondió con `200 OK` y en el cuerpo devolvió el texto que está dentro del archivo de prueba. Esto confirma que el parámetro `pdfName` permitió salir del directorio `/invoices` y acceder a un archivo arbitrario en `/tmp`, demostrando la vulnerabilidad de Path Traversal.

---

### Remediar

Para resolver la vulnerabilidad, lo que haremos es modificar el método estático `getReceipt` en donde encontramos la vulnerabilidad:
**Antes:**
```tsx
  static async getReceipt(
    invoiceId: string,
    pdfName: string
  ) {
    // check if the invoice exists
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId}).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    try {
      const filePath = `/invoices/${pdfName}`;
      const content = await fs.readFile(filePath, 'utf-8');
      return content;
    } catch (error) {
      // send the error to the standard output
      console.error('Error reading receipt file:', error);
      throw new Error('Receipt not found');

    } 
```

**Después:**
```tsx
   static async getReceipt(
    invoiceId: string,
    pdfName: string
  ) {
    // check if the invoice exists
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId}).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    try {
      const baseFilePath = path.resolve('/', 'invoices');
      const resolved = path.resolve(path.join(baseFilePath, pdfName));
      const baseWithSep = baseFilePath.endsWith(path.sep) ? baseFilePath : baseFilePath + path.sep;
      if (!resolved.startsWith(baseWithSep)) throw new Error('Access denied');

      //const filePath = `/invoices/${pdfName}`;
      //const content = await fs.readFile(filePath, 'utf-8');
      const content = await fs.readFile(resolved);
      return content;
    } catch (error) {
      // send the error to the standard output
      console.error('Error reading receipt file:', error);
      throw new Error('Receipt not found');

    } 

  }; 
```

**Lo que hicimos fue:**
Comenzamos definiendo el directorio base seguro (`baseFilePath`), luego normalizamos la ruta juntando ese directorio con el `pdfName` mediante `path.resolve`, lo que elimina secuencias como `..` o `.` y devuelve una ruta absoluta. Después, con `baseWithSep` nos aseguramos de que la ruta final siga dentro de `/invoices`, evitando escapes hacia otros directorios.

Si todas estas validaciones se cumplen, se utiliza la ruta resultante (`resolved`) para acceder al archivo solicitado juntando `baseFilePath` con `pdfName` .

---

**Validar**

Lo que haremos es explotar de nuevo la vulnerabilidad, en el caso de que la misma no aparezca, eso quiere decir que la mitigación de la misma se realizó de manera correcta.

Para hacer esto, lo que haremos es realizar el paso 6 del PoC para poder visualizar la respuesta que nos da la consulta hecha con la ruta relativa que apunta al archivo `.txt` que creamos en el PoC.

**Nota**: cabe aclarar que para hacer esta validación, en el caso que se hayan bajado y levantado los contenedores, se debe de realizar de nuevo el “paso4: autenticaremos el usuario para saber el token de acceso” del PoC para así poder utilizar ese `TOKEN` en la consulta, ya que sino el mismo cambia al bajar y subir los contenedores y dará error de autenticación.

**Realizaremos la consulta (paso 6 del PoC):**
```bash
  curl -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiaWF0IjoxNzU4NzE3OTUwLCJleHAiOjE3NTg3MjE1NTB9.mYFNOHfS50eEHncZCeyuslJDb5nHxHCbKY3tOlOjBFE" \
    "http://localhost:5000/invoices/1/invoice?pdfName=../tmp/carpetaPOC/archivoEncontrado.txt"
```

**Respuesta obtenida:**
![alt text](image-21.png)

La respuesta obtenida fue de `500 Internal Server Error`. Esto indica que la validación implementada en la mitigación detectó que la ruta solicitada salía del directorio permitido (`/invoices`) y bloqueó el acceso. De esta manera concluimos que la mitigación quedó realizada de manera correcta.

---
---

## FALTA DE AUTORIZACIÓN (CWE-862)

### Identificar 

Código encontrado en el backend: `services/backend/src/services/invoiceService.ts`
```tsx
   static async  getInvoice( invoiceId:string): Promise<Invoice> {
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    return invoice as Invoice;
  }
```

La consulta sólo filtra por `id` de factura. Si un usuario autenticado conoce o adivina el `invoiceId` de otra persona, puede solicitar `GET /invoices/:id` y obtener los datos de una factura que no le pertenece, motivo por el cuál se trata de una vulnerabilidad de Missing authorization.

También dentro del archivo `services/backend/src/controllers/invoiceController.ts`  el controlador toma el `invoiceId` de la URL y llama al servicio sin pasar la identidad del usuario autenticado, por lo que el servicio no puede verificar si el usuario que esta pidiendo esa factura es el dueño de la misma.

```tsx
  const getInvoice = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const invoiceId = req.params.id;
      const invoice = await InvoiceService.getInvoice(invoiceId);
      res.status(200).json(invoice);

    } catch (err) {
      next(err);
    }
  };
```

### Validar

#### Introducción
Para visualizar esta vulnerabilidad, lo que haremos será, primero hacer una consulta a la base de datos para saber que facturas están cargadas en la base y a que `userId` le pertenece cada una. Luego saber qué id de factura `invoiceId` le pertenece a qué `userId`, entonces haremos un `CURL` utilizando en la `URL` el `id` de la factura del usuario “atacado” y el `TOKEN` del usuario “atacante” para simular que nos autenticamos con un usuario, y queremos visualizar la factura de otro usuario.

Si con el `id` de un usuario al que no le pertenece la factura que queremos obtener, logramos visualizar la misma, lograremos ver la vulnerabilidad anteriormente identificada.

#### Paso 1: Listaremos las facturas
Mediante una consulta, listaremos las facturas cargadas en la base de datos para poder identificar qué factura le pertenece a qué usuario mediante los `id`.

```bash
  docker compose exec -it postgres psql -U user -d jwt_api -c "SELECT id, \"userId\", amount, \"dueDate\", status FROM invoices ORDER BY id LIMIT 10;"
```
![alt text](image-22.png)

#### Paso 2: Listaremos los usuarios
Mediante otra consulta, listaremos a los usuarios para saber sus credenciales y averiguar el `TOKEN` del usuario con el que haremos el ataque.

```bash
  docker compose exec postgres psql -U user -d jwt_api -c "SELECT * FROM
users;"
```
![alt text](image-23.png)

#### Paso 3: Autenticaremos el usuario para saber el token de acceso
Mediante un `CURL`  con las credenciales del usuario de `id=1` nos autenticaremos para saber el token que utilizaremos para realizar el ataque.

```bash
  curl -i -X POST http://localhost:5000/auth/login \
 -H 'Content-Type: application/json' \
 -d '{"username":"test","password":"password"}'
```
![alt text](image-24.png)

#### Paso 4: Consulta autenticada a factura ajena
Con el usuario de `id=1`, mediante un `CURL`, solicitaremos la factura de `id=4` perteneciente al usuario de `id=1` (visto en el paso 1). Este paso es clave ya que define si la vulnerabilidad realmente existe o no, en el caso que exista, podremos visualizar la factura que no le pertenece al usuario que realiza la solicitud.

```bash
  curl -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiaWF0IjoxNzU4MzA4ODc5LCJleHAiOjE3NTgzMTI0Nzl9.Hqrr25WpQrLhTH-Cgm10v3mu3y6YJ4N53y1W7Pzp8W8" \
  "http://localhost:5000/invoices/4"
```
![alt text](image-25.png)

La respuesta fue `200 OK` y nos mostró la factura del usuario de `id=2`, por lo que la vulnerabilidad realmente existe.

---

### Remediar

Para resolver esta vulnerabilidad, lo que haremos es:

Dentro del controlador `getInvoice` ubicado en `services/backend/src/controllers/invoiceController.ts`:

Le agregaremos para que se traiga dentro de la variable `currentUserId`, el `userId` del `TOKEN`, y usaremos ese mismo en el servicio cuando lo llamemos.

**Antes:**
```tsx
  const getInvoice = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = req.params.id;
    const invoice = await InvoiceService.getInvoice(invoiceId);
    res.status(200).json(invoice);

  } catch (err) {
    next(err);
  }
};
```
**Después:**
```tsx
  const getInvoice = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = req.params.id;
    const currentUserId = (req as any).user!.id;
    const invoice = await InvoiceService.getInvoice(invoiceId, currentUserId);
    res.status(200).json(invoice);

  } catch (err) {
    next(err);
  }
};
```

En el servicio recientemente visto, ubicado en `Uservices/backend/src/services/invoiceService.ts` :

Le cambiaremos, para que reciba como parámetro no solo el `invoiceId`, sino también el `currentUserId` que nos traeremos del token en el controlador.

Esto generará que la base de datos devuelva la factura solamente si pertenece al usuario que hizo la consulta `currentUserId` (token válido).

**Antes:**
```tsx
   static async  getInvoice( invoiceId:string): Promise<Invoice> {
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    return invoice as Invoice;
  }
  
```
**Después:**
```tsx
    static async  getInvoice( invoiceId:string, currentUserId: string): Promise<Invoice> {
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId, userId: currentUserId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    return invoice as Invoice;
  }
  
```

### Validar

Para validar la mitigación lo que haremos es el paso 4 nombrado en el PoC, un primer intento igual a como lo hicimos en ese paso, y un segundo intento con el token del usuario al que le pertenece esa factura de `id=4`, que es el usuario de `id=2`.

#### Paso 1: Petición autenticada a factura ajena
Utilizaremos el token del usuario de `id=1` que fue el `TOKEN` que extrajimos en el paso 3 del PoC, para consultar la factura de `id=4` perteneciente al usuario de `id=2`.
```bash
    curl -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiaWF0IjoxNzU4MzA4ODc5LCJleHAiOjE3NTgzMTI0Nzl9.Hqrr25WpQrLhTH-Cgm10v3mu3y6YJ4N53y1W7Pzp8W8" \
  "http://localhost:5000/invoices/4"
```
![alt text](image-26.png)

La respuesta obtenida fue de `500 Internal Server Error`, eso quiere decir que la mitigación quedó de manera correcta, para lograr confirmarlo, haremos la consulta con el `TOKEN` del usuario dueño de esa factura, por lo que nos tendría que mostrar la misma.

#### Paso 2: Autenticaremos el usuario para saber el token de acceso
Mediante un `CURL`  con las credenciales del usuario de `id=2` nos autenticaremos para saber el `TOKEN` que utilizaremos para consultar la factura.

```bash
    curl -i -X POST http://localhost:5000/auth/login \
 -H 'Content-Type: application/json' \
 -d '{"username":"prod","password":"password"}'
```
![alt text](image-27.png)

#### Paso 3: confirmaremos la correcta mitigación de la vulnerabilidad
Con el `TOKEN` recientemente consultado, consultaremos por la factura de `id=4` perteneciente a ese usuario.

```bash
    curl -i -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwiaWF0IjoxNzU4MzA5OTk4LCJleHAiOjE3NTgzMTM1OTh9.CF1zjZc-FjSM8ZK6f4cT1yN9fCtYi0bwJZWI0rI6tdA" \
  "http://localhost:5000/invoices/4"
```
![alt text](image-28.png)

Obtuvimos una respuesta correcta, se pudo visualizar la factura perteneciente al usuario. Concluimos que la vulnerabilidad de Missing authorization identificada se mitigó de manera correcta.

---
---

## ALMACENAMIENTO INSEGURO (CWE-256)

### Identificar

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

![alt text](image-3.png)

### Remediar

Implementar el uso de `bcrypt` con un factor de `costo configurado en 12` para el almacenamiento de contraseñas. Esto permite que cada contraseña se guarde como un hash irreversible con una `sal` única generada automáticamente, impidiendo que dos usuarios con la misma contraseña tengan el mismo valor en la base de datos, así como dificultar los ataques de fuerza bruta. 

También incorporar el uso de una variable `pepper`, otro valor secreto que se concatena con la contraseña antes de hashearla, que diferencia del salt, no se almacena en la base de datos, sino en un entorno seguro, como una variable de entorno.

En el proceso de autenticación se reemplaza la comparación directa de contraseñas por `bcrypt.compare`, garantizando verificaciones seguras y resistentes a ataques de temporización. 

Por último, con fines de facilitar la conversión de contraseña desde texto plano a hasheada, se agrega funcionalidad `LEGACY_PW_MIGRATION` para verificar si la contraseña aun esta en texto plano, y conviertirla automáticamente.

Cambios aplicados en `services/backend/src/services/authService.ts`:

![alt text](image-4.png)

![alt text](image-5.png)

![alt text](image-6.png)

![alt text](image-7.png)

![alt text](image-8.png)

![alt text](image-9.png)

Si bien la funcionalidad `LEGACY_PW_MIGRATION`no introduce una nueva vulnerabilidad por sí misma (ya que si la base de datos contenía contraseñas en texto plano y si el atacante ya leyó la esta información, podrá autenticarse con o sin migración. De todas formas se agrega una bandera para desactivar esta funcionalidad.

![alt text](image-10.png)

![alt text](image-11.png)

### Verificar

Accedemos como lo haciamos desde el inicio

```bash
curl -s -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"password"}'
```

![alt text](image-12.png)

Comprobamos si la contraseña de ese usuario se a convertido de texto plano a hash en la base de datos

```bash
docker compose exec postgres psql -U user -d jwt_api -c "SELECT username, password FROM users;"
```

![alt text](image-13.png)

Volvemos a logueranos de la misma forma

![alt text](image-14.png)

Y ya podemos confirmar que en este nuevo intento, la contraseña ya no es en texto plano tampoco la información devuelta por el backend (independiémente de si devolver ese valor es una buena práctica o no).

