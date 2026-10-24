# DataShield-PS

**Kit local de protección de datos, revisión heurística e integridad de archivos para Windows PowerShell.**

DataShield-PS es un proyecto educativo de ciberseguridad defensiva. Ayuda a revisar carpetas autorizadas para localizar posibles datos sensibles en archivos de texto y a detectar cambios entre una línea base de integridad y el estado actual de los archivos.

> **Alcance:** es una herramienta auxiliar para revisión y auditoría. No es un sistema DLP empresarial ni garantiza la detección de todos los secretos o datos personales. Las coincidencias pueden ser falsos positivos y deben validarse.

## Funciones

- **Scan:** busca patrones indicativos de claves privadas, credenciales incrustadas, identificadores de acceso de nube, tokens JWT, correos, teléfonos peruanos y DNI precedidos por una etiqueta.
- **Baseline:** crea una línea base SHA-256 de los archivos inventariados.
- **Verify:** compara los hashes actuales con una línea base e informa archivos agregados, modificados o eliminados.
- Genera reportes **CSV y JSON** para facilitar la revisión y automatizar procesos posteriores.
- No incluye los valores detectados ni líneas completas en el reporte de hallazgos.
- Omite directorios comunes de dependencias y compilación, como `.git`, `node_modules`, `bin`, `obj` y `dist`.
- No abre conexiones de red, no carga datos a servicios externos y no modifica los archivos inspeccionados.
- Incluye `examples/demo-data.txt` con cadenas ficticias para probar reglas; los hallazgos esperados son intencionales.

## Requisitos

- Windows PowerShell 5.1 o PowerShell 7+.
- Permisos de lectura sobre la carpeta de análisis y escritura en la carpeta de reportes.
- No requiere módulos de terceros.

## Uso rápido

Abre PowerShell en la carpeta del proyecto. Si Windows bloquea la ejecución del script, puedes ejecutar las prácticas desde una sesión de PowerShell conforme a las políticas de tu equipo; no es necesario desactivar globalmente la política de ejecución.

### 1. Escaneo de posibles datos sensibles

```powershell
.\DataShield.ps1 -Action Scan -Path "C:\Ruta\CarpetaAutorizada"
```

Se crea `DataShield-Reports` en el directorio actual, con un reporte `scan-<fecha>.csv` y otro `.json`. Por defecto se analizan archivos de texto de hasta 2 MB. Puedes cambiar el límite:

```powershell
.\DataShield.ps1 -Action Scan -Path "C:\Ruta\CarpetaAutorizada" -MaxScanFileSizeMB 5 -OutputDirectory "C:\Auditoria\DataShield-Reports"
```

Los archivos mayores al límite se omiten en el escaneo de contenido, pero no se omiten de la línea base de integridad.

Para probar el escaneo con datos completamente ficticios, puedes ejecutar:

```powershell
.\DataShield.ps1 -Action Scan -Path ".\examples"
```

### 2. Crear una línea base de integridad

```powershell
.\DataShield.ps1 -Action Baseline -Path "C:\Ruta\CarpetaAutorizada"
```

Por defecto guarda `DataShield-Reports\baseline.json`. Se calcula SHA-256 para todos los archivos inventariados, incluidos los archivos binarios y los de más de 2 MB. En carpetas grandes este paso puede tardar y consumir lectura de disco.

### 3. Verificar cambios

```powershell
.\DataShield.ps1 -Action Verify -Path "C:\Ruta\CarpetaAutorizada"
```

La verificación compara el estado actual con `DataShield-Reports\baseline.json` e informa las diferencias. Para indicar otra línea base:

```powershell
.\DataShield.ps1 -Action Verify -Path "C:\Ruta\CarpetaAutorizada" -BaselinePath "D:\Baselines\baseline.json" -OutputDirectory "D:\Auditoria\Reportes"
```

### 4. Revisar los reportes

- `scan-*.csv` y `scan-*.json`: ruta relativa, número de línea, severidad y categoría heurística.
- `integrity-*.csv` y `integrity-*.json`: archivos `Added`, `Modified` o `Removed` y sus hashes SHA-256.
- `baseline.json`: inventario y hashes de referencia. **Protégelo contra modificaciones no autorizadas** y conserva una copia controlada fuera de la carpeta analizada.

## Patrones revisados

| Categoría | Ejemplos detectados |
|---|---|
| Claves privadas | Marcadores PEM habituales |
| Credenciales y tokens | Asignaciones tipo `password=...`, ciertos identificadores de acceso de nube y tokens con formato JWT |
| Información personal probable | Correos electrónicos, números de móvil peruanos y DNI con etiqueta textual |

El análisis se limita a extensiones de texto configuradas en el script. Archivos cifrados, formatos no compatibles, datos ofuscados y patrones desconocidos pueden pasar desapercibidos. Una coincidencia no prueba por sí sola que el valor sea real, válido o esté expuesto.

## Flujo sugerido a escala

1. Define un alcance autorizado y comienza por una carpeta de prueba.
2. Ejecuta `Scan` y valida manualmente las coincidencias sin copiar valores sensibles a tickets o chats.
3. Clasifica hallazgos, asigna responsables y aplica remediaciones en los sistemas fuente.
4. Crea una línea base después de validar una versión conocida y confiable.
5. Ejecuta `Verify` en ventanas programadas mediante el Programador de tareas de Windows si tu política lo permite.
6. Protege las salidas, limita su retención y revisa falsos positivos antes de convertir los resultados en alertas.
7. Prueba límites de tamaño, permisos, carpetas grandes y recuperación ante errores antes de adoptarlo en producción.

Para despliegues empresariales, añade control de acceso, almacenamiento central seguro, firma de scripts, registro supervisado, pruebas automatizadas y una herramienta DLP aprobada por la organización. No uses esta utilidad como único control de protección de datos.

## Privacidad y seguridad

- Ejecuta solo sobre carpetas propias o para las que tengas autorización expresa.
- Los reportes revelan rutas relativas, categorías de hallazgo y, en integridad, hashes; trátalos como información interna.
- `baseline.json` debe resguardarse: si un atacante cambia el archivo y su línea base, una comparación local podría no advertirlo. Guarda la referencia en una ubicación con acceso restringido o de solo lectura.
- No realiza cuarentena, borrado, bloqueo de cuentas, explotación ni acciones de contraataque.

## Licencia

Este proyecto se publica bajo la licencia MIT. Consulta `LICENSE`.
