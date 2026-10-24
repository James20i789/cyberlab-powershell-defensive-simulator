# CyberLab — PowerShell Defensive Event Simulator

Simulador educativo en PowerShell para practicar la detección básica de patrones sospechosos mediante eventos ficticios de autenticación.

## Alcance

- Genera una secuencia de 12 intentos de acceso fallidos simulados.
- Muestra una alerta al alcanzar el umbral configurado.
- Utiliza `192.0.2.25`, una dirección reservada para documentación y ejemplos.
- No realiza conexiones de red, no modifica configuraciones del sistema y no crea persistencia.

> Este proyecto es una demostración local. No supervisa autenticaciones reales ni sustituye una herramienta de monitoreo de seguridad.

## Requisitos

- Windows con PowerShell.

## Ejecución

Abre PowerShell en la carpeta del proyecto y ejecuta:

```powershell
.\CyberLab.ps1
```

Si la política local impide ejecutar scripts, revisa la política establecida por tu organización antes de cambiarla. También puedes abrir el archivo y ejecutar el contenido en una sesión de prueba autorizada.

## Parámetros principales

Dentro de `CyberLab.ps1`:

- `$totalIntentos`: cantidad de eventos ficticios que se mostrarán.
- `$umbralAlerta`: cantidad de intentos a partir de la cual se genera la alerta.
- `$ipPrueba`: dirección reservada usada como origen ficticio.

## Uso responsable

Diseñado para aprendizaje, demostraciones de consola y prácticas defensivas en un entorno controlado. No incluye funciones de explotación, evasión, propagación ni envío de datos.
