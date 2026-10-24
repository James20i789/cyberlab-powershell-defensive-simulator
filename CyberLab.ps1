# CyberLab.ps1
# Simulador defensivo de eventos de seguridad para aprendizaje.
# Solo genera eventos ficticios en la consola; no conecta a la red,
# no modifica configuraciones y no crea persistencia.

Clear-Host

$ipPrueba = '192.0.2.25'  # Dirección reservada para documentación y ejemplos
$totalIntentos = 12
$umbralAlerta = 5
$alertaEmitida = $false

Write-Host '======================================' -ForegroundColor Cyan
Write-Host '         CYBERLAB - DEFENSA           ' -ForegroundColor Cyan
Write-Host '======================================' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Simulación local de eventos de acceso'
Write-Host "Origen ficticio: $ipPrueba"
Write-Host "Umbral de alerta: $umbralAlerta intentos fallidos"
Write-Host ''

for ($i = 1; $i -le $totalIntentos; $i++) {
    Start-Sleep -Milliseconds 400
    $hora = Get-Date -Format 'HH:mm:ss'

    Write-Host "[$hora] [SIMULADO] Acceso fallido #$i" -ForegroundColor Yellow

    if ($i -ge $umbralAlerta -and -not $alertaEmitida) {
        $alertaEmitida = $true
        Write-Host ''
        Write-Host '[ALERTA DE SEGURIDAD]' -ForegroundColor Red
        Write-Host 'Se detectó una secuencia ficticia de intentos fallidos.'
        Write-Host "Origen simulado: $ipPrueba"
        Write-Host "Intentos registrados: $i"
        Write-Host 'Acción sugerida: revisar los registros de autenticación.'
        Write-Host ''
    }
}

Write-Host '======================================' -ForegroundColor Cyan
Write-Host 'Simulación finalizada.' -ForegroundColor Green
Write-Host 'No se realizaron conexiones de red.'
Write-Host 'No se modificó ninguna configuración.'
Write-Host '======================================' -ForegroundColor Cyan
