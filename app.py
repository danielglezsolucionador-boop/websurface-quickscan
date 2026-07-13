from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx

app = FastAPI(
    title="WebSurface QuickScan API",
    description="Escaneo rápido de cabeceras de seguridad y exposición web.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return {
        "service": "WebSurface QuickScan API",
        "status": "online",
        "version": "1.0.0",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/v1/scan")
async def scan_website(url: str):
    if not url.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400,
            detail="La URL debe empezar con http:// o https://",
        )

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10.0,
        ) as client:
            response = await client.get(url)
            headers_data = dict(response.headers)

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Error al conectar con el sitio: {str(exc)}",
        ) from exc

    security_analysis = {
        "url_scanned": str(response.url),
        "status_code": response.status_code,
        "has_csp": "content-security-policy" in headers_data,
        "has_hsts": "strict-transport-security" in headers_data,
        "has_x_frame_options": "x-frame-options" in headers_data,
        "has_x_content_type_options": "x-content-type-options" in headers_data,
        "server_info": headers_data.get(
            "server",
            "Oculto o no definido",
        ),
        "vulnerabilities_found": [],
    }

    if not security_analysis["has_csp"]:
        security_analysis["vulnerabilities_found"].append(
            "Falta Content-Security-Policy (Riesgo de XSS)"
        )

    if not security_analysis["has_hsts"]:
        security_analysis["vulnerabilities_found"].append(
            "Falta HSTS (Riesgo de downgrade HTTP)"
        )

    if not security_analysis["has_x_frame_options"]:
        security_analysis["vulnerabilities_found"].append(
            "Falta X-Frame-Options (Riesgo de Clickjacking)"
        )

    if not security_analysis["has_x_content_type_options"]:
        security_analysis["vulnerabilities_found"].append(
            "Falta X-Content-Type-Options (Riesgo de MIME sniffing)"
        )

    return security_analysis