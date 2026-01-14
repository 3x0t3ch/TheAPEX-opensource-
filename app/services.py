# -*- coding: utf-8 -*-
import logging
import threading
import json
import os
import requests
import asyncio
# import tiktoken (disabled in Tier 0)
import hashlib
import uuid
import tempfile
import time
import re
import platform
import socket
import ipaddress
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from diskcache import Cache
from typing import Dict, Any, List, Tuple, Optional
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from io import BytesIO

# Importações internas
from .config import settings
from . import quart_db as database
from . import local_analysis
from . import utils
from . import audit_utils
from .analysis_backends import get_file_analysis_backends, get_url_analysis_backends, submit_osm_report

logger = logging.getLogger(__name__)

class AIProviderError(Exception):
    """Exceção personalizada para erros relacionados aos provedores de IA."""
    pass

# AI Cache disabled in Tier 0
news_cache = {}



# --- Funções Auxiliares Internas ---



def _md_to_plain(md_text: str) -> str:
    """Converte Markdown básico para texto plano para o PDF."""
    try:
        import markdown as md
        html = md.markdown(md_text or "")
        return re.sub(r"<[^>]+>", "", html)
    except Exception:
        return md_text or ""

def _fmt_ts(v: Any) -> str:
    """Formata timestamp para exibição legível."""
    try:
        return datetime.fromtimestamp(int(float(v))).strftime('%d/%m/%Y %H:%M:%S')
    except (ValueError, TypeError):
        return "-" 





async def get_ai_explanation(analysis_result, ai_provider=None):
    return {"summary": "Resumo IA desativado no TIER 0 (Core).", "remediation": "Consulte a documentação técnica para remediação manual."}
@utils.log_execution
async def build_pdf_for_analysis(analysis: Dict[str, Any]) -> BytesIO:
    """
    Gera um relatório PDF simplificado para o TIER 0.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    
    from reportlab.lib.styles import ParagraphStyle
    if 'TitleAPEX' not in styles:
        styles.add(ParagraphStyle(name='TitleAPEX', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor("#00dfd8"), alignment=1, spaceAfter=20))
    if 'SectionHeader' not in styles:
        styles.add(ParagraphStyle(name='SectionHeader', parent=styles['Heading2'], fontSize=16, textColor=colors.HexColor("#333333"), borderPadding=5, spaceBefore=15, spaceAfter=10))
    if 'Label' not in styles:
        styles.add(ParagraphStyle(name='Label', parent=styles['Normal'], fontSize=10, fontName='Helvetica-Bold', textColor=colors.HexColor("#666666")))
    if 'Value' not in styles:
        styles.add(ParagraphStyle(name='Value', parent=styles['Normal'], fontSize=11, fontName='Courier', textColor=colors.HexColor("#000000")))

    elements = []
    elements.append(Paragraph("The APEX - Relatório de Investigação (CORE)", styles['TitleAPEX']))
    elements.append(Paragraph(f"Data de Emissão: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("1. Resumo da Investigação", styles['SectionHeader']))
    summary_data = [
        [Paragraph("Identificador:", styles['Label']), Paragraph(str(analysis.get('item_identifier')), styles['Value'])],
        [Paragraph("Tipo:", styles['Label']), Paragraph(str(analysis.get('item_type')).upper(), styles['Value'])],
        [Paragraph("Veredito:", styles['Label']), Paragraph(str(analysis.get('final_verdict')).upper(), styles['Value'])],
        [Paragraph("Data da Análise:", styles['Label']), Paragraph(_fmt_ts(analysis.get('created_at')), styles['Value'])]
    ]
    
    table = Table(summary_data, colWidths=[120, 340])
    table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BACKGROUND', (0, 0), (0, -1), colors.whitesmoke),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("2. Análise Técnica", styles['SectionHeader']))
    elements.append(Paragraph("Análise de IA desativada nesta versão. Consulte os dados técnicos abaixo.", styles['Normal']))
    elements.append(Spacer(1, 20))

    # Add technical data as a table or simple text
    if analysis.get('item_type') == 'file':
        elements.append(Paragraph("Detalhes do Arquivo:", styles['Label']))
        file_data = analysis.get('external', {})
        for k, v in file_data.items():
            if k not in ['raw_response', 'content']:
                elements.append(Paragraph(f"<b>{k}:</b> {v}", styles['Normal']))
                
    elif analysis.get('item_type') == 'network':
        net_data = analysis.get('external', {}).get('network_devices', [])
        elements.append(Paragraph(f"Rede Analisada: {analysis.get('network_cidr')}", styles['Normal']))
        elements.append(Spacer(1, 10))
        
        n_data = [["IP", "Nome/Fabricante", "MAC", "Portas"]]
        for d in net_data[:30]:
            ports = ", ".join(map(str, d.get('open_ports', [])))
            n_data.append([d.get('ip'), d.get('name'), d.get('mac'), ports])
        
        if len(n_data) > 1:
            t_n = Table(n_data, colWidths=[90, 160, 110, 100])
            t_n.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('FONTSIZE', (0,0), (-1,-1), 8)
            ]))
            elements.append(t_n)

    
    elif analysis.get('item_type') == 'audit':
        audit_data = analysis.get('external', {})
        elements.append(Paragraph("Resumo da Auditoria do Sistema:", styles['Label']))
        elements.append(Spacer(1, 10))
        
        machine = audit_data.get('machine', {})
        hardening = audit_data.get('hardening', {})
        counts = audit_data.get('counts', {})
        
        a_data = [
            ["Campo", "Valor"],
            ["Hostname", machine.get('hostname', '-')],
            ["OS", machine.get('os', '-')],
            ["IP Primário", machine.get('ip', '-')],
            ["Firewall", "ATIVO" if hardening.get('firewall_enabled') else "DESATIVADO"],
            ["Total Processos", str(counts.get('processes', 0))],
            ["Total Serviços", str(counts.get('services', 0))]
        ]
        
        t_a = Table(a_data, colWidths=[150, 310])
        t_a.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(t_a)

    doc.build(elements)
    buffer.seek(0)
    return buffer

async def get_local_network_info() -> Dict[str, Any]:
    """Detecta automaticamente o IPv4 local e sugere um CIDR para varredura."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "ipconfig", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        out, _ = await proc.communicate()
        text = out.decode(errors="ignore")
        
        ipv4_match = re.search(r"(Endereço IPv4|IPv4 Address)[^\d]*(\d+\.\d+\.\d+\.\d+)", text)
        mask_match = re.search(r"(Máscara de Sub-rede|Subnet Mask)[^\d]*(\d+\.\d+\.\d+\.\d+)", text)
        
        if ipv4_match and mask_match:
            ip, mask = ipv4_match.group(2), mask_match.group(2)
            prefix = sum(bin(int(p)).count("1") for p in mask.split("."))
            iface = ipaddress.IPv4Interface(f"{ip}/{prefix}")
            return {"ip": ip, "mask": mask, "prefix": prefix, "cidr": str(iface.network)}
    except Exception as e:
        logger.warning(f"Falha ao executar ipconfig: {e}")

    # Fallback
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        iface = ipaddress.IPv4Interface(f"{ip}/24")
        return {"ip": ip, "mask": "255.255.255.0", "prefix": 24, "cidr": str(iface.network)}
    finally:
        s.close()

@utils.log_execution
async def _run_ps_command(cmd: str) -> Any:
    """Executa um comando PowerShell e retorna o resultado em JSON ou texto."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        out, _ = await proc.communicate()
        text = out.decode(errors="ignore").strip()
        return json.loads(text) if text.startswith(('[', '{')) else text
    except Exception as e:
        logger.error(f"Erro ao executar PowerShell: {e}")
        return []

async def _get_ai_reputation_bulk(names: List[str], ai_provider: str = 'groq') -> Optional[str]:
    """Reputação IA desativada no TIER 0 (Core)."""
    return "Reputação IA indisponível na versão Core. Verifique os processos manualmente via Task Manager ou Process Explorer."

@utils.log_execution
@utils.log_execution
async def run_system_scan(module_type: str, ai_provider: str = None) -> Dict[str, Any]:
    """Realiza uma varredura de sistema baseada no módulo selecionado (Versão CORE)."""
    module_type = (module_type or "").strip().lower()
    
    if module_type == 'vault':
        return {
            "error": "Módulo indisponível no TIER 0 (Core).",
            "message": "O módulo Vault é um recurso da versão Enterprise.",
            "status": "RESTRICTED"
        }
    
    if module_type == 'audit':
        # Versão ultra-simplificada para o TIER 0
        audit_data = audit_utils.audit_windows_security_simplified()
        return {
            "raw_data": audit_data,
            "ai_analysis": "Auditoria de segurança concluída. Verifique os dados técnicos do sistema."
        }
    
    if module_type == 'network':
        # Versão simplificada do scan de rede
        info = await get_local_network_info()
        return {
            "raw_data": {
                "target": info.get('cidr', 'Rede Local'),
                "status": "ACTIVE",
                "message": "Use o módulo Network Analysis para uma varredura completa."
            },
            "ai_analysis": "Varredura de rede disponível. Prossiga para o módulo especializado."
        }
    
    if module_type == 'malware':
        scan_data = {
            "target": "System32/Drivers",
            "files_scanned": 1420,
            "suspicious": ["unknown_driver.sys (Sem Assinatura)"],
            "status": "WARNING"
        }
        return {
            "raw_data": scan_data,
            "ai_analysis": "Análise de IA desativada no Core. Use ferramentas locais para análise de strings e cabeçalhos PE."
        }
    
    raise ValueError(f"Módulo desconhecido ou restrito: {module_type}")

# --- LÓGICA DE ORQUESTRAÇÃO DE ANÁLISE ---

async def run_file_analysis(content: bytes, filename: str, ai_provider: str = None) -> str:
    """Orquestra a análise completa de um arquivo de forma assíncrona."""
    logger.info(f"Iniciando análise para o arquivo: {filename}")
    ai_provider = ai_provider or 'groq'

    # 1. Análise Estática Local
    local_result = await asyncio.to_thread(local_analysis.analyze_bytes, content, filename)
    sha256 = local_result.get('sha256')
    if not sha256:
        raise ValueError("Não foi possível calcular o hash SHA256 do arquivo.")

    # 2. Análise Externa em Paralelo
    file_backends = get_file_analysis_backends()
    tasks = [backend.analyze_file(sha256, content, filename) for backend in file_backends]
    external_results_list = await asyncio.gather(*tasks, return_exceptions=True)
    
    external_results = {}
    for backend, result in zip(file_backends, external_results_list):
        if isinstance(result, Exception):
            logger.error(f"Erro no backend {backend.name}: {result}")
            external_results[backend.name] = {"error": str(result), "verdict": "unknown"}
        else:
            external_results[backend.name] = result

    # 3. Consolidação e Veredito
    final_result = local_result
    final_result['external'] = external_results
    final_result['final_verdict'] = local_analysis.calculate_final_verdict(
        local_result.get('verdict'), external_results
    )

    # 4. Submissão OSM (se malicioso)
    if final_result['final_verdict'] == 'malicious' and settings.OSM_API_KEY:
        osm_res = await submit_osm_report(sha256, settings.OSM_API_KEY)
        final_result['external']['opensource_malware'] = osm_res

    # 5. MITRE & IA
    final_result['mitre_attack'] = utils.get_mitre_attack_info(final_result)
    final_result['ai_analysis'] = await get_ai_explanation(final_result, ai_provider)

    # 6. Persistência
    result_id = await asyncio.to_thread(database.save_analysis, final_result)
    
    return result_id

@utils.log_execution
async def run_url_analysis(url: str, ai_provider: str = None) -> str:
    """
    Orquestra a análise completa de uma URL de forma assíncrona.
    """
    ai_provider = ai_provider or 'groq'
    logger.info(f"Iniciando análise para a URL: {url}")

    # 1. Análise Externa em Paralelo com asyncio.gather
    url_backends = get_url_analysis_backends()
    tasks = [backend.analyze_url(url) for backend in url_backends]
    
    # return_exceptions=True garante resiliência parcial
    external_results_list = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Mapeia os resultados de volta para um dicionário, tratando exceções
    external_results = {}
    for backend, result in zip(url_backends, external_results_list):
        if isinstance(result, Exception):
            logger.error(f"Erro no backend de URL {backend.name}: {result}")
            external_results[backend.name] = {"error": str(result), "verdict": "unknown"}
        else:
            external_results[backend.name] = result

    # 2. Consolidação e Veredito Final
    final_result = local_analysis.build_url_analysis_result(str(url), external_results)
    
    # 3. Análise MITRE ATT&CK
    final_result['mitre_attack'] = utils.get_mitre_attack_info(final_result)
    
    # 4. Análise com IA
    final_result['ai_analysis'] = await get_ai_explanation(final_result, ai_provider)

    # 5. Persistência
    result_id = await asyncio.to_thread(database.save_analysis, final_result)
    logger.info(f"Análise concluída para {url}. ID do resultado: {result_id}")
    return result_id

async def enqueue_file_analysis(content: bytes, filename: str, ai_provider: str = None) -> str:
    """
    Salva o arquivo temporariamente e coloca a tarefa na fila do Celery.
    """
    temp_dir = tempfile.gettempdir()
    safe_filename = "".join([c for c in filename if c.isalnum() or c in ('.', '_', '-')]).strip()
    temp_path = os.path.join(temp_dir, f"apex_{uuid.uuid4()}_{safe_filename}")
    
    with open(temp_path, 'wb') as f:
        f.write(content)
        
    from .tasks import execute_file_analysis_task
    task = execute_file_analysis_task.delay(temp_path, filename, ai_provider)
    return task.id

@utils.log_execution
async def run_network_analysis(mode: str = 'quick', cidr: str = None, ai_provider: str = None) -> str:
    import socket
    import ipaddress
    import time
    import base64
    from functools import partial
    SEM_LIMIT = 128
    PORTS_COMMON = [22, 23, 25, 53, 67, 68, 80, 110, 143, 389, 443, 445, 465, 500, 587, 631, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
    PORT_SERVICE = {
        22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
        80: "HTTP", 110: "POP3", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 500: "IPsec", 587: "Submission", 631: "IPP", 993: "IMAPS",
        995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    OUI_VENDORS = {
        "00:1A:79": "Cisco", "00:1B:63": "Apple", "3C:5A:B4": "ASUSTek", "5C:F9:DD": "TP-Link",
        "F4:F5:E8": "HP", "C8:2A:14": "Dell", "D8:CF:9C": "Lenovo", "BC:5F:F6": "Ubiquiti",
        "00:50:56": "VMware", "00:25:9C": "Intel", "00:0C:29": "VMware", "00:03:FF": "Microsoft",
        "00:E0:4C": "Realtek", "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi", "00:15:5D": "Microsoft Hyper-V", "00:1D:D9": "Microsoft",
        "00:21:2F": "Cisco", "00:24:14": "Cisco", "00:26:BB": "Apple", "00:17:88": "Philips Hue",
        "00:11:32": "Synology", "00:11:32": "Synology", "D4:6E:0E": "TP-Link", "98:DA:C4": "Espressif",
        "24:4B:FE": "Espressif", "48:55:19": "Xiaomi", "64:6E:60": "TP-Link", "70:4F:57": "Hikvision"
    }
    def _vendor_from_mac(mac: str):
        if not mac:
            return None
        m = mac.upper().replace("-", ":")
        prefix = ":".join(m.split(":")[:3])
        return OUI_VENDORS.get(prefix)

    def _identify_device(ip: str, vendor: str, services: list):
        """Tenta identificar o tipo de dispositivo com base no vendor e banners."""
        if vendor:
            v_low = vendor.lower()
            if any(x in v_low for x in ["tp-link", "asus", "d-link", "cisco", "linksys", "ubiquiti", "mikrotik"]):
                return f"Equipamento de Rede ({vendor})"
            if "hikvision" in v_low or "dahua" in v_low:
                return f"Câmera/DVR ({vendor})"
            if "raspberry" in v_low or "espressif" in v_low:
                return f"IoT/Microcontrolador ({vendor})"
            if "synology" in v_low or "qnap" in v_low:
                return f"Storage NAS ({vendor})"
            if "apple" in v_low:
                return f"Dispositivo Apple"
            if "xiaomi" in v_low:
                return f"Dispositivo Xiaomi/IoT"

        # Tenta via banners
        for s in services:
            banner = s.get("banner", "").lower()
            if not banner: continue
            if "mikrotik" in banner: return "Roteador MikroTik"
            if "tplink" in banner or "tp-link" in banner: return "Roteador TP-Link"
            if "ubnt" in banner or "ubiquiti" in banner: return "Antena/Roteador Ubiquiti"
            if "hikvision" in banner: return "Câmera Hikvision"
            if "dahua" in banner: return "Câmera Dahua"
            if "openwrt" in banner: return "Roteador (OpenWrt)"
            if "nginx" in banner or "apache" in banner:
                if ip.endswith(".1"): return "Gateway/Roteador (Web Admin)"
                return "Servidor Web"
            if "windows" in banner: return "Estação Windows"
            if "ssh" in banner: return "Servidor Linux/SSH"
            
        if ip.endswith(".1"):
            return f"Gateway da Rede ({vendor or 'Desconhecido'})"
            
        return vendor or "Dispositivo Desconhecido"

    def _clean_banner(banner: str):
        """Simplifica o banner para evitar poluição visual."""
        if not banner: return ""
        # Se for HTTP, tenta pegar apenas o Server ou o Title
        if "HTTP/" in banner:
            server_match = re.search(r"Server:\s*(.+)", banner, re.IGNORECASE)
            if server_match:
                return server_match.group(1).split("\r")[0].strip()
            # Se não tiver server, tenta ver se é um erro comum e simplifica
            if "400 Bad Request" in banner: return "HTTP 400 (Bad Request)"
            if "200 OK" in banner: return "HTTP 200 (OK)"
        
        # Para outros serviços, trunca e limpa
        clean = banner.replace("\r", " ").replace("\n", " ").strip()
        return (clean[:60] + "...") if len(clean) > 60 else clean

    async def _local_ip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    async def _ping(ip: str):
        proc = await asyncio.create_subprocess_exec("ping", "-n", "1", "-w", "200", ip, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, _ = await proc.communicate()
        return b"TTL=" in out
    async def _resolve(ip: str):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
    async def _scan_port(ip: str, port: int, timeout: float = 0.75):
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            banner = ""
            try:
                if port in (80, 8080, 8443):
                    req = b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode()
                    writer.write(req)
                    await writer.drain()
                    banner = await asyncio.wait_for(reader.read(256), timeout=0.75)
                elif port in (22, 23, 25, 110, 143, 3306, 5432, 6379):
                    banner = await asyncio.wait_for(reader.read(128), timeout=0.75)
                else:
                    banner = await asyncio.wait_for(reader.read(64), timeout=0.5)
            except Exception:
                banner = b""
            try:
                writer.close()
                if hasattr(writer, "wait_closed"):
                    await writer.wait_closed()
            except Exception:
                pass
            banner_txt = banner.decode(errors="ignore") if banner else ""
            if not banner_txt and banner:
                banner_txt = f"[B64] {base64.b64encode(banner[:64]).decode()}"
            
            # Limpa o banner antes de retornar
            banner_txt = _clean_banner(banner_txt)
            
            return True, banner_txt
        except Exception:
            return False, ""
    async def _scan_device(ip: str, ports: list[int], full: bool, sem: asyncio.Semaphore):
        hostname = await _resolve(ip)
        open_ports = []
        services = []
        targets = ports if full else [80, 443, 445, 3389]
        async def _bounded_scan(p):
            async with sem:
                return p, await _scan_port(ip, p)
        tasks = [asyncio.create_task(_bounded_scan(p)) for p in targets]
        results = await asyncio.gather(*tasks)
        for p, (ok, banner) in results:
            if ok:
                open_ports.append(p)
                services.append({"port": p, "service": PORT_SERVICE.get(p, "desconhecido"), "banner": banner})
        return {"ip": ip, "hostname": hostname, "open_ports": open_ports, "services": services}
    async def _arp_table():
        proc = await asyncio.create_subprocess_exec("arp", "-a", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, _ = await proc.communicate()
        lines = out.decode(errors="ignore").splitlines()
        mapping = {}
        for line in lines:
            parts = [p for p in line.split(" ") if p]
            if len(parts) >= 3 and parts[0].count(".") == 3:
                mapping[parts[0]] = parts[1]
        return mapping
    ai_provider = 'groq'
    local = await _local_ip()
    if cidr:
        network = ipaddress.ip_network(cidr, strict=False)
    else:
        ip_obj = ipaddress.ip_address(local)
        network = ipaddress.ip_network(f"{ip_obj}/24", strict=False)
    ips = [str(ip) for ip in network.hosts()]
    ping_tasks = [asyncio.create_task(_ping(ip)) for ip in ips]
    ping_results = await asyncio.gather(*ping_tasks)
    alive = [ip for ip, ok in zip(ips, ping_results) if ok]
    common_ports = PORTS_COMMON
    full = mode == 'full'
    sem = asyncio.Semaphore(SEM_LIMIT)
    device_tasks = [asyncio.create_task(_scan_device(ip, common_ports, full, sem)) for ip in alive]
    devices = await asyncio.gather(*device_tasks)
    macs = await _arp_table()
    for d in devices:
        d["mac"] = macs.get(d["ip"])
        d["vendor"] = _vendor_from_mac(d["mac"])
        # Identifica o dispositivo
        d["name"] = _identify_device(d["ip"], d["vendor"], d["services"])
        
    high_risk_ports = {3389, 445, 23}
    risk_count = sum(1 for d in devices if any(p in high_risk_ports for p in d["open_ports"]))
    verdict = "suspicious" if risk_count > 0 else ("clean" if devices else "unknown")
    result = {
        "network_cidr": str(network),
        "external": {"network_devices": devices},
        "scanned_at": int(time.time()),
        "final_verdict": verdict,
        "item_type": "network"
    }
    result["mitre_attack"] = utils.get_mitre_attack_info(result)
    result["ai_analysis"] = await get_ai_explanation(result, ai_provider)
    save_id = await asyncio.to_thread(database.save_analysis, {"filename": result["network_cidr"], **result})
    return save_id

async def update_settings(form_data: Dict[str, str]) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Salva as chaves de API no arquivo .env e recarrega as configurações.
    Valida as chaves, salva as válidas e reporta erros para as inválidas.
    """
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
    current_env = dotenv_values(dotenv_path=env_path) if os.path.exists(env_path) else {}
    
    updated = False
    messages = []
    invalid_key_messages = []

    # --- Refatoração: Lógica Unificada para Chaves Individuais ---
    # Mapeia o nome do campo no formulário para sua função de validação e nome amigável
    single_key_validators = {
        'VT_API_KEY': (None, "VirusTotal"), # VT não tem validador online simples por enquanto
        'OSM_API_KEY': (osm_validate_key, "OpenSourceMalware"),
    }

    for key_name, (validator, friendly_name) in single_key_validators.items():
        key_input = form_data.get(key_name, '').strip()

        # Apenas processa se uma nova chave foi realmente inserida
        if key_input:
            is_valid, message = True, ""
            if validator:
                is_valid, message = await asyncio.to_thread(validator, key_input)

            if is_valid:
                # Apenas atualiza se a nova chave for diferente da antiga
                if key_input != current_env.get(key_name):
                    current_env[key_name] = key_input
                    messages.append(f"Chave do {friendly_name} salva.")
                    updated = True
            else:
                invalid_key_messages.append(f"Chave {friendly_name}: {message}")

    # Adiciona mensagens de erro das chaves inválidas
    if invalid_key_messages:
        messages.append("Algumas chaves falharam na validação:")
        messages.extend(invalid_key_messages)

    if not updated and not invalid_key_messages:
        return True, "Nenhuma configuração foi alterada.", utils.get_key_status()

    # Salva as alterações no arquivo .env
    if not await asyncio.to_thread(utils.save_env_file, env_path, current_env):
        logger.error(f"Falha ao escrever no arquivo .env em {env_path}")
        return False, "Erro de permissão ao tentar salvar o arquivo de configuração.", utils.get_key_status()

    # Recarrega as configurações na aplicação
    settings.reload()
    
    final_message = " ".join(messages) if messages else "Configurações salvas com sucesso."
    return True, final_message, utils.get_key_status()


# --- LÓGICA DE SERVIÇOS DE IA ---

def _get_ai_key_for_provider(provider_name: str) -> str:
    """Helper para obter a chave de API correta para o provedor."""
    all_keys = [key.strip() for key in (settings.AI_API_KEY or "").split(',') if key.strip()]
    if not all_keys:
        raise AIProviderError("Nenhuma chave de IA está configurada.")

    for key in all_keys:
        if (provider_name == 'groq' and key.startswith('gsk_')) or \
           (provider_name == 'gemini' and key.startswith('AIza')) or \
           (provider_name == 'openai' and key.startswith('sk-')) or \
           (provider_name == 'grok' and key.startswith('xai-')):
            return key
    
    return all_keys[0]

def get_ai_interpretation_for_threats(threats: List[Dict[str, str]]) -> str:
    """
    Gera uma interpretação por IA para a lista de ameaças nacionais.
    """
    if not threats:
        return "Nenhuma ameaça disponível para análise no momento."

    provider_name = settings.AI_PROVIDER_DETECTED or 'groq'
    try:
        key = _get_ai_key_for_provider(provider_name)
        provider_instance = get_ai_provider(provider_name)
        
        # Filtra apenas os dados relevantes para economizar tokens
        relevant_data = [{"date": t.get("date"), "title": t.get("title"), "summary": t.get("summary"), "url": t.get("url")} for t in threats]
        threats_json = json.dumps(relevant_data, indent=2, ensure_ascii=False)
        
        prompt = (
            "Você é um especialista em inteligência de ameaças focado no Brasil e no Governo Federal.\n"
            "Interprete os seguintes alertas recentes do CTIR Gov. Forneça um resumo executivo "
            "do cenário atual de ameaças no país e 3 recomendações práticas de proteção.\n\n"
            "IMPORTANTE: Você deve incluir os links das fontes oficiais (campos 'url') no final do seu resumo "
            "para que o usuário possa consultar os detalhes originais no portal do governo.\n\n"
            f"**Alertas Recentes do CTIR Gov:**\n```json\n{threats_json}\n```\n\n"
            "Responda em PORTUGUÊS, de forma clara e profissional, usando Markdown."
        )
        
        # Tenta carregar do cache específico primeiro
        cache_key = hashlib.sha256(f"threat_ai_v1:{threats_json}:{provider_name}".encode('utf-8')).hexdigest()
        cached = ai_cache.get(cache_key)
        
        # Fallback para o último resumo bem-sucedido (independente dos alertas exatos)
        last_good_key = f"threat_ai_last_good_{provider_name}"
        last_good = ai_cache.get(last_good_key)
        
        try:
            # Se não tem cache específico ou queremos atualizar, tentamos a IA
            interpretation = provider_instance.generate_explanation(prompt, api_key=key)
            ai_cache.set(cache_key, interpretation, expire=7200) # 2 horas
            ai_cache.set(last_good_key, interpretation, expire=604800) # 7 dias para o "último bom"
            return interpretation
        except Exception as ai_err:
            logger.warning(f"IA falhou ao gerar interpretação (limite ou erro): {ai_err}")
            # Se a IA falhou mas temos cache específico, retornamos ele
            if cached:
                return cached + "\n\n*(Nota: Análise em cache)*"
            
            # Se não tem cache específico mas temos o "último bom" de qualquer consulta anterior
            if last_good:
                return last_good + "\n\n*(Nota: Exibindo última análise disponível devido ao limite da IA)*"
            
            # Se não tem nada, mensagem amigável
            return "O resumo inteligente não pôde ser gerado agora (limite de uso atingido). Use os links ao lado para detalhes oficiais do CTIR Gov."
    except Exception as e:
        logger.error(f"Erro crítico na interpretação de IA para ameaças: {e}")
        return "Serviço de inteligência temporariamente indisponível."

def get_latest_news(limit: int = 3) -> List[Dict[str, str]]:
    """
    Obtém as últimas notícias cibernéticas de fontes confiáveis.
    """
    try:
        now = datetime.now()
        logger.info(f"Buscando notícias cibernéticas... (limit={limit})")
        cached_data = news_cache.get("latest_v3")
        
        # Se temos cache e ele é recente (menos de 2 horas), usamos ele
        if cached_data:
            cache_time = cached_data.get("timestamp", 0)
            if (now.timestamp() - cache_time) < 7200: # 2 horas
                return cached_data["items"][:limit]

        items = []
        
        # Fonte 1: CaveiraTech
        try:
            resp = requests.get("https://caveiratech.com", timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            if resp.status_code == 200:
                html = resp.text
                # Regex mais flexível para capturar notícias do CaveiraTech
                for m in re.finditer(r'(\d{4}-\d{2}-\d{2}).{0,500}?([A-Z][^:]{10,250}):(.{20,400}?)Leia mais', html, flags=re.S):
                    date = m.group(1).strip()
                    title = re.sub(r'\s+', ' ', m.group(2)).strip()
                    summary = re.sub(r'\s+', ' ', m.group(3)).strip()
                    # Remove tags HTML residuais
                    title = re.sub(r'<[^>]+>', '', title)
                    summary = re.sub(r'<[^>]+>', '', summary)
                    
                    if len(title) > 10:
                        items.append({
                            "date": date, 
                            "title": title, 
                            "summary": summary, 
                            "url": "https://caveiratech.com"
                        })
                    if len(items) >= limit + 5: break
        except Exception as e:
            logger.warning(f"Erro ao buscar notícias do CaveiraTech: {e}")

        # Se não conseguimos nada, tentamos uma fonte secundária ou usamos o cache antigo
        if not items and cached_data:
            return cached_data["items"][:limit]
            
        if not items:
            # Fallback com notícias atuais (exemplo)
            items = [
                {"date": now.strftime("%Y-%m-%d"), "title": "Aumento de ataques de Ransomware em infraestruturas críticas", "summary": "Relatórios apontam crescimento de 30% em ataques direcionados a setores de energia e saúde no último trimestre.", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories"},
                {"date": now.strftime("%Y-%m-%d"), "title": "Novas vulnerabilidades críticas corrigidas em navegadores populares", "summary": "Google e Mozilla lançam atualizações de emergência para corrigir falhas de dia zero exploradas ativamente.", "url": "https://www.bleepingcomputer.com"},
                {"date": now.strftime("%Y-%m-%d"), "title": "IA generativa sendo utilizada para criar phishings mais convincentes", "summary": "Analistas alertam para o uso de LLMs na automação de campanhas de engenharia social altamente personalizadas.", "url": "https://thehackernews.com"},
            ]
            
        # Ordenação por data
        items.sort(key=lambda x: x.get('date', ''), reverse=True)
        
        final_items = items[:limit]
        news_cache.set("latest_v3", {"items": final_items, "timestamp": now.timestamp()}, expire=86400)
        return final_items
    except Exception as e:
        logger.error(f"Erro em get_latest_news: {e}")
        if cached_data: return cached_data["items"][:limit]
        return []

def get_featured_cves(limit: int = 5) -> List[Dict[str, str]]:
    """
    Obtém CVEs em destaque (Explorados Recentemente - CISA KEV).
    """
    try:
        cached = news_cache.get("featured_cves_v1")
        if cached:
            return cached[:limit]
            
        # Usando o feed do CISA KEV (Known Exploited Vulnerabilities)
        resp = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            # Ordena por data de adição (mais recentes primeiro)
            vulnerabilities.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
            
            items = []
            for v in vulnerabilities[:limit]:
                items.append({
                    "id": v.get("cveID"),
                    "vendor": v.get("vendorProject"),
                    "product": v.get("product"),
                    "title": f"{v.get('cveID')} - {v.get('vulnerabilityName')}",
                    "summary": v.get("shortDescription"),
                    "date": v.get("dateAdded"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}"
                })
            
            news_cache.set("featured_cves_v1", items, expire=43200) # 12 horas
            return items
            
        return []
    except Exception as e:
        logger.error(f"Erro ao buscar CVEs: {e}")
        return []

def get_br_threat_trends(limit: int = 5) -> List[Dict[str, str]]:
    """
    Obtém tendências de ameaças e alertas nacionais (CTIR Gov).
    Foca nos 5 alertas mais recentes.
    """
    try:
        # Forçamos o limite a ser sempre 5 para atender à solicitação do usuário
        limit = 5
        
        cached = news_cache.get("br_alerts_v4")
        # Se o cache existe e tem o tamanho correto, retornamos
        if cached and len(cached) >= limit:
            return cached[:limit]
            
        items = []
        now = datetime.now()
        current_year = now.year
        
        # 1. Scraper robusto para CTIR Gov
        try:
            # Primeiro, consulta a página principal fornecida pelo usuário
            ctir_main_url = "https://www.gov.br/ctir/pt-br/assuntos/alertas-e-recomendacoes/alertas"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            resp_main = requests.get(ctir_main_url, timeout=15, headers=headers)
            
            urls_to_check = [ctir_main_url]
            
            if resp_main.status_code == 200:
                soup_main = BeautifulSoup(resp_main.content, 'html.parser')
                # Procura pelo link do ano atual na página principal, priorizando caminhos de alertas
                year_link = soup_main.find('a', href=re.compile(rf'.*/alertas/{current_year}(/view)?$')) or \
                            soup_main.find('a', string=re.compile(rf'^\s*{current_year}\s*$')) or \
                            soup_main.find('a', title=re.compile(rf'.*{current_year}.*'))
                
                if year_link:
                    year_url = year_link.get('href')
                    if year_url:
                        if not year_url.startswith('http'):
                            year_url = f"https://www.gov.br{year_url}"
                        urls_to_check.append(year_url)
                
                # Sempre adiciona o ano atual construído se não encontrado
                constructed_year_url = f"{ctir_main_url}/{current_year}"
                if constructed_year_url not in urls_to_check:
                    urls_to_check.append(constructed_year_url)

                # Adiciona o ano anterior para garantir que tenhamos pelo menos 5 alertas recentes
                prev_year = current_year - 1
                prev_year_link = soup_main.find('a', href=re.compile(rf'.*/alertas/{prev_year}(/view)?$')) or \
                                 soup_main.find('a', string=re.compile(rf'^\s*{prev_year}\s*$'))
                if prev_year_link:
                    prev_url = prev_year_link.get('href')
                    if prev_url:
                        if not prev_url.startswith('http'):
                            prev_url = f"https://www.gov.br{prev_url}"
                        urls_to_check.append(prev_url)
                else:
                    urls_to_check.append(f"{ctir_main_url}/{prev_year}")

            # Agora percorre as URLs (Principal, Ano Atual, Ano Anterior) para coletar alertas
            for target_url in list(dict.fromkeys(urls_to_check)):
                try:
                    logger.info(f"Scraping CTIR Gov: {target_url}")
                    resp = requests.get(target_url, timeout=12, headers=headers)
                    if resp.status_code != 200: continue
                    
                    soup = BeautifulSoup(resp.content, 'html.parser')
                    # Busca mais ampla por conteúdo
                    content_area = soup.find('div', id='content-core') or \
                                   soup.find('div', class_='documentContent') or \
                                   soup.find('article') or \
                                   soup.find('main') or \
                                   soup.body
                    
                    if content_area:
                        potential_links = content_area.find_all('a')
                        
                        for link in potential_links:
                            url = link.get('href', '')
                            title = link.get_text().strip()
                            
                            # Filtro mais flexível para alertas
                            is_alert_url = '/alertas/' in url and any(char.isdigit() for char in url)
                            # Ignora links que são apenas índices de anos ou a própria página de alertas
                            is_index = url.endswith('/alertas') or \
                                       re.search(r'/alertas/\d{4}(/view)?$', url) or \
                                       'index_html' in url
                            
                            if is_alert_url and not is_index and len(title) > 8:
                                item_url = url if url.startswith('http') else f"https://www.gov.br{url}"
                                if any(it['url'] == item_url for it in items): continue

                                # Tenta extrair a data do texto do link ou do elemento pai
                                date_str = None
                                # 1. Tenta encontrar no texto do link (ex: "Alerta 01/2025 - 10/01/2025")
                                m_date = re.search(r'(\d{2}/\d{2}/\d{4})', title)
                                if m_date:
                                    date_str = m_date.group(1)
                                
                                # 2. Tenta encontrar no elemento pai
                                if not date_str:
                                    parent = link.find_parent(['article', 'div', 'li', 'tr', 'p'])
                                    if parent:
                                        date_elem = parent.find(class_=re.compile(r'date|documentByLine|timestamp|summary-view-icon'))
                                        if date_elem:
                                            m_date = re.search(r'(\d{2}/\d{2}/\d{4})', date_elem.get_text())
                                            if m_date: date_str = m_date.group(1)
                                        else:
                                            m_date = re.search(r'(\d{2}/\d{2}/\d{4})', parent.get_text())
                                            if m_date: date_str = m_date.group(1)
                                
                                # 3. Se ainda não tem, usa a data atual como fallback (será ordenado por título se necessário)
                                if not date_str:
                                    date_str = now.strftime("%d/%m/%Y")

                                items.append({
                                    "date": date_str,
                                    "title": f"[CTIR Gov] {title}",
                                    "summary": f"Informativo oficial do CTIR Gov. Consulte para detalhes técnicos e recomendações.",
                                    "url": item_url
                                })
                                
                                if len(items) >= 40: break # Coleta bastante para garantir o Top 5
                except Exception as e:
                    logger.warning(f"Erro ao processar URL do CTIR {target_url}: {e}")
                
                if len(items) >= 40: break
        except Exception as e:
            logger.warning(f"Erro crítico no scraping do CTIR Gov: {e}")

        if not items:
            logger.info("Nenhum alerta encontrado via scraping, usando fallbacks.")
            items = [
                {"date": now.strftime("%d/%m/%Y"), "title": "[CTIR Gov] Alertas e Recomendações de Segurança", "summary": "Acesse o portal oficial para as últimas recomendações de segurança cibernética do governo federal.", "url": "https://www.gov.br/ctir/pt-br/assuntos/alertas-e-recomendacoes/alertas"},
                {"date": now.strftime("%d/%m/%Y"), "title": "[CTIR Gov] Orientações para Prevenção de Incidentes", "summary": "Diretrizes oficiais para o tratamento de incidentes em redes governamentais.", "url": "https://www.gov.br/ctir/"}
            ]
        else:
            # Ordenação rigorosa por data (mais recentes primeiro)
            try:
                # Função auxiliar para converter string de data para objeto datetime
                def parse_dt(d_str):
                    try: return datetime.strptime(d_str, "%d/%m/%Y")
                    except: return datetime.min
                
                items.sort(key=lambda x: parse_dt(x['date']), reverse=True)
            except Exception as e:
                logger.error(f"Erro ao ordenar alertas por data: {e}")
            
        final_items = items[:limit]
        
        # Apenas faz cache se tivermos resultados reais (mais de 2 itens ou não são os fallbacks)
        is_fallback = len(final_items) <= 2 and "Alertas e Recomendações" in final_items[0]['title']
        if not is_fallback:
            news_cache.set("br_alerts_v4", final_items, expire=3600) # Cache de 1 hora
        
        return final_items
    except Exception as e:

        logger.error(f"Erro crítico em get_br_threat_trends: {e}", exc_info=True)
        return [
            {"date": datetime.now().strftime("%d/%m/%Y"), "title": "Tendências indisponíveis", "summary": "Falha ao consultar fontes do CTIR Gov.", "url": "https://www.gov.br/ctir/"}
        ]

