# 🛡️ The APEX — Open Core Security Platform (v2.0.4)

O **The APEX** é uma plataforma integrada de segurança cibernética de alta performance, projetada para consolidar análise de ameaças, monitoramento de ativos e inteligência tática em uma única interface moderna e totalmente assíncrona.

Baseado no modelo **Open Core**, o The APEX oferece uma fundação transparente e auditável para pesquisadores e entusiastas, enquanto mantém módulos avançados para operações profissionais e governamentais.

---

## 🚀 Modelo de Negócio (Tiers)

O The APEX é distribuído em três níveis de acesso, garantindo que desde o estudante até o SOC corporativo tenham as ferramentas certas:

### [TIER 0] CORE (Open Source)
**Foco:** Pesquisa, Auditoria e Estudo.
- **Backend:** Código fonte completo em Python/Quart.
- **Motores:** Análise estática local (PE Files, Strings, Phishing Detection).
- **Interface:** UI Básica Atlas (Grayscale).
- **Licença:** MIT (Permissiva).
- **Custo:** R$ 0,00 (Gratuito).

### [TIER 1] OPERADOR (Professional)
**Foco:** Consultores e Pentesters.
- **Tudo do Tier 0** +
- **Dashboard Operacional:** Interface Standard.
- **Reputação:** Integração automatizada com VirusTotal.
- **Relatórios:** Geração de PDF simplificado.
- **Distribuição:** Container Docker Privado.

### [TIER 2] ENTERPRISE (Elite)
**Foco:** SOCs, Governo e Grandes Corporações.
- **Full Unlock:** Interface **Dark Matter** (Visualização em tempo real).
- **IA Cognitiva:** Resumos executivos e remediação automatizada (BYOK).
- **Network Sniffer:** Monitoramento de nível de kernel (Detecção de Beacons).
- **Orquestração:** Multi-API (VT, Bitdefender, CTIR Gov, etc).
- **Suporte:** 24/7 direto com a engenharia.

---

## 🛠️ Funcionalidades (Core Version)

- **Análise Estática de Malware:** Detecção de anomalias em arquivos e URLs sem envio para nuvem.
- **Monitoramento de Rede:** Varredura assíncrona de ativos e serviços.
- **Auditoria de Cofre (Windows):** Identificação de credenciais expostas no sistema.
- **Threat Intelligence Brasil:** Integração nativa com alertas do CTIR Gov.
- **Arquitetura Async:** Performance extrema com Quart e Hypercorn.
- **Pronto para SIEM:** Exportação manual/automatizada para Elastic Stack.

---

## 💻 Tecnologias

- **Linguagem:** Python 3.12+
- **Framework:** Quart (ASGI)
- **Frontend:** Glassmorphism UI (Vanilla JS / CSS)
- **Banco de Dados:** SQLite (Async)
- **Integrações:** CTIR Gov, Elastic Stack, MITRE ATT&CK®.

---

## 🔧 Instalação Rápida (Core)

### Via Docker (Recomendado)
```bash
docker build -t the-apex .
docker run -d -p 5000:5000 --name the-apex the-apex
```

### Via Python Local
1. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
2. Inicie a aplicação:
   ```bash
   python initializer.py
   ```
3. Acesse: `http://localhost:5000`

---

## ⚖️ Licença
Este repositório contém a versão **Core** do The APEX, licenciada sob a **MIT License**. Para acesso aos Tiers superiores, entre em contato com a equipe comercial.

---
*Desenvolvido por [Germano Roberto](https://github.com/GermanoRoberto)*
