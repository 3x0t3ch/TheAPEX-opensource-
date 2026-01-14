# ⚡ THE APEX — Open Core Security Platform (© 2024-2026 The APEX Community)

O **The APEX** é uma plataforma de segurança cibernética de alta performance, projetada para consolidação de inteligência de ameaças, monitoramento de ativos e análise tática. Esta versão **Core** é a fundação tecnológica do projeto, oferecendo um motor totalmente assíncrono e transparente para pesquisadores e auditores.

---

## 🏛️ Modelo Open Core (Tiers)

O ecossistema The APEX é dividido em níveis de acesso para atender desde a pesquisa acadêmica até operações de SOC corporativo:

### [TIER 0] CORE (Open Source) — **ESTA VERSÃO**
- **Foco:** Pesquisa, Auditoria e Estudo de Malware.
- **Backend:** Python 3.12+ / Quart (ASGI).
- **Motores:** Análise estática local (PE/ELF), Detecção de Phishing (Homógrafo).
- **Reputação:** Integração com VirusTotal e OpenSourceMalware.
- **Interface:** UI Atlas (Grayscale Edition).
- **Licença:** MIT (Permissiva).

### [TIER 1] OPERADOR (Professional)
- **Tudo do Tier 0** +
- **Interface:** Dashboard Operacional Standard.
- **Automação:** Relatórios PDF e updates semanais de Threat Intel.
- **Distribuição:** Container Docker Privado.

### [TIER 2] ENTERPRISE (Elite)
- **Interface:** **Dark Matter** (Visualização tática em tempo real).
- **Inteligência:** IA Cognitiva para resumos executivos e correlação de ameaças (BYOK).
- **Network:** Sniffer de nível de kernel (Kernel-Level Monitoring).
- **Orquestração:** Multi-API (VT, Bitdefender, CTIR Gov, etc).

---

## 🛠️ Funcionalidades da Versão Core

- **Malware Analyzer:** Análise estática de arquivos (Strings, Importações, Entropia) e URLs.
- **Network Monitor:** Varredura assíncrona de ativos e serviços de rede.
- **System Audit:** Auditoria de credenciais expostas (Windows Vault) e integridade.
- **Alertas Brasil:** Integração nativa com feeds de ameaças do CTIR Gov.
- **Privacy First:** Processamento local prioritário, com consultas externas limitadas a serviços de reputação aprovados.

---

## 💻 Stack Tecnológica

- **Backend:** [Quart](https://pgjones.gitlab.io/quart/) (Fast ASGI Framework)
- **Frontend:** Glassmorphism UI (Vanilla JS & Modern CSS)
- **Database:** SQLite com acesso assíncrono.
- **Security:** CSRF Protection, Pydantic Validation, Local Sandboxing.

---

## 🔧 Instalação e Execução

### Pré-requisitos
- Python 3.12 ou superior.
- Docker (opcional, para execução via container).

### Execução Local
1. Instale as dependências:
   ```powershell
   pip install -r requirements.txt
   ```
2. Inicie a aplicação:
   ```powershell
   python initializer.py
   ```
3. Acesse no navegador: `http://localhost:5000`

### Execução via Docker
```powershell
docker-compose up --build -d
```

---

## ⚖️ Licenciamento

O código contido neste repositório é licenciado sob a **Licença Comunitária The APEX**. Sinta-se à vontade para contribuir, auditar e adaptar a ferramenta para seus propósitos de pesquisa, respeitando o uso não-comercial.

---
*Desenvolvido por [Germano Roberto](https://github.com/GermanoRoberto)*
