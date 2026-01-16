# ⚡ THE APEX — Open Core Security Platform (© 2024-2026 The APEX Community)

## 👁️ Visão Geral

O **The APEX** é uma plataforma de segurança cibernética de alta performance focada em inteligência de ameaças e análise tática. Esta versão **[TIER 0] CORE** serve como a fundação open source do projeto, projetada para pesquisadores, estudantes e auditores de segurança.

**Destaques da Versão Core:**
- **Malware Analyzer:** Análise estática profunda (PE/ELF), extração de strings e cálculo de entropia.
- **Network Monitor:** Varredura assíncrona de ativos e descoberta de serviços.
- **System Audit:** Verificação de integridade e auditoria de segurança local (compatível com Windows 10/11/Server).
- **Threat Intel:** Integração nativa com feeds de ameaças (ex: CTIR Gov) e serviços de reputação (VirusTotal).
- **Privacy First:** Processamento local prioritário, garantindo que dados sensíveis permaneçam sob seu controle.

---

## 🔧 Instalação

### Pré-requisitos
- **Sistema Operacional:** Windows 10/11 ou Server (Recomendado para auditoria completa).
- **Python:** Versão 3.12 ou superior.
- **Permissões:** Acesso de Administrador (para coleta de métricas de sistema via PowerShell).

### Passo a Passo
1. Clone o repositório:
   ```bash
   git clone https://github.com/3x0t3ch/TheAPEX-opensource-
   cd TheAPEX-opensource-
   ```

2. Instale as dependências:
   ```powershell
   pip install -r requirements.txt
   ```

---

## 🚀 Uso Rápido

1. **Inicie o Servidor:**
   Execute o script de inicialização automatizado:
   ```powershell
   python initializer.py
   ```
   *Ou utilize o atalho `iniciar.bat` se preferir.*

2. **Acesse a Interface:**
   Abra seu navegador e navegue para:
   `http://localhost:5000`

3. **Primeiros Passos:**
   - Navegue até **Audit** para verificar o status de segurança da máquina local.
   - Use **Analyzer** para submeter arquivos suspeitos para análise estática.
   - Consulte **Threat Map** para visualizar alertas recentes.

---

## 🏗️ Arquitetura

O The APEX foi construído sobre uma arquitetura moderna e assíncrona, eliminando gargalos de I/O comuns em ferramentas de segurança legadas.

- **Backend:** [Quart](https://pgjones.gitlab.io/quart/) (ASGI Framework) — Performance assíncrona nativa.
- **Frontend:** Glassmorphism UI — Interface leve construída com Vanilla JS e CSS moderno (sem frameworks pesados).
- **Database:** SQLite (Async) — Persistência leve e eficiente para implantações locais.
- **Security:**
  - Validação rigorosa com Pydantic.
  - Proteção CSRF/XSS.
  - Isolamento de execução via subprocessos seguros.

---

## ⚖️ Licenciamento

O código contido neste repositório é licenciado sob a **Licença Comunitária The APEX**.
Sinta-se à vontade para contribuir, auditar e adaptar a ferramenta para fins de pesquisa e educação (uso não-comercial).

*Desenvolvido por [Germano Roberto](https://github.com/GermanoRoberto)*
