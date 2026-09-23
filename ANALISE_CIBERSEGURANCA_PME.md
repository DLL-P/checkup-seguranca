# Análise: Casos Mais Comuns de Cibersegurança em PMEs/Usuários Finais e Soluções Desenvolvíveis

> Foco: pequenas e médias empresas (PMEs) e usuários finais — o segmento mais atacado e o mais mal-atendido pelo mercado de segurança, que hoje é dominado por soluções caras e complexas voltadas a grandes empresas.

## 1. Por que esse segmento importa

- PMEs não têm orçamento nem equipe dedicada de segurança (geralmente 0 a 1 pessoa de TI, quando muito).
- São alvo preferencial de ataques automatizados porque a defesa é fraca e o "custo de ataque" é baixo.
- A maioria das ferramentas enterprise (SIEM, EDR corporativo, DLP) é cara demais e complexa demais para esse público — é um espaço aberto para produtos simplificados.
- Usuários finais (pessoas físicas, freelancers, profissionais liberais) enfrentam os mesmos problemas sem nenhuma camada de proteção corporativa.

## 2. Casos mais comuns (ordenados por frequência/impacto)

| # | Caso | Como acontece | Impacto típico |
|---|------|----------------|-----------------|
| 1 | **Phishing / BEC (Business Email Compromise)** | E-mails falsos pedindo pagamento, troca de dados bancários, ou clique em link malicioso | Perda financeira direta, credenciais roubadas |
| 2 | **Ransomware** | Criptografa arquivos após phishing, RDP exposto ou software desatualizado | Paralisação total da operação, resgate ou perda de dados |
| 3 | **Senhas fracas e ausência de MFA** | Reuso de senha, senha fraca, sem segundo fator | Acesso indevido a e-mail, sistemas financeiros, nuvem |
| 4 | **Acesso remoto exposto (RDP/VPN mal configurado)** | Porta aberta na internet sem proteção | Porta de entrada nº1 para ransomware |
| 5 | **Software e sistemas desatualizados** | Falta de rotina de patch/atualização | Exploração de vulnerabilidades conhecidas (CVEs antigas) |
| 6 | **Backup inexistente ou não testado** | "Backup" só local, nunca testado, sem cópia offline/imutável | Perda permanente de dados em caso de ransomware ou falha |
| 7 | **Configuração incorreta de nuvem (M365/Google Workspace)** | Compartilhamento público de arquivos, MFA desligado, regras de encaminhamento maliciosas no e-mail | Vazamento de dados, fraude interna |
| 8 | **Falta de treinamento/conscientização dos funcionários** | Ninguém reconhece phishing, engenharia social, golpes por WhatsApp | Causa raiz da maioria dos incidentes acima |
| 9 | **Dispositivos pessoais/IoT com credenciais padrão** | Câmeras, roteadores, impressoras nunca configurados | Ponto de entrada na rede, botnets |
| 10 | **Risco de terceiros/fornecedores (supply chain)** | Contador, agência de marketing, prestador com acesso a sistemas sem controle | Vetor indireto de invasão |
| 11 | **Ameaça interna (funcionário insatisfeito/saída mal conduzida)** | Acesso não revogado após demissão | Vazamento de dados, sabotagem |

**Observação:** os casos 1, 3, 4, 5 e 8 respondem, isoladamente, pela grande maioria dos incidentes reais em PMEs — são o ponto de maior alavancagem para qualquer solução.

## 3. Soluções práticas e desenvolvíveis

Organizadas por "o que dá para construir", não só por "o que fazer" — pensando em produtos/ferramentas que poderiam ser desenvolvidos.

### 3.1 Alto impacto, baixo esforço de desenvolvimento (prioridade para MVP)

| Solução | O que resolve | Como construir |
|---|---|---|
| **Verificador de postura de segurança (security checkup)** | Diagnóstico rápido: MFA ativo?, backups configurados?, portas expostas?, software desatualizado? | Script/CLI ou webapp que consulta APIs do M365/Google Workspace + scan de portas públicas (Shodan/censys ou scan próprio) e gera relatório com nota e plano de ação |
| **Rollout assistido de MFA + gerenciador de senhas** | Elimina causa nº1 de comprometimento de conta | Playbook + automação (scripts) para forçar MFA em M365/Google Workspace/serviços SaaS comuns via APIs administrativas |
| **Monitor de exposição de RDP/VPN** | Fecha a porta de entrada nº1 de ransomware | Scanner periódico (Shodan API ou nmap próprio) que alerta quando uma porta crítica (3389, 22, etc.) aparece exposta |
| **Simulador de phishing + treinamento** | Ataca a causa raiz (fator humano) | Plataforma simples de envio de e-mails de phishing simulados + métricas de quem clicou + microtreinamento (open source como GoPhish pode ser base) |
| **Checklist/scanner de configuração de nuvem (M365/GWS)** | Detecta compartilhamento público, regras de encaminhamento suspeitas, MFA desligado | Script usando Graph API (Microsoft) / Admin SDK (Google) que roda auditoria e gera relatório |

### 3.2 Impacto alto, esforço médio

| Solução | O que resolve | Como construir |
|---|---|---|
| **Backup gerenciado com cópia imutável/offsite** | Garante recuperação de ransomware sem pagar resgate | Serviço/agente que automatiza backup 3-2-1, testa restauração periodicamente, usa storage imutável (ex: S3 com Object Lock) |
| **Patch management leve para PME** | Fecha vulnerabilidades conhecidas | Agente leve (baseado em osquery, Ansible ou WSUS simplificado) que audita e aplica patches em máquinas Windows/Linux |
| **EDR/monitoramento leve open-source (baseado em Wazuh)** | Detecção de comportamento malicioso sem custo de EDR enterprise | Empacotar Wazuh (ou OSSEC) com dashboards simplificados e alertas configurados para o perfil de PME |
| **Gestão de acesso e offboarding automatizado** | Evita ameaça interna por acesso não revogado | Ferramenta que integra com RH/SaaS e revoga acessos automaticamente no desligamento |

### 3.3 Impacto alto, esforço maior (roadmap de médio prazo)

| Solução | O que resolve | Como construir |
|---|---|---|
| **"SOC-as-a-service" simplificado para PME** | Monitoramento contínuo sem equipe própria | Combinar Wazuh/SIEM leve + triagem humana terceirizada + alertas priorizados |
| **Gestão de risco de fornecedores (vendor risk)** | Reduz risco de supply chain | Plataforma de questionário + scoring automatizado de terceiros com acesso a sistemas |
| **Plataforma de resposta a incidentes (runbooks + simulação)** | Reduz tempo de resposta e dano em caso de incidente real | Templates de runbook por tipo de incidente + ferramenta de tabletop exercise |

## 4. Priorização recomendada (matriz impacto x esforço)

```
Alto impacto  |  [MVP: Security Checkup]     [Backup gerenciado]
              |  [MFA rollout]                [Patch mgmt]
              |  [Scanner RDP exposto]         [EDR leve/Wazuh]
              |  [Phishing sim + treino]
              |  [Scanner config nuvem]
              |
Baixo impacto |                                [SOC simplificado]
              |________________________________________________
                Baixo esforço                    Alto esforço
```

## 5. Ponto de partida sugerido

Começar pelo **"Security Checkup"** (item 3.1) é a escolha de maior alavancagem:
- É o menor MVP possível (script/CLI que já entrega valor sozinho).
- Serve como **porta de entrada** para vender/oferecer as outras soluções (o relatório de diagnóstico naturalmente indica "você precisa de MFA", "seu backup não existe", etc.).
- Não depende de integração profunda — pode rodar com poucas permissões (leitura via API + scan de rede pública).
- Gera dado real sobre quais problemas são mais comuns na prática, validando as prioridades acima.

**Próximo passo natural:** definir o escopo técnico do Security Checkup (quais checks entram na v1, quais integrações — M365, Google Workspace, scan de porta) e montar o esqueleto do projeto.

## 6. Escopo técnico do MVP: "Security Checkup"

Requisito não-negociável do produto: **qualquer pessoa, mesmo sem conhecimento técnico, tem que conseguir rodar e entender o resultado.** Isso molda tanto os checks quanto a interface.

### 6.1 Checks da v1

| Categoria | O que verificar | Fonte/técnica |
|---|---|---|
| **IPs** | IP público exposto, portas críticas abertas (RDP 3389, SSH 22, DB 3306/5432, SMB 445), presença em blacklists de abuso | Scan próprio (nmap/masscan em modo leve) + AbuseIPDB API + Shodan/Censys API |
| **Domínios** | Registro SPF/DKIM/DMARC (proteção contra phishing/spoofing do domínio), certificado SSL válido/expirando, subdomínios esquecidos vulneráveis a takeover, WHOIS exposto, domínios "sósia" (typosquatting) registrados por golpistas | DNS lookup direto, crt.sh (certificados), APIs de WHOIS, checagem de typosquat (variações do domínio) |
| **Chaves/segredos vazados** | API keys, tokens, senhas expostas em repositórios públicos (GitHub/GitLab) ou pastebins associados ao nome da empresa/domínio | GitHub code search API, regras estilo TruffleHog/Gitleaks, busca em paste sites |
| **Dados da instituição vazados (credential/data breach)** | E-mails corporativos (@dominio.com) presentes em vazamentos conhecidos; senhas associadas circulando | Have I Been Pwned API (domain search) ou equivalente |
| **Configuração de nuvem (opcional, se houver login)** | MFA desligado, compartilhamento público de arquivos, regras de encaminhamento de e-mail suspeitas | Microsoft Graph API / Google Admin SDK (fase 2, exige autenticação OAuth do cliente) |

A v1 pode rodar **só com domínio + IP informados pelo usuário**, sem exigir login em nada — reduz fricção e já cobre boa parte do valor (IP, domínio, chaves vazadas, e-mails vazados). Login no M365/Google Workspace fica para uma v2, já que exige mais confiança/fricção do usuário.

### 6.2 Requisito central: facilidade de uso

- **Entrada única e simples:** o usuário só digita o domínio da empresa (ex: `minhaempresa.com.br`) — o sistema descobre IPs, e-mails e ativos relacionados sozinho sempre que possível, em vez de pedir uma lista técnica.
- **Zero jargão no resultado:** nada de "porta 3389 exposta" sem explicação — o relatório traduz para "seu servidor está com acesso remoto aberto pra internet, isso é uma das formas mais comuns de invasão por ransomware".
- **Sistema de sinal (semáforo):** cada item do relatório é 🔴 crítico / 🟡 atenção / 🟢 ok, com nota geral no topo (ex: "sua nota de segurança: 4/10").
- **Ação clara por item, sem ambiguidade:** cada alerta vem com "o que fazer agora" em 1-2 frases, sem assumir que o usuário sabe configurar nada sozinho (e um link/indicação de quem pode ajudar, se aplicável).
- **Sem instalação/CLI:** interface web, sem terminal, sem comando para digitar — só abrir o site e clicar em "verificar".
- **Relatório exportável:** PDF simples para o dono do negócio mostrar ao contador/sócio/prestador de TI, sem precisar entender tecnicamente.
- **Sem falso alarme em excesso:** priorizar poucos alertas de alto impacto no topo, em vez de uma lista longa e assustadora — isso é o que diferencia de ferramentas técnicas existentes (que assumem que quem lê é de TI).

### 6.3 Fluxo de uso ideal (ponta a ponta)

1. Usuário acessa o site, digita o domínio da empresa.
2. Clica em "Verificar minha segurança" (sem cadastro obrigatório para o resultado básico).
3. Sistema roda os checks da tabela 6.1 em background (leva alguns segundos a ~1 minuto).
4. Usuário recebe relatório visual (nota geral + lista semáforo + ações recomendadas em linguagem simples).
5. Opção de exportar PDF / receber por e-mail / (upsell futuro: "quer que a gente resolva isso pra você?").
