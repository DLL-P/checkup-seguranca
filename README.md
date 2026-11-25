# Diagnóstico de Segurança — Nebula Host

No ar em **[checkupseguro.fly.dev](https://checkupseguro.fly.dev/)**.

Serviço gratuito e sem fins lucrativos oferecido pela [Nebula Host](https://nebulahost.com.br) para a comunidade — diagnóstico de segurança simples e sem jargão técnico, pensado para qualquer pessoa usar (não só quem é de TI).

Contexto completo do produto, casos de uso e roadmap: veja [ANALISE_CIBERSEGURANCA_PME.md](ANALISE_CIBERSEGURANCA_PME.md).

## O que ele verifica

- **Domínio:** SPF / DKIM / DMARC (proteção contra falsificação de e-mail) e validade do certificado SSL do site
- **Servidor (passivo):** portas perigosas abertas na internet (RDP, SMB, bancos de dados…) e **falhas conhecidas** nos programas do servidor, cruzadas com o catálogo **KEV da CISA** (exploração ativa confirmada, inclusive por ransomware) e o **EPSS** (chance de ataque nos próximos 30 dias). Os dados vêm do **Shodan InternetDB**: o diagnóstico **não envia nenhum pacote** ao servidor analisado
- **Domínios "sósia":** variações de erro de digitação do seu domínio já registradas por terceiros (possível golpe de phishing)
- **Dados vazados:** e-mails do domínio presentes em vazamentos conhecidos (requer `HIBP_API_KEY`)
- **Chaves vazadas:** chaves/senhas expostas em repositórios públicos do GitHub (requer `GITHUB_TOKEN`)
- **CNPJ (opcional):** situação cadastral da empresa na Receita Federal — dado público, útil também para checar fornecedores (via BrasilAPI, sem chave necessária)
- **Seu telefone (opcional):** checagem de vazamento de dados — hoje é um *placeholder* (veja nota abaixo)
- **Número suspeito que te ligou (opcional):** tipo de linha (fixa/móvel/VOIP), como sinal de possível golpe por telefone (requer `TWILIO_ACCOUNT_SID` + `TWILIO_AUTH_TOKEN`)

As checagens acima que citam uma chave exigem credenciais de terceiros. Sem elas configuradas, aparecem no relatório como "não configurado" em vez de quebrar o resto do diagnóstico. Uma falha momentânea de consulta (DNS fora do ar, serviço instável) aparece como ⚪ "não foi possível verificar", nunca como problema.

> **Nota sobre dados pessoais (LGPD):** propositalmente **não** existe (e não vamos adicionar) uma busca reversa de CPF ou telefone que devolva identidade/dados de uma pessoa — isso é o padrão clássico de ferramenta de "people search"/doxxing, incompatível com o objetivo do produto (autoverificação de segurança da própria empresa). A checagem de "telefone em vazamentos" é só um placeholder porque, diferente do e-mail (HIBP) e do CNPJ (Receita Federal), não existe hoje um provedor de autoatendimento confiável para isso — o próprio HIBP restringiu essa busca por risco de abuso.

## Pensado para o dono do negócio

- **Nota de 0 a 10 com regra pública** ([/metodologia](https://checkupseguro.fly.dev/metodologia)): o peso de cada problema segue o risco real de virar ataque (RDP aberto ou falha explorada por ransomware pesam muito mais do que DKIM ausente). A tabela de regras em `app/scoring.py` calcula a nota **e** gera a página, então o que o site explica é exatamente o que o código faz.
- **"Comece por aqui":** os 3 pontos que mais pesam na nota aparecem no topo do relatório, com o que fazer em linguagem simples.
- **Detalhes técnicos para encaminhar** a quem cuida do TI, e um caminho para pedir ajuda à Nebula Host.

## Privacidade desde o projeto

Qualquer pessoa pode consultar qualquer domínio, então o relatório tem **dois níveis**:

| Visitante anônimo vê | Só o dono comprovado do domínio vê |
|---|---|
| A nota, os problemas e as contagens ("3 e-mails vazados") | **Quais** e-mails vazaram |
| "Possível chave exposta no GitHub" | **Onde** estão as chaves (as URLs) |
| "2 falhas exploradas agora, 1 por ransomware" | A lista exata de CVEs do servidor |

Para um visitante qualquer, essas listas seriam o mapa de um ataque. O dono comprova o domínio de dois jeitos: **entrando com o e-mail da empresa** (joao@minhaempresa.com.br comprova minhaempresa.com.br; provedores públicos como Gmail nunca contam) ou criando um **registro TXT** `nebula-checkup=<código>` no DNS.

Também: o IP do visitante nunca é guardado em claro (o limite de uso conta pedidos por um HMAC do IP), o que é digitado no diagnóstico não é guardado, não existe senha (entrada por link mágico de uso único, guardado só como hash) e a conta pode ser apagada pelo próprio painel. Os detalhes estão na página [/privacidade](https://checkupseguro.fly.dev/privacidade).

## Conta grátis e monitoramento

"A verificação é de uma vez" — com a conta, cada domínio comprovado é verificado de novo a cada `MONITOR_INTERVAL_DAYS` (padrão: 7) e o dono recebe um aviso **por e-mail e/ou WhatsApp** quando algo **piora**: uma porta perigosa que abriu, uma falha do servidor que entrou em exploração ativa, o certificado prestes a vencer, um e-mail novo em vazamento. A primeira verificação vira o retrato de referência; falhas momentâneas de consulta não geram aviso.

- `python -m app.monitor` roda os domínios pendentes pela linha de comando.
- `POST /tarefas/monitor` (com `Authorization: Bearer $CRON_SECRET`) faz o mesmo em lotes pequenos e responde quantos faltam. O workflow `.github/workflows/monitor.yml` chama esse gatilho todo dia, até zerar.

### Modelo do WhatsApp

Mensagem iniciada pela empresa só pode ser enviada com um modelo aprovado pela Meta (categoria **Utilidade**) e com a autorização da pessoa, que o painel registra. Crie no WhatsApp Manager um modelo chamado `alerta_seguranca` (ou o nome em `WHATSAPP_TEMPLATE`), idioma `pt_BR`, com 3 variáveis no corpo, por exemplo:

```
Alerta de segurança em {{1}}: {{2}}. Veja o relatório completo e o que fazer: {{3}}
```

`{{1}}` é o domínio, `{{2}}` o resumo do que mudou e `{{3}}` o link do relatório.

## Como rodar localmente

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env  # opcional — preencha as chaves de API que tiver
# para testar a conta sem configurar e-mail: DEV_SHOW_LOGIN_LINK=1 no .env
uvicorn app.main:app --reload
```

Depois abra http://localhost:8000

Testes (sem rede, tudo simulado):

```bash
python -m pytest -q
```

## Estrutura

```
app/
  main.py         # rotas FastAPI (diagnóstico, conta, painel, gatilho do monitoramento)
  report.py       # roda todas as checagens e monta o relatório
  scoring.py      # regras públicas da nota (também geram /metodologia)
  intel.py        # CISA KEV, EPSS e Shodan InternetDB
  auth.py         # conta sem senha (link mágico) e sessão
  verification.py # comprovação de domínio (e-mail da empresa ou TXT no DNS)
  monitor.py      # monitoramento contínuo e avisos
  notify.py       # envio por e-mail (Resend) e WhatsApp (Cloud API)
  db.py           # SQLite
  config.py       # variáveis de ambiente
  abuse_guard.py  # proteção contra abuso (cooldown por domínio, limite por HMAC do IP)
  captcha.py      # verificação do Cloudflare Turnstile
  checks/         # cada arquivo é uma categoria de checagem (domínio, IP, vazamentos...)
  templates/      # HTML
  static/         # CSS, logo
tests/            # testes (pytest)
Dockerfile        # build de produção
fly.toml          # config de deploy no Fly.io
```

## Proteção contra abuso

Como o formulário é público e anônimo, sem essas proteções qualquer pessoa poderia usar a ferramenta para varrer porta de domínio de terceiros à vontade, ou estourar o custo das chaves de API pagas (HIBP, Twilio) só martelando o endpoint:

- **CAPTCHA** (Cloudflare Turnstile) no formulário — opcional via `TURNSTILE_SITE_KEY`/`TURNSTILE_SECRET_KEY`, degrada graciosamente (sem bloquear) quando não configurado, útil pra rodar localmente sem precisar resolver captcha toda hora.
- **Limite por IP:** 5 verificações por hora (via `slowapi`), com mensagem de erro em linguagem simples em vez de um 429 cru.
- **Cooldown por domínio:** o mesmo domínio não pode ser verificado de novo antes de 10 minutos, não importa quem esteja pedindo — impede que a ferramenta vire um jeito de martelar repetidamente a infraestrutura de outra pessoa.
- **Sem varredura ativa:** as portas e falhas vêm do Shodan InternetDB; nenhum pacote é enviado ao servidor analisado.

Com `REDIS_URL` configurado, o limite e o cooldown ficam no Redis e valem para todas as máquinas; sem ele, ficam em memória do processo (ok para 1 máquina só, que é o caso com o volume do SQLite).

## Deploy (Fly.io)

```bash
flyctl auth login
flyctl launch --no-deploy   # já existe fly.toml, reaproveita a config
flyctl volumes create checkup_data --region gru --size 1   # banco das contas (uma vez)
flyctl secrets set SECRET_KEY=... CRON_SECRET=... RESEND_API_KEY=... \
  PRIVACY_CONTACT_EMAIL=... CONTROLLER_DOCUMENT="CNPJ ..." \
  GITHUB_TOKEN=... TURNSTILE_SITE_KEY=... TURNSTILE_SECRET_KEY=...
flyctl deploy
```

Para o monitoramento diário, no GitHub: crie o secret `CHECKUP_CRON_SECRET` (mesmo valor do `CRON_SECRET`) e a variável `CHECKUP_URL` (`https://checkupseguro.fly.dev`). Para o WhatsApp, defina também `WHATSAPP_TOKEN` e `WHATSAPP_PHONE_NUMBER_ID` (token permanente de usuário do sistema, nunca o temporário).

`min_machines_running = 0` no `fly.toml` deixa a máquina desligar sozinha sem tráfego (economiza no plano gratuito).

## Fontes e licenças

CISA KEV (CC0 1.0) · EPSS da FIRST.org (uso gratuito com crédito) · Shodan InternetDB (uso gratuito **não comercial** — rever se o diagnóstico passar a ser cobrado) · Have I Been Pwned (CC BY 4.0, com crédito) · GitHub Code Search · BrasilAPI.

## Roadmap (próximos passos)

- Checagem de configuração de nuvem (Microsoft 365 / Google Workspace) via OAuth
- Reputação de IP (AbuseIPDB)
- Domínio próprio `checkupseguro.com.br` (registrado no Registro.br, apontar DNS pro Fly)
- Exportar relatório em PDF
- Relatório mensal por domínio, escrito em linguagem simples para o dono do negócio
