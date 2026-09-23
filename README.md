# Diagnóstico de Segurança — Nebula Host

No ar em **[checkupseguro.fly.dev](https://checkupseguro.fly.dev/)**.

Serviço gratuito e sem fins lucrativos oferecido pela [Nebula Host](https://nebulahost.com.br) para a comunidade — diagnóstico de segurança simples e sem jargão técnico, pensado para qualquer pessoa usar (não só quem é de TI).

Contexto completo do produto, casos de uso e roadmap: veja [ANALISE_CIBERSEGURANCA_PME.md](ANALISE_CIBERSEGURANCA_PME.md).

## O que ele verifica hoje (v1)

- **Domínio:** SPF / DKIM / DMARC (proteção contra falsificação de e-mail) e validade do certificado SSL do site
- **IP:** portas sensíveis expostas direto na internet (RDP, SSH, bancos de dados, etc.), com proteção contra varredura de endereços internos/privados
- **Domínios "sósia":** variações de erro de digitação do seu domínio já registradas por terceiros (possível golpe de phishing)
- **Dados vazados:** e-mails do domínio presentes em vazamentos conhecidos (requer `HIBP_API_KEY`)
- **Chaves vazadas:** chaves/senhas expostas em repositórios públicos do GitHub (requer `GITHUB_TOKEN`)
- **CNPJ (opcional):** situação cadastral da empresa na Receita Federal — dado público, útil também para checar fornecedores (via BrasilAPI, sem chave necessária)
- **Seu telefone (opcional):** checagem de vazamento de dados — hoje é um *placeholder* (veja nota abaixo)
- **Número suspeito que te ligou (opcional):** tipo de linha (fixa/móvel/VOIP), como sinal de possível golpe por telefone (requer `TWILIO_ACCOUNT_SID` + `TWILIO_AUTH_TOKEN`)

As checagens acima que citam uma chave exigem credenciais de terceiros. Sem elas configuradas, aparecem no relatório como "não configurado" em vez de quebrar o resto do diagnóstico.

> **Nota sobre dados pessoais (LGPD):** propositalmente **não** existe (e não vamos adicionar) uma busca reversa de CPF ou telefone que devolva identidade/dados de uma pessoa — isso é o padrão clássico de ferramenta de "people search"/doxxing, incompatível com o objetivo do produto (autoverificação de segurança da própria empresa). A checagem de "telefone em vazamentos" é só um placeholder porque, diferente do e-mail (HIBP) e do CNPJ (Receita Federal), não existe hoje um provedor de autoatendimento confiável para isso — o próprio HIBP restringiu essa busca por risco de abuso.

## Como rodar localmente

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # opcional — preencha as chaves de API que tiver
uvicorn app.main:app --reload
```

Depois abra http://localhost:8000

## Estrutura

```
app/
  main.py         # rotas FastAPI (formulário + relatório)
  report.py       # roda todas as checagens e calcula a nota geral
  abuse_guard.py  # proteção contra abuso (cooldown por domínio)
  captcha.py      # verificação do Cloudflare Turnstile
  checks/         # cada arquivo é uma categoria de checagem (domínio, IP, vazamentos...)
  templates/      # HTML do formulário e do relatório
  static/         # CSS, logo
Dockerfile        # build de produção
fly.toml          # config de deploy no Fly.io
```

## Proteção contra abuso

Como o formulário é público e anônimo, sem essas proteções qualquer pessoa poderia usar a ferramenta para varrer porta de domínio de terceiros à vontade, ou estourar o custo das chaves de API pagas (HIBP, Twilio) só martelando o endpoint:

- **CAPTCHA** (Cloudflare Turnstile) no formulário — opcional via `TURNSTILE_SITE_KEY`/`TURNSTILE_SECRET_KEY`, degrada graciosamente (sem bloquear) quando não configurado, útil pra rodar localmente sem precisar resolver captcha toda hora.
- **Limite por IP:** 5 verificações por hora (via `slowapi`), com mensagem de erro em linguagem simples em vez de um 429 cru.
- **Cooldown por domínio:** o mesmo domínio não pode ser verificado de novo antes de 10 minutos, não importa quem esteja pedindo — impede que a ferramenta vire um jeito de martelar repetidamente a infraestrutura de outra pessoa.

Limitação conhecida: o cooldown por domínio e o rate limit são em memória do processo — reiniciam ao reiniciar o servidor e não são compartilhados entre múltiplos workers/instâncias. Antes de rodar com mais de 1 máquina simultânea no Fly, trocar por um backend compartilhado (ex: Redis).

## Deploy (Fly.io)

```bash
flyctl auth login
flyctl launch --no-deploy   # já existe fly.toml, reaproveita a config
flyctl secrets set GITHUB_TOKEN=... TURNSTILE_SITE_KEY=... TURNSTILE_SECRET_KEY=...
flyctl deploy
```

`min_machines_running = 0` no `fly.toml` deixa a máquina desligar sozinha sem tráfego (economiza no plano gratuito).

## Roadmap (próximos passos)

- Checagem de configuração de nuvem (Microsoft 365 / Google Workspace) via OAuth
- Reputação de IP (AbuseIPDB / Shodan)
- Domínio próprio `checkupseguro.com.br` (registrado no Registro.br, apontar DNS pro Fly)
- Exportar relatório em PDF
- Histórico de verificações por conta
