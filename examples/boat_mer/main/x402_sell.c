// The device sells its readings over HTTP with x402 (CONFIG_MER_X402_SELL_PORT).
//
// GET /reading without a payment answers 402, with the payment requirements
// in the PAYMENT-REQUIRED header (base64 JSON, x402 v2) and the body: the
// "exact" scheme, CONFIG_MER_X402_SELL_PRICE base units of the EIP-3009 token
// CONFIG_MER_X402_SELL_TOKEN on CONFIG_MER_X402_SELL_CHAIN_ID, paid to the
// device's own address. Any x402 client can pay it (@x402/fetch, say).
//
// With a PAYMENT-SIGNATURE header the device checks the payment itself
// (x402_check.c: payee, price, validity, and the EIP-712 signature, recovered
// with MER's secp256k1), then has the facilitator at
// CONFIG_MER_X402_SELL_FACILITATOR settle it on-chain (POST /settle), so the
// device needs no gas. Only once it is settled does the device answer 200 with
// an attested reading and a PAYMENT-RESPONSE header carrying the transaction.
// packages/wdk-protocol-boat-evm/examples/x402/facilitator.js is such a
// facilitator, signing and paying gas with a WDK account.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_http_server.h"
#include "esp_timer.h"
#include "sodium.h"

#include "boat_crypto.h"
#include "boat_pal.h"
#include "mer.h"
#include "x402_check.h"

#define MAX_HEADER 3000
#define RECENT 16

static x402_terms_t terms;
static char requirements[512]; // one entry of "accepts", also sent back to the facilitator
static uint8_t recent[RECENT][32]; // nonces being settled or settled, so one is not served twice
static int recent_next;
static unsigned sold, refused;

bool
x402_sell_enabled (void) {
  return CONFIG_MER_X402_SELL_PORT > 0 && CONFIG_MER_X402_SELL_FACILITATOR[0] != '\0';
}

static char *
base64 (const char *s) {
  size_t n = strlen(s);
  size_t cap = sodium_base64_ENCODED_LEN(n, sodium_base64_VARIANT_ORIGINAL);
  char *out = malloc(cap);
  if (out) sodium_bin2base64(out, cap, (const unsigned char *) s, n, sodium_base64_VARIANT_ORIGINAL);
  return out;
}

static esp_err_t
payment_required (httpd_req_t *req, const char *error) {
  char host[64] = "device";
  httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host));
  char *body = malloc(1024);
  if (!body) return httpd_resp_send_500(req);
  snprintf(body, 1024, "{\"x402Version\":2,\"error\":\"%s\",\"resource\":{\"url\":\"http://%s/reading\",\"description\":\"A reading attested by the device (did:mw)\",\"mimeType\":\"application/json\"},\"accepts\":[%s]}", error, host, requirements);
  char *header = base64(body);
  httpd_resp_set_status(req, "402 Payment Required");
  httpd_resp_set_type(req, "application/json");
  if (header) httpd_resp_set_hdr(req, "PAYMENT-REQUIRED", header);
  esp_err_t err = httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
  free(header);
  free(body);
  return err;
}

static bool
seen (const uint8_t nonce[32]) {
  for (int i = 0; i < RECENT; i++) {
    if (memcmp(recent[i], nonce, 32) == 0) return true;
  }
  return false;
}

static esp_err_t
on_reading (httpd_req_t *req) {
  size_t len = httpd_req_get_hdr_value_len(req, "PAYMENT-SIGNATURE");
  if (len == 0) return payment_required(req, "PAYMENT-SIGNATURE header is required");
  if (len > MAX_HEADER) return payment_required(req, "payment too large");

  char *header = malloc(len + 1);
  char *json = malloc(len + 1);
  char *settle = malloc(len + 1024);
  char *resp = malloc(1024);
  esp_err_t err = ESP_OK;
  if (!header || !json || !settle || !resp) {
    err = httpd_resp_send_500(req);
    goto done;
  }
  httpd_req_get_hdr_value_str(req, "PAYMENT-SIGNATURE", header, len + 1);
  size_t json_len;
  if (sodium_base642bin((unsigned char *) json, len, header, len, NULL, &json_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
    err = payment_required(req, "PAYMENT-SIGNATURE is not base64");
    goto done;
  }
  json[json_len] = '\0';

  x402_auth_t auth;
  const char *why = x402_parse_payment(json, &auth);
  if (!why && boat_pal_time() < MER_CLOCK_SET) why = "device clock not set yet";
  if (!why) why = x402_check_payment(&terms, &auth, boat_pal_time());
  if (!why && seen(auth.nonce)) why = "payment already used";
  char payer[43] = "0x";
  sodium_bin2hex(payer + 2, 41, auth.from, 20);
  if (why) {
    refused++;
    printf("MER|x402 sell refused from=%.12s...: %s (sold=%u refused=%u)\n", payer, why, sold, refused);
    err = payment_required(req, why);
    goto done;
  }
  memcpy(recent[recent_next], auth.nonce, 32);
  recent_next = (recent_next + 1) % RECENT;

  // settle before serving: the facilitator submits the authorization and pays the gas
  int64_t t0 = esp_timer_get_time();
  snprintf(settle, len + 1024, "{\"x402Version\":2,\"paymentPayload\":%s,\"paymentRequirements\":%s}", json, requirements);
  char url[160];
  snprintf(url, sizeof(url), "%s/settle", CONFIG_MER_X402_SELL_FACILITATOR);
  int status = 0;
  boat_err_t e = boat_pal_http_post(url, NULL, "application/json", settle, &status, resp, 1024);
  long settle_ms = (long) ((esp_timer_get_time() - t0) / 1000);
  char tx[80] = "";
  bool settled = e == BOAT_OK && status == 200 && strstr(resp, "\"success\":true") != NULL && json_str(resp, "transaction", tx, sizeof(tx));
  if (!settled) {
    refused++;
    printf("MER|x402 sell settle failed from=%.12s... status=%d ms=%ld: %.160s\n", payer, status, settle_ms, resp);
    err = payment_required(req, "settlement failed");
    goto done;
  }

  static char reading[640];
  int n = attested_reading(reading, sizeof(reading));
  snprintf(resp, 1024, "{\"success\":true,\"transaction\":\"%s\",\"network\":\"eip155:%u\",\"payer\":\"%s\"}", tx, (unsigned) terms.chain_id, payer);
  char *receipt = base64(resp);
  httpd_resp_set_type(req, "application/json");
  if (receipt) httpd_resp_set_hdr(req, "PAYMENT-RESPONSE", receipt);
  err = httpd_resp_send(req, reading, n > 0 ? n : 0);
  free(receipt);
  sold++;
  printf("MER|x402 sold reading to=%.12s... value=%llu tx=%.18s... settle_ms=%ld (sold=%u refused=%u)\n", payer, (unsigned long long) auth.value, tx, settle_ms, sold, refused);
  log_heap("x402-sell");

done:
  free(header);
  free(json);
  free(settle);
  free(resp);
  return err;
}

void
x402_sell_start (void) {
  if (!x402_sell_enabled()) return;
  terms.chain_id = CONFIG_MER_X402_SELL_CHAIN_ID;
  terms.name = CONFIG_MER_X402_SELL_TOKEN_NAME;
  terms.version = CONFIG_MER_X402_SELL_TOKEN_VERSION;
  terms.price = CONFIG_MER_X402_SELL_PRICE;
  terms.max_timeout_s = 300;
  memcpy(terms.payee, kp.eth_address, 20);
  if (boat_hex_to_bytes(CONFIG_MER_X402_SELL_TOKEN, terms.token, 20) != 20) {
    printf("MER|x402 sell: bad CONFIG_MER_X402_SELL_TOKEN\n");
    return;
  }
  snprintf(requirements, sizeof(requirements), "{\"scheme\":\"exact\",\"network\":\"eip155:%u\",\"amount\":\"%u\",\"asset\":\"%s\",\"payTo\":\"%s\",\"maxTimeoutSeconds\":%u,\"extra\":{\"name\":\"%s\",\"version\":\"%s\"}}",
           (unsigned) terms.chain_id, (unsigned) terms.price, CONFIG_MER_X402_SELL_TOKEN, kp.eth_addr_hex, (unsigned) terms.max_timeout_s, terms.name, terms.version);

  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.server_port = CONFIG_MER_X402_SELL_PORT;
  config.stack_size = 8192;
  config.max_open_sockets = 3;
  httpd_handle_t server = NULL;
  if (httpd_start(&server, &config) != ESP_OK) {
    printf("MER|x402 sell: http server failed\n");
    return;
  }
  httpd_uri_t uri = {.uri = "/reading", .method = HTTP_GET, .handler = on_reading};
  httpd_register_uri_handler(server, &uri);
  printf("MER|x402 sell port=%d price=%u token=%s/%s chain=%u payTo=%s facilitator=%s\n", CONFIG_MER_X402_SELL_PORT, (unsigned) terms.price, terms.name, terms.version, (unsigned) terms.chain_id, kp.eth_addr_hex, CONFIG_MER_X402_SELL_FACILITATOR);
}
