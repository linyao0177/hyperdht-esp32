idf_component_register(
  SRCS "main.c" "anchor.c" "signer.c" "solana.c" "x402.c" "x402_check.c" "x402_sell.c"
  REQUIRES hdht hdht_ota boat-mer esp_http_server nvs_flash esp_netif esp_event esp_timer protocol_examples_common
)
