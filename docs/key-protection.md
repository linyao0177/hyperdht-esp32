# Key protection

A device's Ed25519 seed is its identity: whoever reads it can be the device, sign its data and pay from its wallet. In the examples, the seed sits in NVS in plain text. Anyone holding the board can read it with `esptool.py read_flash`, and anyone who can flash it can replace the firmware with one that leaks it. This is fine for development, but not for a product.

The ESP32-C3 closes both paths in hardware. [`examples/app_template/sdkconfig.secure`](../examples/app_template/sdkconfig.secure) turns on all of it:

| Feature | What it stops | Setting |
|---|---|---|
| Secure boot v2 (RSA-3072) | Firmware not signed with your key. The ROM checks the bootloader, and the bootloader checks the app | `CONFIG_SECURE_BOOT`, `CONFIG_SECURE_BOOT_V2_ENABLED` |
| Flash encryption, release mode | Reading flash in plain text. The key is generated inside the chip and never leaves it. JTAG is disabled | `CONFIG_SECURE_FLASH_ENC_ENABLED`, `..._MODE_RELEASE` |
| NVS encryption | Reading the seed, owner and credential from the NVS partition. Its keys are kept in the encrypted `nvs_keys` partition | `CONFIG_NVS_ENCRYPTION`, `CONFIG_NVS_SEC_KEY_PROTECT_USING_FLASH_ENC` |
| Secure download mode | Reading flash or memory over the serial bootloader. Writing signed images still works | `CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE` |

The application code does not change. `nvs_flash_init()` finds and creates the NVS keys by itself, and the same `nvs_get_blob` calls read the seed.

## Irreversible

The first boot of firmware built with these settings burns eFuses: the flash encryption key, the secure boot key digest, and the bits that disable JTAG and plain download mode. eFuses cannot be cleared. From then on:

- the chip runs only firmware signed with your signing key, so losing that key leaves the device unable to take updates;
- the flash can be rewritten only with images signed with that key, and encrypted, through secure download mode or OTA;
- there is no going back to a development setup on that chip.

Try it on boards you can spare, and keep the signing key offline (an HSM or a well-protected machine), never in the repository. `.gitignore` excludes `*.pem`.

## Build

```bash
espsecure.py generate_signing_key --version 2 --scheme rsa3072 examples/app_template/secure_boot_signing_key.pem
```

```bash
cd examples/app_template && idf.py -D APP_SECURE=1 -B build-secure -D SDKCONFIG=sdkconfig.secure-build build
```

The build signs the bootloader and the app. A signed bootloader is 48 KB, so the partition table moves to 0x10000 ([`partitions_secure.csv`](../examples/app_template/partitions_secure.csv)), and an `nvs_keys` partition is added.

Flash a blank chip once with `idf.py -B build-secure flash`. After that first boot, follow ESP-IDF's guides for [secure boot v2](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/security/secure-boot-v2.html) and [flash encryption](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/security/flash-encryption.html) for every later update.

## Factory line

1. Flash the secure build. The first boot burns the eFuses, encrypts flash in place and creates the device seed in encrypted NVS.
2. Read the DID from the serial log or with `AT+ID?`, then issue and provision its credential ([credentials.md](credentials.md)).
3. Check the device as a customer would: `node tools/host/issuer.js verify <did>`.

The seed never leaves the chip, and nobody on the line handles it.

## Status

The secure configuration builds: bootloader and app signed, partition table correct, 25% bootloader headroom, app 1.06 MB with 43% of its partition free. **It has not run on a chip.** Burning the eFuses of the only test board was not done, and needs the owner's decision. Until it has run, check the first secure boot, the in-place encryption, NVS reads after encryption, and a signed OTA update on a spare board.

## What it does not cover

- **A seed copied before the secure build.** Devices that ran a development build should be given new keys, which means new DIDs.
- **Side channels and fault injection.** The C3 is not a secure element. For high-value keys, an external secure element (for example an ATECC608) holding the key would be stronger, at the cost of a C port of signing through it.
- **The key in RAM.** The running firmware has the seed in memory, as it must to sign. Firmware bugs that leak memory over the network are not covered by any of the above.
