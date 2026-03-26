# Changelog

## [1.3.0](https://github.com/EternisAI/attestation-server/compare/v1.2.0...v1.3.0) (2026-03-26)


### Features

* add endorsements.skip_validation setting for disaster recovery ([92cba6f](https://github.com/EternisAI/attestation-server/commit/92cba6fa9baa6866284f867fa693e39d6c3b74df))
* add endorsements.skip_validation setting for disaster recovery ([1a0bb9e](https://github.com/EternisAI/attestation-server/commit/1a0bb9e519e9d37645d272cfecd9ed4911203d61))
* add health check endpoints ([dc8dd79](https://github.com/EternisAI/attestation-server/commit/dc8dd79ea283575ecffc8c9738ba5c5b7cee2298))


### Bug Fixes

* only skip retrieval errors under endorsements.skip_validation ([77564f2](https://github.com/EternisAI/attestation-server/commit/77564f273c54fdc3baa4b22513b6d99c1053265f))


### Documentation

* compress CLAUDE.md from 42k to 12k chars ([6ce19a1](https://github.com/EternisAI/attestation-server/commit/6ce19a1069065a0b95b1327ec4504074173cc595))

## [1.2.0](https://github.com/EternisAI/attestation-server/compare/v1.1.0...v1.2.0) (2026-03-26)


### Features

* make private TLS certificate optional for public-cert-only deployments ([a4349b1](https://github.com/EternisAI/attestation-server/commit/a4349b180eb5d76476eb9aaa43d8031fec1520ec))
* verify dependency server TLS certificate against attestation report ([42dd053](https://github.com/EternisAI/attestation-server/commit/42dd053b0e67523e92643b27b4db6cdc79e1553b))


### Bug Fixes

* preserve handler-controlled error messages for 5xx responses ([bc3c407](https://github.com/EternisAI/attestation-server/commit/bc3c40774bd6d9ab4ed4cf0ac177635659cda029))
* return 500 instead of 503 for TLS certificate verification failures ([d2855c9](https://github.com/EternisAI/attestation-server/commit/d2855c94f39ac826d8ba78fe4c2d7947928187a2))


### Refactoring

* extract makeTestReport helper in dependency tests ([e723373](https://github.com/EternisAI/attestation-server/commit/e7233739191271f7a2f1a556c59a8b661f2847f0))


### Documentation

* document config validation rules and Nix closure stripping in CLAUDE.md ([1600ee0](https://github.com/EternisAI/attestation-server/commit/1600ee02489914f5e1ce4891b03ca77d20b43159))

## [1.1.0](https://github.com/EternisAI/attestation-server/compare/v1.0.0...v1.1.0) (2026-03-26)


### Features

* make HTTP cache default TTL configurable (http.cache.default_ttl) ([6e46691](https://github.com/EternisAI/attestation-server/commit/6e466913e1e5e51dba7528b0d116fa5747ac6b6f))


### Bug Fixes

* clamp defaultTTL to 24h cap in parseCacheTTL ([50b3025](https://github.com/EternisAI/attestation-server/commit/50b3025628bafcd3cfed3201292830327c961645))
* default bind address to 127.0.0.1 instead of 0.0.0.0 ([4ead045](https://github.com/EternisAI/attestation-server/commit/4ead0452af1f77fba3956b09615ed0aa48557d20))
* fail on invalid duration and byte-size config values ([ad7ddbf](https://github.com/EternisAI/attestation-server/commit/ad7ddbf93aa503f6b78b29b492df3661ad98e175))
* guard parseByteSize against uint64-to-int64 overflow ([97ef623](https://github.com/EternisAI/attestation-server/commit/97ef6232221afce5eb9ebb780e79dfcfe4ac1ed4))
* reject negative durations in parseDuration ([ae5e012](https://github.com/EternisAI/attestation-server/commit/ae5e0121d8322c6eb96945fe694a275cd0c6e893))
* reject zero durations for timeout and interval config values ([11b3304](https://github.com/EternisAI/attestation-server/commit/11b3304acf75867818f4bb768846738000ab97df))
* respect no-cache/no-store TTL=0 from parseCacheTTL ([8b20cae](https://github.com/EternisAI/attestation-server/commit/8b20cae9341c29af159536b0f9863a7e4435fcc8))


### Refactoring

* use dustin/go-humanize for http.cache.size parsing ([98d895b](https://github.com/EternisAI/attestation-server/commit/98d895b5289e0f953b8fb4ec2ca0f7e8c38dc3be))


### Documentation

* fix parseDuration comment to reflect actual behavior ([c601b56](https://github.com/EternisAI/attestation-server/commit/c601b56c87cc9f455617131cc835e5519d0a43cc))

## 1.0.0 (2026-03-26)


### ⚠ BREAKING CHANGES

* AttestationReportData JSON schema changed.

### Features

* add background CRL fetching for TEE endorsement key revocation checking ([6df4203](https://github.com/EternisAI/attestation-server/commit/6df4203b0e94829c3797d3bbd52c33fd519df7aa))
* add CI and release workflows with Nix-built Docker image ([9eb73b0](https://github.com/EternisAI/attestation-server/commit/9eb73b09c485beb1cb86ea00f22ccca5c6ea67c7))
* add configurable VMPL level for SEV-SNP attestation ([4de9b13](https://github.com/EternisAI/attestation-server/commit/4de9b137d55d91215ae7368ba9659fef195d92d0))
* add debug logging with duration for evidence retrieval and TPM PCR reads ([8407737](https://github.com/EternisAI/attestation-server/commit/8407737c8d56790717addcdaef90ae3530eb222e))
* add duration and cache TTL logging to HTTP fetch paths ([e098d27](https://github.com/EternisAI/attestation-server/commit/e098d27b065456e4b194924d420ddf6bbfcf9193))
* add generic TPM PCR reading via google/go-tpm ([402ea6f](https://github.com/EternisAI/attestation-server/commit/402ea6fb97cc28ded11da8d36494d55254e0b788))
* add GET /api/v1/attestation handler with Nitro NSM evidence ([ca6979f](https://github.com/EternisAI/attestation-server/commit/ca6979f089c4828062c62425b05776d7be3de694))
* add http.allow_proxy setting for ambient proxy support ([d787137](https://github.com/EternisAI/attestation-server/commit/d7871375050d09c21dd97171a8b95f8cd67c32db))
* add Intel TDX attestation via go-tdx-guest library ([40d3c30](https://github.com/EternisAI/attestation-server/commit/40d3c30d8573c44d556c2b8b919a717d04e5d04f))
* add NitroTPM attestation via raw TPM2 protocol over /dev/tpm0 ([7e025df](https://github.com/EternisAI/attestation-server/commit/7e025df86bc87f86d9e698708271f17ecc80f46f))
* add Nix flake for reproducible hermetic builds ([5972380](https://github.com/EternisAI/attestation-server/commit/5972380a5f5f7cc83f9ae05f73f7bc8fce407c20))
* add report configuration section with evidence and user_data.env settings ([024bb60](https://github.com/EternisAI/attestation-server/commit/024bb606ac78830400b8c51d74f16cef9ec8278c))
* add SEV-SNP attestation via go-sev-guest library ([8f4add5](https://github.com/EternisAI/attestation-server/commit/8f4add5383d2edece555cf16ed6d77c961943deb))
* add timestamp to report data, flatten TLS fingerprints, verify public cert ([d29ac78](https://github.com/EternisAI/attestation-server/commit/d29ac78311b7cf9b261e163a854bb374f261336b))
* add TLS certificate loading with inotify-based hot reload ([f73dea3](https://github.com/EternisAI/attestation-server/commit/f73dea34d3f80f80036e9f1b7d56e4a31542ec73))
* add transitive dependency attestation ([eeb092b](https://github.com/EternisAI/attestation-server/commit/eeb092b716800311c8d74cda7e36dccc65a9d05f))
* add UEFI Secure Boot state verification ([6a3e929](https://github.com/EternisAI/attestation-server/commit/6a3e929ec757805d8da3b6ee86090a1420be02e5))
* cache TDX collateral fetches via shared ristretto cache ([4c88029](https://github.com/EternisAI/attestation-server/commit/4c8802981a98060b8500b9402246289258186bd5))
* enforce mTLS and end-to-end encryption for dependency attestation ([5f857d7](https://github.com/EternisAI/attestation-server/commit/5f857d7cca99886f3ffcd90e61479a8045b3dcf2))
* implement initial server scaffold ([eb19b79](https://github.com/EternisAI/attestation-server/commit/eb19b79475a8650f3be75429caa843b3d09b6305))
* load build info and endorsements files on startup ([eaff8a7](https://github.com/EternisAI/attestation-server/commit/eaff8a72b3b23fbd21ccf70e9b2b3f6fadccfa40))
* replace AD-flag DNSSEC check with cryptographic chain-of-trust validation ([2310474](https://github.com/EternisAI/attestation-server/commit/231047423db51a5ae3ae1ac73131d73fb9ba3146))
* replace encoding/json with goccy/go-json for better performance ([4ef0561](https://github.com/EternisAI/attestation-server/commit/4ef05610e87dcb3e565785e0237fc6b324a8159b))
* replace report.evidence string list with boolean flags per evidence type ([82d2d35](https://github.com/EternisAI/attestation-server/commit/82d2d35bd275427dcbfd96c7676bdc0217cf273c))
* security hardening across error handling, rate limiting, trust verification, and TLS ([c1cf403](https://github.com/EternisAI/attestation-server/commit/c1cf4038e89dc993f4713544e7b84b5a59d2b09d))
* switch configuration to TOML config file with env var prefix ([b8a3818](https://github.com/EternisAI/attestation-server/commit/b8a381892eca5fb48ad9004b576680a899d400b1))
* validate endorsement documents against TEE evidence measurements ([f2d6a0a](https://github.com/EternisAI/attestation-server/commit/f2d6a0a665a68a428e00b1939c104e999a3fe456))
* validate PCR endorsement HashAlgorithm and digest lengths at parse time ([07979cb](https://github.com/EternisAI/attestation-server/commit/07979cbd44f8c52d80dc80491084af0b7e4cd3fe))
* verify cosign signatures on endorsement documents ([39e378a](https://github.com/EternisAI/attestation-server/commit/39e378a9c489f86ee9c8819153d8bfd64451d0cb))
* verify NitroTPM attestation document and decode CBOR fields ([a1ff785](https://github.com/EternisAI/attestation-server/commit/a1ff785dfd52f70c7890bca97dc66b7cf3df3988))


### Bug Fixes

* add environment variable binding for report.evidence.sevsnp_vmpl ([8c8a552](https://github.com/EternisAI/attestation-server/commit/8c8a55290d4a6a4ae3eea70dbaece8a347d3547d))
* add missing env var binding for tls.public.skip_verify ([3f170f8](https://github.com/EternisAI/attestation-server/commit/3f170f81447646a6eda1df8984d319b01851d34a))
* auto-disable TPM PCR reads when NitroNSM evidence is enabled ([4ae24dd](https://github.com/EternisAI/attestation-server/commit/4ae24ddf976fafe1d4f9756ad65b53b157ed49aa))
* clone IP string before storing as rate limiter map key ([68849d3](https://github.com/EternisAI/attestation-server/commit/68849d3c8f1da4c2ae36bd8a3a4ab2f3d6618a40))
* eliminate errgroup context cancellation race in dependency tests ([32c7508](https://github.com/EternisAI/attestation-server/commit/32c75083fafd21001c4eeb907de28b96319ea765))
* ensure attestation response data matches nonce digest bytes ([4565bc7](https://github.com/EternisAI/attestation-server/commit/4565bc772ffaf76fb01fcc2df95eb9de756b05cc))
* fetch SEV-SNP CRLs when dependencies are configured ([ebd4cb3](https://github.com/EternisAI/attestation-server/commit/ebd4cb3ab8a121b1a94585afc6e537de1d996049))
* interrupt fetch backoff and rate limit stalls on graceful shutdown ([ef114cd](https://github.com/EternisAI/attestation-server/commit/ef114cd3da833a61f4cf22066072d33295a5b599))
* log per-attempt errors during endorsement/signature fetch retries ([6293f93](https://github.com/EternisAI/attestation-server/commit/6293f939f9ebc24c7369c69c50818badcc2f8f5e))
* self-verify TDX and SEV-SNP evidence before returning from handler ([7681f68](https://github.com/EternisAI/attestation-server/commit/7681f681c48b021e0e10ed7fdf11b0cd9e4ad621))
* skip UEFI secure boot detection in Nitro Enclaves ([574990f](https://github.com/EternisAI/attestation-server/commit/574990f3b6af625a722f16a0adb08ac7e5052f49))
* use ConfigFS QuoteProvider for TDX attestation ([2796238](https://github.com/EternisAI/attestation-server/commit/279623814f95faf9d7e5423128f3a1c8dee7c1a9))
* work around go-sev-guest issues preventing SEV-SNP attestation on AWS ([8add34b](https://github.com/EternisAI/attestation-server/commit/8add34b3f44ef06ddbef922f7801b371f7253aa8))


### Miscellaneous

* add LICENSE and NOTICE ([b8fab24](https://github.com/EternisAI/attestation-server/commit/b8fab240546f59c287cf4c6dc3d93567c5ba8c9c))
* go fmt ([c19a0e1](https://github.com/EternisAI/attestation-server/commit/c19a0e1bc007eca8ec300333c3f873e01563aca8))
* initial commit ([8967da7](https://github.com/EternisAI/attestation-server/commit/8967da7a71e6d12de40ce1236db598a9d7577e0d))


### Refactoring

* classify upstream errors into distinct HTTP status codes ([2a6f694](https://github.com/EternisAI/attestation-server/commit/2a6f69423db5c331539d67ed55d734b21261e65b))
* consistent public API for TEE evidence packages ([06c68ca](https://github.com/EternisAI/attestation-server/commit/06c68ca12db3f75abc2dc1de38223e0b786a9977))
* embed Intel SGX Root CA and pass as TrustedRoots for TDX verification ([850b25a](https://github.com/EternisAI/attestation-server/commit/850b25adc32d44feed79e715ba2839d46dd62200))
* extract Nitro NSM into separate NitroNSM struct ([e067758](https://github.com/EternisAI/attestation-server/commit/e067758470cf16a282cf53994d69434f478882fe))
* extract shared HexBytes type into pkg/hexbytes ([a1dfde2](https://github.com/EternisAI/attestation-server/commit/a1dfde2320ab6efd14b8014b4098f42eacc986f9))
* extract TEE attestation code into reusable pkg/ packages ([7d45e73](https://github.com/EternisAI/attestation-server/commit/7d45e73a2f3f8ad80bae50fc62e97fe3182fa64a))
* generalize Nitro attestation verification for both NSM and TPM ([7d3b74a](https://github.com/EternisAI/attestation-server/commit/7d3b74ac8ba676f4bf151b31b1ba08967f7fa3e6))
* restructure TPM PCR data to include hash algorithm ([2b017ee](https://github.com/EternisAI/attestation-server/commit/2b017ee6afd11ef2bb8184c4fe2be5238c7e5d39))
* route early startup errors through slog JSON logger ([59ddc70](https://github.com/EternisAI/attestation-server/commit/59ddc70de0d60c2189cdaa5077371f615529ed9e))
* scope rate limiting to the attestation endpoint only ([7f10966](https://github.com/EternisAI/attestation-server/commit/7f109665a57719a5456fab66aad5fa504552923a))
* simplify PCR endorsement format and types ([1c0dfdb](https://github.com/EternisAI/attestation-server/commit/1c0dfdb07be8d40a8393fed7bbe9e349b4373e52))
* use map[int]HexBytes for TPM PCRs to match other TEE packages ([726084f](https://github.com/EternisAI/attestation-server/commit/726084f8141e8bf84342ce9ab2f70d732a4ba4c2))


### Documentation

* add comments for security implications, architectural decisions, and caveats ([34dad14](https://github.com/EternisAI/attestation-server/commit/34dad14a2b8517f40f5e6a871c9eb52f50746242))
* add doc comments to internal types and key functions ([5c696dc](https://github.com/EternisAI/attestation-server/commit/5c696dcfaa6918a7fc6e8f6403b935d9c60ebe48))
* add project documentation ([298f58b](https://github.com/EternisAI/attestation-server/commit/298f58b8a40ab34592fd8d6388ff54d4c73843e0))
* fix config section ordering in CLAUDE.md to match actual config.toml ([46b136e](https://github.com/EternisAI/attestation-server/commit/46b136eb8d530ecf590a6cc8e3e6b14954dd5b79))
* improve code comments across the codebase ([8f3e135](https://github.com/EternisAI/attestation-server/commit/8f3e135537385425dd13aa99411b5c8e061442bf))
* sync documentation with current code state ([8ab2817](https://github.com/EternisAI/attestation-server/commit/8ab28178820faa5cfb1d3028338515e3de7962cf))


### Tests

* add chained NitroTPM+SEV-SNP attestation verification test ([508f6c3](https://github.com/EternisAI/attestation-server/commit/508f6c3a4193ca17b32a47a62e754ec4fa137b8e))
* add multi-provider SEV-SNP attestation fixtures (AWS, GCP) ([891be7c](https://github.com/EternisAI/attestation-server/commit/891be7c269ab518e0fd648612d4513343817e816))
* add tests for tdxVerifyOpt, NewTimestamp, shutdownCtx, and rate limiter cleanup ([f7af71b](https://github.com/EternisAI/attestation-server/commit/f7af71b3b11c0d8ee2bd1dd22904a5151f1e3b40))
* add unit tests for all packages with real TEE attestation fixtures ([9e09ffe](https://github.com/EternisAI/attestation-server/commit/9e09ffeb7b694fccb19e5aa47199a7f980a7d9ec))
* fail on missing fixtures instead of skipping ([b2b515a](https://github.com/EternisAI/attestation-server/commit/b2b515aced2e49a27e308505613c6dcc2c51e54f))
* improve test coverage and harden endorsement validation ([c6794c7](https://github.com/EternisAI/attestation-server/commit/c6794c73a4a101b11aaeb8ee4a41dd07a8d60a80))
