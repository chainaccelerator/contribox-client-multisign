FROM debian:buster

ARG LIBWALLY_CORE_VERSION

RUN apt-get update && apt-get install -yqq git \
    uncrustify \
    python3-distutils-extra \
    python3-dev \
    build-essential \
    libffi-dev \
    autoconf \
    libtool \
    pkg-config \
    lib32z1 \
    unzip \
    curl \
    apt-transport-https

RUN git clone https://github.com/emscripten-core/emsdk.git /src/emsdk

WORKDIR /src/emsdk
RUN ./emsdk install latest && ./emsdk activate latest

RUN git clone https://github.com/ElementsProject/libwally-core.git -b release_$LIBWALLY_CORE_VERSION /src/contribox/libwally
WORKDIR /src/contribox/libwally
RUN git submodule init && \
    git submodule sync --recursive && \
    git submodule update --init --recursive

ARG PYTHON_VERSION=3
ENV SOURCE_EMSDK='. /src/emsdk/emsdk_env.sh'
RUN ./tools/cleanup.sh && ./tools/autogen.sh
SHELL [ "/bin/bash", "-c" ]
ARG CFLAGS="-fno-stack-protector"
RUN ${SOURCE_EMSDK} && emconfigure ./configure \
    --build=$HOST_OS \
    ac_cv_c_bigendian=no \
    --disable-swig-python \
    --disable-swig-java \
    --enable-elements \
    --disable-ecmult-static-precomputation \
    --disable-tests \
    --enable-export-all \
    --disable-shared
RUN ${SOURCE_EMSDK} && emmake make -j$(nproc)
ADD wasm-module/ /src/contribox
WORKDIR /src/contribox
RUN ./tools/autogen.sh
RUN ${SOURCE_EMSDK} && emconfigure ./configure 
ARG EXTRA_EXPORTED_RUNTIME_METHODS="['getValue', 'UTF8ToString', 'ccall', 'cwrap']"
ARG EXPORTED_FUNCTIONS="['_malloc','_free','_wally_init','_wally_cleanup','_wally_bzero','_wally_free_string','_wally_secp_randomize','_wally_hex_from_bytes','_wally_hex_to_bytes','_wally_base58_from_bytes','_wally_base58_to_bytes','_wally_base58_get_length','_wally_get_operations','_wally_set_operations','_wally_is_elements_build','_wally_scrypt','_wally_aes','_wally_aes_cbc','_wally_sha256','_wally_sha256_midstate','_wally_sha256d','_wally_sha512','_wally_hash160','_wally_hmac_sha256','_wally_hmac_sha512','_wally_pbkdf2_hmac_sha256','_wally_pbkdf2_hmac_sha512','_wally_ec_private_key_verify','_wally_ec_public_key_verify','_wally_ec_public_key_from_private_key','_wally_ec_public_key_decompress','_wally_ec_public_key_negate','_wally_ec_sig_from_bytes','_wally_ec_sig_normalize','_wally_ec_sig_to_der','_wally_ec_sig_from_der','_wally_ec_sig_verify','_wally_ec_sig_to_public_key','_wally_format_bitcoin_message','_wally_ecdh','_wally_addr_segwit_from_bytes','_wally_addr_segwit_to_bytes','_wally_address_to_scriptpubkey','_wally_scriptpubkey_to_address','_wally_wif_from_bytes','_wally_wif_to_bytes','_wally_wif_is_uncompressed','_wally_wif_to_public_key','_wally_bip32_key_to_address','_wally_bip32_key_to_addr_segwit','_wally_wif_to_address','_bip32_key_free','_bip32_key_init','_bip32_key_init_alloc','_bip32_key_from_seed','_bip32_key_from_seed_alloc','_bip32_key_serialize','_bip32_key_unserialize','_bip32_key_unserialize_alloc','_bip32_key_from_parent','_bip32_key_from_parent_alloc','_bip32_key_from_parent_path','_bip32_key_from_parent_path_alloc','_bip32_key_to_base58','_bip32_key_from_base58','_bip32_key_from_base58_alloc','_bip32_key_strip_private_key','_bip32_key_get_fingerprint','_bip38_raw_from_private_key','_bip38_from_private_key','_bip38_raw_to_private_key','_bip38_to_private_key','_bip38_raw_get_flags','_bip38_get_flags','_bip39_get_languages','_bip39_get_wordlist','_bip39_get_word','_bip39_mnemonic_from_bytes','_bip39_mnemonic_to_bytes','_bip39_mnemonic_validate','_bip39_mnemonic_to_seed','_wally_scriptpubkey_get_type','_wally_scriptpubkey_p2pkh_from_bytes','_wally_scriptsig_p2pkh_from_sig','_wally_witness_p2wpkh_from_sig','_wally_scriptsig_p2pkh_from_der','_wally_witness_p2wpkh_from_der','_wally_scriptpubkey_op_return_from_bytes','_wally_scriptpubkey_p2sh_from_bytes','_wally_scriptpubkey_multisig_from_bytes','_wally_scriptsig_multisig_from_bytes','_wally_witness_multisig_from_bytes','_wally_scriptpubkey_csv_2of2_then_1_from_bytes','_wally_scriptpubkey_csv_2of2_then_1_from_bytes_opt','_wally_scriptpubkey_csv_2of3_then_2_from_bytes','_wally_script_push_from_bytes','_wally_varint_get_length','_wally_varint_to_bytes','_wally_varbuff_get_length','_wally_varbuff_to_bytes','_wally_witness_program_from_bytes','_wally_map_init_alloc','_wally_map_free','_wally_map_find','_wally_map_add','_wally_map_add_keypath_item','_wally_map_sort','_wally_psbt_input_is_finalized','_wally_psbt_input_set_utxo','_wally_psbt_input_set_witness_utxo','_wally_psbt_input_set_redeem_script','_wally_psbt_input_set_witness_script','_wally_psbt_input_set_final_scriptsig','_wally_psbt_input_set_final_witness','_wally_psbt_input_set_keypaths','_wally_psbt_input_find_keypath','_wally_psbt_input_add_keypath_item','_wally_psbt_input_set_signatures','_wally_psbt_input_find_signature','_wally_psbt_input_add_signature','_wally_psbt_input_set_unknowns','_wally_psbt_input_find_unknown','_wally_psbt_input_set_sighash','_wally_psbt_output_set_redeem_script','_wally_psbt_output_set_witness_script','_wally_psbt_output_set_keypaths','_wally_psbt_output_find_keypath','_wally_psbt_output_add_keypath_item','_wally_psbt_output_set_unknowns','_wally_psbt_output_find_unknown','_wally_psbt_init_alloc','_wally_psbt_free','_wally_psbt_is_finalized','_wally_psbt_set_global_tx','_wally_psbt_add_input_at','_wally_psbt_remove_input','_wally_psbt_add_output_at','_wally_psbt_remove_output','_wally_psbt_from_bytes','_wally_psbt_get_length','_wally_psbt_to_bytes','_wally_psbt_from_base64','_wally_psbt_to_base64','_wally_psbt_combine','_wally_psbt_clone_alloc','_wally_psbt_sign','_wally_psbt_finalize','_wally_psbt_extract','_wally_psbt_is_elements','_wally_symmetric_key_from_seed','_wally_symmetric_key_from_parent','_wally_tx_witness_stack_init_alloc','_wally_tx_witness_stack_clone_alloc','_wally_tx_witness_stack_add','_wally_tx_witness_stack_add_dummy','_wally_tx_witness_stack_set','_wally_tx_witness_stack_set_dummy','_wally_tx_witness_stack_free','_wally_tx_input_init_alloc','_wally_tx_input_free','_wally_tx_output_init','_wally_tx_output_init_alloc','_wally_tx_output_clone_alloc','_wally_tx_output_clone','_wally_tx_output_free','_wally_tx_init_alloc','_wally_tx_clone_alloc','_wally_tx_add_input','_wally_tx_add_input_at','_wally_tx_add_raw_input','_wally_tx_add_raw_input_at','_wally_tx_remove_input','_wally_tx_set_input_script','_wally_tx_set_input_witness','_wally_tx_add_output','_wally_tx_add_output_at','_wally_tx_add_raw_output','_wally_tx_add_raw_output_at','_wally_tx_remove_output','_wally_tx_get_witness_count','_wally_tx_free','_wally_tx_get_txid','_wally_tx_get_length','_wally_tx_from_bytes','_wally_tx_from_hex','_wally_tx_to_bytes','_wally_tx_to_hex','_wally_tx_get_weight','_wally_tx_get_vsize','_wally_tx_vsize_from_weight','_wally_tx_get_total_output_satoshi','_wally_tx_get_btc_signature_hash','_wally_tx_get_signature_hash','_wally_tx_is_coinbase']"
RUN ${SOURCE_EMSDK} && emcc \
    -s "EXTRA_EXPORTED_RUNTIME_METHODS=$EXTRA_EXPORTED_RUNTIME_METHODS" \
    -s "EXPORTED_FUNCTIONS=$EXPORTED_FUNCTIONS" \
    src/contribox.c \
    -Llibwally/src/.libs -lwallycore \
    -Llibwally/src/secp256k1/.libs -lsecp256k1 \
    -o contribox.html 
ENTRYPOINT [ "python3", "-m", "http.server" ]
