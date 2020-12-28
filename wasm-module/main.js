var element = document.getElementById('output');
var wally_example = function() {
    element.value = "wally_init ... " + ccall("wally_init", 'number', ['number'], [0]);

    var entropy_ctx = new Uint8Array(32); // WALLY_SECP_RANDOMIZE_LEN
    window.crypto.getRandomValues(entropy_ctx);

    element.value = element.value + "\nwally_secp_randomize ... " + ccall("wally_secp_randomize", 'number', ['array', 'number'], [entropy_ctx, entropy_ctx.length]);

    var entropy_bip39 = new Uint8Array(40); // BIP39_ENTROPY_LEN_320
    window.crypto.getRandomValues(entropy_bip39);
    var mnemonic_ptr = Module._malloc(32);

    element.value = element.value + "\nbip39_mnemonic_from_bytes ... " + ccall('bip39_mnemonic_from_bytes', 'number', ['number', 'array', 'number', 'number'], [null, entropy_bip39, entropy_bip39.length, mnemonic_ptr]);
    element.value = element.value + "\n\t" + UTF8ToString(getValue(mnemonic_ptr, '*'));
    element.value = element.value + "\nwally_free_string ... " + ccall('wally_free_string', 'number', ['number'], [mnemonic_ptr]);
    Module._free(mnemonic_ptr);
}
var Module = {
preRun: [],
postRun: [wally_example],
};
