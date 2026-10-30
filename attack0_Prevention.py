MAX_SKIP = 100   # 1. Enforce strict upper bound on message gap

def ratchet_decrypt(st, header, ct):
    # 2. Reject immediately if gap is too large (prevents CPU exhaustion)
    if (header["n"] - st.Nr) > MAX_SKIP or (header["pn"] - st.PN) > MAX_SKIP:
        raise Error("Too many skipped messages — potential DoS attack")

    # 3. Derive keys tentatively into a temporary list (do not touch permanent state yet)
    temp_skipped = []
    ck = st.CKr
    nr = st.Nr
    while nr < header["n"]:
        mk, ck = kdf_ck(ck)
        temp_skipped.append(((st.DHr, nr), mk))
        nr += 1

    target_mk, ck = kdf_ck(ck)

    # 4. Authenticate & Decrypt FIRST
    plaintext = aead_decrypt(target_mk, ct, st.AD + serialize(header))

    # 5. Commit state ONLY if decrypt succeeded (prevents memory exhaustion)
    st.CKr = ck
    st.Nr = nr + 1
    for key_id, mk in temp_skipped:
        st.skipped[key_id] = mk

    return plaintext

# Why this fixes both flaws in 2 steps:
# CPU protected: header["n"] - st.Nr > MAX_SKIP aborts in 𝑂(1) time before doing any hash loops.
# Memory protected: If a message is tampered with, aead_decrypt fails and temp_skipped is discarded without polluting Bob's persistent memory.