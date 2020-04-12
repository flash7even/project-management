from random import randint


def find_document_id(document_name, pref_len, suf_len):
    document_name = "".join(document_name.split())
    document_name = document_name[0:pref_len]
    suffix_name = str(randint(100000, 999999))
    if suf_len == 4:
        suffix_name = str(randint(1000, 9999))
    return document_name + '_' + suffix_name
