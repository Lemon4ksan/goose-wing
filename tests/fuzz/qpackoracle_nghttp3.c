/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Lemon4ksan
 *
 * QPACK reference oracle using vendor/nghttp3 (RFC 9204, RFC 9114).
 * Usage:
 *   qpackoracle_nghttp3 decode <batch_file>
 *   qpackoracle_nghttp3 encode <batch_file> [huffman:0|1]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <nghttp3/nghttp3.h>

#define MAX_LINE 65536
#define MAX_FIELDS 1024
#define MAX_PAYLOAD (512 * 1024)

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool decode_hex_or_dash(const char *hex_str, uint8_t *dst, size_t *out_len, size_t max_len) {
    if (strcmp(hex_str, "-") == 0 || strlen(hex_str) == 0) {
        *out_len = 0;
        return true;
    }
    size_t slen = strlen(hex_str);
    if ((slen % 2) != 0) {
        return false;
    }
    size_t count = slen / 2;
    if (count > max_len) {
        return false;
    }
    for (size_t i = 0; i < count; i++) {
        int hi = hex_val(hex_str[2 * i]);
        int lo = hex_val(hex_str[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        dst[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = count;
    return true;
}

static void print_hex_or_dash(const uint8_t *src, size_t len) {
    if (len == 0) {
        printf("-");
        return;
    }
    for (size_t i = 0; i < len; i++) {
        printf("%02x", src[i]);
    }
}

typedef struct {
    uint8_t name[1024];
    size_t name_len;
    uint8_t val[8192];
    size_t val_len;
} PendingField;

static void run_decode(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "failed to open %s\n", path);
        exit(1);
    }

    const nghttp3_mem *mem = nghttp3_mem_default();
    nghttp3_qpack_decoder *dec = NULL;
    size_t max_dtable = 4096;
    size_t max_blocked = 16;
    int64_t cur_stream_id = 0;

    nghttp3_qpack_decoder_new(&dec, max_dtable, max_blocked, mem);
    nghttp3_qpack_decoder_set_max_dtable_capacity(dec, max_dtable);

    char line[MAX_LINE];
    uint8_t raw_buf[MAX_PAYLOAD];

    while (fgets(line, sizeof(line), f)) {
        // Strip trailing newline / CR
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\r' || line[len - 1] == '\n')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;

        char *cmd = line;
        char *arg = strchr(line, ' ');
        if (arg) {
            *arg++ = '\0';
            while (*arg == ' ') arg++;
        }

        if (strcmp(cmd, "conn") == 0) {
            if (arg) {
                size_t cap = 4096;
                size_t blk = 16;
                if (sscanf(arg, "%zu %zu", &cap, &blk) >= 1) {
                    max_dtable = cap;
                    max_blocked = blk;
                }
            }
            if (dec) nghttp3_qpack_decoder_del(dec);
            nghttp3_qpack_decoder_new(&dec, max_dtable, max_blocked, mem);
            nghttp3_qpack_decoder_set_max_dtable_capacity(dec, max_dtable);
            continue;
        }

        if (strcmp(cmd, "stream") == 0) {
            if (arg) {
                cur_stream_id = (int64_t)strtoll(arg, NULL, 10);
            }
            continue;
        }

        if (strcmp(cmd, "encoder_inst") == 0) {
            if (!arg) continue;
            size_t inst_len = 0;
            if (!decode_hex_or_dash(arg, raw_buf, &inst_len, sizeof(raw_buf))) {
                printf("error\n");
                continue;
            }
            if (inst_len > 0) {
                int64_t nread = nghttp3_qpack_decoder_read_encoder(dec, raw_buf, inst_len);
                if (nread < 0) {
                    printf("error\n");
                    continue;
                }
            }
            continue;
        }

        if (strcmp(cmd, "block") == 0) {
            if (!arg) {
                printf("error\n");
                continue;
            }
            size_t blk_len = 0;
            if (!decode_hex_or_dash(arg, raw_buf, &blk_len, sizeof(raw_buf))) {
                printf("error\n");
                continue;
            }

            nghttp3_qpack_stream_context *sctx = NULL;
            int srv = nghttp3_qpack_stream_context_new(&sctx, cur_stream_id, mem);
            if (srv != 0) {
                printf("error\n");
                continue;
            }

            uint8_t *pos = raw_buf;
            size_t left = blk_len;
            bool ok = true;
            bool blocked = false;

            typedef struct {
                char *name;
                size_t name_len;
                char *val;
                size_t val_len;
            } Emitted;

            Emitted emitted[MAX_FIELDS];
            size_t emitted_count = 0;

            for (;;) {
                nghttp3_qpack_nv nv;
                uint8_t flags = 0;
                int64_t nread = nghttp3_qpack_decoder_read_request(
                    dec, sctx, &nv, &flags, pos, left, 1);
                if (nread < 0) {
                    ok = false;
                    break;
                }
                pos += nread;
                left -= nread;

                if (flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
                    nghttp3_vec name_vec = nghttp3_rcbuf_get_buf(nv.name);
                    nghttp3_vec val_vec = nghttp3_rcbuf_get_buf(nv.value);
                    if (emitted_count < MAX_FIELDS) {
                        emitted[emitted_count].name = malloc(name_vec.len + 1);
                        memcpy(emitted[emitted_count].name, name_vec.base, name_vec.len);
                        emitted[emitted_count].name[name_vec.len] = '\0';
                        emitted[emitted_count].name_len = name_vec.len;

                        emitted[emitted_count].val = malloc(val_vec.len + 1);
                        memcpy(emitted[emitted_count].val, val_vec.base, val_vec.len);
                        emitted[emitted_count].val[val_vec.len] = '\0';
                        emitted[emitted_count].val_len = val_vec.len;
                        emitted_count++;
                    }
                    nghttp3_rcbuf_decref(nv.name);
                    nghttp3_rcbuf_decref(nv.value);
                }

                if (flags & NGHTTP3_QPACK_DECODE_FLAG_BLOCKED) {
                    blocked = true;
                    ok = false;
                    break;
                }

                if (flags & NGHTTP3_QPACK_DECODE_FLAG_FINAL) {
                    break;
                }
            }

            nghttp3_qpack_stream_context_del(sctx);

            if (ok && !blocked) {
                printf("ok\n");
                for (size_t i = 0; i < emitted_count; i++) {
                    printf("field ");
                    print_hex_or_dash((const uint8_t *)emitted[i].name, emitted[i].name_len);
                    printf(" ");
                    print_hex_or_dash((const uint8_t *)emitted[i].val, emitted[i].val_len);
                    printf("\n");
                    free(emitted[i].name);
                    free(emitted[i].val);
                }
            } else {
                for (size_t i = 0; i < emitted_count; i++) {
                    free(emitted[i].name);
                    free(emitted[i].val);
                }
                printf("error\n");
            }
        }
    }

    if (dec) nghttp3_qpack_decoder_del(dec);
    fclose(f);
}

static void run_encode(const char *path, bool use_huffman) {
    (void)use_huffman;
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "failed to open %s\n", path);
        exit(1);
    }

    const nghttp3_mem *mem = nghttp3_mem_default();
    nghttp3_qpack_encoder *enc = NULL;
    size_t max_dtable = 4096;
    size_t max_blocked = 16;
    int64_t cur_stream_id = 0;

    nghttp3_qpack_encoder_new(&enc, max_dtable, mem);
    nghttp3_qpack_encoder_set_max_dtable_capacity(enc, max_dtable);
    nghttp3_qpack_encoder_set_max_blocked_streams(enc, max_blocked);

    PendingField *pending = malloc(sizeof(PendingField) * MAX_FIELDS);
    if (!pending) {
        fprintf(stderr, "malloc failed\n");
        exit(1);
    }
    size_t pending_count = 0;

    char line[MAX_LINE];
    uint8_t raw_n[1024];
    uint8_t raw_v[8192];

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\r' || line[len - 1] == '\n')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;

        if (strcmp(line, "endblock") == 0) {
            nghttp3_nv nva[MAX_FIELDS];
            for (size_t i = 0; i < pending_count; i++) {
                nva[i].name = pending[i].name;
                nva[i].namelen = pending[i].name_len;
                nva[i].value = pending[i].val;
                nva[i].valuelen = pending[i].val_len;
                nva[i].flags = NGHTTP3_NV_FLAG_NONE;
            }

            nghttp3_buf pbuf, rbuf, ebuf;
            nghttp3_buf_init(&pbuf);
            nghttp3_buf_init(&rbuf);
            nghttp3_buf_init(&ebuf);

            int rv = nghttp3_qpack_encoder_encode(enc, &pbuf, &rbuf, &ebuf, cur_stream_id, nva, pending_count);
            if (rv != 0) {
                printf("error\n");
            } else {
                size_t elen = nghttp3_buf_len(&ebuf);
                if (elen > 0) {
                    printf("encoder_inst ");
                    print_hex_or_dash(ebuf.pos, elen);
                    printf("\n");
                }
                size_t plen = nghttp3_buf_len(&pbuf);
                size_t rlen = nghttp3_buf_len(&rbuf);
                printf("block ");
                for (size_t i = 0; i < plen; i++) printf("%02x", pbuf.pos[i]);
                for (size_t i = 0; i < rlen; i++) printf("%02x", rbuf.pos[i]);
                printf("\n");
                nghttp3_qpack_encoder_ack_everything(enc);
            }

            nghttp3_buf_free(&pbuf, mem);
            nghttp3_buf_free(&rbuf, mem);
            nghttp3_buf_free(&ebuf, mem);
            pending_count = 0;
            continue;
        }

        char *cmd = line;
        char *arg = strchr(line, ' ');
        if (arg) {
            *arg++ = '\0';
            while (*arg == ' ') arg++;
        }

        if (strcmp(cmd, "conn") == 0) {
            if (arg) {
                size_t cap = 4096;
                size_t blk = 16;
                if (sscanf(arg, "%zu %zu", &cap, &blk) >= 1) {
                    max_dtable = cap;
                    max_blocked = blk;
                }
            }
            if (enc) nghttp3_qpack_encoder_del(enc);
            nghttp3_qpack_encoder_new(&enc, max_dtable, mem);
            nghttp3_qpack_encoder_set_max_dtable_capacity(enc, max_dtable);
            nghttp3_qpack_encoder_set_max_blocked_streams(enc, max_blocked);
            pending_count = 0;
            printf("conn %zu %zu\n", max_dtable, max_blocked);
            continue;
        }

        if (strcmp(cmd, "stream") == 0) {
            if (arg) {
                cur_stream_id = (int64_t)strtoll(arg, NULL, 10);
            }
            printf("stream %lld\n", (long long)cur_stream_id);
            continue;
        }

        if (strcmp(cmd, "field") == 0) {
            if (!arg) continue;
            char *sp = strchr(arg, ' ');
            if (!sp) continue;
            *sp++ = '\0';
            while (*sp == ' ') sp++;

            size_t nlen = 0, vlen = 0;
            if (decode_hex_or_dash(arg, raw_n, &nlen, sizeof(raw_n)) &&
                decode_hex_or_dash(sp, raw_v, &vlen, sizeof(raw_v))) {
                if (pending_count < MAX_FIELDS) {
                    memcpy(pending[pending_count].name, raw_n, nlen);
                    pending[pending_count].name_len = nlen;
                    memcpy(pending[pending_count].val, raw_v, vlen);
                    pending[pending_count].val_len = vlen;
                    pending_count++;
                }
            }
            continue;
        }
    }

    if (enc) nghttp3_qpack_encoder_del(enc);
    free(pending);
    fclose(f);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: qpackoracle_nghttp3 <decode|encode> <batch_file> [huffman:0|1]\n");
        return 1;
    }

    if (strcmp(argv[1], "decode") == 0) {
        run_decode(argv[2]);
        return 0;
    }

    if (strcmp(argv[1], "encode") == 0) {
        bool use_huffman = true;
        if (argc >= 4 && strcmp(argv[3], "0") == 0) {
            use_huffman = false;
        }
        run_encode(argv[2], use_huffman);
        return 0;
    }

    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 1;
}
