/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "packetcrypt/Validate.h"
#include "packetcrypt/PacketCrypt.h"
#include "Buf.h"
#include "Hash.h"
#include "Time.h"
#include "FilePath.h"
#include "WorkQueue.h"
#include "FileUtil.h"
#include "ContentMerkle.h"
#include "Util.h"
#include "config.h"

#include "sodium/core.h"
#include "sodium/randombytes.h"

#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>

// The initial capacity of the deduplication table, 8 times this number
// times 2 to the power of STATE_OUTPUT_BITS will be allocated at the start
// but if more is needed, it will be realloc'd
#define DEDUPE_INITIAL_CAP (1024*16)

// Maximum number of incoming announcements to process in one shot.
// This is only a performance affecting number as a single file can
// have as many announcements as you want, they will just be read
// one block at a time.
#define IN_ANN_CAP 256

// Number of announcements to group before outputting a file, 1024 anns will make
// the files coming from checkanns be 1MB each.
#define OUT_ANN_CAP 1024

// Every WRITE_EVERY_SECONDS seconds, we will output a (potentially very small)
// file, even if the chain is not moving and announcements are coming in slowly.
#define WRITE_EVERY_SECONDS 60

// Number of previous blocks that we will accept announcements for
// is 2 to the power of STATE_OUTPUT_BITS
// Make sure this aligns with AnnHandler.js
#define STATE_OUTPUT_BITS 2


#define DEBUGF0(format) \
    fprintf(stderr, "checkanns: " format)

#define DEBUGF(format, ...) \
    fprintf(stderr, "checkanns: " format, __VA_ARGS__)

static int usage() {
    fprintf(stderr, "Usage: ./checkanns <indir> <outdir> <anndir> <tmpdir> <paylogdir>\n"
        "    <indir>           # a dir which will be scanned for incoming ann files\n"
        "    <outdir>          # a dir where result files will be placed\n"
        "    <anndir>          # a dir where verified announcements will be placed\n"
        "    <tempdir>         # a dir which will be used for creating result files\n"
        "    <paylogdir>       # a dir to put logs of who should be paid for announcements\n"
        "\n"
        "    See https://github.com/cjdelisle/PacketCrypt/blob/master/docs/checkanns.md\n"
        "    for more information\n");
    return 100;
}

typedef struct Config_s {
    uint32_t version;

    // Accept only this version of announcements
    uint8_t annVersion;

    // 0-indexed number of this handler
    uint8_t handlerNum;

    // Number of ann handlers
    uint8_t handlerCount;

    // x out of 256 chance of skipping the verification
    uint8_t skipCheckChance;

    // This token is checked against the command line argument
    // it is present in case the handler allows direct http posts
    // to the indir, since otherwise anyone could update the conf.
    uint64_t confToken;

    // Refuse any ann signed with a different key, consider
    // anns unsigned if they don't bear any signature at all
    Buf32_t signingKey;

    // Hash of the parent block to expect for anns at this height
    Buf32_t parentBlockHash;

    // Minimum amount of work that is acceptable for anns
    uint32_t minWork;

    // Height which must be used
    uint32_t parentBlockHeight;
} Config_t;
#define Config_SZ (4+1+1+1+1+8+32+32+4+4)
_Static_assert(sizeof(Config_t) == Config_SZ, "");

static void checkedWrite(const char* filename, int fileno, void* ptr, int len) {
    ssize_t written = write(fileno, ptr, len);
    if (written < 0) {
        DEBUGF("Unable to write to file [%s] [%s]\n", filename, strerror(errno));
    } else if (written < len) {
        DEBUGF("Short write to file [%s] [%d] bytes of [%d]\n",
            filename, (int)written, len);
    } else {
        return;
    }
    assert(0);
}

typedef struct Result_s {
    // The minimum amount of work which was practically done in this submission
    uint32_t minWork;

    // The amount of accepted anns
    uint32_t accepted;

    // Number of duplicates
    uint32_t duplicates;

    // Number of invalids
    uint32_t invalid;

    // 1 if the file is truncated
    uint32_t runt;

    // Number of internal errors while processing
    uint32_t internalError;

    // Number of anns which are not signed
    uint32_t unsignedCount;
} Result_t;

typedef struct Dedup_s {
    // Number of entries in dedupTable
    int dedupTableLen;

    // Number of entries which dedupTable can hold before it needs to be realloc()'d
    int dedupTableCap;

    // If true then the table should be read from dedupTableCap-1 backward
    bool endAligned;

    // Make 32 and 64 bit machines use same layout
    int _pad;

    // The dedup table
    uint64_t entries[];
} Dedup_t;
#define Dedup_SIZE(entries) (sizeof(Dedup_t) + ((entries) * sizeof(uint64_t)))
_Static_assert(Dedup_SIZE(0) == 16, "");
_Static_assert(Dedup_SIZE(1) == 16 + sizeof(uint64_t), "");

typedef struct StateAndOutput_s {
    Config_t conf;

    // Number of elements in dedupsOut and out (they are appended in lockstep)
    int outCount;

    // Time when the last anns file was written (or when the daemon was started)
    uint64_t timeOfLastWrite;

    PacketCrypt_Announce_t out[OUT_ANN_CAP];
} StateAndOutput_t;

typedef struct DedupEntry_s {
    uint64_t hash;
    uint32_t annNum;
} DedupEntry_t;

typedef struct LocalWorker_s {
    // Read from the incoming announcement file, if the file is more than IN_ANN_CAP
    // then it is processed in chunks but the first AnnPost_HEADER_SZ bytes of the AnnPost
    // is always from the first chunk of the file.
    PacketCrypt_Announce_t annsIn[IN_ANN_CAP];

    // Dedup entries created from inBuf
    DedupEntry_t dedupsIn[IN_ANN_CAP];

    // Used to decide whether a full check is done on every announcement or not.
    uint32_t random;

    FilePath_t* inFile;

    // The report back to the submitter of the announcement(s)
    FilePath_t outFile;

    // This is a file in the temp dir, it's used to write a file then copy it after.
    // its name can change at any time so it must be set just before opening it.
    FilePath_t tmpFile;

    // This is a file which stores a batch of announcement headers for downloading by block miners.
    FilePath_t annFile;

    // This is the SAO which we are currently writing to disk, we do a switcheroo between
    // this and the active SAO so that we will not make a filesystem write call while holding
    // the global lock.
    StateAndOutput_t* backupSao;

    // Used for validation
    PacketCrypt_ValidateCtx_t vctx;
} LocalWorker_t;

static void mkDedupes(DedupEntry_t* dedupsOut, const PacketCrypt_Announce_t* annsIn, int annCount) {
    for (int i = 0; i < annCount; i++) {
        Buf32_t b;
        Hash_COMPRESS32_OBJ(&b, &annsIn[i]);
        dedupsOut[i].hash = b.longs[0];
        dedupsOut[i].annNum = i;
    }
}

typedef struct ParseNameResult_s {
    int32_t softver;
    int32_t parentBlockHeight;
    uint8_t payTo[64];
} ParseNameResult_t;

const bool SUPPORT_V1 = true;

// This is a little bit tricky.
// Soft version 1 changes the rule from splitting by hash to splitting by soft nonce
// which allows the miners to send more anns to each handler.
//
// However, the soft version is not committed in the ann itself so someone could submit
// an ann to different handlers claiming versions 1 and 2 and get paid twice.
// To allow both version 1 and version 2 at the same time without opening up the chance
// of this happening, we use a hack. We reject any v1 announcements where the content/hash
// field is non-zero and reject any v2 anns where it is.
//
// If v1 is not supported then this rule is removed.
//
static bool isHashNumOk(
    const ParseNameResult_t* pnr,
    const PacketCrypt_Announce_t* ann,
    uint64_t dedup,
    const Config_t* conf)
{
    if (SUPPORT_V1) {
        if (pnr->softver < 2) {
            return Buf_IS_ZERO(ann->hdr.contentHash) && (dedup % conf->handlerCount) == conf->handlerNum;
        } else if (Buf_IS_ZERO(ann->hdr.contentHash)) {
            return false;
        }
    }
    return (ann->hdr.hardNonce % conf->handlerCount) == conf->handlerNum;
}

// This marks entries in dedupsIn to be start = 0 in order to make them invalid
static const char* validateAnns(
    LocalWorker_t* lw,
    int annCount,
    Result_t* res,
    const Config_t* conf,
    const ParseNameResult_t* pnr)
{
    for (int i = 0; i < annCount; i++) {
        bool isUnsigned = Buf_IS_ZERO(lw->annsIn[i].hdr.signingKey);
        if (!isUnsigned && Buf_OBJCMP(&conf->signingKey, &lw->annsIn[i].hdr.signingKey)) {
            // wrong signing key (probably a race condition in the miner mixing different anns)
            return "wrong signing key";
        } else if (conf->parentBlockHeight != lw->annsIn[i].hdr.parentBlockHeight) {
            // wrong parent block height
            return "mixed parent block";
        } else if (conf->minWork < lw->annsIn[i].hdr.workBits) {
            return "not enough work";
        } else if (lw->dedupsIn[i].hash == 0 || lw->dedupsIn[i].hash == UINT64_MAX) {
            // duplicate of the 0 hash or the pad
            return "zero or fff hash";
        } else if (isHashNumOk(pnr, &lw->annsIn[i], lw->dedupsIn[i].hash, conf)) {
            // intended for a different validator node
            return "submit elsewhere";
        } else if (lw->annsIn[i].hdr.version != conf->annVersion) {
            // wrong version
            return "wrong ann version";
        } else if (((lw->dedupsIn[i].hash ^ lw->random) & 0xff) < conf->skipCheckChance) {
            // skip the validation check
            // fallthrough
        } else if (Validate_checkAnn(NULL, &lw->annsIn[i], conf->parentBlockHash.bytes, &lw->vctx)) {
            // doesn't check out
            return "Validate_checkAnn";
        }
        res->unsignedCount += isUnsigned;
        if (res->minWork < lw->annsIn[i].hdr.workBits) {
            res->minWork = lw->annsIn[i].hdr.workBits;
        }
    }
    return NULL;
}

static void writeAnns(LocalWorker_t* lw, int annFileNo, StateAndOutput_t* anns) {

    if (anns->outCount == 0) { return; }

    snprintf(lw->annFile.name, FilePath_NAME_SZ, "anns_%u_%u_%d.bin",
        anns->conf.parentBlockHeight, anns->conf.handlerNum, annFileNo);
    strcpy(lw->tmpFile.name, lw->annFile.name);
    int annFileno = open(lw->tmpFile.path, O_EXCL | O_CREAT | O_WRONLY, 0666);
    if (annFileno < 0) {
        DEBUGF("Unable to open ann output temp file [%s] [%s]\n",
            lw->tmpFile.path, strerror(errno));
        assert(0);
    }
    DEBUGF("Writing ann file [%s]\n", lw->tmpFile.name);

    checkedWrite(lw->tmpFile.path, annFileno, anns->out,
        anns->outCount * sizeof(anns->out[0]));
    close(annFileno);
    if (rename(lw->tmpFile.path, lw->annFile.path)) {
        DEBUGF("error renaming temp file [%s] to ann file [%s] [%s]\n",
            lw->tmpFile.path, lw->annFile.path, strerror(errno));
        assert(0);
    }
}


/// locks and such happen below here

typedef struct Output_s {
    StateAndOutput_t* stateAndOutput;
    Dedup_t* dedup;
    pthread_mutex_t lock;
} Output_t;

#define MS_BETWEEN_CLEANUP 60000

typedef struct Global_s {
    // Number which will be used in the name of the next ann file that is output
    // Incremented by everyone.
    _Atomic int nextAnnFileNo;

    // Time of last cleanup as units of MS_BETWEEN_CLEANUP since the epoch
    _Atomic int lastCleanupNum;

    // Read by workers, written only once by master
    int paylogFileNo;

    WorkQueue_t* q;

    // Any config update must contain the same token
    uint64_t confToken;

    Output_t output[1<<STATE_OUTPUT_BITS];
} Global_t;

typedef struct Worker_s {
    Global_t* g;
    LocalWorker_t lw;
} Worker_t;

#define OUTPUT(g, parentBlockHeight) \
    (&(g)->output[(parentBlockHeight) & ((1<<STATE_OUTPUT_BITS)-1)])

// must be called with the output lock held
static void tryWriteAnnsCritical(Worker_t* w, Output_t* output, const Config_t* conf) {
    // If we don't manage a write, it's because there was nothing to write.
    // in any case, we will update the time so as to avoid busy-looping on
    // attempts to write nothing.
    StateAndOutput_t* current = output->stateAndOutput;
    if (!current->outCount) {
        current->timeOfLastWrite = Time_nowMilliseconds() / 1000;
        return;
    }

    StateAndOutput_t* next = w->lw.backupSao;
    w->lw.backupSao = current;
    output->stateAndOutput = next;
    if (conf) {
        Buf_OBJCPY(&next->conf, conf);
    } else {
        Buf_OBJCPY(&next->conf, &current->conf);
    }

    next->outCount = 0;
    next->timeOfLastWrite = Time_nowMilliseconds() / 1000;

    int afn = w->g->nextAnnFileNo++;
    assert(!pthread_mutex_unlock(&output->lock));
    writeAnns(&w->lw, afn, current);
    assert(!pthread_mutex_lock(&output->lock));
}

static Dedup_t* dedupChkRealloc(Dedup_t* dedup, int inCount) {
    int cap = dedup->dedupTableCap;
    if (dedup->dedupTableLen + inCount <= cap) {
        return dedup;
    }
    while (dedup->dedupTableLen + inCount > cap) {
        cap *= 2;
    }
    if (dedup->endAligned) {
        // The dedup is reversed then we'll flip it forward before reallocaing
        memmove(
            dedup->entries,
            &dedup->entries[dedup->dedupTableCap - dedup->dedupTableLen],
            dedup->dedupTableLen * sizeof(*dedup->entries)
        );
        dedup->endAligned = false;
    }
    dedup = realloc(dedup, Dedup_SIZE(cap));
    dedup->dedupTableCap = cap;
}

// must be called with the dedup lock
static int countDuplicatesCritical(Worker_t* w, Output_t* output, int inCount) {
    LocalWorker_t* lw = &w->lw;
    Dedup_t* dedup = output->dedup = dedupChkRealloc(output->dedup, inCount);
    StateAndOutput_t* sao = output->stateAndOutput;
    int oc = sao->outCount;
    int dupeCount = 0;

    if (!dedup->endAligned) {
        // the dedup is begin-aligned, we're going to convert it to end-aligned
        // we need to read both tables backwards to construct a end-aligned table
        // which still has the "first entry" (lowest index) be the lowest hash
        // so it's is not reversed, just end-aligned
        int inputIdx = inCount - 1;
        int dedupIdx = dedup->dedupTableLen - 1;
        int outIdx = dedup->dedupTableCap - 1;
        for (;;) {
            if (inputIdx < 0) {
                // Ran out of new data, copy the rest of the table over
                while (dedupIdx >= 0) {
                    dedup->entries[outIdx--] = dedup->entries[dedupIdx--];
                }
                break;
            }
            const DedupEntry_t* in = &lw->dedupsIn[inputIdx];
            if (in->hash == 0) {
                // Duplicate with itself / invalid
                inputIdx--;
                dupeCount++;
                continue;
            }
            if (dedupIdx >= 0) {
                const uint64_t dd = dedup->entries[dedupIdx];
                if (in->hash <= dd) {
                    if (in->hash == dd) {
                        // Duplicate with an existing entry
                        inputIdx--;
                        dupeCount++;
                    }
                    dedup->entries[outIdx--] = dd;
                    dedupIdx--;
                    continue;
                }
            }
            dedup->entries[outIdx--] = in->hash;
            Buf_OBJCPY(&sao->out[oc], &lw->annsIn[in->annNum]);
            inputIdx--;
        }
        assert(outIdx >= 0);
        dedup->dedupTableLen = dedup->dedupTableCap - outIdx;
    } else {
        // We have an end-aligned dedup table, we're going to read it
        // from center to end in order to re-construct it back at the
        // beginning.
        int inputIdx = 0;
        int dedupIdx = dedup->dedupTableCap - dedup->dedupTableLen;
        int outIdx = 0;
        const int dedupTableLen = dedup->dedupTableLen;
        for (;;) {
            if (inputIdx >= inCount) {
                // Ran out of new data, copy the rest of the table over
                while (dedupIdx < dedupTableLen) {
                    dedup->entries[outIdx++] = dedup->entries[dedupIdx++];
                }
                break;
            }
            const DedupEntry_t* in = &lw->dedupsIn[inputIdx];
            if (in->hash == 0) {
                // Duplicate with itself / invalid
                inputIdx++;
                dupeCount++;
                continue;
            }
            if (dedupIdx < dedupTableLen) {
                const uint64_t dd = dedup->entries[dedupIdx];
                if (in->hash >= dd) {
                    if (in->hash == dd) {
                        // Duplicate with an existing entry
                        inputIdx++;
                        dupeCount++;
                    }
                    dedup->entries[outIdx++] = dd;
                    dedupIdx++;
                    continue;
                }
            }
            dedup->entries[outIdx++] = in->hash;
            Buf_OBJCPY(&sao->out[oc], &lw->annsIn[in->annNum]);
            inputIdx++;
        }
        assert(outIdx < dedup->dedupTableCap);
        dedup->dedupTableLen = outIdx;
    }
    sao->outCount = oc;

    return dupeCount;
}

static int dedupCompare(const void* vnegIfFirst, const void* vposIfFirst) {
    const DedupEntry_t* negIfFirst = vnegIfFirst;
    const DedupEntry_t* posIfFirst = vposIfFirst;
    if (negIfFirst->hash < posIfFirst->hash) {
        return -1;
    } else if (negIfFirst->hash > posIfFirst->hash) {
        return 1;
    }
    return 0;
}

// Expects a sorted dedup list
static void selfDedup(DedupEntry_t* dedups, int annCount) {
    uint64_t lastHash = 0;
    for (int i = 0; i < annCount; i++) {
        if (dedups[i].hash == lastHash) {
            dedups[i].hash = 0;
        }
        lastHash = dedups[i].hash;
    }
}

static const char* processAnns1(
    Worker_t* w,
    const ParseNameResult_t* pnr,
    Result_t* res,
    int fileNo,
    int annCount,
    const Config_t* conf)
{
    mkDedupes(w->lw.dedupsIn, w->lw.annsIn, annCount);
    const char* err = validateAnns(&w->lw, annCount, res, conf, pnr);
    if (err) {
        return err;
    }

    qsort(w->lw.dedupsIn, annCount, sizeof(*w->lw.dedupsIn), dedupCompare);
    selfDedup(w->lw.dedupsIn, annCount);

    uint64_t now = Time_nowMilliseconds() / 1000;
    Output_t* output = OUTPUT(w->g, pnr->parentBlockHeight);
    int dupes = 0;
    assert(!pthread_mutex_lock(&output->lock));
    do {
        StateAndOutput_t* sao = output->stateAndOutput;
        if (sao->conf.parentBlockHeight != pnr->parentBlockHeight) {
            // it was ok when we started but now it's too old
            err = "too old";
            break;
        } else if ((sao->outCount + annCount >= OUT_ANN_CAP) ||
            (sao->timeOfLastWrite + WRITE_EVERY_SECONDS < now))
        {
            // file is full (or WRITE_EVERY_SECONDS seconds have elapsed), write it out
            tryWriteAnnsCritical(w, output, NULL);
        }
        dupes = countDuplicatesCritical(w, output, annCount);
    } while (0);
    assert(!pthread_mutex_unlock(&output->lock));

    if (!err) {
        res->accepted += annCount - dupes;
        res->duplicates = dupes;
    }
    return err;
}

#define ANN_SHARE_PREFIX "annshr_"


// correct filename format is as follows: annshr_<softver>_<blocknum>_<payto>_<add>.bin
// maximum filename length is 100 chars.
// * softver is the protocol soft version
// * blocknum must be the number of the parent block for this share of anns
// * payto is the address to be paid out
// * add can be anything alphanumeric, used by the ann miner to query the result
//   of their share submission.
static const char* parseName(ParseNameResult_t* res, const char* filename) {
    uint8_t buf[101];
    buf[100] = '\0';
    strncpy(buf, filename, 100);
    if (buf[100] != '\0') {
        return "too long";
    }
    if (strncmp(buf, ANN_SHARE_PREFIX, strlen(ANN_SHARE_PREFIX))) {
        return "wrong prefix";
    }

    char* softverS = &buf[ strlen(ANN_SHARE_PREFIX) ];
    char* blocknumS = NULL;
    char* payToS = NULL;
    char* additionalS = NULL;

    for (int i = strlen(ANN_SHARE_PREFIX);; i++) {
        if (i >= 100) {
            // too much data
            return "too long";
        } if (buf[i] < 32 || buf[i] > 126) {
            // hit the end of the string, or some unexpected char
            return "bad chars";
        } else if (buf[i] == '\\' || buf[i] == '"') {
            // those chars are not allowed
            return "bad chars";
        } else if (buf[i] == '_') {
            buf[i] = '\0';
            if (!blocknumS) {
                // first _ (after the prefix) is the beginning of blocknum (end of softver)
                blocknumS = &buf[i+1];
            } else if (!payToS) {
                // second _ is the beginning of payTo (end of blockNum)
                payToS = &buf[i+1];
            } else if (!additionalS) {
                // third _ is the beginning of additional (end of payTo)
                additionalS = &buf[i+1];
            } else {
                // additional _ are not allowed
                return "too many _";
            }
        } else if (buf[i] == '.') {
            if (!additionalS) {
                // Only one . allowed
                return "malformed";
            }
            buf[i] = '\0';
            if (strcmp(buf[i+1], "bin")) {
                // must end with .bin
                return "end is not .bin";
            } else {
                break;
            }
        }
    }

    long softver = strtol(softverS, NULL, 10);
    if (softver < 1 || softver > 0x7fffffff) {
        // unparsable blocknum
        return "softver out of range";
    }
    res->softver = softver;

    long blocknum = strtol(blocknumS, NULL, 10);
    if (blocknum < 1 || blocknum > 0x7fffffff) {
        // unparsable blocknum
        return "blocknum out of range";
    }
    res->parentBlockHeight = blocknum;

    if (strlen(payToS) > 63) {
        // payto size limit
        return "payto too long";
    }
    strcpy(res->payTo, payToS);

    // we don't really care that much about the id, we're going to copy the filename wholesale
    return NULL;
}

static void cleanup(Worker_t* w) {
    int cleanupNum = (Time_nowMilliseconds() / MS_BETWEEN_CLEANUP);
    int lastCleanupNum = atomic_exchange(&w->g->lastCleanupNum, cleanupNum);
    if (lastCleanupNum == cleanupNum) {
        // someone else already got to it
        return;
    }
    
}

static void processAnns(Worker_t* w, int fileNo) {
    Result_t res; Buf_OBJSET(&res, 0);
    Config_t conf; Buf_OBJSET(&conf, 0);

    ParseNameResult_t pnr; Buf_OBJSET(&pnr, 0);
    const char* err = parseName(&pnr, w->lw.inFile->name);

    if (!err) {
        Output_t* output = OUTPUT(w->g, pnr.parentBlockHeight);
        assert(!pthread_mutex_lock(&output->lock));
        Buf_OBJCPY(&conf, &output->stateAndOutput->conf);
        assert(!pthread_mutex_unlock(&output->lock));
    }
    if (conf.parentBlockHeight != pnr.parentBlockHeight) {
        err = "height out of range";
    }

    //DEBUGF("Processing ann file %s\n", w->lw.inFile->name);
    while (!err) {
        ssize_t bytes = read(fileNo, w->lw.annsIn, sizeof(w->lw.annsIn));
        if (bytes < 0) {
            DEBUGF("Error reading file errno=[%s]\n", strerror(errno));
            err = "internal: read file";
            break;
        } else if (bytes == 0) {
            break;
        } else if (bytes < 1024) {
            DEBUGF("File [%s] contains a runt ann\n", w->lw.inFile->name);
            err = "runt file";
            break;
        }
        int annCount = bytes / 1024;
        if (annCount * 1024 != bytes) {
            DEBUGF("File [%s] size is not an even multiple of 1024\n", w->lw.inFile->name);
            err = "runt file";
            break;
        }
        err = processAnns1(w, &pnr, &res, fileNo, annCount, &conf);
    }
 
    strncpy(w->lw.tmpFile.name, w->lw.inFile->name, FilePath_NAME_SZ);
    int outFileNo = open(w->lw.tmpFile.path, O_EXCL | O_CREAT | O_WRONLY, 0666);
    if (outFileNo < 0) {
        DEBUGF("Unable to open output file [%s] [%s]\n",
            w->lw.tmpFile.path, strerror(errno));
        assert(0);
    }

    // make an eventId from the filename
    uint8_t eventBuf[32];
    Hash_compress32(eventBuf, w->lw.inFile->name, strlen(w->lw.inFile->name));
    char eventId[33];
    for (int i = 0; i < 16; i++) {
        snprintf(&eventId[i*2], 3, "%02x", eventBuf[i]);
    }

    // Align with Protocol.js Protocol_AnnsEvent_t
    char buf[2048];
    snprintf(buf, 2048, "{"
        "\"type\":\"anns\","
        "\"accepted\":%u,"
        "\"dupes\":%u,"
        "\"payTo\":\"%s\","
        "\"unsigned\":%u,"
        "\"time\":%llu,"
        "\"eventId\":\"%s\","
        "\"target\":%u,"
        "\"error\":\"%s\""
    "}\n",
        res.accepted,
        res.duplicates,
        pnr.payTo,
        res.unsignedCount,
        Time_nowMilliseconds(),
        eventId,
        res.minWork,
        (err ? err : "none")
    );
    checkedWrite(w->lw.tmpFile.path, outFileNo, buf, strlen(buf)-1);
    checkedWrite("paylog file", w->g->paylogFileNo, buf, strlen(buf));
    close(outFileNo);
    strncpy(w->lw.outFile.name, w->lw.inFile->name, FilePath_NAME_SZ);
    if (rename(w->lw.tmpFile.path, w->lw.outFile.path)) {
        DEBUGF("error renaming temp file [%s] to out file [%s] [%s]\n",
            w->lw.tmpFile.path, w->lw.outFile.path, strerror(errno));
        assert(0);
    }
    printf("%s", buf);
}

void updateConf(Worker_t* w, int inFileNo) {
    Config_t myConf;
    ssize_t bytes = read(inFileNo, &myConf, sizeof(Config_t));
    if (bytes != sizeof(Config_t)) {
        DEBUGF("Error reading conf errno=[%s]\n", strerror(errno));
        return;
    } else if (myConf.version > 0) {
        DEBUGF("Unrecognized config version [%u]\n", myConf.version);
        return;
    } else if (myConf.confToken != w->g->confToken) {
        DEBUGF0("drop config.bin file with invalid confToken\n");
        return;
    }
    Output_t* output = OUTPUT(w->g, myConf.parentBlockHeight);
    assert(!pthread_mutex_lock(&output->lock));
    tryWriteAnnsCritical(w, output, &myConf);
    assert(!pthread_mutex_unlock(&output->lock));
}

void* workerLoop(void* vWorker) {
    Worker_t* w = vWorker;
    int inFileNo = -1;
    for (;;) {
        if (inFileNo > -1) {
            close(inFileNo);
            if (unlink(w->lw.inFile->path)) {
                DEBUGF("Unable to delete input file [%s] [%s]\n",
                    w->lw.inFile->path, strerror(errno));
                assert(0);
            }
            inFileNo = -1;
        }
        w->lw.inFile = WorkQueue_workerGetWork(w->g->q, w->lw.inFile);
        if (!w->lw.inFile) {
            return NULL;
        }
    
        bool newConf = false;
        if (!strcmp(w->lw.inFile->name, "config.bin")) {
            newConf = true;
        } else if (strncmp(w->lw.inFile->name, ANN_SHARE_PREFIX, strlen(ANN_SHARE_PREFIX))) {
            // Some other type of file, skip
            continue;
        }

        inFileNo = open(w->lw.inFile->path, O_RDONLY);
        if (inFileNo < 0) {
            DEBUGF("Error opening file [%s] errno=[%s]\n", w->lw.inFile->path, strerror(errno));
            continue;
        }

        if (newConf) {
            updateConf(w, inFileNo);
        } else {
            processAnns(w, inFileNo);
        }
    }
}

///
/// Master thread stuff
///

typedef struct MasterThread_s {
    Global_t g;
    FilePath_t paylogFile;
    Time paylogCycleTime;
    int threadCount;
    Worker_t* workers;
} MasterThread_t;

static void* checkmem(void* mem) {
    assert(mem && "Not enough memory");
    return mem;
}

static void initOutput(Output_t* out) {
    out->dedup = checkmem(malloc(Dedup_SIZE(DEDUPE_INITIAL_CAP)));
    out->dedup->dedupTableCap = DEDUPE_INITIAL_CAP;
    out->dedup->dedupTableLen = 0;

    out->stateAndOutput = checkmem(calloc(sizeof(StateAndOutput_t), 1));
    out->stateAndOutput->timeOfLastWrite = Time_nowMilliseconds() / 1000;

    assert(!pthread_mutex_init(&out->lock, NULL));
}

static void destroyOutput(Output_t* out) {
    pthread_mutex_destroy(&out->lock);
    free(out->dedup);
    free(out->stateAndOutput);
}

static void initWorker(
    Worker_t* w,
    Global_t* g,
    const char* outDir,
    const char* annDir,
    const char* tmpDir
) {
    w->g = g;
    w->lw.backupSao = checkmem(calloc(sizeof(StateAndOutput_t), 1));
    FilePath_create(&w->lw.outFile, outDir);
    FilePath_create(&w->lw.annFile, annDir);
    FilePath_create(&w->lw.tmpFile, tmpDir);
    w->lw.random = randombytes_random();
}

static void destroyWorker(Worker_t* w) {
    free(w->lw.backupSao);
    FilePath_destroy(&w->lw.outFile);
    FilePath_destroy(&w->lw.annFile);
    FilePath_destroy(&w->lw.tmpFile);
}

static MasterThread_t* createMaster(
    int threadCount,
    const char* inDir,
    const char* outDir,
    const char* annDir,
    const char* tmpDir,
    const char* paylogDir
) {
    MasterThread_t* mt = checkmem(calloc(sizeof(MasterThread_t), 1));
    for (int i = 0; i < (1<<STATE_OUTPUT_BITS); i++) {
        initOutput(&mt->g.output[i]);
    }

    mt->g.q = WorkQueue_create(inDir, threadCount);

    FilePath_create(&mt->paylogFile, paylogDir);
    mt->g.paylogFileNo = -1;

    mt->threadCount = threadCount;
    mt->workers = checkmem(calloc(sizeof(Worker_t), threadCount));

    for (int i = 0; i < threadCount; i++) {
        initWorker(&mt->workers[i], &mt->g, outDir, annDir, tmpDir);
    }
    return mt;
}

static void destroyMaster(MasterThread_t* mt) {
    for (int i = 0; i < mt->threadCount; i++) {
        destroyWorker(&mt->workers[i]);
    }
    free(mt->workers);
    FilePath_destroy(&mt->paylogFile);
    WorkQueue_destroy(mt->g.q);
    for (int i = 0; i < (1<<STATE_OUTPUT_BITS); i++) {
        destroyOutput(&mt->g.output[i]);
    }
    free(mt);
}

// Open the highest numbered file in the logdir
// if mt->g.paylogFileNo > -1 then dup2 the file descriptor over this
// otherwise mt->g.paylogFileNo is configured to the fileno
// returns 0 on success, -1 on error
static int openPayLog(MasterThread_t* mt, DIR* logDir, const char* paylogDir) {
    long biggestFile = 0;
    errno = 0;
    for (;;) {
        struct dirent* file = readdir(logDir);
        if (file == NULL) {
            if (errno != 0) {
                DEBUGF("Error reading paylog dir [%s] errno=[%s]\n",
                    paylogDir, strerror(errno));
                return -1;
            }
            rewinddir(logDir);
            break;
        }
        if (strncmp(file->d_name, "paylog_", 7)) { continue; }
        long fileNum = strtol(&file->d_name[7], NULL, 10);
        if (fileNum > biggestFile) { biggestFile = fileNum; }
    }
    biggestFile++;
    snprintf(mt->paylogFile.name, FilePath_NAME_SZ, "paylog_%ld.ndjson", biggestFile);
    DEBUGF("Opening paylog file [%s]\n", mt->paylogFile.path);
    int f = open(mt->paylogFile.path, O_CREAT | O_WRONLY | O_APPEND, 0666);
    if (f < 0) {
        DEBUGF("Error opening paylog dir [%s] errno=[%s]\n", mt->paylogFile.path, strerror(errno));
        return -1;
    }
    if (mt->g.paylogFileNo > -1) {
        if (dup2(f, mt->g.paylogFileNo) < 0) {
            DEBUGF("Error: unable to dup2() outfile [%s]\n", strerror(errno));
            return -1;
        }
        close(f);
    } else {
        mt->g.paylogFileNo = f;
    }
    Time_BEGIN(mt->paylogCycleTime);
    return 0;
}

static int getNextAnn(MasterThread_t* mt, DIR* anndir, const char* annDir) {
    long biggestFile = 0;
    errno = 0;
    for (;;) {
        struct dirent* file = readdir(anndir);
        if (file == NULL) {
            if (errno != 0) {
                DEBUGF("Error reading anndir [%s] errno=[%s]\n",
                    annDir, strerror(errno));
                return -1;
            }
            rewinddir(anndir);
            break;
        }
        if (strncmp(file->d_name, "anns_", 5)) { continue; }
        long fileNum = strtol(&file->d_name[5], NULL, 10);
        if (fileNum > biggestFile) { biggestFile = fileNum; }
    }
    mt->g.nextAnnFileNo = biggestFile + 1;
    return 0;
}

static volatile bool g_pleaseStop = false;
void sigHandler(int sig) {
    g_pleaseStop = true;
    signal(sig, SIG_IGN);
}

int main(int argc, const char** argv) {
    assert(!sodium_init());
    int threads = 1;
    int arg = 1;
    unsigned long long confToken = 0;

    if ((argc - arg) < 5) { return usage(); }

    while (arg < argc) {
        if (!strcmp(argv[arg], "--threads")) {
            arg++;
            threads = strtol(argv[arg], NULL, 10);
            if (threads < 1) {
                DEBUGF("I don't understand thread count [%s]", argv[arg]);
                return 100;
            }
            arg++;
        }
        if (!strcmp(argv[arg], "--conftoken")) {
            arg++;
            confToken = strtoull(argv[arg], NULL, 16);
            if (confToken < 1) {
                DEBUGF("I don't understand conftoken [%s]", argv[arg]);
                return 100;
            }
            arg++;
        }
    }
    if ((argc - arg) < 5) { return usage(); }

    const char* inDir = argv[arg++];
    const char* outDir = argv[arg++];
    const char* annDir = argv[arg++];
    const char* tmpDir = argv[arg++];
    const char* paylogDir = argv[arg++];

    FileUtil_checkDir("input", inDir);
    FileUtil_checkDir("output", outDir);
    FileUtil_checkDir("announcement", annDir);
    FileUtil_checkDir("temp", tmpDir);
    FileUtil_checkDir("paylog", paylogDir);

    MasterThread_t* mt = createMaster(threads, inDir, outDir, annDir, tmpDir, paylogDir);

    mt->g.confToken = confToken;

    DIR* logdir = opendir(paylogDir);
    if (!logdir) {
        DEBUGF("Could not access paylog directory [%s] errno=[%s]", paylogDir, strerror(errno));
        assert(0);
    }
    if (openPayLog(mt, logdir, paylogDir)) {
        assert(0 && "Unable to open payLog");
    }

    DIR* anndir = opendir(annDir);
    if (!anndir) {
        DEBUGF("Could not access announcement output directory [%s] errno=[%s]", annDir, strerror(errno));
        assert(0);
    }
    if (getNextAnn(mt, anndir, annDir)) {
        assert(0 && "Unable to open annDir");
    }

    // Attach sig handler as late as possible before we start touching things that can
    // lead to the need to flush data to disk in order to maintain consistancy.
    signal(SIGINT, sigHandler);
    signal(SIGHUP, sigHandler);
    signal(SIGPIPE, sigHandler);

    FileUtil_mkNonblock(STDIN_FILENO);

    WorkQueue_start(mt->g.q, workerLoop, mt->workers, sizeof(mt->workers[0]));

    while (!g_pleaseStop) {
        uint8_t discard[8];
        if (1 > read(STDIN_FILENO, discard, 8) && (EAGAIN != errno)) {
            DEBUGF0("Stdin is nolonger connected, exiting\n");
            break;
        }
        if (WorkQueue_masterScan(mt->g.q)) { Time_nsleep(50000); }
        Time_END(mt->paylogCycleTime);
        if (Time_MICROS(mt->paylogCycleTime) > 60000000) {
            openPayLog(mt, logdir, paylogDir);
        }
    }

    DEBUGF0("Got request to stop, stopping threads...\n");

    WorkQueue_stop(mt->g.q);

    destroyMaster(mt);
    DEBUGF0("Graceful shutdown complete\n");
}
